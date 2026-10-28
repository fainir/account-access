"""Public Bitwarden export fixtures use the ordinary owner import boundary."""

import copy
import json
import threading
from contextlib import contextmanager

import httpx2 as httpx
import pytest

from account_access import password_import
from account_access.demo import DEMO_PASSWORD, DEMO_SEED
from account_access.errors import AccessError
from account_access.models import origin
from account_access.owner import make_owner_server
from account_access.password_import import apply, parse, preview


def login_item(url="https://example.test/login", **changes):
    item = {"id": "fictional-item", "type": 1, "deletedDate": None,
            "name": "Ignored name", "notes": "ignored-private-note",
            "passwordHistory": [{"password": "ignored-old-password"}],
            "fields": [{"name": "Ignored", "value": "ignored-custom-field"}],
            "login": {"username": "demo@example.test", "password": DEMO_PASSWORD,
                      "uris": [{"uri": url, "match": None}], "totp": None,
                      "fido2Credentials": [{"keyValue": "ignored-passkey"}]}}
    item.update(changes)
    return item


def export(*items):
    return json.dumps({"encrypted": False, "folders": [{"name": "ignored-folder"}],
                       "items": list(items)})


def selection(row="0:0", account="demo-web", **changes):
    return {"row": row, "account": account, "operations": ["summary"], **changes}


def test_bitwarden_json_preserves_unicode_and_quoted_login_values():
    item = login_item()
    item["login"].update(username="owner+\u00e9@example.test", password='unicode-\u00e9,quote"\npassword')
    rows = parse("\ufeff \n" + export(item))
    assert rows == [{"id": "0:0", "url": "https://example.test/login",
                     "username": item["login"]["username"], "password": item["login"]["password"]}]


def test_only_login_web_uris_survive_without_expanding_manager_matching_rules():
    item = login_item()
    item["login"]["uris"] = [
        {"uri": "androidapp://com.example", "match": None},
        {"uri": "https://example.test/login", "match": 3},
        {"uri": "https://example.test/login", "match": None},
        {"uri": "https://other.example.test/login", "match": 0},
        {"uri": "https://never.example.test", "match": 5},
        {"uri": "https://regex.example.test/.*", "match": 4},
        {"uri": "https://owner:password@userinfo.example.test", "match": None},
        {"uri": None, "match": None},
        {"uri": "javascript:alert(1)", "match": None},
    ]
    rows = parse(export(item, login_item(type=2), login_item(type=3),
                        login_item(deletedDate="2026-01-01T00:00:00.000Z")))
    assert [(row["id"], row["url"]) for row in rows] == [
        ("0:1", "https://example.test/login"), ("0:3", "https://other.example.test/login")]
    assert all(set(row) == {"id", "url", "username", "password"} for row in rows)


@pytest.mark.parametrize("uris", [None, [], "omitted"])
def test_login_without_uris_does_not_reject_other_valid_exported_logins(uris):
    no_destination = login_item()
    if uris == "omitted":
        no_destination["login"].pop("uris")
    else:
        no_destination["login"]["uris"] = uris
    no_destination["login"]["password"] = "unrelated-no-website-password"
    rows = parse(export(no_destination, login_item()))
    assert [row["id"] for row in rows] == ["1:0"]
    assert "unrelated-no-website-password" not in json.dumps(rows)


def test_json_preview_discards_unrelated_secrets_and_requires_selected_review(env):
    provider, broker, _ = env
    url = broker.store.config().accounts["demo-web"].login_url
    unsupported = login_item("https://unsupported.example.test")
    unsupported["login"]["password"] = "unrelated-login-password"
    result = preview(broker.store, export(login_item(url), unsupported))
    assert result["unsupported"] == 1
    assert {match["id"] for match in result["rows"][0]["matches"]} == {"demo-web"}
    public = json.dumps(result)
    staged = json.dumps(broker.store.get("password-import:" + result["id"]))
    for secret in [DEMO_PASSWORD, "ignored-private-note", "ignored-old-password",
                   "ignored-custom-field", "ignored-passkey", "ignored-folder", "unrelated-login-password"]:
        assert secret not in public
        if secret != DEMO_PASSWORD:
            assert secret not in staged
    assert "https://unsupported.example.test" not in staged
    assert DEMO_PASSWORD.encode() not in broker.store.path.read_bytes()
    assert provider.login_count == 0
    apply(broker, result["id"], [selection()], ["test"])
    assert broker.run("test", "demo-web", "summary")["status"] == "COMPLETED"
    assert provider.login_count == 1
    assert broker.store.get("password-import:" + result["id"]) is None


def test_multiple_uris_and_ambiguous_catalog_matches_do_not_choose_an_account(env):
    _, broker, _ = env
    specs = broker.store.config().accounts
    item = login_item(specs["demo-web"].login_url)
    item["login"]["uris"].extend([
        {"uri": specs["demo-mfa"].login_url, "match": 1},
        {"uri": origin(specs["demo-web"].login_url) + "/unknown", "match": None}])
    before = broker.store.config().model_dump()
    result = preview(broker.store, export(item))
    matches = [{match["id"] for match in row["matches"]} for row in result["rows"]]
    assert matches == [{"demo-web"}, {"demo-mfa"}, {"demo-web", "demo-mfa"}]
    assert broker.store.config().model_dump() == before
    with pytest.raises(AccessError, match="invalid_import_selection"):
        apply(broker, result["id"], [selection(), selection("0:2")], ["test"])
    assert broker.store.get("password-import:" + result["id"]) is not None


@pytest.mark.parametrize("include", [False, True])
def test_json_authenticator_remains_explicit_opt_in_for_matching_factor(env, include):
    provider, broker, _ = env
    item = login_item(broker.store.config().accounts["demo-mfa"].login_url)
    item["login"]["totp"] = f"otpauth://totp/Example?secret={DEMO_SEED}"
    broker.store.put("source:demo-totp", None)
    result = preview(broker.store, export(item))
    assert result["rows"][0]["has_authenticator"] is True
    assert DEMO_SEED not in json.dumps(result)
    apply(broker, result["id"], [selection(account="demo-mfa", include_authenticator=include)], ["test"])
    if include:
        assert broker.run("test", "demo-mfa", "summary")["status"] == "COMPLETED"
        assert provider.totp_count == 1
    else:
        assert broker.store.get("source:demo-totp") is None


@pytest.mark.parametrize("include", [False, True])
@pytest.mark.parametrize("owner_action", ["reenroll", "revoke", "legacy_preview"])
def test_stale_authenticator_authority_cannot_restore_an_old_export_seed(env, include, owner_action):
    from account_access.factors import enroll, revoke
    _, broker, _ = env
    store = broker.store
    item = login_item(store.config().accounts["demo-mfa"].login_url)
    item["login"]["totp"] = DEMO_SEED
    result = preview(store, export(item))
    if owner_action == "legacy_preview":
        staged = store.get("password-import:" + result["id"])
        staged.pop("source_generations")
        store.put("password-import:" + result["id"], staged)
    elif owner_action == "revoke":
        revoke(store, "demo-totp")
    else:
        # Identical seed bytes still represent a new enrollment authority.
        enroll(store, "demo-totp", {"seed": DEMO_SEED})
    source = store.get("source:demo-totp")
    generation = store.get("source-generation:demo-totp")
    credential = store.get("credential:demo-mfa")
    chosen = [selection(account="demo-mfa", include_authenticator=include)]
    if include:
        with pytest.raises(AccessError, match="import_authenticator_changed"):
            apply(broker, result["id"], chosen, ["test"])
        assert store.get("credential:demo-mfa") == credential
        assert store.get("password-import:" + result["id"]) is not None
    else:
        apply(broker, result["id"], chosen, ["test"])
    assert store.get("source:demo-totp") == source
    assert store.get("source-generation:demo-totp") == generation


def test_unsupported_totp_is_reported_without_retaining_secret(env):
    _, broker, _ = env
    item = login_item(broker.store.config().accounts["demo-mfa"].login_url)
    item["login"]["totp"] = "steam://unsupported-secret"
    result = preview(broker.store, export(item))
    assert result["rows"][0]["unsupported_authenticator"] is True
    assert result["rows"][0]["has_authenticator"] is False
    assert item["login"]["totp"] not in json.dumps(result)
    assert item["login"]["totp"] not in json.dumps(broker.store.get("password-import:" + result["id"]))


def test_json_staging_rejects_current_connector_revision_change(env):
    _, broker, _ = env
    result = preview(broker.store, export(login_item(broker.store.config().accounts["demo-web"].login_url)))
    config = broker.store.config()
    config.accounts["demo-web"].label = "Reviewed connector changed"
    broker.store.configure(config)
    previous = broker.store.get("credential:demo-web")
    with pytest.raises(AccessError, match="import_connector_changed"):
        apply(broker, result["id"], [selection()], ["test"])
    assert broker.store.get("credential:demo-web") == previous


@pytest.mark.parametrize("include", [False, True])
@pytest.mark.parametrize("format", ["csv", "json"])
def test_new_catalog_totp_definition_is_preview_only_until_selected_import(env, include, format):
    from account_access.catalog import PYPI_ACCOUNT, PYPI_SOURCE, pypi
    _, broker, _ = env
    store = broker.store
    before = store.config().model_dump()
    spec = pypi()
    item = login_item(spec.login_url)
    item["login"]["totp"] = DEMO_SEED
    raw = (export(item) if format == "json" else
           f'url,username,password,totp\n{spec.login_url},demo@example.test,{DEMO_PASSWORD},{DEMO_SEED}\n')
    result = preview(store, raw)
    assert store.config().model_dump() == before
    assert store.get("source:" + PYPI_SOURCE) is None
    assert result["rows"][0]["matches"][0]["id"] == PYPI_ACCOUNT
    assert result["rows"][0]["matches"][0]["authenticator_supported"] is True
    assert DEMO_SEED not in json.dumps(result)
    row = "0:0" if format == "json" else "0"
    apply(broker, result["id"], [{"row": row, "account": PYPI_ACCOUNT,
          "operations": ["status"], "include_authenticator": include}], ["test"])
    after = store.config()
    assert set(after.accounts) == set(before["accounts"]) | {PYPI_ACCOUNT}
    assert set(after.code_sources) == set(before["code_sources"]) | {PYPI_SOURCE}
    assert after.code_sources[PYPI_SOURCE].kind == "totp"
    assert store.get("source:" + PYPI_SOURCE) == ({"seed": DEMO_SEED} if include else None)
    assert bool(store.get("source-generation:" + PYPI_SOURCE)) is include


def test_unrelated_fixed_source_collision_does_not_block_other_password_imports(env):
    from account_access.catalog import PYPI_ACCOUNT, PYPI_SOURCE, pypi
    from account_access.models import CodeSource
    _, broker, _ = env
    store, config = broker.store, broker.store.config()
    config.code_sources[PYPI_SOURCE] = CodeSource(kind="totp")
    store.configure(config)
    store.put("source:" + PYPI_SOURCE, {"seed": "unrelated-owner-source"})
    before = store.config().model_dump()
    with pytest.raises(AccessError, match="catalog_code_source_conflict"):
        preview(store, export(login_item(pypi().login_url)))
    result = preview(store, export(login_item(config.accounts["demo-web"].login_url)))
    apply(broker, result["id"], [selection()], ["test"])
    assert store.config().model_dump() == before
    assert PYPI_ACCOUNT not in store.config().accounts
    assert store.get("source:" + PYPI_SOURCE) == {"seed": "unrelated-owner-source"}


def test_new_source_collision_after_preview_preserves_original_authority(env):
    from account_access.catalog import PYPI_ACCOUNT, PYPI_SOURCE, pypi
    from account_access.models import CodeSource
    _, broker, _ = env
    store = broker.store
    result = preview(store, export(login_item(pypi().login_url)))
    config = store.config()
    config.code_sources[PYPI_SOURCE] = CodeSource(kind="totp")
    store.configure(config)
    store.put("source:" + PYPI_SOURCE, {"seed": "unrelated-owner-source"})
    before = store.config().model_dump()
    with pytest.raises(AccessError, match="catalog_code_source_conflict"):
        apply(broker, result["id"], [{"row": "0:0", "account": PYPI_ACCOUNT,
                                    "operations": ["status"]}], ["test"])
    assert store.config().model_dump() == before
    assert store.get("credential:" + PYPI_ACCOUNT) is None
    assert store.get("source:" + PYPI_SOURCE) == {"seed": "unrelated-owner-source"}


@pytest.mark.parametrize("expired", [False, True])
def test_waiting_for_account_lock_rechecks_connector_and_preview_lifetime(env, monkeypatch, expired):
    _, broker, _ = env
    store = broker.store
    result = preview(store, export(login_item(store.config().accounts["demo-web"].login_url)))
    initial_credential = store.get("credential:demo-web")
    original_lock, changed = store.lock, False

    @contextmanager
    def intervening_owner_action(name, **kwargs):
        nonlocal changed
        if name == "account:demo-web" and not changed:
            changed = True
            if expired:
                expires = store.get("password-import:" + result["id"])["expires"]
                # Simulate a long lock wait without sleeping or changing the
                # already-authorized staging record itself.
                monkeypatch.setattr(password_import.time, "time", lambda: expires + 1)
            else:
                config = store.config()
                config.accounts["demo-web"].label = "Newer owner-reviewed connector"
                store.configure(config)
        with original_lock(name, **kwargs) as held:
            yield held

    monkeypatch.setattr(store, "lock", intervening_owner_action)
    with pytest.raises(AccessError, match="password_import_expired" if expired else "import_connector_changed"):
        apply(broker, result["id"], [selection()], ["test"])
    assert changed and store.get("credential:demo-web") == initial_credential
    if expired:
        assert store.get("password-import:" + result["id"]) is None
    else:
        assert store.config().accounts["demo-web"].label == "Newer owner-reviewed connector"
        assert store.get("password-import:" + result["id"]) is not None


def test_json_import_disconnects_an_older_password_source_and_session(env):
    _, broker, _ = env
    store = broker.store
    item = login_item(store.config().accounts["demo-web"].login_url)
    item["login"]["password"] = "new-selected-export-password"
    store.put("password-link:demo-web", {"token": "synthetic-old-link"})
    store.put("connection:demo-web", {"cookies": []})
    result = preview(store, export(item))
    apply(broker, result["id"], [selection()], ["test"])
    assert store.get("password-link:demo-web") is None
    assert store.get("connection:demo-web") is None
    assert store.get("credential:demo-web")["password"] == item["login"]["password"]


@pytest.mark.parametrize("contents", [
    '{"encrypted":false,"encrypted":true,"items":[]}',
    '{"encrypted":false,"items":[{"type":1,"type":2}]}',
    '{"encrypted":false,"items":[{"type":1,"login":{"password":"secret","password":"other"}}]}',
    '{"encrypted":false,"items":[],"ignored":{"nested":1,"nested":2}}',
    '{"encrypted":false,"items":[],"ignored":NaN}',
    '{"encrypted":false,"items":[],"ignored":Infinity}',
    '{"encrypted":false,"items":[',
])
def test_duplicate_keys_constants_and_malformed_json_are_fixed_errors(contents):
    with pytest.raises(AccessError, match="invalid_password_export") as result:
        parse(contents)
    assert "secret" not in str(result.value) and "other" not in str(result.value)


@pytest.mark.parametrize("value", [{"encrypted": True, "items": [login_item()]},
                                    {"encrypted": True, "data": "opaque-encrypted-backup"}])
def test_encrypted_exports_are_refused_before_any_preview(env, value):
    _, broker, _ = env
    with pytest.raises(AccessError, match="password_export_encrypted"):
        preview(broker.store, json.dumps(value))
    with broker.store.db() as db:
        assert not db.execute("SELECT id FROM records WHERE id LIKE 'password-import:%'").fetchall()


@pytest.mark.parametrize("value", [[], {"items": []}, {"encrypted": 0, "items": []},
                                    {"encrypted": "false", "items": []},
                                    {"encrypted": False, "items": {}}])
def test_unsupported_json_format_is_not_guessed(value):
    with pytest.raises(AccessError, match="unsupported_password_export"):
        parse(json.dumps(value))


@pytest.mark.parametrize("damage", ["item", "type", "login", "uris", "uri", "match", "username", "password", "port"])
def test_invalid_login_shapes_never_partially_import(damage):
    item = login_item()
    if damage == "item":
        item = "not-an-item"
    elif damage == "type":
        item["type"] = True
    elif damage in {"login", "uris"}:
        if damage == "login":
            item["login"] = []
        else:
            item["login"]["uris"] = "https://example.test"
    elif damage in {"uri", "match", "port"}:
        item["login"]["uris"][0] = ({"uri": 42} if damage == "uri" else
                                      {"uri": "https://example.test", "match": True} if damage == "match" else
                                      {"uri": "https://example.test:invalid"})
    else:
        item["login"][damage] = {"unexpected": "secret"}
    with pytest.raises(AccessError, match="invalid_password_export"):
        parse(export(login_item(), item))


def test_json_bounds_cover_input_items_uri_fanout_and_expanded_rows(monkeypatch):
    monkeypatch.setattr(password_import, "MAX_ROWS", 2)
    with pytest.raises(AccessError, match="invalid_password_export"):
        parse(export(*(login_item(type=2) for _ in range(3))))
    item = login_item()
    item["login"]["uris"] = [{"uri": f"https://example.test/{x}"} for x in range(2)]
    with pytest.raises(AccessError, match="invalid_password_export"):
        parse(export(item, copy.deepcopy(item)))
    monkeypatch.setattr(password_import, "MAX_ITEM_URIS", 1)
    with pytest.raises(AccessError, match="invalid_password_export"):
        parse(export(item))
    monkeypatch.setattr(password_import, "MAX_BYTES", 20)
    with pytest.raises(AccessError, match="password_file_too_large"):
        parse(export())


@pytest.mark.parametrize("contents", ['url,username,password\nhttps://example.test,person,\ud800',
                                      '{"encrypted":false,"items":[[[[' + '[' * 1100,
                                      export(login_item()).replace("demo@example.test", "\\ud800")])
def test_invalid_unicode_and_excessive_json_nesting_are_sanitized(contents):
    with pytest.raises(AccessError, match="invalid_password_export"):
        parse(contents)


def test_owner_route_keeps_legacy_request_shape_and_its_capability_boundary(env, monkeypatch):
    _, broker, agent_token = env
    server, owner_token = make_owner_server(broker)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{server.server_port}"
    raw = export(login_item(broker.store.config().accounts["demo-web"].login_url))
    try:
        with httpx.Client(base_url=base, trust_env=False) as client:
            assert client.post("/owner/import/preview", json={"csv": raw}, headers={
                "Authorization": "Bearer " + agent_token, "Origin": base}).status_code == 403
            headers = {"Authorization": "Bearer " + owner_token, "Origin": base}
            response = client.post("/owner/import/preview", json={"csv": raw}, headers=headers)
            assert response.status_code == 200 and response.json()["rows"][0]["id"] == "0:0"
            assert DEMO_PASSWORD not in response.text
            monkeypatch.setattr(password_import, "MAX_BYTES", 128)
            response = client.post("/owner/import/preview", json={"csv": raw}, headers=headers)
            assert response.status_code == 403
            assert response.json()["reason"] == "password_file_too_large"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
