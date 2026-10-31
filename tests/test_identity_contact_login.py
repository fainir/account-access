"""Fictional ID/phone/SMS journey; no insurance account or physical phone."""

from contextlib import contextmanager
import json
from pathlib import Path
import threading
import time

import httpx2 as httpx
import pytest
from playwright.sync_api import sync_playwright
from pydantic import ValidationError

from account_access.errors import AccessError
from account_access.factors import replace_source, source_mutation
from account_access.models import BrowserAccount, BrowserOperation, CodeSource, Configuration, LoginForm, TaskRequest
from account_access.owner import make_owner_server
from account_access.phone import deliver


ACCOUNT = "identity-fixture"
SOURCE = "identity-phone"
CREDENTIAL = {"identity": "fixture-identity", "phone": "fixture-phone"}


def enable_source(broker, enabled):
    with source_mutation(broker.store, SOURCE), broker.store.db() as db:
        replace_source(broker.store, SOURCE, {"enabled": enabled}, db=db)


def configure(env, *, revoke_on_delivery=False, javascript=False, harel_public_form=False):
    provider, broker, _ = env
    provider.identity_contact_mode = True
    provider.identity_contact_harel_form = harel_public_form
    provider.identity_contact_get_attempted = False
    base = provider.base + "/sms"
    identity_selector = "#uid" if harel_public_form else "#identity"
    spec = BrowserAccount(
        kind="browser", label="Fictional identity login", login_url=base + "/login", ready_selector="#ready",
        javascript=javascript,
        login=LoginForm(submit_selector="#login-submit", code_wait_ms=5000,
                        identity_contact={"identity_selector": identity_selector, "phone_selector": "#phone",
                                          "post_url": base + "/login"},
                        factors={"sms": {"code_source": SOURCE, "code_selector": "#code",
                                         "code_submit_selector": "#code-submit"}}),
        login_resources=[base + "/login", base + "/code", base + "/summary"],
        login_post_urls=[base + "/login", base + "/code"],
        challenge_selectors={"login": "#identity-login", "sms": "#sms-challenge", "action": "#action-challenge"},
        operations={"status": BrowserOperation(description="Confirm the signed-in session", session_only=True,
                                                url=base + "/summary")})
    config = broker.store.config()
    config.accounts[ACCOUNT] = spec
    config.code_sources[SOURCE] = CodeSource(kind="phone_relay", sender="Fictional", recipient="owner",
                                            template="Fictional login: {code}")
    broker.store.configure(Configuration.model_validate(config.model_dump()))
    broker.store.put("credential:" + ACCOUNT, dict(CREDENTIAL))
    broker.store.put("phone-pair:" + SOURCE, {"token": "fictional-pair-token"})
    enable_source(broker, True)
    broker.grant("test", ACCOUNT, ["status"])
    delivered = []

    def delivery(kind, code):
        assert kind == "sms"
        if revoke_on_delivery:
            enable_source(broker, False)
            return
        message = {"id": "fixture-" + str(len(delivered)), "sender": "Fictional", "recipient": "owner",
                   "body": "Fictional login: " + code, "received_at": time.time()}
        with pytest.raises(AccessError, match="phone_message_mismatch"):
            deliver(broker.store, SOURCE, {**message, "sender": "Unrelated"}, pair_token="fictional-pair-token")
        assert deliver(broker.store, SOURCE, message, pair_token="fictional-pair-token") == {"status": "RECEIVED"}
        delivered.append(message)

    provider.delivery = delivery
    return delivered


@contextmanager
def owner(broker):
    server, token = make_owner_server(broker, guided=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{server.server_port}"
    try:
        with httpx.Client(base_url=base, trust_env=False) as client:
            yield client, {"Authorization": "Bearer " + token, "Origin": base}, base, token
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


@pytest.mark.parametrize("javascript", [False, True])
def test_identity_sms_task_recovers_reuses_and_expires_without_secret_output(env, javascript):
    provider, broker, _ = env
    delivered = configure(env, javascript=javascript)
    job = broker.submit("test", TaskRequest(key="identity-status", steps=[{"account": ACCOUNT, "operation": "status"}]))
    broker.advance(job["task_id"])
    result = broker.task("test", job["task_id"])
    assert result["status"] == "COMPLETED"
    assert result["results"][0]["data"] == {"authenticated": True}
    assert provider.identity_contact_received and provider.login_count == provider.sms_count == 1
    assert broker.run("test", ACCOUNT, "status")["data"] == {"authenticated": True}
    assert provider.login_count == 1
    with pytest.raises(AccessError, match="no_current_login_window"):
        deliver(broker.store, SOURCE, delivered[0], pair_token="fictional-pair-token")
    provider.sessions.clear()
    broker.store.put("login-attempt:" + ACCOUNT, 0)
    assert broker.run("test", ACCOUNT, "status")["data"] == {"authenticated": True}
    assert provider.login_count == provider.sms_count == 2
    output = json.dumps([result, broker.accounts("test")])
    assert all(secret not in output for secret in [*CREDENTIAL.values(), provider.last_login_code])
    provider.transaction_challenge = True
    assert broker.run("test", ACCOUNT, "status")["challenge"]["kind"] == "action"
    assert provider.sms_count == 2


@pytest.mark.parametrize("case", ["missing", "password_shape", "get_form", "submit_override", "redirect_replay",
                                  "missing_source", "revoked_during_delivery", "skipped_sms"])
def test_identity_flow_refuses_incomplete_or_changed_authority(env, case):
    provider, broker, _ = env
    configure(env, revoke_on_delivery=case == "revoked_during_delivery")
    if case == "missing":
        broker.store.put("credential:" + ACCOUNT, None)
    elif case == "password_shape":
        broker.store.put("credential:" + ACCOUNT, {"username": CREDENTIAL["identity"], "password": CREDENTIAL["phone"]})
    elif case == "get_form":
        provider.identity_contact_form_method = "get"
    elif case == "submit_override":
        provider.identity_contact_submit_target = "/sms/code"
    elif case == "redirect_replay":
        provider.login_redirect = provider.base + "/sms/code"
    elif case == "missing_source":
        enable_source(broker, False)
    elif case == "skipped_sms":
        provider.identity_contact_skip_sms = True
    result = broker.run("test", ACCOUNT, "status")
    if case == "revoked_during_delivery":
        assert result["status"] == "DENIED" and result["reason"] == "login_code_window_missing"
    else:
        assert result["status"] == "NEEDS_USER", result
    assert "data" not in result
    assert provider.sms_count == 0
    assert not broker.store.get("connection:" + ACCOUNT)
    if case not in {"revoked_during_delivery", "skipped_sms", "redirect_replay"}:
        assert provider.login_count == 0 and not provider.identity_contact_received


def test_harel_public_get_form_refuses_before_identity_or_phone_enters_url(env):
    """Pin the public Harel form shape without submitting to the real insurer."""
    provider, broker, _ = env
    configure(env, harel_public_form=True)
    provider.identity_contact_form_method = "get"
    result = broker.run("test", ACCOUNT, "status")
    assert result["status"] == "NEEDS_USER"
    assert result["reason"] == "login_form_destination_changed"
    assert not provider.identity_contact_get_attempted
    assert provider.login_count == provider.sms_count == 0
    assert not provider.identity_contact_received
    assert not broker.store.get("connection:" + ACCOUNT)
    assert all(secret not in json.dumps(result) for secret in CREDENTIAL.values())


def test_identity_owner_enrollment_is_separate_and_does_not_clear_presence_gates(env):
    _, broker, agent_token = env
    configure(env)
    assert broker.run("test", ACCOUNT, "status")["status"] == "COMPLETED"
    broker.store.challenge(ACCOUNT, "device", "browser_device_required")
    broker.store.challenge(ACCOUNT, "login", "identity_contact_not_connected")
    with owner(broker) as (client, headers, _, _):
        body = {"account": ACCOUNT, "identity": "replacement-fixture", "phone": "replacement-phone"}
        assert client.post("/owner/credential", json=body, headers={**headers, "Authorization": "Bearer " + agent_token}).status_code == 403
        for invalid in [{"account": ACCOUNT, "username": "x", "password": "y"},
                        {**body, "password": "unrelated"}, {**body, "identity": " "},
                        {**body, "phone": "x\nvalue"}, {**body, "identity": "x" * 129}]:
            assert client.post("/owner/credential", json=invalid, headers=headers).status_code == 400
        assert client.post("/owner/credential", json=body, headers=headers).json() == {"status": "SAVED"}
        state = client.get("/owner/state", headers=headers).json()
    assert broker.store.get("credential:" + ACCOUNT) == {k: body[k] for k in ["identity", "phone"]}
    assert broker.store.get("connection:" + ACCOUNT) is None
    assert [x["kind"] for x in broker.store.pending(ACCOUNT)] == ["device"]
    item = next(x for x in state["accounts"] if x["account"] == ACCOUNT)
    assert item["login_method"] == "identity_phone_sms"
    assert all(value not in json.dumps(state) for value in [body["identity"], body["phone"]])


def test_identity_accounts_cannot_import_or_sync_passwords_or_expand_read_scope(env):
    from account_access.password_import import preview
    from account_access.password_sync import validate_link
    _, broker, _ = env
    configure(env)
    config = broker.store.config()
    url = config.accounts[ACCOUNT].login_url
    result = preview(broker.store, f"name,url,username,password\nExample,{url},fake-id,fake-phone\n")
    assert not any(ACCOUNT in json.dumps(row) for row in result.get("rows", []))
    with pytest.raises(AccessError, match="password_sync_account_unsupported"):
        validate_link(broker.store, ACCOUNT, {})
    for change in ["read", "alias", "mixed_password", "no_sms"]:
        data = config.model_dump()
        spec = data["accounts"][ACCOUNT]
        if change == "read":
            spec["operations"]["status"].update(session_only=False, fields={"name": "#private"})
        elif change == "alias":
            spec["password_import_origins"] = ["https://example.test"]
        elif change == "mixed_password":
            spec["login"]["password_selector"] = "#password"
        else:
            spec["login"]["factors"] = {}
        with pytest.raises(ValidationError):
            Configuration.model_validate(data)


def test_identity_schema_preserves_existing_password_fingerprints(env, monkeypatch):
    _, broker, _ = env
    config = broker.store.config()
    before = config.fingerprint("demo-web")
    original = BrowserAccount.model_dump

    def old_dump(self, **kwargs):
        data = original(self, **kwargs)
        if data.get("login"):
            data["login"].pop("identity_contact", None)
        return data

    monkeypatch.setattr(BrowserAccount, "model_dump", old_dump)
    assert config.fingerprint("demo-web") == before


@pytest.mark.parametrize(("empty_fields", "expected"), [
    (("username_selector",), "38a680b076f4ec072387fa92d68967529643e716c730dd2135b409a875985e21"),
    (("password_selector",), "7d909a55414edb8db1813df600a77d444988f8c3b4ec7786d68b0c9af26726df"),
    (("username_selector", "password_selector"), "0a6b342e5856b3ffa5cced69ca59affd0e08cee5d95de41a83e9e9d3d8b94339"),
])
def test_existing_empty_controls_do_not_block_configuration_upgrade(empty_fields, expected):
    # Golden fingerprints were generated with the frozen build80 model. An
    # unusable old connector must not stop unrelated accounts loading on update.
    data = json.loads((Path(__file__).parents[1] / "examples/browser-verification.json").read_text())
    for name in empty_fields:
        data["accounts"]["example-account"]["login"][name] = ""
    config = Configuration.model_validate(data)
    assert config.fingerprint("example-account") == expected
    assert Configuration.model_validate_json(config.model_dump_json()).fingerprint("example-account") == expected


@pytest.mark.parametrize("missing", ["username_selector", "password_selector"])
def test_password_login_still_requires_both_control_fields(missing):
    fields = {"username_selector": "#username", "password_selector": "#password", "submit_selector": "#sign-in"}
    fields.pop(missing)
    with pytest.raises(ValidationError):
        LoginForm.model_validate(fields)


def test_identity_login_never_reads_a_password_manager(env, monkeypatch):
    _, broker, _ = env
    configure(env)

    def unexpected_refresh(*args, **kwargs):
        raise AssertionError("Identity/phone login cannot refresh a password source")

    monkeypatch.setattr("account_access.password_sync.refresh", unexpected_refresh)
    assert broker.run("test", ACCOUNT, "status")["data"] == {"authenticated": True}
    assert broker.run("test", ACCOUNT, "status")["data"] == {"authenticated": True}


def test_identity_values_are_redacted_at_the_agent_boundary(env, monkeypatch):
    from account_access.providers import credential_values
    _, broker, _ = env
    configure(env)
    assert credential_values(CREDENTIAL) == set(CREDENTIAL.values())
    # Exercise the broker's independent defense against an adapter returning
    # unexpected text. Normal identity operations return only authenticated=True.
    monkeypatch.setattr(broker.browser, "read", lambda *args, **kwargs: {"unexpected": list(CREDENTIAL.values())})
    assert broker.run("test", ACCOUNT, "status")["data"] == {"unexpected": ["[REDACTED]", "[REDACTED]"]}


def test_owner_browser_masks_identity_phone_and_saves_distinct_fields(env):
    _, broker, _ = env
    configure(env)
    with owner(broker) as (_, _, base, token), sync_playwright() as pw:
        browser = pw.chromium.launch(headless=True, chromium_sandbox=True)
        try:
            page = browser.new_page()
            page.goto(base + "/manage#" + token)
            page.get_by_text("Save identity and phone for permitted login recovery", exact=True).click()
            identity = page.get_by_label("Identity number", exact=True)
            phone = page.get_by_label("Phone number for login SMS", exact=True)
            assert identity.get_attribute("type") == phone.get_attribute("type") == "password"
            identity.fill("browser-fixture-identity")
            phone.fill("browser-fixture-phone")
            identity.locator("xpath=..").get_by_role("button", name="Save locally").click()
            page.get_by_text("Saved locally.", exact=True).wait_for()
            assert identity.input_value() == phone.input_value() == ""
            assert broker.store.get("credential:" + ACCOUNT) == {
                "identity": "browser-fixture-identity", "phone": "browser-fixture-phone"}
        finally:
            browser.close()


def test_guided_browser_adds_identity_login_with_owner_selected_sms_scope(env, monkeypatch):
    provider, broker, _ = env
    configure(env)
    config = broker.store.config()
    spec = config.accounts.pop(ACCOUNT)
    broker.store.configure(config)
    broker.store.put("credential:" + ACCOUNT, None)
    broker.store.new_client("generic")
    monkeypatch.setattr("account_access.catalog.entries", lambda: {ACCOUNT: spec})
    monkeypatch.setattr("account_access.install.install_detected", lambda store: {"status": "INSTALLED"})
    with owner(broker) as (_, _, base, token), sync_playwright() as pw:
        browser = pw.chromium.launch(headless=True, chromium_sandbox=True)
        try:
            page = browser.new_page()
            page.goto(base + "/#" + token)
            page.locator("#service option").wait_for(state="attached")
            page.locator("#show-connect").click()
            identity = page.get_by_label("Identity number", exact=True)
            phone = page.get_by_label("Phone number for login SMS", exact=True)
            assert identity.get_attribute("type") == phone.get_attribute("type") == "password"
            identity.fill(CREDENTIAL["identity"])
            phone.fill(CREDENTIAL["phone"])
            page.locator("#allow").check()
            with page.expect_response(lambda response: response.url == base + "/owner/add") as reply:
                page.locator("#add").click()
            assert reply.value.status == 200
            # Refresh removes the newly connected catalog entry and may relabel
            # these same controls for the next service before this assertion.
            assert page.locator("#username").input_value() == page.locator("#password").input_value() == ""
            deadline = time.monotonic() + 15
            while time.monotonic() < deadline and not broker.store.get("connection:" + ACCOUNT):
                time.sleep(.05)
            assert broker.store.get("connection:" + ACCOUNT)
            assert broker.store.get("credential:" + ACCOUNT) == CREDENTIAL
            assert provider.login_count == provider.sms_count == 1
        finally:
            browser.close()
    assert broker.run("generic", ACCOUNT, "status")["data"] == {"authenticated": True}
