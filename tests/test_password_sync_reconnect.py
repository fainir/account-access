import copy
import json
import threading

import pytest

from account_access import password_sync
from account_access.errors import AccessError
from account_access.models import TaskRequest


@pytest.fixture(params=["connect", "service-account"])
def linked(env, monkeypatch, request):
    provider, broker, _ = env
    store = broker.store
    saved = store.get("credential:demo-web")
    state = {"calls": [], "credential": saved, "error": None}

    def fetch(connection, expected_origin):
        state["calls"].append((copy.deepcopy(connection), expected_origin))
        if state["error"]:
            raise state["error"]
        return dict(state["credential"])

    monkeypatch.setattr(password_sync, "fetch", fetch)
    connection = {"token": "synthetic-old-token", "vault": "a" * 26, "item": "b" * 26}
    if request.param == "service-account":
        connection["provider"] = password_sync.SERVICE_ACCOUNT
    else:
        connection["endpoint"] = "https://connect.example.test"
    password_sync.enroll(store, "demo-web", connection)
    return provider, broker, state, connection


def grants(store):
    with store.db() as db:
        return [tuple(row) for row in db.execute("SELECT * FROM grants ORDER BY 1,2,3")]


def reconnect(store, *, token="synthetic-new-token", generation=None):
    return password_sync.reconnect(store, "demo-web", {
        "token": token, "generation": generation or password_sync.view(store)[0]["generation"]})


def test_token_replacement_keeps_exact_target_and_preserves_authority(linked):
    _, broker, state, connection = linked
    store = broker.store
    old = store.get("password-link:demo-web")
    before = grants(store)
    unrelated = store.challenge("demo-web", "passkey", "browser_passkey_required")
    repaired = store.challenge("demo-web", "login", "password_source_access_removed")
    store.put("connection:demo-web", {"synthetic": "existing-session"})
    assert reconnect(store) == {"status": "SYNCED", "account": "demo-web"}
    new = store.get("password-link:demo-web")
    assert state["calls"][-1][0] == {**connection, "token": "synthetic-new-token"}
    assert state["calls"][-1][1] == state["calls"][0][1]
    assert new["generation"] != old["generation"]
    assert {key: new[key] for key in ["username", "fingerprint", "vault", "item"]} == {
        key: old[key] for key in ["username", "fingerprint", "vault", "item"]}
    assert store.get("connection:demo-web") == {"synthetic": "existing-session"}
    assert grants(store) == before
    pending = store.pending("demo-web")
    assert {item["id"] for item in pending} == {unrelated["id"]}
    assert repaired["id"] not in {item["id"] for item in pending}
    public = json.dumps(password_sync.view(store))
    for secret in ["synthetic-old-token", "synthetic-new-token", state["credential"]["password"],
                   connection["vault"], connection["item"]]:
        assert secret not in public
        assert secret.encode() not in store.path.read_bytes()


def test_token_replacement_adopts_rotated_password_and_invalidates_session_atomically(linked):
    _, broker, state, _ = linked
    store = broker.store
    store.put("connection:demo-web", {"synthetic": "old-session"})
    state["credential"] = {**state["credential"], "password": "synthetic-rotated-password"}
    before = grants(store)
    reconnect(store)
    assert store.get("credential:demo-web") == state["credential"]
    assert store.get("connection:demo-web") is None
    assert grants(store) == before


def test_renewed_token_resumes_original_task_and_real_controlled_password_login(linked):
    provider, broker, state, _ = linked
    store = broker.store
    state["error"] = AccessError("DENIED", "password_source_access_removed")
    source = store.get("password-link:demo-web")
    source["next_at"] = 0
    store.put("password-link:demo-web", source)
    task = broker.submit("test", TaskRequest.model_validate({
        "key": "renew-token-without-reentering-source",
        "steps": [{"account": "demo-web", "operation": "summary"}]}))
    broker.tick()
    assert broker.task("test", task["task_id"])["status"] == "NEEDS_USER"
    assert provider.login_count == 0
    state["error"] = None
    provider.password = "synthetic-new-manager-password"
    state["credential"] = {**state["credential"], "password": provider.password}
    before = grants(store)
    reconnect(store)
    assert not store.pending("demo-web")
    assert provider.login_count == 0
    with store.db() as db:
        db.execute("UPDATE jobs SET next_at=0 WHERE id=?", (task["task_id"],))
    broker.tick()
    original = broker.task("test", task["task_id"])
    assert original["status"] == "COMPLETED" and original["progress"] == 1
    assert provider.login_count == 1
    assert state["calls"][-1][0]["token"] == "synthetic-new-token"
    assert grants(store) == before


@pytest.mark.parametrize("status,reason", [("RETRYABLE", "password_source_unavailable"),
                                          ("DENIED", "password_source_access_removed"),
                                          ("DENIED", "password_source_item_changed")])
def test_failed_replacement_preserves_old_source_credentials_session_and_gates(linked, status, reason):
    _, broker, state, _ = linked
    store = broker.store
    store.put("connection:demo-web", {"synthetic": "existing-session"})
    store.challenge("demo-web", "login", "password_source_access_removed")
    previous = [store.get(key + ":demo-web") for key in ["password-link", "credential", "connection"]]
    pending = store.pending("demo-web")
    before = grants(store)
    state["error"] = AccessError(status, reason)
    with pytest.raises(AccessError, match=reason):
        reconnect(store)
    assert [store.get(key + ":demo-web") for key in ["password-link", "credential", "connection"]] == previous
    assert store.pending("demo-web") == pending
    assert grants(store) == before


@pytest.mark.parametrize("change", ["source", "token", "edit", "unlink", "connector", "username"])
def test_stale_reconnect_never_restores_replaced_or_removed_authority(linked, change):
    _, broker, state, connection = linked
    store = broker.store
    generation = password_sync.view(store)[0]["generation"]
    expected = "password_sync_connection_changed"
    if change == "source":
        password_sync.enroll(store, "demo-web", {**connection, "item": "c" * 26})
    elif change == "token":
        reconnect(store, token="synthetic-intervening-token")
    elif change == "unlink":
        password_sync.unlink(store, "demo-web")
        expected = "password_sync_not_connected"
    elif change == "edit":
        with store.lock("account:demo-web"):
            store.put("credential:demo-web", {"username": "demo@example.test", "password": "owner-edit"})
            store.put("password-link:demo-web", None)
        expected = "password_sync_not_connected"
    elif change == "connector":
        config = store.config()
        config.accounts["demo-web"].label = "Changed reviewed connector"
        store.configure(config)
        expected = "password_sync_connector_changed"
    elif change == "username":
        store.put("credential:demo-web", {"username": "different@example.test", "password": "owner-edit"})
        expected = "password_sync_identity_mismatch"
    calls = len(state["calls"])
    old = store.get("password-link:demo-web"), store.get("credential:demo-web")
    with pytest.raises(AccessError, match=expected):
        reconnect(store, generation=generation)
    assert len(state["calls"]) == calls
    assert (store.get("password-link:demo-web"), store.get("credential:demo-web")) == old


@pytest.mark.parametrize("mutation,reason", [("generation", "password_sync_connection_changed"),
                                            ("connector", "password_sync_connector_changed")])
def test_network_result_rechecks_current_authority_before_commit(linked, monkeypatch, mutation, reason):
    _, broker, _, _ = linked
    store = broker.store
    previous = store.get("credential:demo-web")
    original = password_sync.fetch

    def changed_while_waiting(*args):
        result = original(*args)
        if mutation == "generation":
            link = store.get("password-link:demo-web")
            link["generation"] = "c" * 32
            store.put("password-link:demo-web", link)
        else:
            config = store.config()
            config.accounts["demo-web"].label = "Changed during source read"
            store.configure(config)
        return {**result, "password": "stale-response-password"}

    monkeypatch.setattr(password_sync, "fetch", changed_while_waiting)
    with pytest.raises(AccessError, match=reason):
        reconnect(store)
    assert store.get("credential:demo-web") == previous
    assert store.get("password-link:demo-web")["token"] == "synthetic-old-token"


@pytest.mark.parametrize("change", ["edit", "remove"])
def test_reconnect_helper_cannot_adopt_config_changed_after_outer_check(linked, monkeypatch, change):
    _, broker, state, _ = linked
    store = broker.store
    previous = store.get("password-link:demo-web"), store.get("credential:demo-web")
    original = password_sync.validate_link

    def changed_before_helper_snapshot(*args):
        result = original(*args)
        config = store.config()
        if change == "edit":
            config.accounts["demo-web"].label = "Changed before helper snapshot"
        else:
            config.accounts.pop("demo-web")
        store.configure(config)
        return result

    monkeypatch.setattr(password_sync, "validate_link", changed_before_helper_snapshot)
    with pytest.raises(AccessError, match="password_sync_connector_changed"):
        reconnect(store)
    assert len(state["calls"]) == 1  # The replacement token was never fetched.
    assert (store.get("password-link:demo-web"), store.get("credential:demo-web")) == previous


def test_background_refresh_preserves_reconnect_generation(linked):
    _, broker, _, _ = linked
    store = broker.store
    before = password_sync.view(store)[0]["generation"]
    with store.lock("account:demo-web"):
        password_sync.refresh(store, "demo-web", force=True)
    assert password_sync.view(store)[0]["generation"] == before


def test_reconnect_waiting_for_replacement_rechecks_generation_after_account_lock(linked, monkeypatch):
    _, broker, state, connection = linked
    store = broker.store
    generation = password_sync.view(store)[0]["generation"]
    fetched, release, reconnect_started = threading.Event(), threading.Event(), threading.Event()
    original = password_sync.fetch
    errors = []

    def delayed_fetch(*args):
        result = original(*args)
        fetched.set()
        assert release.wait(5)
        return result

    monkeypatch.setattr(password_sync, "fetch", delayed_fetch)

    def replace():
        try:
            password_sync.enroll(store, "demo-web", {**connection, "item": "c" * 26})
        except Exception as exc:
            errors.append(exc)

    def repair_old():
        reconnect_started.set()
        try:
            reconnect(store, generation=generation)
        except Exception as exc:
            errors.append(exc)

    replacing, stale = threading.Thread(target=replace), threading.Thread(target=repair_old)
    replacing.start()
    try:
        assert fetched.wait(5)
        with pytest.raises(AccessError, match="account_busy"):
            with store.lock("account:demo-web", timeout=0):
                pass
        stale.start()
        assert reconnect_started.wait(5)
    finally:
        release.set()
        replacing.join(timeout=5)
        if stale.ident is not None:
            stale.join(timeout=5)
    assert not replacing.is_alive() and not stale.is_alive()
    assert len(errors) == 1 and isinstance(errors[0], AccessError)
    assert errors[0].reason == "password_sync_connection_changed"
    assert store.get("password-link:demo-web")["item"] == "c" * 26
    assert store.get("password-link:demo-web")["token"] == "synthetic-old-token"
    assert len(state["calls"]) == 2  # Initial enrollment and replacement only.


def test_legacy_links_get_one_opaque_generation_without_changing_source_authority(linked):
    _, broker, _, _ = linked
    store = broker.store
    old = store.get("password-link:demo-web")
    old.pop("generation")
    store.put("password-link:demo-web", old)
    before = grants(store)
    first = password_sync.view(store)[0]
    assert password_sync.GENERATION.fullmatch(first["generation"])
    assert password_sync.view(store)[0]["generation"] == first["generation"]
    saved = store.get("password-link:demo-web")
    assert {key: value for key, value in saved.items() if key != "generation"} == old
    assert grants(store) == before


def test_legacy_generation_migration_waits_for_busy_account_without_blocking_state(linked):
    _, broker, _, _ = linked
    store = broker.store
    old = store.get("password-link:demo-web")
    old.pop("generation")
    store.put("password-link:demo-web", old)
    acquired, release = threading.Event(), threading.Event()

    def busy():
        with store.lock("account:demo-web"):
            acquired.set()
            assert release.wait(5)

    thread = threading.Thread(target=busy)
    thread.start()
    try:
        assert acquired.wait(5)
        assert password_sync.view(store)[0]["generation"] is None
        assert store.get("password-link:demo-web") == old
    finally:
        release.set()
        thread.join(timeout=5)
    assert not thread.is_alive()
    assert password_sync.GENERATION.fullmatch(password_sync.view(store)[0]["generation"])


@pytest.mark.parametrize("update", [{"generation": "x" * 32}, {"generation": "a" * 31},
                                    {"generation": None}, {"endpoint": "https://elsewhere.test"},
                                    {"provider": "other-provider"}, {"item": "c" * 26},
                                    {"token": None}, {"token": ""}, {"token": "x\ny"},
                                    {"token": "x" * 8193}])
def test_reconnect_rejects_target_overrides_and_malformed_input(linked, update):
    _, broker, state, _ = linked
    store = broker.store
    data = {"token": "synthetic-new-token", "generation": password_sync.view(store)[0]["generation"], **update}
    previous = store.get("password-link:demo-web")
    calls = len(state["calls"])
    with pytest.raises(AccessError, match="invalid_password_sync_link"):
        password_sync.reconnect(store, "demo-web", data)
    assert len(state["calls"]) == calls
    assert store.get("password-link:demo-web") == previous
