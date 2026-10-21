"""Explicit owner edits cannot be silently undone by an old manager link."""

import threading

import httpx2 as httpx
import pytest

from account_access import password_sync
from account_access.errors import AccessError
from account_access.models import TaskRequest
from account_access.owner import make_owner_server


def save_owner_credential(broker, account, chosen):
    server, token = make_owner_server(broker)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{server.server_port}"
    try:
        with httpx.Client(base_url=base, trust_env=False) as client:
            return client.post("/owner/credential", json={"account": account, **chosen},
                               headers={"Authorization": "Bearer " + token, "Origin": base})
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


@pytest.mark.parametrize("changed", ["username", "password", "unchanged"])
def test_owner_credential_edit_preserves_the_chosen_login(env, monkeypatch, changed):
    provider, broker, _ = env
    store = broker.store
    account = "demo-web"
    original = store.get("credential:" + account)
    fetched = []

    def fetch(link, expected_origin):
        fetched.append(expected_origin)
        return dict(original)

    monkeypatch.setattr(password_sync, "fetch", fetch)
    password_sync.enroll(store, account, {
        "endpoint": "https://manager.example.test", "vault": "a" * 26,
        "item": "b" * 26, "token": "synthetic-manager-token"})
    assert broker.run("test", account, "summary")["status"] == "COMPLETED"
    previous_session = store.get("connection:" + account)
    previous_link = store.get("password-link:" + account)
    fetches = len(fetched)
    chosen = dict(original)
    if changed == "username":
        chosen["username"] = "new-owner@example.test"
    elif changed == "password":
        chosen["password"] = provider.password = "explicit-owner-password"
    with store.db() as db:
        grants = [tuple(x) for x in db.execute("SELECT * FROM grants ORDER BY 1,2,3")]
    attention = store.challenge(account, "captcha", "browser_captcha_required")
    response = save_owner_credential(broker, account, chosen)
    assert response.status_code == 200
    assert response.json() == {"status": "SAVED"}
    assert chosen["password"] not in response.text
    assert store.get("credential:" + account) == chosen
    assert store.pending(account)[0]["id"] == attention["id"]
    with store.db() as db:
        assert grants == [tuple(x) for x in db.execute("SELECT * FROM grants ORDER BY 1,2,3")]
    if changed == "unchanged":
        assert store.get("password-link:" + account) == previous_link
        assert store.get("connection:" + account) == previous_session
        return
    assert store.get("password-link:" + account) is None
    assert store.get("connection:" + account) is None
    with store.lock("account:" + account):
        password_sync.refresh(store, account, force=True)
    assert len(fetched) == fetches
    assert store.get("credential:" + account) == chosen
    if changed == "password":
        # Only the fixture owner resolves its independent attention gate. The
        # subsequent website login must use the edited password, without sync.
        with store.db() as db:
            db.execute("UPDATE challenges SET resolved=1 WHERE id=?", (attention["id"],))
        store.put("login-attempt:" + account, 0)
        assert broker.run("test", account, "summary")["status"] == "COMPLETED"
        assert len(fetched) == fetches and provider.login_count == 2


@pytest.mark.parametrize("reason", ["password_source_access_removed", "password_source_item_changed",
                                   "password_sync_identity_mismatch", "password_sync_connector_changed"])
def test_replacing_a_failed_source_resumes_the_original_task(env, monkeypatch, reason):
    provider, broker, _ = env
    store = broker.store
    account = "demo-web"
    original = store.get("credential:" + account)
    fetched, available = [], True

    def fetch(link, expected_origin):
        fetched.append(expected_origin)
        if not available:
            raise AccessError("NEEDS_USER", reason)
        return dict(original)

    monkeypatch.setattr(password_sync, "fetch", fetch)
    password_sync.enroll(store, account, {
        "endpoint": "https://manager.example.test", "vault": "a" * 26,
        "item": "b" * 26, "token": "synthetic-manager-token"})
    available = False
    link = store.get("password-link:" + account)
    link["next_at"] = 0
    store.put("password-link:" + account, link)
    task = broker.submit("test", TaskRequest.model_validate({
        "key": "manual-login-replaces-failed-source",
        "steps": [{"account": account, "operation": "summary"}]}))
    broker.tick()
    assert broker.task("test", task["task_id"])["status"] == "NEEDS_USER"
    assert store.pending(account)[0]["reason"] == reason and provider.login_count == 0
    chosen = {**original, "password": "explicit-owner-recovery-password"}
    provider.password = chosen["password"]
    fetches = len(fetched)
    response = save_owner_credential(broker, account, chosen)
    assert response.status_code == 200
    assert not store.pending(account)
    with store.db() as db:
        db.execute("UPDATE jobs SET next_at=0 WHERE id=?", (task["task_id"],))
    broker.tick()
    result = broker.task("test", task["task_id"])
    assert result["status"] == "COMPLETED" and result["progress"] == 1
    assert result["task_id"] == task["task_id"] and provider.login_count == 1
    assert len(fetched) == fetches and store.get("password-link:" + account) is None


def test_manual_edit_cannot_clear_an_unbound_historical_source_gate(env):
    _, broker, _ = env
    store, account = broker.store, "demo-web"
    challenge = store.challenge(account, "login", "password_source_access_removed")
    original = store.get("credential:" + account)
    response = save_owner_credential(broker, account, {**original, "password": "new-owner-password"})
    assert response.status_code == 200
    assert store.pending(account)[0]["id"] == challenge["id"]
