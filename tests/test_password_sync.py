import copy
import json
import threading
import time
from contextlib import ExitStack
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest
from fastapi.testclient import TestClient

from account_access.demo import DEMO_PASSWORD
from account_access.errors import AccessError
from account_access.models import TaskRequest
from account_access.password_sync import due, enroll, refresh, unlink, view
from account_access.service import create_app


@pytest.fixture
def manager(env):
    _, broker, _ = env
    vault, item = "a" * 26, "b" * 26
    state = {"status": 200, "calls": 0, "item": {
        "id": item, "vault": {"id": vault}, "category": "LOGIN", "state": "ACTIVE",
        "urls": [{"href": broker.store.config().accounts["demo-web"].login_url}],
        "fields": [{"purpose": "USERNAME", "value": "demo@example.test"},
                   {"purpose": "PASSWORD", "value": DEMO_PASSWORD}]}}

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_GET(self):
            assert self.path == f"/v1/vaults/{vault}/items/{item}"
            assert self.headers["Authorization"] == "Bearer synthetic-connect-token"
            state["calls"] += 1
            self.send_response(state["status"])
            if state["status"] == 307:
                self.send_header("Location", "/unexpected-secret-destination")
            self.end_headers()
            self.wfile.write(json.dumps(state["item"]).encode())

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    link = {"endpoint": f"http://127.0.0.1:{server.server_port}", "vault": vault,
            "item": item, "token": "synthetic-connect-token"}
    try:
        yield state, link
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def test_rotation_reauthenticates_without_owner_or_permission_expansion(env, manager):
    provider, broker, token = env
    state, link = manager
    with broker.store.db() as db:
        before = [tuple(x) for x in db.execute("SELECT * FROM grants ORDER BY 1,2,3")]
    enroll(broker.store, "demo-web", link)
    assert broker.run("test", "demo-web", "summary")["status"] == "COMPLETED"
    assert provider.login_count == 1
    provider.password = state["item"]["fields"][1]["value"] = "changed-synthetic-password"
    saved = broker.store.get("password-link:demo-web")
    saved["next_at"] = 0
    broker.store.put("password-link:demo-web", saved)
    broker.store.put("login-attempt:demo-web", 0)
    due(broker.store)
    result = broker.run("test", "demo-web", "summary")
    assert result["status"] == "COMPLETED"
    assert provider.login_count == 2
    assert not broker.store.pending("demo-web")
    with broker.store.db() as db:
        assert before == [tuple(x) for x in db.execute("SELECT * FROM grants ORDER BY 1,2,3")]
    with TestClient(create_app(broker, worker=False)) as client:
        auth = {"Authorization": "Bearer " + token}
        for path in ["/v1/accounts", "/v1/audit"]:
            text = client.get(path, headers=auth).text
            assert provider.password not in text and link["token"] not in text
        assert client.post("/owner/password-sync", headers=auth, json=link).status_code == 404
    assert provider.password.encode() not in broker.store.path.read_bytes()
    assert link["token"] not in json.dumps(view(broker.store))


@pytest.mark.parametrize("change", ["username", "origin", "deleted", "duplicate", "item", "vault"])
def test_sync_stops_on_changed_identity_destination_or_item(env, manager, change):
    _, broker, _ = env
    state, link = manager
    enroll(broker.store, "demo-web", link)
    original = broker.store.get("credential:demo-web")
    item = state["item"]
    if change == "username":
        item["fields"][0]["value"] = "different-owner@example.test"
    elif change == "origin":
        item["urls"] = [{"href": "https://phishing.example"}]
    elif change == "deleted":
        item["state"] = "TRASHED"
    elif change == "duplicate":
        item["fields"].append(copy.deepcopy(item["fields"][1]))
    else:
        if change == "item":
            item["id"] = "c" * 26
        else:
            item["vault"]["id"] = "c" * 26
    with broker.store.lock("account:demo-web"):
        with pytest.raises(AccessError):
            refresh(broker.store, "demo-web", force=True)
    assert broker.store.get("credential:demo-web") == original
    assert broker.run("test", "demo-web", "summary")["status"] == "NEEDS_USER"


def test_sync_rejects_redirect_and_network_error_retries_without_owner(env, manager):
    _, broker, _ = env
    state, link = manager
    enroll(broker.store, "demo-web", link)
    state["status"] = 503
    saved = broker.store.get("password-link:demo-web")
    saved["next_at"] = 0
    broker.store.put("password-link:demo-web", saved)
    assert broker.run("test", "demo-web", "summary")["status"] == "RETRYABLE"
    assert not broker.store.pending("demo-web")
    state["status"] = 307
    with broker.store.lock("account:demo-web"):
        with pytest.raises(AccessError, match="password_source_access_removed"):
            refresh(broker.store, "demo-web", force=True)
    assert state["calls"] == 3


def test_sync_reenrollment_unlink_and_configuration_drift(env, manager):
    _, broker, _ = env
    _, link = manager
    with pytest.raises(AccessError, match="invalid_password_sync_link"):
        enroll(broker.store, "demo-web", {**link, "item": "../other"})
    with pytest.raises(AccessError, match="password_sync_requires_https_origin"):
        enroll(broker.store, "demo-web", {**link, "endpoint": "https://example.com/path"})
    enroll(broker.store, "demo-web", link)
    broker.store.challenge("demo-web", "action", "browser_action_required")
    with broker.store.lock("account:demo-web"):
        refresh(broker.store, "demo-web", force=True)
    assert broker.store.pending("demo-web")[0]["kind"] == "action"
    config = broker.store.config()
    config.accounts["demo-web"].label = "Changed connector"
    broker.store.configure(config)
    with pytest.raises(AccessError, match="password_sync_connector_changed"):
        refresh(broker.store, "demo-web", force=True)
    unlink(broker.store, "demo-web")
    assert broker.store.get("credential:demo-web") is None
    assert broker.store.get("connection:demo-web") is None
    assert view(broker.store) == []


def test_sync_cannot_silently_change_existing_account_identity(env, manager):
    _, broker, _ = env
    state, link = manager
    state["item"]["fields"][0]["value"] = "other@example.test"
    with pytest.raises(AccessError, match="password_sync_identity_mismatch"):
        enroll(broker.store, "demo-web", link)
    assert not broker.store.get("password-link:demo-web")


def test_import_removes_old_continuous_source(env, manager):
    from account_access.password_import import apply, preview
    _, broker, _ = env
    _, link = manager
    enroll(broker.store, "demo-web", link)
    url = broker.store.config().accounts["demo-web"].login_url
    staged = preview(broker.store, f"url,username,password\n{url},demo@example.test,new-import\n")
    apply(broker, staged["id"], [{"row": "0", "account": "demo-web", "operations": ["summary"]}], ["test"])
    assert broker.store.get("password-link:demo-web") is None
    assert broker.store.get("credential:demo-web")["password"] == "new-import"


@pytest.mark.parametrize("update", ["refresh", "reenroll"])
def test_source_update_preserves_unrelated_login_presence_and_original_task(env, manager, update):
    provider, broker, _ = env
    state, link = manager
    account = "demo-web"
    enroll(broker.store, account, link)
    protected = [broker.store.challenge(account, kind, "browser_" + kind + "_required")
                 for kind in ["captcha", "device", "passkey", "admin", "recovery", "unknown",
                              "action", "email", "sms", "totp", "method"]]
    protected.append(broker.store.challenge(account, "login", "browser_login_failed"))
    task = broker.submit("test", TaskRequest.model_validate({
        "key": "password-rotation-does-not-verify-website",
        "steps": [{"account": account, "operation": "summary"}]}))
    broker.tick()
    assert broker.task("test", task["task_id"])["status"] == "NEEDS_USER"
    provider.password = state["item"]["fields"][1]["value"] = "rotated-synthetic-password"
    if update == "reenroll":
        enroll(broker.store, account, link)
    else:
        saved = broker.store.get("password-link:" + account)
        saved["next_at"] = 0
        broker.store.put("password-link:" + account, saved)
    broker.tick()
    assert broker.store.get("credential:" + account)["password"] == provider.password
    assert {x["id"] for x in broker.store.pending(account)} == {x["id"] for x in protected}
    original = broker.task("test", task["task_id"])
    assert original["task_id"] == task["task_id"]
    assert original["status"] == "NEEDS_USER" and original["progress"] == 0
    assert provider.login_count == 0


@pytest.mark.parametrize("reason", ["password_not_connected", "browser_login_required"])
def test_rotation_can_resume_only_the_original_credential_prerequisite(env, manager, reason):
    provider, broker, _ = env
    state, link = manager
    account = "demo-web"
    enroll(broker.store, account, link)
    broker.store.challenge(account, "login", reason)
    task = broker.submit("test", TaskRequest.model_validate({
        "key": "password-rotation-repairs-credential-prerequisite",
        "steps": [{"account": account, "operation": "summary"}]}))
    broker.tick()
    assert broker.task("test", task["task_id"])["status"] == "NEEDS_USER"
    provider.password = state["item"]["fields"][1]["value"] = "rotated-synthetic-password"
    saved = broker.store.get("password-link:" + account)
    saved["next_at"] = 0
    broker.store.put("password-link:" + account, saved)
    # The existing task's retry time passes without a new owner action.
    with broker.store.db() as db:
        db.execute("UPDATE jobs SET next_at=0 WHERE id=?", (task["task_id"],))
    broker.tick()
    original = broker.task("test", task["task_id"])
    assert original["task_id"] == task["task_id"]
    assert original["status"] == "COMPLETED" and original["progress"] == 1
    assert not broker.store.pending(account)
    assert provider.login_count == 1


def test_source_repair_resumes_original_task_without_a_password_change(env, manager):
    provider, broker, _ = env
    state, link = manager
    account = "demo-web"
    enroll(broker.store, account, link)
    state["status"] = 403
    saved = broker.store.get("password-link:" + account)
    saved["next_at"] = 0
    broker.store.put("password-link:" + account, saved)
    task = broker.submit("test", TaskRequest.model_validate({
        "key": "source-repair-resumes-original-task",
        "steps": [{"account": account, "operation": "summary"}]}))
    broker.tick()
    assert broker.task("test", task["task_id"])["status"] == "NEEDS_USER"
    assert broker.store.pending(account)[0]["reason"] == "password_source_access_removed"
    assert provider.login_count == 0
    state["status"] = 200
    saved = broker.store.get("password-link:" + account)
    saved["next_at"] = 0
    broker.store.put("password-link:" + account, saved)
    with broker.store.db() as db:
        db.execute("UPDATE jobs SET next_at=0 WHERE id=?", (task["task_id"],))
    broker.tick()
    assert broker.task("test", task["task_id"])["status"] == "COMPLETED"
    assert not broker.store.pending(account)
    assert provider.login_count == 1


def test_reenrollment_immediately_resumes_original_task_before_next_source_poll(env, manager):
    provider, broker, _ = env
    state, link = manager
    store, account = broker.store, "demo-web"
    enroll(store, account, link)
    state["status"] = 403
    saved = store.get("password-link:" + account)
    saved["next_at"] = 0
    store.put("password-link:" + account, saved)
    task = broker.submit("test", TaskRequest.model_validate({
        "key": "reenrollment-immediately-repairs-source",
        "steps": [{"account": account, "operation": "summary"}]}))
    broker.tick()
    assert broker.task("test", task["task_id"])["status"] == "NEEDS_USER"
    assert store.pending(account)[0]["reason"] == "password_source_access_removed"
    with store.db() as db:
        grants = [tuple(row) for row in db.execute("SELECT * FROM grants ORDER BY 1,2,3")]
    state["status"] = 200
    assert enroll(store, account, link) == {"status": "SYNCED", "account": account}
    assert store.get("password-link:" + account)["next_at"] > time.time()
    # Source repair is immediately usable, but is not website verification.
    assert not store.pending(account)
    assert store.get("connection:" + account) is None
    assert provider.login_count == 0
    with store.db() as db:
        db.execute("UPDATE jobs SET next_at=0 WHERE id=?", (task["task_id"],))
        assert grants == [tuple(row) for row in db.execute("SELECT * FROM grants ORDER BY 1,2,3")]
    # Leave the newly linked source's future next_at unchanged. The original
    # task must resume on this tick rather than wait for its five-minute poll.
    broker.tick()
    original = broker.task("test", task["task_id"])
    assert original["task_id"] == task["task_id"]
    assert original["status"] == "COMPLETED" and original["progress"] == 1
    assert provider.login_count == 1


def test_failed_reenrollment_preserves_source_gate_old_link_and_credential(env, manager):
    provider, broker, _ = env
    state, link = manager
    store, account = broker.store, "demo-web"
    enroll(store, account, link)
    state["status"] = 403
    saved = store.get("password-link:" + account)
    saved["next_at"] = 0
    store.put("password-link:" + account, saved)
    assert broker.run("test", account, "summary")["status"] == "NEEDS_USER"
    old_link, credential, pending = (store.get("password-link:" + account),
                                    store.get("credential:" + account), store.pending(account))
    with pytest.raises(AccessError, match="password_source_access_removed"):
        enroll(store, account, link)
    assert store.get("password-link:" + account) == old_link
    assert store.get("credential:" + account) == credential
    assert store.pending(account) == pending
    assert provider.login_count == 0


def test_source_outage_cannot_submit_a_stale_password_during_retry_backoff(env, manager):
    provider, broker, _ = env
    state, link = manager
    account = "demo-web"
    enroll(broker.store, account, link)
    state["status"] = 503
    posted_before = provider.posted_paths[:]
    saved = broker.store.get("password-link:" + account)
    saved["next_at"] = 0
    broker.store.put("password-link:" + account, saved)
    for _ in range(2):
        result = broker.run("test", account, "summary")
        assert result["status"] == "RETRYABLE"
        assert result["reason"] == "password_source_unavailable"
        assert not broker.store.pending(account)
        assert provider.login_count == 0 and provider.posted_paths == posted_before
    # The second call reached forced source validation at the new-login
    # boundary, even though its background retry timestamp had not elapsed.
    assert state["calls"] == 3
    state["status"] = 200
    assert broker.run("test", account, "summary")["status"] == "COMPLETED"
    assert provider.login_count == 1
    assert not broker.store.pending(account)


def test_due_rotates_past_more_than_two_locked_accounts(env, monkeypatch):
    from account_access import password_sync
    _, broker, _ = env
    store = broker.store
    accounts = [f"sync-{n:02}" for n in range(6)]
    for account in accounts:
        store.put("password-link:" + account, {"next_at": 0})
    refreshed = []

    def refresh_one(store, account):
        refreshed.append(account)
        store.put("password-link:" + account, {"next_at": time.time() + 300})

    monkeypatch.setattr(password_sync, "refresh", refresh_one)
    acquired, release = threading.Event(), threading.Event()

    def hold_busy_accounts():
        with ExitStack() as locks:
            for account in accounts[:3]:
                locks.enter_context(store.lock("account:" + account))
            acquired.set()
            assert release.wait(10)

    thread = threading.Thread(target=hold_busy_accounts)
    thread.start()
    try:
        assert acquired.wait(5)
        due(store)
        due(store)
        assert refreshed == [accounts[3]]
        due(store)
        assert refreshed == accounts[3:]
    finally:
        release.set()
        thread.join(timeout=5)
    assert not thread.is_alive()
    # Previously busy links are still reached after the scan wraps around.
    due(store)
    due(store)
    assert set(refreshed) == set(accounts)


def test_due_bounds_inspection_and_keeps_rotating_over_not_due_records(env, monkeypatch):
    _, broker, _ = env
    store = broker.store
    keys = [f"password-link:sync-{n:02}" for n in range(45)]
    for key in keys:
        store.put(key, {"next_at": time.time() + 300})
    inspected = []
    original_get = store.get

    def tracked_get(key, *args, **kwargs):
        if key.startswith("password-link:"):
            inspected.append(key)
        return original_get(key, *args, **kwargs)

    monkeypatch.setattr(store, "get", tracked_get)
    due(store)
    assert inspected == keys[:20]
    due(store)
    assert inspected == keys[:40]
    due(store)
    assert inspected == keys
    due(store)
    assert inspected == keys + keys[:20]


@pytest.mark.parametrize("action", ["edit", "unlink"])
def test_inflight_enrollment_cannot_overwrite_a_later_owner_action(env, manager, monkeypatch, action):
    from account_access import password_sync
    _, broker, _ = env
    _, link = manager
    store = broker.store
    account = "demo-web"
    fetched, release, owner_started = threading.Event(), threading.Event(), threading.Event()
    original_fetch = password_sync.fetch
    failures = []
    edited = {"username": "demo@example.test", "password": "newer-owner-password"}

    def delayed_fetch(*args):
        credential = original_fetch(*args)
        fetched.set()
        if not release.wait(10):
            raise AssertionError("source response was never released")
        return credential

    monkeypatch.setattr(password_sync, "fetch", delayed_fetch)

    def connect():
        try:
            enroll(store, account, link)
        except BaseException as exc:
            failures.append(exc)

    def owner_action():
        try:
            owner_started.set()
            if action == "unlink":
                unlink(store, account)
            else:
                # The explicit owner edit detaches the manager like a reviewed
                # CSV import. It shares the same account lock as enrollment.
                with store.lock("account:" + account):
                    with store.db() as db:
                        store.put("credential:" + account, edited, db=db)
                        store.put("password-link:" + account, None, db=db)
                        store.put("connection:" + account, None, db=db)
        except BaseException as exc:
            failures.append(exc)

    connecting = threading.Thread(target=connect)
    overriding = threading.Thread(target=owner_action)
    connecting.start()
    try:
        assert fetched.wait(5)
        # A real competing lock proves that the fetched response is still
        # serialized; no timing sleep or thread scheduling assumption is used.
        with pytest.raises(AccessError, match="account_busy"):
            with store.lock("account:" + account, timeout=0):
                pass
        overriding.start()
        assert owner_started.wait(5)
    finally:
        release.set()
        connecting.join(timeout=5)
        if overriding.ident is not None:
            overriding.join(timeout=5)
    assert not connecting.is_alive() and not overriding.is_alive()
    assert failures == []
    assert store.get("password-link:" + account) is None
    assert store.get("credential:" + account) == (edited if action == "edit" else None)
    assert store.get("connection:" + account) is None
