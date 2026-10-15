import copy
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest
from fastapi.testclient import TestClient

from account_access.demo import DEMO_PASSWORD
from account_access.errors import AccessError
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
