import threading
import time

import httpx2 as httpx

from account_access.errors import AccessError
from account_access.owner import make_owner_server
from account_access.demo import DEMO_PASSWORD
from account_access.models import TaskRequest


def test_only_owner_can_finish_an_already_stopped_visible_review(env, monkeypatch):
    _, broker, agent_token = env
    attention_allowed = threading.Event()
    read_started = threading.Event()
    before = broker.store.config().model_dump()

    def inspect(*args, **kwargs):
        assert kwargs["visible"] is True
        read_started.set()
        assert attention_allowed.wait(5)
        kwargs["on_attention"]("NEEDS_USER", "browser_action_required", "action", {})
        assert kwargs["review_stop"].wait(5)
        raise AccessError("NEEDS_USER", "browser_action_required", "action")

    monkeypatch.setattr(broker.browser, "read", inspect)
    server, token = make_owner_server(broker, guided=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{server.server_port}"
    headers = {"Authorization": "Bearer " + token, "Origin": base}
    try:
        with httpx.Client(base_url=base, trust_env=False) as client:
            job = client.post("/owner/verify", json={"account": "demo-web", "visible": True}, headers=headers).json()
            ident = job["id"]
            assert read_started.wait(3)
            path = "/owner/verify/finish-review"
            assert client.post(path, json={"id": ident}, headers=headers).status_code == 403
            attention_allowed.set()
            deadline = time.monotonic() + 3
            while time.monotonic() < deadline:
                state = client.get("/owner/state", headers=headers).json()
                if state["connection_jobs"][ident].get("attention"):
                    break
                time.sleep(.01)
            assert state["connection_jobs"][ident]["status"] == "RUNNING"
            for invalid_headers in [{}, {"Authorization": "Bearer " + agent_token, "Origin": base},
                                    {"Authorization": "Bearer " + token, "Origin": "https://evil.test"}]:
                assert client.post(path, json={"id": ident}, headers=invalid_headers).status_code == 403
            assert client.post(path, json={"id": "unknown"}, headers=headers).status_code == 403
            assert client.post(path, json={"id": ident, "account": "demo-web"}, headers=headers).status_code == 400
            assert client.post(path, json={"id": ident}, headers=headers).json() == {"status": "REVIEW_FINISHED"}
            deadline = time.monotonic() + 3
            while time.monotonic() < deadline:
                state = client.get("/owner/state", headers=headers).json()
                result = state["connection_jobs"][ident]
                if result["status"] != "RUNNING":
                    break
                time.sleep(.01)
            assert result["status"] == "NEEDS_USER" and result["reason"] == "browser_action_required"
            assert client.post(path, json={"id": ident}, headers=headers).status_code == 403
            assert broker.store.config().model_dump() == before
    finally:
        attention_allowed.set()
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def test_saving_password_preserves_presence_gates_and_original_pending_task(env):
    provider, broker, _ = env
    account = "demo-web"
    protected = [broker.store.challenge(account, kind, "browser_" + kind + "_required")
                 for kind in ["captcha", "device", "passkey", "admin", "recovery", "unknown", "action"]]
    password = broker.store.challenge(account, "login", "password_not_connected")
    task = broker.submit("test", TaskRequest.model_validate({"key": "credential-does-not-verify-presence",
        "steps": [{"account": account, "operation": "summary"}]}))
    broker.tick()
    assert broker.task("test", task["task_id"])["status"] == "NEEDS_USER"
    server, token = make_owner_server(broker, guided=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{server.server_port}"
    try:
        with httpx.Client(base_url=base, trust_env=False) as client:
            response = client.post("/owner/credential", headers={"Authorization": "Bearer " + token, "Origin": base},
                json={"account": account, "username": "demo@example.test", "password": DEMO_PASSWORD})
            assert response.json() == {"status": "SAVED"}
        pending = broker.store.pending(account)
        assert {x["id"] for x in pending} == {x["id"] for x in protected}
        assert password["id"] not in {x["id"] for x in pending}
        broker.tick()
        original = broker.task("test", task["task_id"])
        assert original["status"] == "NEEDS_USER" and original["progress"] == 0
        assert provider.login_count == 0
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def test_changed_browser_credentials_cannot_keep_the_previous_verified_session(env):
    provider, broker, _ = env
    account = "demo-web"
    assert broker.run("test", account, "summary")["status"] == "COMPLETED"
    saved = broker.store.get("connection:" + account)
    assert saved and provider.login_count == 1
    server, token = make_owner_server(broker, guided=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{server.server_port}"
    headers = {"Authorization": "Bearer " + token, "Origin": base}
    try:
        with httpx.Client(base_url=base, trust_env=False) as client:
            credential = {"account": account, "username": "demo@example.test", "password": DEMO_PASSWORD}
            assert client.post("/owner/credential", headers=headers, json=credential).json()["status"] == "SAVED"
            assert broker.store.get("connection:" + account) == saved
            assert client.post("/owner/credential", headers=headers,
                json={**credential, "username": "other@example.test"}).json()["status"] == "SAVED"
            assert broker.store.get("connection:" + account) is None
            assert provider.login_count == 1
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
