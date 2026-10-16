import threading
import time

import httpx2 as httpx

from account_access.errors import AccessError
from account_access.owner import make_owner_server


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
