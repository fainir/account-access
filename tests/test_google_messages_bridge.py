from contextlib import contextmanager
import secrets
import socket
import threading

import httpx2 as httpx
import pytest

from account_access.google_messages import handle
from account_access.owner import make_owner_server
from test_google_messages import armed, delivery


@contextmanager
def private_bridge(broker):
    path = str(broker.store.root / "browser-owner.sock")
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(path)
    token = secrets.token_urlsafe(32)
    server, _ = make_owner_server(broker, guided=True, owner_token=token,
                                 server_socket=listener, origin_port=8765, local_host_actions=False)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        with httpx.Client(transport=httpx.HTTPTransport(uds=path), base_url="http://127.0.0.1:8765",
                          headers={"Authorization": "Bearer " + token, "Origin": "http://127.0.0.1:8765"},
                          trust_env=False) as client:
            yield client
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def test_protected_browser_bridge_delivers_only_to_an_enrolled_active_window(env, monkeypatch):
    _, broker, _ = env
    codes, started, base = armed(broker)
    monkeypatch.setattr("account_access.google_messages_host.load_key", lambda *a: pytest.fail("No keyring read"))
    with private_bridge(broker) as client:
        missing = client.post("/owner/browser-message", json={"message": delivery({**base, "window": "0" * 32})})
        assert missing.status_code == 403
        result = client.post("/owner/browser-message", json={"message": delivery(base)})
        assert result.status_code == 200 and result.json() == {"status": "RECEIVED"}
        assert "123456" not in result.text
        assert codes.resolve("google-sms", started, set()) == "123456"
        broker.store.put("source:google-sms", {"enabled": False})
        result = client.post("/owner/browser-message", json={"message": delivery(base)})
        assert result.status_code == 403


@pytest.mark.parametrize("body", [
    {"message": {"method": "session-import"}},
    {"message": {"method": "credential"}},
    {"message": {"method": "pending", "path": "/tmp/untrusted"}},
    {"message": {"method": "pending"}, "token": "untrusted"},
    {"method": "pending"},
])
def test_protected_bridge_cannot_select_owner_routes_or_import_cookies(env, body):
    _, broker, _ = env
    with private_bridge(broker) as client:
        result = client.post("/owner/browser-message", json=body)
        assert result.status_code in {400, 403}
        assert result.json()["status"] == "DENIED"


def test_browser_bridge_is_not_exposed_by_the_legacy_loopback_console(env):
    _, broker, _ = env
    server, token = make_owner_server(broker, guided=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        url = "http://127.0.0.1:" + str(server.server_port)
        result = httpx.post(url + "/owner/browser-message", json={"message": {"method": "pending"}},
                            headers={"Authorization": "Bearer " + token, "Origin": url}, trust_env=False)
        assert result.status_code == 403 and result.json()["reason"] == "trusted_owner_route_required"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def test_private_browser_bridge_requires_the_private_owner_capability(env):
    _, broker, _ = env
    with private_bridge(broker) as client:
        result = client.post("/owner/browser-message", json={"message": {"method": "pending"}},
                             headers={"Authorization": "Bearer invalid"})
        assert result.status_code == 403
        assert handle(broker.store, {"method": "pending"}) == {"pending": [], "source_enabled": False}


@pytest.mark.asyncio
async def test_agent_transport_cannot_reach_browser_bridge(env):
    from account_access.service import create_app
    _, broker, token = env
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=create_app(broker, worker=False)),
                                 base_url="http://localhost", headers={"Authorization": "Bearer " + token}) as client:
        for path in ["/owner/browser-message", "/v1/browser-message"]:
            result = await client.post(path, json={"message": {"method": "pending"}})
            assert result.status_code == 404
