import concurrent.futures
import time

import pytest

from account_access.errors import AccessError
from account_access.models import CodeSource
from account_access.native_messages import (
    NativeMessagesRelay,
    NativeMessagesUnavailable,
    request_body,
    response_body,
)


def body(action="begin"):
    value = {
        "action": action,
        "source": "sms",
        "sender": "Example",
        "template": "Example login: {code}",
        "started": time.time(),
    }
    if action == "read":
        value.update(after_row=42, used=[])
    return value


def pending(relay):
    deadline = time.monotonic() + 2
    while time.monotonic() < deadline:
        request = relay.next()["request"]
        if request is not None:
            return request
        time.sleep(0.005)
    raise AssertionError("No bounded native request appeared")


def test_private_relay_returns_only_matching_single_use_reply():
    relay = NativeMessagesRelay()
    with concurrent.futures.ThreadPoolExecutor() as pool:
        future = pool.submit(relay.request, body(), lambda: None)
        request = pending(relay)
        assert request["body"]["action"] == "begin"
        relay.respond(request["id"], {"status": "READY", "after_row": 42})
        assert future.result(timeout=2) == {"status": "READY", "after_row": 42}
    assert relay.next()["request"] is None and not relay.pending
    with pytest.raises(AccessError, match="native_messages_request_missing"):
        relay.respond(request["id"], {"status": "READY", "after_row": 42})
    assert "Example" not in repr(relay)


def test_revocation_while_waiting_prevents_delivery():
    relay = NativeMessagesRelay()
    revoked = False

    def guard():
        if revoked:
            raise AccessError("DENIED", "verification_source_disabled")

    with concurrent.futures.ThreadPoolExecutor() as pool:
        future = pool.submit(relay.request, body("read"), guard)
        request = pending(relay)
        revoked = True
        assert relay.next()["request"] is None
        with pytest.raises(AccessError):
            relay.respond(
                request["id"], {"status": "FOUND", "id": "fictional-message", "code": "123456"}
            )
        with pytest.raises(AccessError, match="verification_source_disabled"):
            future.result(timeout=2)
    assert not relay.pending


@pytest.mark.parametrize("mode", ["timeout", "close"])
def test_stopped_or_expired_requests_cannot_receive_late_codes(mode):
    relay = NativeMessagesRelay(timeout=0.15 if mode == "timeout" else 8)
    with concurrent.futures.ThreadPoolExecutor() as pool:
        future = pool.submit(relay.request, body("read"), lambda: None)
        request = pending(relay)
        if mode == "close":
            relay.close()
        with pytest.raises(NativeMessagesUnavailable):
            future.result(timeout=2)
    with pytest.raises(AccessError, match="native_messages_request_missing"):
        relay.respond(
            request["id"], {"status": "FOUND", "id": "fictional-message", "code": "123456"}
        )
    assert not relay.pending


@pytest.mark.parametrize(
    "action,value",
    [
        ("begin", {"status": "READY", "after_row": True}),
        ("begin", {"status": "READY", "after_row": 2**63}),
        ("begin", {"status": "READY", "after_row": 0, "extra": "do not expose"}),
        ("begin", {"status": "FOUND", "id": "fictional-message", "code": "123456"}),
        ("read", {"status": "FOUND", "id": "fictional-message", "code": "12345"}),
        ("read", {"status": "FOUND", "id": "fictional-message", "code": 123456}),
        ("read", {"status": "FOUND", "id": "", "code": "123456"}),
        ("read", {"status": "NEEDS_USER", "reason": "untrusted raw message"}),
    ],
)
def test_reader_response_is_typed_and_bounded(action, value):
    with pytest.raises(AccessError, match="invalid_message_reader_response") as error:
        response_body(action, value)
    assert "do not expose" not in str(error.value)


@pytest.mark.parametrize(
    "field,value",
    [
        ("started", True),
        ("started", float("nan")),
        ("started", 0),
        ("source", ""),
        ("sender", "Example\n"),
        ("template", "Missing code placeholder"),
        ("after_row", True),
        ("used", ["x" * 129]),
    ],
)
def test_invalid_native_requests_are_rejected_before_queueing(field, value):
    request = body("read")
    request[field] = value
    with pytest.raises(AccessError, match="invalid_native_messages_request"):
        request_body(request)


def test_isolated_codes_rechecks_source_and_removes_failed_baseline_window(env):
    _, broker, _ = env
    config = broker.store.config()
    config.code_sources["sms"] = CodeSource(
        kind="mac_messages", sender="Example", recipient="owner", template="Example login: {code}"
    )
    broker.store.configure(config)
    broker.store.put("source:sms", {"enabled": True})

    def transport(request, guard):
        guard()
        assert broker.store.get("code-window:sms") is not None
        broker.store.put("source:sms", {"enabled": False})
        return {"status": "READY", "after_row": 42}

    broker.codes.native_transport = transport
    with pytest.raises(AccessError, match="verification_source_disabled"):
        broker.codes.begin("sms", "demo-web", time.time())
    assert broker.store.get("code-window:sms") is None


def test_collector_cannot_be_enabled_on_legacy_loopback():
    from account_access.owner import make_owner_server

    with pytest.raises(AccessError, match="trusted_owner_route_required"):
        make_owner_server(None, native_messages=NativeMessagesRelay())


def test_private_unix_transport_and_agent_surface_remain_separate(env):
    import json
    import socket
    import threading
    import httpx2 as httpx
    from fastapi.testclient import TestClient
    from account_access.owner import make_owner_server
    from account_access.service import create_app

    _, broker, agent_token = env
    relay = NativeMessagesRelay()
    path = str(broker.store.root / "native.sock")
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(path)
    listener.listen(8)
    server, token = make_owner_server(
        broker,
        server_socket=listener,
        origin_port=8765,
        local_host_actions=False,
        native_messages=relay,
    )
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        with httpx.Client(
            transport=httpx.HTTPTransport(uds=path),
            base_url="http://127.0.0.1:8765",
            trust_env=False,
        ) as client:
            route = "/owner/native-messages/next"
            assert client.get(route).status_code == 401
            headers = {"Authorization": "Bearer " + token, "Origin": "http://127.0.0.1:8765"}
            with concurrent.futures.ThreadPoolExecutor() as pool:
                future = pool.submit(relay.request, body("read"), lambda: None)
                pending(relay)
                response = client.get(route, headers=headers)
                item = response.json()["request"]
                assert response.status_code == 200 and "code" not in item["body"]
                reply = {
                    "id": item["id"],
                    "response": {"status": "FOUND", "id": "fictional-message", "code": "123456"},
                }
                assert (
                    client.post(
                        "/owner/native-messages/respond",
                        headers={"Authorization": "Bearer " + token},
                        json=reply,
                    ).status_code
                    == 403
                )
                accepted = client.post(
                    "/owner/native-messages/respond", headers=headers, json=reply
                )
                assert accepted.json() == {"status": "ACCEPTED"}
                assert future.result(timeout=2)["code"] == "123456"
                assert "123456" not in json.dumps(client.get(route, headers=headers).json())
        with TestClient(create_app(broker, worker=False)) as agent:
            for route in ["/owner/native-messages/next", "/v1/native-messages/next"]:
                assert (
                    agent.get(route, headers={"Authorization": "Bearer " + agent_token}).status_code
                    == 404
                )
    finally:
        relay.close()
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def test_pending_queue_capacity_is_bounded():
    relay = NativeMessagesRelay()
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        futures = [pool.submit(relay.request, body(), lambda: None) for _ in range(4)]
        deadline = time.monotonic() + 2
        while len(relay.pending) < 4 and time.monotonic() < deadline:
            time.sleep(0.005)
        with pytest.raises(NativeMessagesUnavailable):
            relay.request(body(), lambda: None)
        relay.close()
        for future in futures:
            with pytest.raises(NativeMessagesUnavailable):
                future.result(timeout=2)
