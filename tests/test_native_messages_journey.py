"""Synthetic browser + private collector transport; no phone or native UID proof."""

from contextlib import contextmanager
import json
import socket
import threading

import httpx2 as httpx
import pytest

from account_access.models import CodeSource, LoginFactor
from account_access.native_messages import NativeMessagesRelay
from account_access.owner import make_owner_server


@contextmanager
def collector(broker, provider, *, revoke=False):
    relay = NativeMessagesRelay()
    broker.codes.native_transport = relay.request
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    path = str(broker.store.root / "collector.sock")
    listener.bind(path)
    listener.listen(8)
    server, token = make_owner_server(
        broker,
        server_socket=listener,
        origin_port=8765,
        local_host_actions=False,
        native_messages=relay,
    )
    host = threading.Thread(target=server.serve_forever, daemon=True)
    host.start()
    stopped = threading.Event()
    arrived = threading.Event()
    messages, seen, failures = [], [], []

    def deliver(kind, code):
        assert kind == "sms"
        messages.append(code)
        if revoke:
            broker.store.put("source:owner-sms", {"enabled": False})
        arrived.set()

    provider.delivery = deliver

    def serve():
        try:
            with httpx.Client(
                transport=httpx.HTTPTransport(uds=path),
                base_url="http://127.0.0.1:8765",
                trust_env=False,
                timeout=2,
                headers={"Authorization": "Bearer " + token, "Origin": "http://127.0.0.1:8765"},
            ) as client:
                while not stopped.is_set():
                    pending = client.get("/owner/native-messages/next")
                    assert pending.status_code == 200
                    item = pending.json()["request"]
                    if item is None:
                        stopped.wait(0.01)
                        continue
                    body = item["body"]
                    seen.append(body["action"])
                    assert body["source"] == "owner-sms"
                    assert body["sender"] == "Example"
                    assert body["template"] == "Example login: {code}"
                    if body["action"] == "begin":
                        assert provider.login_count == 0 and not arrived.is_set()
                        response = {"status": "READY", "after_row": 41}
                    else:
                        assert body["after_row"] == 41 and body["used"] == []
                        assert arrived.wait(2)
                        response = {
                            "status": "FOUND",
                            "id": "fixture-new-message",
                            "code": messages[-1],
                        }
                    answer = client.post(
                        "/owner/native-messages/respond",
                        json={"id": item["id"], "response": response},
                    )
                    assert answer.status_code == 200
                    assert answer.json() == {"status": "ACCEPTED"}
        except Exception as error:
            failures.append(type(error).__name__)

    worker = threading.Thread(target=serve, daemon=True)
    worker.start()
    try:
        yield seen, arrived
    finally:
        stopped.set()
        relay.close()
        worker.join(timeout=5)
        server.shutdown()
        server.server_close()
        host.join(timeout=5)
        assert not worker.is_alive() and not host.is_alive()
        assert not failures, failures
        assert not relay.pending


def configure(broker):
    config = broker.store.config()
    spec = config.accounts["demo-mfa"].model_copy(deep=True)
    spec.login_url = spec.login_url.replace("/mfa/", "/sms/")
    for name in ["login_resources", "login_post_urls", "read_resources"]:
        setattr(spec, name, [url.replace("/mfa/", "/sms/") for url in getattr(spec, name)])
    for operation in spec.operations.values():
        operation.url = operation.url.replace("/mfa/", "/sms/")
    spec.login.code_source = spec.login.code_selector = spec.login.code_submit_selector = None
    spec.login.factors = {
        "sms": LoginFactor(
            code_source="owner-sms", code_selector="#code", code_submit_selector="#code-submit"
        )
    }
    spec.challenge_selectors.pop("totp")
    spec.challenge_selectors["sms"] = "#sms-challenge"
    config.accounts["isolated-sms"] = spec
    config.code_sources["owner-sms"] = CodeSource(
        kind="mac_messages", sender="Example", recipient="owner", template="Example login: {code}"
    )
    broker.store.configure(config)
    broker.store.put("credential:isolated-sms", broker.store.get("credential:demo-mfa"))
    broker.store.put("source:owner-sms", {"enabled": True})
    broker.grant("test", "isolated-sms", ["summary"])


@pytest.mark.parametrize("revoke", [False, True])
def test_password_private_collector_and_sms_browser_login(env, revoke):
    provider, broker, _ = env
    configure(broker)
    with collector(broker, provider, revoke=revoke) as (seen, arrived):
        result = broker.run("test", "isolated-sms", "summary")
        assert provider.login_count == 1 and arrived.is_set()
        assert seen[0] == "begin"
        if revoke:
            assert result["status"] == "NEEDS_USER"
            assert result["reason"] == "verification_source_disabled"
            assert provider.sms_count == 0
        else:
            assert result["status"] == "COMPLETED" and provider.sms_count == 1
            assert seen == ["begin", "read"]
            assert broker.run("test", "isolated-sms", "summary")["status"] == "COMPLETED"
            assert provider.login_count == 1 and seen == ["begin", "read"]
        assert broker.store.get("code-window:owner-sms") is None
        with broker.store.db() as db:
            events = [dict(row) for row in db.execute("SELECT * FROM audit")]
        if provider.last_login_code:
            assert provider.last_login_code not in json.dumps(result)
            assert provider.last_login_code not in json.dumps(events)
