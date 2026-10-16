import base64
import time
from email.utils import formatdate

import pytest

from account_access.demo import connect_demo
from account_access.errors import AccessError
from account_access.models import CodeSource


def test_gmail_login_code_filters_and_does_not_expose_mailbox(env, monkeypatch):
    _, broker, _ = env
    config = broker.store.config()
    config.accounts["demo-api"].scopes.append("https://www.googleapis.com/auth/gmail.readonly")
    config.code_sources["email"] = CodeSource(kind="gmail", account="demo-api", sender="login@example.test",
                                              recipient="demo@example.test", subject="Your sign-in code",
                                              template="Login code: {code}")
    broker.store.configure(config)
    connect_demo(broker)
    started = time.time() - 1
    broker.codes.begin("email", "demo-web", started)
    calls = []
    def get(url, **kwargs):
        calls.append((url, kwargs.get("params")))
        if url.endswith("/messages"):
            return {"messages": [{"id": "valid"}, {"id": "old"}, {"id": "payment"}]}
        ident = url.rsplit("/", 1)[1]
        return {"internalDate": str(int((started - 10 if ident == "old" else time.time()) * 1000)),
                "payload": {"mimeType": "text/plain", "headers": [
                    {"name": "From", "value": "login@example.test"}, {"name": "To", "value": "demo@example.test"},
                    {"name": "Subject", "value": "Your sign-in code"}],
                    "body": {"data": base64.urlsafe_b64encode(("Confirm payment: 654321" if ident == "payment" else "Login code: 123456").encode()).decode()}}}
    monkeypatch.setattr("account_access.codes.get_json", get)
    used = set()
    assert broker.codes.resolve("email", started, used) == "123456"
    assert used == {"valid"}
    assert broker.codes.resolve("email", started, used) is None
    assert "from:login@example.test to:demo@example.test" in calls[0][1]["q"]
    assert "123456" not in str(broker.metrics())


def test_sms_gateway_contract_is_bound_to_login_recipient_sender_and_time(env, monkeypatch):
    _, broker, _ = env
    config = broker.store.config()
    config.code_sources["sms"] = CodeSource(kind="twilio", sender="+15550000001", recipient="+15550000002",
                                            template="Example sign-in: {code}")
    broker.store.configure(config)
    broker.store.put("source:sms", {"sid": "AC" + "0" * 32, "auth_token": "private-gateway-token"})
    started = time.time() - 2
    broker.codes.begin("sms", "demo-web", started)
    messages = [{"sid": "current", "direction": "inbound", "from": "+15550000001", "to": "+15550000002",
                 "date_sent": formatdate(time.time(), usegmt=True), "body": "Example sign-in: 123456"},
                {"sid": "old", "direction": "inbound", "from": "+15550000001", "to": "+15550000002",
                 "date_sent": formatdate(started - 10, usegmt=True), "body": "Example sign-in: 654321"}]
    monkeypatch.setattr("account_access.codes.get_json", lambda *a, **k: {"messages": messages})
    used = set()
    assert broker.codes.resolve("sms", started, used) == "123456"
    assert broker.codes.resolve("sms", started, used) is None
    assert "private-gateway-token" not in str(broker.metrics())


def test_code_window_expiry_requires_owner(env):
    _, broker, _ = env
    with pytest.raises(AccessError, match="login_code_window_expired"):
        broker.codes.resolve("demo-totp", time.time() - 121, set())


def test_mac_sms_boundary_precedes_login_and_is_bound_to_same_window(env, monkeypatch):
    _, broker, _ = env
    config = broker.store.config()
    config.code_sources["sms"] = CodeSource(kind="mac_messages", sender="Example", recipient="owner",
                                           template="Example sign-in: {code}")
    broker.store.configure(config)
    broker.store.put("source:sms", {"enabled": True})
    calls = []
    def native(source_id, source, started, **fields):
        calls.append((source_id, started, fields))
        if fields["action"] == "begin":
            return {"status": "READY", "after_row": 42}
        return {"status": "FOUND", "id": "new-text", "code": "123456"}
    monkeypatch.setattr(broker.codes, "native_messages", native)
    started = time.time() - 1
    broker.codes.begin("sms", "demo-web", started)
    assert broker.store.get("code-window:sms")["after_row"] == 42
    used = set()
    assert broker.codes.resolve("sms", started, used) == "123456"
    assert used == {"new-text"}
    assert calls == [("sms", started, {"action": "begin"}),
                     ("sms", started, {"action": "read", "after_row": 42, "used": []})]
    broker.codes.finish("sms", started)
    with pytest.raises(AccessError, match="message_login_window_missing"):
        broker.codes.messages("sms", config.code_sources["sms"], started, set())
    assert len(calls) == 2


@pytest.mark.parametrize("baseline", [True, -1, 2**63, 0.5, "42", None])
def test_invalid_native_sms_boundary_never_opens_login_window(env, monkeypatch, baseline):
    _, broker, _ = env
    config = broker.store.config()
    config.code_sources["sms"] = CodeSource(kind="mac_messages", sender="Example", recipient="owner",
                                           template="Example sign-in: {code}")
    broker.store.configure(config)
    broker.store.put("source:sms", {"enabled": True})
    monkeypatch.setattr(broker.codes, "native_messages", lambda *a, **k: {"status": "READY", "after_row": baseline})
    with pytest.raises(AccessError, match="mac_messages_permission_required"):
        broker.codes.begin("sms", "demo-web", time.time())
    assert broker.store.get("code-window:sms") is None
