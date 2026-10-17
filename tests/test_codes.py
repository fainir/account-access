import base64
import time
from email.message import EmailMessage
from email.utils import formatdate

import pytest
import pyotp

from account_access.demo import connect_demo
from account_access.errors import AccessError
from account_access.models import CodeSource


def gmail_source(broker):
    config = broker.store.config()
    config.accounts["demo-api"].scopes.append("https://www.googleapis.com/auth/gmail.readonly")
    config.code_sources["email"] = CodeSource(kind="gmail", account="demo-api", sender="login@example.test",
                                              recipient="demo@example.test", subject="Your sign-in code",
                                              template="Login code: {code}")
    broker.store.configure(config)
    connect_demo(broker)


def gmail_message(ident, received, body="<p>Login code: <b>123456</b></p>"):
    message = EmailMessage()
    message["From"], message["To"] = "login@example.test", "demo@example.test"
    message["Subject"] = "Your sign-in code"
    message.set_content(body, subtype="html")
    return {"id": ident, "internalDate": str(int(received * 1000)),
            "raw": base64.urlsafe_b64encode(message.as_bytes()).decode()}


def test_gmail_baseline_excludes_existing_messages_even_with_future_internal_date(env, monkeypatch):
    _, broker, _ = env
    gmail_source(broker)
    started = time.time() - 1
    ids = ["preexisting"]
    fetched = []

    def get(url, **kwargs):
        if url.endswith("/messages"):
            return {"messages": [{"id": ident} for ident in ids]}
        ident = url.rsplit("/", 1)[1]
        fetched.append(ident)
        return gmail_message(ident, time.time() + 2)

    monkeypatch.setattr("account_access.codes.get_json", get)
    broker.codes.begin("email", "demo-web", started)
    assert broker.codes.resolve("email", started, set()) is None
    assert fetched == []
    ids.append("fresh")
    used = set()
    assert broker.codes.resolve("email", started, used) == "123456"
    assert fetched == ["fresh"] and used == {"fresh"}


@pytest.mark.parametrize("case,reason", [
    ("pagination", "mailbox_result_limit"), ("too_many", "mailbox_result_limit"),
    ("list_type", "invalid_mailbox_response"), ("bad_id", "invalid_mailbox_response"),
    ("message_type", "invalid_mailbox_response"), ("id_mismatch", "invalid_mailbox_response"),
    ("ambiguous", "ambiguous_login_code"), ("expired", "login_code_window_missing"),
    ("revoked", "verification_source_disabled"),
])
def test_gmail_never_chooses_from_incomplete_or_invalid_delivery(env, monkeypatch, case, reason):
    _, broker, _ = env
    gmail_source(broker)
    started = time.time() - 1
    fresh = False

    def get(url, **kwargs):
        if url.endswith("/messages"):
            if not fresh:
                return {}
            if case == "pagination":
                return {"messages": [{"id": "fresh"}], "nextPageToken": "another-page"}
            if case == "too_many":
                return {"messages": [{"id": f"fresh-{i}"} for i in range(21)]}
            if case == "list_type":
                return {"messages": {"id": "fresh"}}
            if case == "bad_id":
                return {"messages": [{"id": "../../other-resource"}]}
            return {"messages": [{"id": "fresh"}, {"id": "second"}] if case == "ambiguous" else [{"id": "fresh"}]}
        if case == "message_type":
            return []
        if case == "expired":
            window = broker.store.get("code-window:email")
            window["expires"] = 0
            broker.store.put("code-window:email", window)
        if case == "revoked":
            broker.store.put("source:email", {"enabled": False})
        ident = url.rsplit("/", 1)[1]
        return gmail_message("other" if case == "id_mismatch" else ident, time.time())

    monkeypatch.setattr("account_access.codes.get_json", get)
    broker.codes.begin("email", "demo-web", started)
    fresh = True
    used = set()
    with pytest.raises(AccessError, match=reason):
        broker.codes.resolve("email", started, used)
    assert used == set()


@pytest.mark.parametrize("case", ["old", "future", "invalid_date", "invalid_base64", "oversize", "payment"])
def test_gmail_ignores_stale_invalid_or_different_purpose_messages(env, monkeypatch, case):
    _, broker, _ = env
    gmail_source(broker)
    started = time.time() - 1
    fresh = False

    def get(url, **kwargs):
        if url.endswith("/messages"):
            return {"messages": [{"id": "fresh"}]} if fresh else {}
        at = started - 10 if case == "old" else time.time() + 100 if case == "future" else time.time()
        message = gmail_message("fresh", at, "<p>Confirm payment: 123456</p>" if case == "payment" else "<p>Login code: 123456</p>")
        if case == "invalid_date":
            message["internalDate"] = "NaN"
        if case == "invalid_base64":
            message["raw"] = "%%%"
        if case == "oversize":
            message["raw"] = "A" * 400_000
        return message

    monkeypatch.setattr("account_access.codes.get_json", get)
    broker.codes.begin("email", "demo-web", started)
    fresh = True
    assert broker.codes.resolve("email", started, set()) is None


@pytest.mark.parametrize("case,reason", [
    ("not_connected", "account_not_connected"), ("scope_missing", "mailbox_scope_missing"),
    ("disabled", "verification_source_disabled"), ("unavailable", "network_unavailable"),
])
def test_gmail_preflight_stops_before_password_when_no_mailbox_is_available(env, monkeypatch, case, reason):
    provider, broker, _ = env
    gmail_source(broker)
    config = broker.store.config()
    config.accounts["demo-mfa"].login.code_source = "email"
    broker.store.configure(config)
    broker.grant("test", "demo-mfa", ["summary"])
    if case == "not_connected":
        broker.store.put("connection:demo-api", None)
    elif case == "scope_missing":
        saved = broker.store.get("connection:demo-api")
        saved["token"]["scope"] = "read:summary"
        broker.store.put("connection:demo-api", saved)
    elif case == "disabled":
        broker.store.put("source:email", {"enabled": False})

    def unavailable(*args, **kwargs):
        raise AccessError("RETRYABLE", "network_unavailable", "email")

    monkeypatch.setattr("account_access.codes.get_json", unavailable)
    result = broker.run("test", "demo-mfa", "summary")
    assert result["reason"] == reason, result
    assert provider.login_count == 0
    assert broker.store.get("code-window:email") is None


@pytest.mark.parametrize("case", ["renew", "reject_again", "later_rejection", "lost_rotation", "scope_removed"])
def test_gmail_renews_rejected_access_once_and_never_replays_uncertain_refresh(env, monkeypatch, case):
    provider, broker, _ = env
    gmail_source(broker)
    old = broker.store.get("connection:demo-api")["token"]["access_token"]
    started = time.time() - 1
    # Baseline first; these cases exercise a rejection after the password.
    monkeypatch.setattr("account_access.codes.get_json", lambda *a, **k: {})
    broker.codes.begin("email", "demo-web", started)
    calls = []
    provider.drop_refresh_response = case == "lost_rotation"
    if case == "scope_removed":
        saved = broker.store.get("connection:demo-api")["token"]
        provider.refresh_tokens[saved["refresh_token"]] = "read"

    def get(url, **kwargs):
        presented = kwargs["headers"]["Authorization"]
        calls.append((url, presented))
        if presented == "Bearer " + old or case == "reject_again" or (case == "later_rejection" and not url.endswith("/messages")):
            raise AccessError("NEEDS_USER", "provider_rejected_access")
        if url.endswith("/messages"):
            return {"messages": [{"id": "fresh"}]}
        return gmail_message("fresh", time.time())

    monkeypatch.setattr("account_access.codes.get_json", get)
    if case == "renew":
        assert broker.codes.resolve("email", started, set()) == "123456"
        assert len(calls) == 3
    else:
        reason = {"lost_rotation": "refresh_outcome_uncertain", "scope_removed": "mailbox_scope_missing"}.get(case, "provider_rejected_access")
        with pytest.raises(AccessError, match=reason):
            broker.codes.resolve("email", started, set())
        if case == "lost_rotation":
            with pytest.raises(AccessError, match="refresh_outcome_uncertain"):
                broker.codes.resolve("email", started, set())
        assert len(calls) == (3 if case == "later_rejection" else 2 if case == "reject_again" else 1)
    assert provider.refresh_count == 1


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
    calls = []
    fresh = False
    def get(url, **kwargs):
        calls.append((url, kwargs.get("params")))
        if url.endswith("/messages"):
            return {"messages": [{"id": ident} for ident in
                                 (["valid", "old", "payment"] if fresh else [])]}
        ident = url.rsplit("/", 1)[1]
        assert kwargs["params"] == {"format": "raw"}
        message = EmailMessage()
        message["From"], message["To"] = "login@example.test", "demo@example.test"
        message["Subject"] = "Your sign-in code"
        message.set_content("Confirm payment: 654321" if ident == "payment" else "Login code: 123456")
        return {"id": ident, "internalDate": str(int((started - 10 if ident == "old" else time.time()) * 1000)),
                "raw": base64.urlsafe_b64encode(message.as_bytes()).decode()}
    monkeypatch.setattr("account_access.codes.get_json", get)
    broker.codes.begin("email", "demo-web", started)
    fresh = True
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
    messages = []
    monkeypatch.setattr("account_access.codes.get_json", lambda *a, **k: {"messages": messages})
    broker.codes.begin("sms", "demo-web", started)
    messages.extend([{"sid": "SM" + "1" * 32, "direction": "inbound", "from": "+15550000001", "to": "+15550000002",
                 "date_sent": formatdate(time.time(), usegmt=True), "body": "Example sign-in: 123456"},
                {"sid": "SM" + "2" * 32, "direction": "inbound", "from": "+15550000001", "to": "+15550000002",
                 "date_sent": formatdate(started - 10, usegmt=True), "body": "Example sign-in: 654321"}])
    used = set()
    assert broker.codes.resolve("sms", started, used) == "123456"
    assert broker.codes.resolve("sms", started, used) is None
    assert "private-gateway-token" not in str(broker.metrics())


def test_code_window_expiry_requires_owner(env):
    _, broker, _ = env
    with pytest.raises(AccessError, match="login_code_window_expired"):
        broker.codes.resolve("demo-totp", time.time() - 121, set())


def test_authenticator_waits_for_next_interval_instead_of_submitting_nearly_expired_code(env, monkeypatch):
    from account_access.demo import DEMO_SEED

    _, broker, _ = env
    base = int(time.time() // 30) * 30
    now = [base + 25.5]
    monkeypatch.setattr("account_access.codes.time.time", lambda: now[0])
    started = now[0]
    broker.codes.begin("demo-totp", "demo-mfa", started)
    expires = broker.store.get("code-window:demo-totp")["expires"]
    assert broker.codes.resolve("demo-totp", started, set()) is None
    now[0] = base + 30.2
    assert broker.codes.resolve("demo-totp", started, set()) == pyotp.TOTP(DEMO_SEED).at(now[0])
    assert broker.store.get("code-window:demo-totp")["expires"] == expires
    now[0] = expires + 1
    with pytest.raises(AccessError, match="login_code_window_expired"):
        broker.codes.resolve("demo-totp", started, set())


@pytest.mark.parametrize("kind,credential,reason", [
    ("phone_relay", {}, "phone_not_paired"),
    ("phone_relay", {"enabled": True}, "phone_not_paired"),
    ("phone_relay", {"enabled": False}, "verification_source_disabled"),
    ("twilio", {}, "sms_gateway_not_connected"),
    ("twilio", {"sid": "invalid", "auth_token": "fictional"}, "invalid_sms_gateway"),
])
def test_missing_or_disabled_sms_source_stops_before_password(env, kind, credential, reason):
    provider, broker, _ = env
    config = broker.store.config()
    config.code_sources["sms"] = CodeSource(kind=kind, sender="Example", recipient="owner",
                                           template="Sign in: {code}")
    config.accounts["demo-mfa"].login.code_source = "sms"
    broker.store.configure(config)
    broker.grant("test", "demo-mfa", ["summary"])
    broker.store.put("source:sms", credential)
    result = broker.run("test", "demo-mfa", "summary")
    assert result["reason"] == reason
    assert provider.login_count == 0
    assert broker.store.get("code-window:sms") is None


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
