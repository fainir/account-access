import json
import sqlite3
import time

import pytest

from account_access.errors import AccessError
from account_access.factors import enroll, totp_seed
from account_access.models import CodeSource
from account_access.phone import deliver


def test_owner_authenticator_enrollment_and_real_browser_challenge(env):
    provider, broker, _ = env
    broker.store.put("source:demo-totp", None)
    enroll(broker.store, "demo-totp", {"seed": "otpauth://totp/Example?secret=JBSWY3DPEHPK3PXP"})
    result = broker.run("test", "demo-mfa", "summary")
    assert result["status"] == "COMPLETED"
    assert provider.totp_count == 1
    assert provider.last_login_code not in json.dumps(result)
    with broker.store.db() as db:
        events = [dict(row) for row in db.execute("SELECT * FROM audit")]
    assert any(x["event"] == "login_factor_completed" and x["reason"] == "totp" for x in events)
    assert provider.last_login_code not in json.dumps(events)


@pytest.mark.parametrize("value", ["invalid", "otpauth://hotp/a?secret=JBSWY3DPEHPK3PXP",
                                   "otpauth://totp/a?secret=JBSWY3DPEHPK3PXP&digits=8",
                                   "otpauth://totp/a?secret=JBSWY3DPEHPK3PXP&secret=OTHER"])
def test_authenticator_requires_supported_explicit_secret(value):
    with pytest.raises(AccessError):
        totp_seed(value)


def test_mac_messages_filters_sender_age_incoming_and_ambiguity(env, tmp_path):
    _, broker, _ = env
    path = tmp_path / "messages.db"
    started = time.time() - 1
    date = int((time.time() - 978307200) * 1_000_000_000)
    with sqlite3.connect(path) as db:
        db.executescript("CREATE TABLE handle (id TEXT); CREATE TABLE message (guid TEXT, text TEXT, handle_id INTEGER, is_from_me INTEGER, date INTEGER);")
        db.execute("INSERT INTO handle VALUES (?)", ("Example",))
        db.executemany("INSERT INTO message VALUES (?,?,?,?,?)", [
            ("valid", "Sign in: 123456", 1, 0, date),
            ("old", "Sign in: 654321", 1, 0, date - 300_000_000_000),
            ("outgoing", "Sign in: 654321", 1, 1, date),
            ("payment", "Payment: 654321", 1, 0, date)])
    source = CodeSource(kind="mac_messages", sender="Example", recipient="owner", template="Sign in: {code}")
    used = set()
    assert broker.codes.messages_at(path, source, started, used) == "123456"
    assert broker.codes.messages_at(path, source, started, used) is None
    with sqlite3.connect(path) as db:
        db.execute("INSERT INTO message VALUES (?,?,?,?,?)", ("second", "Sign in: 654321", 1, 0, date))
    with pytest.raises(AccessError, match="ambiguous_login_code"):
        broker.codes.messages_at(path, source, started, set())


def test_android_ingress_binds_code_to_active_login_window_and_consumes_once(env):
    _, broker, _ = env
    config = broker.store.config()
    config.code_sources["phone"] = CodeSource(kind="phone_relay", sender="Example", recipient="owner", template="Sign in: {code}")
    broker.store.configure(config)
    broker.store.put("source:phone", {"enabled": True})
    broker.store.put("phone-pair:phone", {"token": "fictional-paired-phone-token"})
    now = time.time()
    payload = {"id": "one", "sender": "Example", "recipient": "owner", "body": "Sign in: 123456", "received_at": now}
    with pytest.raises(AccessError, match="no_current_login_window"):
        deliver(broker.store, "phone", payload, pair_token="fictional-paired-phone-token")
    broker.codes.begin("phone", "demo-mfa", now - 1)
    with pytest.raises(AccessError, match="phone_message_mismatch"):
        deliver(broker.store, "phone", {**payload, "body": "Approve payment: 123456"}, pair_token="fictional-paired-phone-token")
    assert deliver(broker.store, "phone", payload, pair_token="fictional-paired-phone-token")["status"] == "RECEIVED"
    assert deliver(broker.store, "phone", payload, pair_token="fictional-paired-phone-token")["status"] == "RECEIVED"
    assert broker.codes.resolve("phone", now - 1, set()) == "123456"
    assert broker.codes.resolve("phone", now - 1, set()) is None
    with pytest.raises(AccessError, match="no_current_login_window"):
        deliver(broker.store, "phone", {**payload, "id": "two"}, pair_token="fictional-paired-phone-token")
    broker.codes.finish("phone", now - 1)
    assert broker.store.get("code-window:phone") is None
