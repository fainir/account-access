import datetime
import imaplib
import json
import time
import threading
from contextlib import contextmanager
from email.message import EmailMessage

import pytest
import httpx2 as httpx

from account_access.codes import imap_number
from account_access.errors import AccessError
from account_access.factors import enroll, revoke
from account_access.mailbox_health import GMAIL_PROFILE, check, view
from account_access.models import CodeSource
from account_access.owner import make_owner_server
from account_access.verification_demo import environment
from test_codes import gmail_source


class Mailbox:
    def __init__(self):
        self.ids = b""
        self.validity = b"1"
        self.next = b"10"
        self.fetches = []
        self.searches = []
        self.fetch_status = "OK"
        self.metadata_uid = None
        self.extra_body = False
        self.during_fetch = lambda: None

    def response(self, name):
        return name, [self.validity if name == "UIDVALIDITY" else self.next]

    def uid(self, command, *args):
        if command == "SEARCH":
            self.searches.append(args)
            return "OK", [self.ids]
        ident = args[0]
        self.fetches.append(ident)
        self.during_fetch()
        date = datetime.datetime.now(datetime.timezone.utc).strftime('%d-%b-%Y %H:%M:%S +0000')
        metadata = b'1 (UID ' + (self.metadata_uid or ident) + b' INTERNALDATE "' + date.encode() + b'" BODY[] {100}'
        message = EmailMessage()
        message["From"], message["To"], message["Subject"] = "login@example.test", "demo@example.test", "Sign in"
        message.set_content("Login: 123456")
        body = (metadata, message.as_bytes())
        return self.fetch_status, [body, body] if self.extra_body else [body, b")"]


def setup(broker, monkeypatch):
    config = broker.store.config()
    config.code_sources["mail"] = CodeSource(kind="imap", host="imap.example.test",
        sender="login@example.test", recipient="demo@example.test", subject="Sign in", template="Login: {code}")
    broker.store.configure(config)
    enroll(broker.store, "mail", {"username": "demo@example.test", "password": "fictional-mail-password"})
    mailbox = Mailbox()

    @contextmanager
    def open_mailbox(*args):
        yield mailbox

    monkeypatch.setattr(broker.codes, "mailbox", open_mailbox)
    return mailbox


@pytest.mark.parametrize("value", [b"0", b"-1", b"4294967296", b"NaN", b"1 2", b"01", "1", None])
def test_imap_requires_bounded_unambiguous_tracking_numbers(value):
    with pytest.raises(AccessError, match="mailbox_uid_tracking_unavailable"):
        imap_number([value])


def test_mailbox_check_does_not_fetch_messages_or_start_a_website_login(env, monkeypatch):
    provider, broker, _ = env
    mailbox = setup(broker, monkeypatch)
    assert view(broker.store, "mail") == {"status": "UNTESTED"}
    assert check(broker, "mail") == {"status": "VERIFIED", "source": "mail", "login_delivery_verified": False}
    assert view(broker.store, "mail")["status"] == "VERIFIED"
    assert mailbox.searches == mailbox.fetches == [] and provider.login_count == 0
    assert broker.store.get("code-window:mail") is None
    assert "fictional-mail-password" not in json.dumps(view(broker.store, "mail"))
    revoke(broker.store, "mail")
    assert view(broker.store, "mail") == {"status": "UNTESTED"}
    with pytest.raises(AccessError, match="mailbox_not_connected"):
        check(broker, "mail")


def test_mailbox_check_is_invalidated_when_setup_or_filter_changes(env, monkeypatch):
    _, broker, _ = env
    setup(broker, monkeypatch)
    check(broker, "mail")
    config = broker.store.config()
    config.code_sources["mail"].subject = "Different login"
    broker.store.configure(config)
    assert view(broker.store, "mail") == {"status": "UNTESTED"}
    check(broker, "mail")
    enroll(broker.store, "mail", {"username": "demo@example.test", "password": "different-fictional-password"})
    assert view(broker.store, "mail") == {"status": "UNTESTED"}


def test_mailbox_failure_is_a_fixed_reason_and_never_marks_access_verified(env, monkeypatch):
    _, broker, _ = env
    setup(broker, monkeypatch)

    def rejected(*args):
        raise imaplib.IMAP4.error("fictional-private-provider-response")

    monkeypatch.setattr(broker.codes, "mailbox", rejected)
    with pytest.raises(AccessError, match="^mailbox_connection_failed$"):
        check(broker, "mail")
    state = view(broker.store, "mail")
    assert state["status"] == "NEEDS_USER" and state["reason"] == "mailbox_connection_failed"
    assert "fictional-private" not in json.dumps(state)


@pytest.mark.parametrize("case,reason", [
    ("too_many", "mailbox_result_limit"), ("malformed", "mailbox_uid_tracking_unavailable"),
    ("wrong_uid", "invalid_mailbox_response"), ("fetch_failed", "mailbox_fetch_failed"),
    ("two_bodies", "invalid_mailbox_response"), ("revoked_during_fetch", "login_code_window_missing"),
])
def test_imap_cannot_choose_a_code_from_partial_or_changed_results(env, monkeypatch, case, reason):
    _, broker, _ = env
    mailbox = setup(broker, monkeypatch)
    started = time.time() - 1
    broker.codes.begin("mail", "demo-web", started)
    mailbox.ids = b"10 11"
    if case == "too_many":
        mailbox.ids = b" ".join(str(i).encode() for i in range(10, 31))
    elif case == "malformed":
        mailbox.ids = b"10 garbage"
    elif case == "wrong_uid":
        mailbox.metadata_uid = b"99"
    elif case == "fetch_failed":
        mailbox.fetch_status = "NO"
    elif case == "two_bodies":
        mailbox.extra_body = True
    elif case == "revoked_during_fetch":
        mailbox.during_fetch = lambda: revoke(broker.store, "mail")
    used = set()
    with pytest.raises(AccessError, match=reason):
        broker.codes.resolve("mail", started, used)
    assert used == set()
    if case in {"too_many", "malformed"}:
        assert mailbox.fetches == []


def test_imap_search_bounds_fresh_uids_and_deduplicates_server_results(env, monkeypatch):
    _, broker, _ = env
    mailbox = setup(broker, monkeypatch)
    started = time.time() - 1
    broker.codes.begin("mail", "demo-web", started)
    mailbox.ids = b"9 10 10"
    assert broker.codes.resolve("mail", started, set()) == "123456"
    assert mailbox.fetches == [b"10"]
    assert mailbox.searches[0][:3] == (None, "UID", "10:*")


@pytest.mark.parametrize("case", ["correct", "wrong_account", "revoked_scope", "renew", "reject_again"])
def test_gmail_connection_check_reads_only_profile_and_checks_mailbox_identity(env, monkeypatch, case):
    provider, broker, _ = env
    gmail_source(broker)
    enroll(broker.store, "email", {})
    if case == "revoked_scope":
        saved = broker.store.get("connection:demo-api")
        saved["token"]["scope"] = "read"
        broker.store.put("connection:demo-api", saved)
    calls = []

    def profile(url, **kwargs):
        calls.append(url)
        if case == "reject_again" or (case == "renew" and len(calls) == 1):
            raise AccessError("NEEDS_USER", "provider_rejected_access")
        return {"emailAddress": "other@example.test" if case == "wrong_account" else "demo@example.test"}

    monkeypatch.setattr("account_access.mailbox_health.get_json", profile)
    if case in {"correct", "renew"}:
        assert check(broker, "email")["status"] == "VERIFIED"
        assert provider.refresh_count == (1 if case == "renew" else 0)
    else:
        reason = {"wrong_account": "mailbox_identity_mismatch", "revoked_scope": "mailbox_scope_missing", "reject_again": "provider_rejected_access"}[case]
        with pytest.raises(AccessError, match=reason):
            check(broker, "email")
        assert view(broker.store, "email")["status"] != "VERIFIED"
    assert calls == [GMAIL_PROFILE] * (0 if case == "revoked_scope" else 2 if case in {"renew", "reject_again"} else 1)
    assert provider.login_count == 0


def test_real_tls_mailbox_probe_verifies_connection_without_reading_mail(tmp_path):
    with environment(tmp_path) as (provider, broker, mailbox):
        enroll(broker.store, "example-email", {"username": "demo@example.test", "password": "wrong-example-password"})
        with pytest.raises(AccessError, match="mailbox_connection_failed"):
            check(broker, "example-email")
        from account_access.demo import DEMO_PASSWORD
        enroll(broker.store, "example-email", {"username": "demo@example.test", "password": DEMO_PASSWORD})
        assert check(broker, "example-email")["status"] == "VERIFIED"
        assert mailbox.fetches == provider.login_count == 0


def test_mailbox_check_route_requires_owner_and_never_exposes_private_details(env, monkeypatch):
    provider, broker, _ = env
    mailbox = setup(broker, monkeypatch)
    server, token = make_owner_server(broker, guided=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{server.server_port}"
    headers = {"Authorization": "Bearer " + token, "Origin": base}
    try:
        with httpx.Client(base_url=base, trust_env=False) as client:
            assert client.post("/owner/source/check", json={"source": "mail"}).status_code == 403
            assert client.post("/owner/source/check", json={"source": "mail"}, headers={"Authorization": "Bearer " + token}).status_code == 403
            assert client.post("/owner/source/check", json={"source": "mail", "url": "https://other.example"}, headers=headers).status_code == 400
            result = client.post("/owner/source/check", json={"source": "mail"}, headers=headers)
            assert result.status_code == 200 and result.json()["login_delivery_verified"] is False
            state = client.get("/owner/state", headers=headers).json()
            source = next(x for x in state["code_sources"] if x["id"] == "mail")
            assert source["connection_check"]["status"] == "VERIFIED"
            assert "fictional-mail-password" not in json.dumps(state)
            assert "binding" not in json.dumps(source)
            assert provider.login_count == 0 and mailbox.fetches == []
            assert state["connection_jobs"] == {}
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
