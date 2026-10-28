"""Public owner setup fixtures; no private accounts, passwords or messages."""

import json
import sqlite3
import threading
import time
from contextlib import contextmanager

import httpx2 as httpx
import pytest

from account_access import device_email_setup as setup
from account_access.broker import Broker
from account_access.catalog import PYPI_ACCOUNT, PYPI_SOURCE, pypi
from account_access.errors import AccessError
from account_access.models import CodeSource, Configuration, OAuthAccount
from account_access.owner import make_owner_server
from account_access.storage import Store
from test_pypi_device_email import device_browser  # noqa: F401

MAILBOX = "mailbox-" + "a" * 24
PASSWORD = "fictional-mail-password"
USERNAME = "fictional@example.test"


def profile():
    return {"label": "Example Gmail", "host": "imap.gmail.com", "port": 993,
            "username": USERNAME, "password": PASSWORD, "generation": "b" * 32,
            "connection_check": {"status": "VERIFIED", "checked": time.time()}}


@pytest.fixture
def connected(tmp_path):
    store = Store(tmp_path / "state", b"k" * 32)
    store.configure(Configuration(accounts={PYPI_ACCOUNT: pypi()},
                                  code_sources={PYPI_SOURCE: CodeSource(kind="totp")}))
    store.put("mailbox-profile:" + MAILBOX, profile())
    store.put("credential:" + PYPI_ACCOUNT, {"username": "fictional-owner", "password": "fictional-password"})
    store.put("source:" + PYPI_SOURCE, {"seed": "JBSWY3DPEHPK3PXP"})
    broker = Broker(store)
    store.new_client("fixture")
    broker.grant("fixture", PYPI_ACCOUNT, ["status"], expires=time.time() + 3600)
    return broker


def review(broker):
    config = broker.store.config()
    return setup.preview(broker.store, PYPI_ACCOUNT, config.fingerprint(PYPI_ACCOUNT), MAILBOX)


def snapshot(store):
    with store.db() as db:
        return {"config": store.config().model_dump(),
                "records": {row[0]: store.unseal(row[0], row[1]) for row in db.execute("SELECT id,value FROM records")
                            if not row[0].startswith(setup.PREFIX)},
                "grants": [dict(row) for row in db.execute("SELECT * FROM grants ORDER BY principal,account,operation")],
                "challenges": [dict(row) for row in db.execute("SELECT * FROM challenges")]}


def link(store):
    return {"provider": "onepassword-service-account", "token": "fictional-manager-token",
            "vault": "a" * 26, "item": "b" * 26, "username": "fictional-owner",
            "fingerprint": store.config().fingerprint(PYPI_ACCOUNT), "generation": "c" * 32,
            "status": "SYNCED", "checked": time.time(), "next_at": time.time() + 300}


def test_state_and_encrypted_preview_expose_only_checked_mailbox_and_approved_read(connected, monkeypatch):
    store = connected.store
    before = snapshot(store)
    monkeypatch.setattr(connected.codes, "mailbox", lambda *args: pytest.fail("setup must not read mail"))
    state = setup.view(store)
    assert state == [{"account": PYPI_ACCOUNT, "label": "PyPI",
                      "fingerprint": store.config().fingerprint(PYPI_ACCOUNT), "connected": False,
                      "configured": False,
                      "mailboxes": [{"id": MAILBOX, "label": "Example Gmail", "recipient": USERNAME, "kind": "imap"}]}]
    value = review(connected)
    assert set(value) == {"id", "expires", "account", "label", "recipient", "mailbox_label", "operations"}
    assert value["operations"] == [{"name": "status", "description": "Confirm your signed-in PyPI username"}]
    assert 590 <= value["expires"] - time.time() <= 600
    assert PASSWORD not in json.dumps(state) + json.dumps(value)
    assert PASSWORD.encode() not in store.path.read_bytes()
    assert snapshot(store) == before


def test_missing_mailbox_keeps_configured_binding_visible_and_removable(connected):
    store = connected.store
    setup.apply(store, review(connected)["id"])
    store.put("mailbox-profile:" + MAILBOX, None)
    assert setup.view(store)[0]["configured"] is True
    assert setup.view(store)[0]["connected"] is False
    assert setup.view(store)[0]["mailboxes"] == []
    assert setup.remove(store, PYPI_ACCOUNT, store.config().fingerprint(PYPI_ACCOUNT))["status"] == "REMOVED"
    assert setup.view(store)[0]["configured"] is False


def test_apply_and_remove_preserve_current_reads_session_sync_and_independent_state(connected, monkeypatch):
    store = connected.store
    old = store.config().fingerprint(PYPI_ACCOUNT)
    session = {"fingerprint": old, "state": {"cookies": [], "origins": []}, "generation": "fictional-session"}
    manager = link(store)
    store.put("connection:" + PYPI_ACCOUNT, session)
    store.put("password-link:" + PYPI_ACCOUNT, manager)
    challenge = store.challenge(PYPI_ACCOUNT, "action", "browser_action_required")
    credential = store.get("credential:" + PYPI_ACCOUNT)
    totp = store.get("source:" + PYPI_SOURCE)
    with store.db() as db:
        grants = [dict(row) for row in db.execute("SELECT * FROM grants")]
    result = setup.apply(store, review(connected)["id"])
    assert result["status"] == "ENROLLED" and result["account"] == PYPI_ACCOUNT
    source = result["source"]
    current = store.config()
    assert current.accounts[PYPI_ACCOUNT].login.device_email_source == source
    definition = current.code_sources[source]
    assert definition.message_purpose == "pypi-device-confirmation"
    assert definition.sender == "noreply@pypi.org" and definition.subject == "[PyPI] Unrecognized login to your PyPI account"
    assert definition.recipient == USERNAME and definition.template is None
    assert store.get("source:" + source) == {"mailbox": MAILBOX, "enabled": True}
    assert setup.view(store)[0]["connected"] is True
    assert connected.permit("fixture", PYPI_ACCOUNT, "status").fingerprint(PYPI_ACCOUNT) == current.fingerprint(PYPI_ACCOUNT)
    assert store.get("connection:" + PYPI_ACCOUNT) == {**session, "fingerprint": current.fingerprint(PYPI_ACCOUNT)}
    assert store.get("password-link:" + PYPI_ACCOUNT) == {**manager, "fingerprint": current.fingerprint(PYPI_ACCOUNT)}
    monkeypatch.setattr("account_access.password_sync.fetch", lambda *args: credential)
    from account_access.password_sync import refresh
    with store.lock("account:" + PYPI_ACCOUNT):
        refresh(store, PYPI_ACCOUNT, force=True)
    assert store.get("password-link:" + PYPI_ACCOUNT)["status"] == "SYNCED"
    result = setup.remove(store, PYPI_ACCOUNT, current.fingerprint(PYPI_ACCOUNT))
    assert result == {"status": "REMOVED", "account": PYPI_ACCOUNT, "source": source}
    assert store.config().fingerprint(PYPI_ACCOUNT) == old
    assert store.get("source:" + source) == {"enabled": False}
    assert source not in store.config().code_sources
    assert store.get("connection:" + PYPI_ACCOUNT) == session
    assert store.get("password-link:" + PYPI_ACCOUNT)["fingerprint"] == old
    assert store.get("credential:" + PYPI_ACCOUNT) == credential
    assert store.get("source:" + PYPI_SOURCE) == totp and store.pending(PYPI_ACCOUNT) == [challenge]
    with store.db() as db:
        assert [dict(row) for row in db.execute("SELECT * FROM grants")] == grants


@pytest.mark.parametrize("change", ["revoked-session", "stale-session", "invalid-session", "blocked-link", "stale-link", "wrong-username", "invalid-link"])
def test_stale_or_revoked_authority_cannot_become_current_when_fingerprint_cycles(connected, change):
    store = connected.store
    old = store.config().fingerprint(PYPI_ACCOUNT)
    prefix, value = ("password-link:", link(store)) if "link" in change or change == "wrong-username" else (
        "connection:", {"fingerprint": old, "state": {"cookies": [], "origins": []}})
    if change.startswith("stale"):
        value["fingerprint"] = "0" * 64
    elif change == "revoked-session":
        value["revoked"] = True
    elif change in {"invalid-session", "invalid-link"}:
        value["invalid"] = True
    elif change == "blocked-link":
        value["status"] = "BLOCKED"
    else:
        value["username"] = "different-owner"
    store.put(prefix + PYPI_ACCOUNT, value)
    setup.apply(store, review(connected)["id"])
    setup.remove(store, PYPI_ACCOUNT, store.config().fingerprint(PYPI_ACCOUNT))
    saved = store.get(prefix + PYPI_ACCOUNT)
    assert saved["fingerprint"] != store.config().fingerprint(PYPI_ACCOUNT)
    assert {k: v for k, v in saved.items() if k != "fingerprint"} == {k: v for k, v in value.items() if k != "fingerprint"}


@pytest.mark.parametrize("change", ["delete", "disabled", "password", "generation", "server", "recipient", "bad-check"])
def test_apply_rechecks_saved_mailbox_authority_and_consumes_review(connected, change):
    store = connected.store
    value = review(connected)
    saved = store.get("mailbox-profile:" + MAILBOX)
    if change == "delete":
        saved = None
    elif change == "disabled":
        saved["connection_check"]["status"] = "NEEDS_USER"
    elif change == "password":
        saved["password"] = "changed-without-a-generation"
    elif change == "generation":
        saved["generation"] = "d" * 32
    elif change == "server":
        saved["host"] = "different.example.test"
    elif change == "recipient":
        saved["username"] = "different@example.test"
    else:
        saved["connection_check"]["checked"] = float("nan")
    store.put("mailbox-profile:" + MAILBOX, saved)
    before = snapshot(store)
    with pytest.raises(AccessError, match="device_email_mailbox_(?:unavailable|changed)"):
        setup.apply(store, value["id"])
    assert snapshot(store) == before
    with pytest.raises(AccessError, match="device_email_setup_expired"):
        setup.apply(store, value["id"])


@pytest.mark.parametrize("change", ["url", "read", "selector", "totp-source", "remove"])
def test_apply_cannot_adopt_changed_connector_or_operations(connected, change):
    store = connected.store
    value = review(connected)
    config = store.config()
    if change == "remove":
        del config.accounts[PYPI_ACCOUNT]
    elif change == "totp-source":
        config.code_sources[PYPI_SOURCE] = CodeSource(kind="totp", subject="changed")
    elif change == "url":
        config.accounts[PYPI_ACCOUNT].login_challenge = None
        config.accounts[PYPI_ACCOUNT].operations["status"].url = "https://pypi.org/other/"
    elif change == "read":
        config.accounts[PYPI_ACCOUNT].login_challenge = None
        config.accounts[PYPI_ACCOUNT].operations["extra"] = config.accounts[PYPI_ACCOUNT].operations["status"].model_copy()
    else:
        config.accounts[PYPI_ACCOUNT].login_challenge = None
        config.accounts[PYPI_ACCOUNT].ready_selector = "#different"
    store.configure(config)
    before = snapshot(store)
    with pytest.raises(AccessError, match="device_email_setup_changed"):
        setup.apply(store, value["id"])
    assert snapshot(store) == before


@pytest.mark.parametrize("change", ["revoke-account", "revoke-client", "delete-grant", "expire", "change-expiry", "add-principal"])
def test_only_identical_live_prior_named_reads_survive_owner_review(connected, change):
    store = connected.store
    value = review(connected)
    if change == "revoke-account":
        connected.revoke(account=PYPI_ACCOUNT)
    elif change == "revoke-client":
        connected.revoke(principal="fixture")
    elif change == "add-principal":
        store.new_client("later")
        connected.grant("later", PYPI_ACCOUNT, ["status"])
    else:
        with store.db() as db:
            if change == "delete-grant":
                db.execute("DELETE FROM grants")
            else:
                db.execute("UPDATE grants SET expires=?", (time.time() + (-1 if change == "expire" else 7200),))
    setup.apply(store, value["id"])
    with pytest.raises(AccessError):
        connected.permit("later" if change == "add-principal" else "fixture", PYPI_ACCOUNT, "status")
    if change == "add-principal":
        connected.permit("fixture", PYPI_ACCOUNT, "status")


def test_revocation_after_durable_quarantine_wins_without_grant_recreation(connected, monkeypatch):
    original = setup._quarantine
    def revoke(*args):
        result = original(*args)
        connected.revoke(principal="fixture")
        return result
    monkeypatch.setattr(setup, "_quarantine", revoke)
    setup.apply(connected.store, review(connected)["id"])
    with connected.store.db() as db:
        assert not db.execute("SELECT 1 FROM grants").fetchone()


def test_config_visibility_before_final_commit_exposes_no_grant_session_or_source_authority(connected, monkeypatch):
    store = connected.store
    old = store.config().fingerprint(PYPI_ACCOUNT)
    store.put("connection:" + PYPI_ACCOUNT, {"fingerprint": old, "state": {"cookies": [], "origins": []}})
    store.put("password-link:" + PYPI_ACCOUNT, link(store))
    original = setup._write_config
    observed = []
    def inspect(*args):
        original(*args)
        config = store.config()
        with pytest.raises(AccessError):
            connected.permit("fixture", PYPI_ACCOUNT, "status")
        assert store.get("source:" + config.accounts[PYPI_ACCOUNT].login.device_email_source) is None
        for prefix in ["connection:", "password-link:"]:
            assert store.get(prefix + PYPI_ACCOUNT)["fingerprint"] != config.fingerprint(PYPI_ACCOUNT)
        observed.append(True)
    monkeypatch.setattr(setup, "_write_config", inspect)
    setup.apply(store, review(connected)["id"])
    assert observed == [True]


def test_preview_expiry_limit_discard_and_single_use(connected, monkeypatch):
    values = [review(connected) for _ in range(setup.LIMIT)]
    with pytest.raises(AccessError, match="device_email_setup_limit"):
        review(connected)
    assert setup.discard(connected.store, values[0]["id"]) == {"status": "DISCARDED"}
    with pytest.raises(AccessError, match="device_email_setup_expired"):
        setup.apply(connected.store, values[0]["id"])
    expires = values[1]["expires"]
    monkeypatch.setattr(setup.time, "time", lambda: expires + 1)
    with pytest.raises(AccessError, match="device_email_setup_expired"):
        setup.apply(connected.store, values[1]["id"])
    assert review(connected)["expires"] > expires


@pytest.mark.parametrize("point", ["before-config", "after-config", "source-record", "grant-publish"])
def test_ordinary_publication_failures_restore_only_old_valid_authority(connected, monkeypatch, point):
    store = connected.store
    old = store.config().fingerprint(PYPI_ACCOUNT)
    store.put("connection:" + PYPI_ACCOUNT, {"fingerprint": old, "state": {"cookies": [], "origins": []}})
    store.put("password-link:" + PYPI_ACCOUNT, link(store))
    value = review(connected)
    before = snapshot(store)
    original_write, original_put, original_grants = setup._write_config, store.put, setup._grants
    calls = 0
    def write(*args):
        nonlocal calls
        calls += 1
        if calls == 1 and point == "before-config":
            raise OSError("fictional-sensitive-path")
        original_write(*args)
        if calls == 1 and point == "after-config":
            raise OSError("fictional-sensitive-path")
    def put(key, item, **kwargs):
        if point == "source-record" and key.startswith("source:pypi-device-"):
            raise OSError("fictional-secret")
        return original_put(key, item, **kwargs)
    def grants(*args, **kwargs):
        if point == "grant-publish" and kwargs.get("fingerprint", "").startswith("device-email-quarantine:") and calls == 1:
            raise OSError("fictional-secret")
        return original_grants(*args, **kwargs)
    monkeypatch.setattr(setup, "_write_config", write)
    monkeypatch.setattr(store, "put", put)
    monkeypatch.setattr(setup, "_grants", grants)
    with pytest.raises(AccessError, match="device_email_setup_incomplete") as error:
        setup.apply(store, value["id"])
    assert "fictional" not in str(error.value)
    assert snapshot(store) == before


class Crash(BaseException):
    pass


@pytest.mark.parametrize("next_action", ["remove", "apply"])
def test_crash_cannot_revive_grants_session_or_sync_when_connector_fingerprint_cycles(connected, monkeypatch, next_action):
    store = connected.store
    original_fingerprint = store.config().fingerprint(PYPI_ACCOUNT)
    store.put("connection:" + PYPI_ACCOUNT, {"fingerprint": original_fingerprint, "state": {"cookies": [], "origins": []}})
    store.put("password-link:" + PYPI_ACCOUNT, link(store))
    original = setup._write_config
    def crash(*args):
        original(*args)
        raise Crash()
    monkeypatch.setattr(setup, "_write_config", crash)
    with pytest.raises(Crash):
        setup.apply(store, review(connected)["id"])
    assert store.config().fingerprint(PYPI_ACCOUNT) != original_fingerprint
    with pytest.raises(AccessError):
        connected.permit("fixture", PYPI_ACCOUNT, "status")
    monkeypatch.setattr(setup, "_write_config", original)
    if next_action == "remove":
        setup.remove(store, PYPI_ACCOUNT, store.config().fingerprint(PYPI_ACCOUNT))
        assert store.config().fingerprint(PYPI_ACCOUNT) == original_fingerprint
    else:
        assert review(connected)["operations"] == []
        setup.apply(store, review(connected)["id"])
    with pytest.raises(AccessError):
        connected.permit("fixture", PYPI_ACCOUNT, "status")
    for prefix in ["connection:", "password-link:"]:
        assert store.get(prefix + PYPI_ACCOUNT)["fingerprint"] != store.config().fingerprint(PYPI_ACCOUNT)


def test_apply_lock_wait_is_bounded_and_review_is_consumed(connected):
    value = review(connected)
    ready, stop = threading.Event(), threading.Event()
    def hold():
        with connected.store.lock("account:" + PYPI_ACCOUNT):
            ready.set()
            stop.wait(5)
    thread = threading.Thread(target=hold)
    thread.start()
    assert ready.wait(2)
    started = time.monotonic()
    try:
        with pytest.raises(AccessError, match="account_busy"):
            setup.apply(connected.store, value["id"])
        assert time.monotonic() - started < 3
    finally:
        stop.set()
        thread.join(timeout=2)
    with pytest.raises(AccessError, match="device_email_setup_expired"):
        setup.apply(connected.store, value["id"])


def test_database_contention_is_bounded_without_consuming_an_unread_review(connected):
    value = review(connected)
    ready, stop = threading.Event(), threading.Event()
    def hold():
        with connected.store.db() as db:
            db.execute("BEGIN IMMEDIATE")
            ready.set()
            stop.wait(5)
    thread = threading.Thread(target=hold)
    thread.start()
    assert ready.wait(2)
    started = time.monotonic()
    try:
        with pytest.raises(AccessError, match="account_busy"):
            setup.apply(connected.store, value["id"])
        assert time.monotonic() - started < 3
    finally:
        stop.set()
        thread.join(timeout=2)
    assert setup.apply(connected.store, value["id"])["status"] == "ENROLLED"


@pytest.mark.parametrize("code", [sqlite3.SQLITE_BUSY, sqlite3.SQLITE_LOCKED])
def test_writer_deadline_uses_elapsed_time_despite_overscheduled_sleeps(monkeypatch, code):
    clock, calls, closed = [100.0], [], []
    error = sqlite3.OperationalError("fictional-sensitive-database-detail")
    error.sqlite_errorcode = code
    class Database:
        def execute(self, query):
            calls.append(query)
            if query == "BEGIN IMMEDIATE":
                raise error
    class FictionalStore:
        @contextmanager
        def db(self):
            try:
                yield Database()
            finally:
                closed.append(True)
    def delayed_sleep(seconds):
        assert 0 < seconds <= 0.02
        clock[0] += seconds + 1  # Scheduler delay exceeds requested sleep.
    monkeypatch.setattr(setup.time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(setup.time, "sleep", delayed_sleep)
    with pytest.raises(AccessError, match="account_busy") as failure:
        with setup._database(FictionalStore()):
            pytest.fail("an expired acquisition must not publish")
    assert failure.value.status == "RETRYABLE"
    assert calls == ["PRAGMA busy_timeout=0", "BEGIN IMMEDIATE", "BEGIN IMMEDIATE"]
    assert closed == [True] and clock[0] < 103
    assert "fictional" not in str(failure.value)


@pytest.mark.parametrize("stage", ["open", "pragma", "begin", "body", "commit"])
def test_database_noncontention_errors_are_not_retried_or_leaked(monkeypatch, stage):
    calls, closed = [], []
    error = sqlite3.OperationalError("fictional-sensitive-database-detail")
    error.sqlite_errorcode = sqlite3.SQLITE_IOERR
    class Database:
        def execute(self, query):
            calls.append(query)
            if (stage == "pragma" and query.startswith("PRAGMA")) or (stage == "begin" and query == "BEGIN IMMEDIATE"):
                raise error
    class FictionalStore:
        @contextmanager
        def db(self):
            try:
                if stage == "open":
                    raise error
                yield Database()
                if stage == "commit":
                    raise error
            finally:
                closed.append(True)
    monkeypatch.setattr(setup.time, "sleep", lambda seconds: pytest.fail("non-contention error must not retry"))
    with pytest.raises(AccessError, match="device_email_setup_incomplete") as failure:
        with setup._database(FictionalStore()):
            if stage == "body":
                raise error
    assert failure.value.status == "NEEDS_USER" and "fictional" not in str(failure.value)
    assert calls.count("BEGIN IMMEDIATE") <= 1 and closed == [True]


@pytest.mark.parametrize("acquired", [False, True])
def test_slow_begin_cannot_pass_the_publication_deadline(monkeypatch, acquired):
    clock, closed, calls = [100.0], [], []
    class Database:
        def execute(self, query):
            calls.append(query)
            if query == "BEGIN IMMEDIATE":
                clock[0] += 2.1
                if not acquired:
                    error = sqlite3.OperationalError("fictional-sensitive-database-detail")
                    error.sqlite_errorcode = sqlite3.SQLITE_BUSY
                    raise error
    class FictionalStore:
        @contextmanager
        def db(self):
            try:
                yield Database()
            finally:
                closed.append(True)
    monkeypatch.setattr(setup.time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(setup.time, "sleep", lambda seconds: pytest.fail("deadline is already exceeded"))
    with pytest.raises(AccessError, match="account_busy"):
        with setup._database(FictionalStore()):
            pytest.fail("late acquisition must not publish")
    assert calls == ["PRAGMA busy_timeout=0", "BEGIN IMMEDIATE"] and closed == [True]


def test_device_setup_routes_are_owner_only_and_exact(connected):
    server, token = make_owner_server(connected, guided=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{server.server_port}"
    headers = {"Authorization": "Bearer " + token, "Origin": base}
    body = {"account": PYPI_ACCOUNT, "fingerprint": connected.store.config().fingerprint(PYPI_ACCOUNT), "mailbox": MAILBOX}
    try:
        with httpx.Client(base_url=base, trust_env=False) as client:
            for wrong in [{}, {"Authorization": "Bearer " + token, "Origin": "https://other.example"},
                          {"Authorization": "Bearer " + connected.store.new_client("agent"), "Origin": base}]:
                assert client.post("/owner/device-email/preview", headers=wrong, json=body).status_code == 403
            assert client.post("/owner/device-email/preview", headers=headers, json={**body, "sender": "other"}).status_code == 400
            value = client.post("/owner/device-email/preview", headers=headers, json=body).json()
            assert value["recipient"] == USERNAME
            assert client.post("/owner/device-email/apply", headers=headers, json={"id": value["id"], "account": PYPI_ACCOUNT}).status_code == 400
            assert client.post("/owner/device-email/apply", headers=headers, json={"id": value["id"]}).json()["status"] == "ENROLLED"
            state = client.get("/owner/state", headers=headers).json()
            assert state["device_email_setups"][0]["connected"] is True
            assert any(x["message_purpose"] == "pypi-device-confirmation" for x in state["code_sources"])
            assert PASSWORD not in json.dumps(state)
            body = {"account": PYPI_ACCOUNT, "fingerprint": connected.store.config().fingerprint(PYPI_ACCOUNT)}
            assert client.post("/owner/device-email/remove", headers=headers, json=body).json()["status"] == "REMOVED"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


@pytest.mark.parametrize("credential,expected", [(None, False), ({}, False), ({"generation": "legacy"}, False),
                                               ({"enabled": False}, False), ({"enabled": True}, True)])
def test_owner_state_gmail_enrollment_requires_explicit_true_and_captures_once(connected, monkeypatch, credential, expected):
    store = connected.store
    config = store.config()
    config.accounts["gmail"] = OAuthAccount(kind="oauth", label="Gmail",
        authorization_url="https://accounts.google.com/o/oauth2/v2/auth", token_url="https://oauth2.googleapis.com/token",
        client_id="fictional-client", scopes=["https://www.googleapis.com/auth/gmail.readonly"],
        api_origins=["https://gmail.googleapis.com"], operations={})
    config.code_sources["gmail-code"] = CodeSource(kind="gmail", account="gmail", sender="login@example.test",
        recipient=USERNAME, subject="Login", template="Code: {code}")
    store.configure(config)
    original = store.get
    reads = []
    def disappearing(key, default=None):
        if key == "source:gmail-code":
            reads.append(key)
            return credential if len(reads) == 1 else None
        return original(key, default)
    monkeypatch.setattr(store, "get", disappearing)
    monkeypatch.setattr("account_access.mailbox_health.view", lambda *args: {"status": "UNTESTED"})
    server, token = make_owner_server(connected)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        with httpx.Client(base_url=f"http://127.0.0.1:{server.server_port}", trust_env=False) as client:
            response = client.get("/owner/state", headers={"Authorization": "Bearer " + token})
            assert response.status_code == 200
            result = next(item for item in response.json()["code_sources"] if item["id"] == "gmail-code")
            assert result["enrolled"] is expected and reads == ["source:gmail-code"]
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


@pytest.mark.parametrize("device_browser", ["imap"], indirect=True)
def test_consumer_setup_reaches_password_totp_device_mail_and_reuses_real_browser_session(device_browser, monkeypatch):  # noqa: F811
    _, broker, spec, state = device_browser
    account = "pypi-device"
    core = spec.model_copy(deep=True)
    core.login.device_email_source = None
    monkeypatch.setattr(setup, "pypi", lambda: core.model_copy(deep=True))
    saved = profile()
    saved.update(host="imap.example.test", username=USERNAME)
    broker.store.put("mailbox-profile:" + MAILBOX, saved)
    value = setup.preview(broker.store, account, broker.store.config().fingerprint(account), MAILBOX)
    setup.apply(broker.store, value["id"])
    result = broker.run("test", account, "status")
    assert result["status"] == "COMPLETED", result
    assert result["data"]["username"] == "fictional-owner"
    assert state["passwords"] == state["totps"] == state["confirmations"] == 1 and state["projects"] == 0
    setup.remove(broker.store, account, broker.store.config().fingerprint(account))
    assert broker.run("test", account, "status")["status"] == "COMPLETED"
    assert state["passwords"] == state["totps"] == state["confirmations"] == 1
