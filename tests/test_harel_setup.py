"""Native setup backend with synthetic identities and a real local TLS mailbox."""

import json
import secrets
import time
import threading
from contextlib import contextmanager

import httpx2 as httpx
import pytest

from account_access import harel_setup, harel_protocol, harel_login
from account_access.demo import DEMO_PASSWORD
from account_access.errors import AccessError
from account_access.harel_login import ACCOUNT, SOURCES
from account_access.mailboxes import connect, get
from account_access.verification_demo import environment
from account_access.owner import make_owner_server
from test_harel_protocol import Provider, IDENTITY, PHONE, CODE


def attempt_id(created=None):
    return f"{int(time.time() if created is None else created):08x}" + secrets.token_hex(12)


def wait(setup, ident, states):
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        result = setup.check(ident)
        if result["status"] in states:
            return result
        time.sleep(0.01)
    pytest.fail("Controlled setup did not reach " + str(states) + ": " + str(setup.check(ident)))


@pytest.fixture
def setup(tmp_path, monkeypatch):
    with environment(tmp_path / "fixture") as (_, broker, mailbox):
        broker.store.new_client("generic")
        saved = connect(broker, {"label": "Fixture mailbox", "host": "127.0.0.1", "port": mailbox.port,
                                 "username": "demo@example.test", "password": DEMO_PASSWORD})
        assert saved["connection_check"]["status"] == "VERIFIED"
        provider = Provider()

        def transport(request):
            if str(request.url) == harel_protocol.ENTRY and "HarelVerified=fixture" not in request.headers.get("Cookie", ""):
                provider.authenticated = False
            result = provider(request)
            if request.url.path.endswith("SCValidateOTP"):
                result.headers["Set-Cookie"] = "HarelVerified=fixture; Secure; HttpOnly; Path=/"
            if request.url.path.endswith("StartProcess"):
                mailbox.deliver(CODE)
                # Harel brand/purpose is synthetic fixture content only.
                with mailbox.lock:
                    mailbox.messages[-1]["raw"] = mailbox.messages[-1]["raw"].replace(b"Example sign-in:", b"Harel sign-in:")
            return result

        monkeypatch.setattr(harel_setup, "HarelLogin", lambda channel: harel_protocol.HarelLogin(
            channel, transport=httpx.MockTransport(transport)))
        monkeypatch.setattr(harel_login, "HarelLogin", lambda channel, state=None: harel_protocol.HarelLogin(
            channel, state=state, transport=httpx.MockTransport(transport)))
        manager = harel_setup.HarelSetup(broker)
        data = {"id": attempt_id(), "mailbox": saved["id"], "identity": IDENTITY, "phone": PHONE, "consent": True}
        try:
            yield manager, broker, provider, mailbox, data
        finally:
            manager.close()


def review(manager, data):
    manager.start(data)
    wait(manager, data["id"], {"WAITING_CODE"})
    manager.code(data["id"], CODE)
    result = wait(manager, data["id"], {"REVIEW", "NEEDS_USER"})
    assert result["status"] == "REVIEW", result
    # Advance only this controlled fixture's cooldown. Production still waits
    # a full minute before the separately approved automatic login test.
    manager.broker.store.put("login-attempt:" + ACCOUNT, 0)
    return result


def test_setup_reviews_once_then_saves_only_status_and_reuses_checked_mailbox(setup):
    manager, broker, provider, mailbox, data = setup
    old = broker.store.config()
    before = {key: old.fingerprint(key) for key in old.accounts}
    result = review(manager, data)
    assert result["review"]["template"] == "Harel sign-in: {code}"
    assert CODE not in json.dumps(result)
    assert ACCOUNT not in broker.store.config().accounts
    assert manager.start(data)["status"] == "REVIEW"  # No duplicate send.
    assert len([r for r in provider.requests if r.url.path.endswith("StartProcess")]) == 1
    manager.approve(data["id"], result["candidate"])
    assert wait(manager, data["id"], {"COMPLETED", "NEEDS_USER"})["status"] == "COMPLETED"
    updated = broker.store.config()
    assert {key: updated.fingerprint(key) for key in before} == before
    assert updated.accounts[ACCOUNT].operations.keys() == {"status"}
    assert broker.store.get("source:" + SOURCES["email"]) == {"enabled": True, "mailbox": data["mailbox"]}
    assert broker.store.get("credential:" + ACCOUNT) == {"identity": IDENTITY, "phone": PHONE}
    assert broker.store.get("connection:" + ACCOUNT)["fingerprint"] == updated.fingerprint(ACCOUNT)
    with broker.store.db() as db:
        rows = [dict(row) for row in db.execute("SELECT * FROM grants WHERE account=?", (ACCOUNT,))]
    assert len(rows) == 1 and rows[0]["principal"] == "generic" and rows[0]["operation"] == "status"
    assert len([r for r in provider.requests if r.url.path.endswith("StartProcess")]) == 2
    assert mailbox.fetches == 2  # First local review, then fresh automatic resolution.
    assert broker.store.get("code-window:" + SOURCES["email"]) is None


@pytest.mark.parametrize("stage", ["waiting", "review"])
def test_cancel_preserves_existing_data_and_never_verifies_or_saves(setup, stage):
    manager, broker, provider, _, data = setup
    old = broker.store.config().model_dump()
    if stage == "review":
        review(manager, data)
    else:
        manager.start(data)
        wait(manager, data["id"], {"WAITING_CODE"})
    manager.cancel(data["id"])
    assert wait(manager, data["id"], {"CANCELLED"})["reason"] == "harel_setup_cancelled"
    assert broker.store.config().model_dump() == old
    assert not any(r.url.path.endswith("SCValidateOTP") for r in provider.requests)
    assert broker.store.get("credential:" + ACCOUNT) is None


def test_wrong_local_code_can_be_corrected_without_another_send(setup):
    manager, _, provider, _, data = setup
    manager.start(data)
    wait(manager, data["id"], {"WAITING_CODE"})
    manager.code(data["id"], "123456")
    assert wait(manager, data["id"], {"WAITING_CODE"})["reason"] == "harel_email_not_found"
    manager.code(data["id"], CODE)
    assert wait(manager, data["id"], {"REVIEW"})["review"]["template"] == "Harel sign-in: {code}"
    assert len([r for r in provider.requests if r.url.path.endswith("StartProcess")]) == 1


def test_changed_mailbox_and_cross_attempt_approval_cannot_publish(setup):
    manager, broker, _, _, data = setup
    result = review(manager, data)
    with pytest.raises(AccessError):
        manager.approve(data["id"], secrets.token_hex(16))
    profile = get(broker.store, data["mailbox"])
    broker.store.put("mailbox-profile:" + data["mailbox"], {**profile, "generation": secrets.token_hex(16)})
    manager.approve(data["id"], result["candidate"])
    assert wait(manager, data["id"], {"NEEDS_USER"})["reason"] == "harel_mailbox_changed"
    assert ACCOUNT not in broker.store.config().accounts


@pytest.mark.parametrize("field,value", [("consent", False), ("consent", 1), ("id", "wrong"),
                                         ("identity", "000000000&foo=bar"), ("phone", "+972500000000")])
def test_invalid_or_unapproved_setup_sends_nothing(setup, field, value):
    manager, _, provider, _, data = setup
    with pytest.raises(AccessError):
        manager.start({**data, field: value})
    assert not provider.requests


def test_duplicate_request_cannot_change_identity_or_mailbox(setup):
    manager, _, provider, _, data = setup
    manager.start(data)
    wait(manager, data["id"], {"WAITING_CODE"})
    with pytest.raises(AccessError):
        manager.start({**data, "identity": "111111111"})
    assert len([r for r in provider.requests if r.url.path.endswith("StartProcess")]) == 1


def test_legacy_owner_http_cannot_start_native_harel_setup(setup):
    _, broker, provider, _, data = setup
    server, token = make_owner_server(broker, guided=True)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    base = f"http://127.0.0.1:{server.server_port}"
    try:
        with httpx.Client(base_url=base, trust_env=False) as client:
            result = client.post("/owner/harel/start", json=data,
                                 headers={"Authorization": "Bearer " + token, "Origin": base})
            assert result.status_code == 403 and result.json()["reason"] == "trusted_owner_route_required"
        assert not provider.requests
    finally:
        server.shutdown()
        server.server_close()
        worker.join(timeout=5)


@pytest.mark.parametrize("change", ["cancel", "other-manager-cancel", "profile", "remove"])
def test_first_message_scan_stops_before_another_fetch_after_authority_changes(setup, monkeypatch, change):
    manager, broker, provider, mailbox, data = setup
    original_config = broker.store.config().model_dump()
    manager.start(data)
    wait(manager, data["id"], {"WAITING_CODE"})
    mailbox.deliver(CODE)
    original_mailbox = harel_setup._mailbox
    fetches = []

    @contextmanager
    def instrumented(broker_arg, profile):
        with original_mailbox(broker_arg, profile) as opened:
            original_uid = opened.uid

            def uid(command, *args):
                result = original_uid(command, *args)
                if command == "FETCH":
                    fetches.append(args[0])
                    if len(fetches) == 1:
                        if change in {"cancel", "other-manager-cancel"}:
                            target = manager if change == "cancel" else harel_setup.HarelSetup(broker)
                            target.cancel(data["id"])
                        else:
                            current = get(broker.store, data["mailbox"])
                            broker.store.put("mailbox-profile:" + data["mailbox"],
                                {**current, "generation": secrets.token_hex(16)} if change == "profile" else None)
                return result

            opened.uid = uid
            yield opened

    monkeypatch.setattr(harel_setup, "_mailbox", instrumented)
    manager.code(data["id"], CODE)
    result = wait(manager, data["id"], {"CANCELLED", "NEEDS_USER"})
    assert result["status"] == ("CANCELLED" if "cancel" in change else "NEEDS_USER")
    assert len(fetches) == 1
    assert not any(request.url.path.endswith("SCValidateOTP") for request in provider.requests)
    assert broker.store.config().model_dump() == original_config
    assert broker.store.get("credential:" + ACCOUNT) is None


def test_scan_rechecks_after_search_before_reading_any_message(setup, monkeypatch):
    manager, broker, _, _, data = setup
    manager.start(data)
    wait(manager, data["id"], {"WAITING_CODE"})
    original_mailbox = harel_setup._mailbox
    fetches = []

    @contextmanager
    def instrumented(broker_arg, profile):
        with original_mailbox(broker_arg, profile) as opened:
            original_uid = opened.uid

            def uid(command, *args):
                result = original_uid(command, *args)
                if command == "SEARCH":
                    manager.cancel(data["id"])
                if command == "FETCH":
                    fetches.append(args[0])
                return result

            opened.uid = uid
            yield opened

    monkeypatch.setattr(harel_setup, "_mailbox", instrumented)
    manager.code(data["id"], CODE)
    assert wait(manager, data["id"], {"CANCELLED"})["status"] == "CANCELLED"
    assert not fetches


def test_cancel_before_start_is_durable_and_denies_delayed_start(setup):
    manager, broker, provider, _, data = setup
    cancelled = manager.cancel(data["id"])
    assert cancelled["status"] == "CANCELLED"
    assert manager.start(data)["status"] == "CANCELLED"
    recreated = harel_setup.HarelSetup(broker)
    assert recreated.start(data)["status"] == "CANCELLED"
    assert recreated.check(data["id"])["revision"] > cancelled["revision"]
    assert not provider.requests


def test_lost_start_response_and_recreated_manager_never_resend(setup):
    manager, broker, provider, _, data = setup
    manager.start(data)  # Model a reply lost before the native app sees it.
    before = wait(manager, data["id"], {"WAITING_CODE"})
    recreated = harel_setup.HarelSetup(broker)
    stopped = recreated.start(data)
    assert stopped["status"] == "NEEDS_USER" and stopped["reason"] == "harel_setup_interrupted"
    assert stopped["revision"] > before["revision"]
    assert recreated.check(data["id"])["status"] == "NEEDS_USER"
    assert wait(manager, data["id"], {"NEEDS_USER"})["reason"] == "harel_setup_interrupted"
    assert manager.start(data)["status"] == "NEEDS_USER"
    assert sum(request.url.path.endswith("StartProcess") for request in provider.requests) == 1


def test_simultaneous_managers_cannot_both_create_the_same_first_send(setup, monkeypatch):
    manager, broker, provider, _, data = setup
    other = harel_setup.HarelSetup(broker)
    original_profile = harel_setup._profile
    gate = threading.Barrier(2)
    local = threading.local()
    results = []

    def profile(store, ident):
        result = original_profile(store, ident)
        if getattr(local, "starting", False):
            gate.wait(timeout=3)
        return result

    def start(target):
        local.starting = True
        try:
            results.append(target.start(data))
        finally:
            local.starting = False

    monkeypatch.setattr(harel_setup, "_profile", profile)
    threads = [threading.Thread(target=start, args=(target,)) for target in (manager, other)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=5)
        assert not thread.is_alive()
    assert len(results) == 2
    for target in (manager, other):
        assert wait(target, data["id"], {"NEEDS_USER"})["reason"] == "harel_setup_interrupted"
    assert sum(request.url.path.endswith("StartProcess") for request in provider.requests) <= 1


def test_completed_setup_survives_manager_recreation_without_another_send(setup):
    manager, broker, provider, _, data = setup
    result = review(manager, data)
    manager.approve(data["id"], result["candidate"])
    finished = wait(manager, data["id"], {"COMPLETED"})
    recreated = harel_setup.HarelSetup(broker)
    assert recreated.check(data["id"])["status"] == "COMPLETED"
    assert recreated.start(data)["revision"] > finished["revision"]
    assert recreated.cancel(data["id"])["status"] == "COMPLETED"
    assert sum(request.url.path.endswith("StartProcess") for request in provider.requests) == 2


def test_recreated_manager_stops_a_reserved_attempt_even_before_its_send(setup, monkeypatch):
    manager, broker, provider, _, data = setup
    monkeypatch.setattr(threading.Thread, "start", lambda thread: None)
    assert manager.start(data)["status"] == "STARTING"
    state = broker.store.get(harel_setup.OPERATION_PREFIX + data["id"])
    assert state["issued"] is False
    recreated = harel_setup.HarelSetup(broker)
    assert recreated.start(data)["reason"] == "harel_setup_interrupted"
    assert not provider.requests


def test_unknown_restart_check_is_terminal_and_denies_a_delayed_start(setup):
    manager, _, provider, _, data = setup
    result = manager.check(data["id"])
    assert result["status"] == "NEEDS_USER" and result["reason"] == "harel_setup_interrupted"
    assert manager.start(data)["status"] == "NEEDS_USER"
    assert result["revision"] > 0 and not provider.requests


def test_uncertain_first_send_is_consumed_after_restart(setup):
    manager, broker, provider, _, data = setup

    def lost_response(request):
        raise httpx.ReadError("Synthetic lost response")

    provider.replace["StartProcess"] = lost_response
    manager.start(data)
    assert wait(manager, data["id"], {"NEEDS_USER"})["reason"] == "harel_request_outcome_uncertain"
    recreated = harel_setup.HarelSetup(broker)
    assert recreated.start(data)["reason"] == "harel_request_outcome_uncertain"
    assert sum(request.url.path.endswith("StartProcess") for request in provider.requests) == 1
    state = broker.store.get(harel_setup.OPERATION_PREFIX + data["id"])
    assert state["issued"] is True
    assert set(state) == {"status", "revision", "issued", "reason"}
    assert all(value not in json.dumps(state) for value in (IDENTITY, PHONE, CODE))


def test_other_manager_cancellation_wakes_a_waiting_worker_without_an_owner_code(setup):
    manager, broker, provider, _, data = setup
    manager.start(data)
    wait(manager, data["id"], {"WAITING_CODE"})
    recreated = harel_setup.HarelSetup(broker)
    recreated.cancel(data["id"])
    deadline = time.monotonic() + 3
    while not manager.jobs[data["id"]]["cancelled"] and time.monotonic() < deadline:
        time.sleep(0.01)
    assert manager.jobs[data["id"]]["cancelled"]
    assert manager.check(data["id"])["status"] == "CANCELLED"
    assert not any(request.url.path.endswith("SCValidateOTP") for request in provider.requests)


@pytest.mark.parametrize("offset", [-harel_setup.ATTEMPT_MAX_AGE_SECONDS,
                                   harel_setup.ATTEMPT_FUTURE_SKEW_SECONDS + 1])
def test_expired_and_future_starts_stop_before_any_network(setup, monkeypatch, offset):
    manager, _, provider, _, data = setup
    now = int(time.time())
    monkeypatch.setattr(time, "time", lambda: now)
    data["id"] = attempt_id(now + offset)
    with pytest.raises(AccessError, match="harel_setup_expired"):
        manager.start(data)
    result = manager.check(data["id"])
    assert result["status"] == "NEEDS_USER" and result["revision"] == harel_setup.TERMINAL_REVISION
    assert not provider.requests


@pytest.mark.parametrize("offset", [-harel_setup.ATTEMPT_MAX_AGE_SECONDS + 1,
                                   harel_setup.ATTEMPT_FUTURE_SKEW_SECONDS])
def test_attempt_age_boundary_is_admitted_without_replaying_a_cancellation(setup, monkeypatch, offset):
    manager, _, provider, _, data = setup
    now = int(time.time())
    monkeypatch.setattr(time, "time", lambda: now)
    data["id"] = attempt_id(now + offset)
    assert manager.cancel(data["id"])["status"] == "CANCELLED"
    assert manager.start(data)["status"] == "CANCELLED"
    assert not provider.requests


def test_bounded_state_denies_cancelled_ids_after_slot_expiry_and_pruning(setup, monkeypatch):
    manager, broker, provider, _, data = setup
    base = int(time.time())
    now = [base]
    monkeypatch.setattr(time, "time", lambda: now[0])
    for _ in range(harel_setup.ATTEMPT_LIMIT):
        manager.cancel(attempt_id(base))
    now[0] = base + harel_setup.ATTEMPT_MAX_AGE_SECONDS - 1
    data["id"] = attempt_id()
    assert manager.cancel(data["id"])["status"] == "CANCELLED"
    now[0] += 2  # Old slots have expired; this cancelled ID remains young.
    with pytest.raises(AccessError, match="harel_setup_limit"):
        manager.start(data)
    now[0] = base + 2 * harel_setup.ATTEMPT_MAX_AGE_SECONDS + harel_setup.ATTEMPT_FUTURE_SKEW_SECONDS + 2
    with pytest.raises(AccessError, match="harel_setup_expired"):
        harel_setup.HarelSetup(broker).start(data)
    assert manager.cancel(attempt_id())["status"] == "CANCELLED"
    with broker.store.db() as db:
        count = db.execute("SELECT COUNT(*) FROM records WHERE id LIKE ?",
                           (harel_setup.OPERATION_PREFIX + "%",)).fetchone()[0]
    assert count == 1
    assert not provider.requests


def test_pruned_issued_attempt_is_still_rejected_after_restart(setup, monkeypatch):
    manager, broker, provider, _, data = setup
    manager.start(data)
    wait(manager, data["id"], {"WAITING_CODE"})
    assert broker.store.get(harel_setup.OPERATION_PREFIX + data["id"])["issued"] is True
    later = int(data["id"][:8], 16) + harel_setup.ATTEMPT_MAX_AGE_SECONDS + 1
    monkeypatch.setattr(time, "time", lambda: later)
    recreated = harel_setup.HarelSetup(broker)
    recreated.cancel(attempt_id())  # Admission prunes the expired operation.
    assert broker.store.get(harel_setup.OPERATION_PREFIX + data["id"]) is None
    with pytest.raises(AccessError, match="harel_setup_expired"):
        recreated.start(data)
    assert recreated.check(data["id"])["status"] == "NEEDS_USER"
    assert sum(request.url.path.endswith("StartProcess") for request in provider.requests) == 1


def test_first_code_window_expiry_is_terminal_without_a_resend(setup):
    manager, _, provider, _, data = setup
    manager.start(data)
    wait(manager, data["id"], {"WAITING_CODE"})
    manager.jobs[data["id"]]["deadline"] = time.monotonic() - 1
    manager.jobs[data["id"]]["event"].set()
    assert wait(manager, data["id"], {"NEEDS_USER"})["reason"] == "login_code_window_expired"
    assert manager.start(data)["status"] == "NEEDS_USER"
    assert sum(request.url.path.endswith("StartProcess") for request in provider.requests) == 1


def test_polling_expires_a_window_even_while_the_first_send_response_is_pending(setup, monkeypatch):
    manager, _, provider, _, data = setup
    entered, release, closed = threading.Event(), threading.Event(), threading.Event()
    original_close = harel_protocol.HarelLogin.close

    def close(session):
        original_close(session)
        closed.set()

    def pending_response(request):
        entered.set()
        assert release.wait(3)
        return httpx.Response(200, json={"Status": 0, "Details": {"ProcessSuccess": "OTPWasSent", "OTPChannel": 1}})

    monkeypatch.setattr(harel_protocol.HarelLogin, "close", close)
    provider.replace["StartProcess"] = pending_response
    manager.start(data)
    try:
        assert entered.wait(3)
        manager.jobs[data["id"]]["deadline"] = time.monotonic() - 1
        expired = manager.check(data["id"])
        assert expired["status"] == "NEEDS_USER" and expired["reason"] == "login_code_window_expired"
        assert manager.check(data["id"])["revision"] > expired["revision"]
    finally:
        release.set()
    assert closed.wait(3)
    assert not any(request.url.path.endswith("SCValidateOTP") for request in provider.requests)


@pytest.mark.parametrize("failure", ["connection", "operation-completion"])
def test_publication_failure_rolls_back_config_credentials_source_and_grant(setup, monkeypatch, failure):
    manager, broker, _, _, data = setup
    old = broker.store.config().model_dump()
    candidate = review(manager, data)["candidate"]
    original_put = broker.store.put

    def put(key, value, db=None):
        if ((failure == "connection" and key == "connection:" + ACCOUNT)
                or (failure == "operation-completion" and key == harel_setup.OPERATION_PREFIX + data["id"]
                    and value.get("status") == "COMPLETED")):
            raise OSError("Synthetic publication failure")
        return original_put(key, value, db=db)

    monkeypatch.setattr(broker.store, "put", put)
    manager.approve(data["id"], candidate)
    assert wait(manager, data["id"], {"NEEDS_USER"})["status"] == "NEEDS_USER"
    assert broker.store.config().model_dump() == old
    assert broker.store.get("credential:" + ACCOUNT) is None
    assert broker.store.get("connection:" + ACCOUNT) is None
    assert broker.store.get("source:" + SOURCES["email"]) is None
    assert broker.store.get("source-generation:" + SOURCES["email"]) is None
    assert broker.store.get("code-window:" + SOURCES["email"]) is None
    with broker.store.db() as db:
        assert db.execute("SELECT COUNT(*) FROM grants WHERE account=?", (ACCOUNT,)).fetchone()[0] == 0
