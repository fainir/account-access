"""Deterministic authority changes during controlled SMS/mailbox operations."""

import threading
import time
from contextlib import contextmanager
from types import SimpleNamespace

import pytest

from account_access.errors import AccessError
from account_access.factors import enroll, revoke
from account_access.google_messages import connect, handle
from account_access.mailboxes import check, connect as connect_mailbox, link, update_password, view
from account_access.models import CodeSource
from account_access.phone import PhoneRelay, deliver
from account_access.verification_demo import environment
from test_codes import gmail_source
from test_google_messages import delivery
from test_mailbox_health import Mailbox
from test_mailboxes import data as mailbox_data
from test_sms_setup import pilot


def start_call(name, function):
    outcome = {}

    def run():
        try:
            outcome["value"] = function()
        except BaseException as error:
            outcome["error"] = error

    worker = threading.Thread(name=name, target=run, daemon=True)
    worker.start()
    return worker, outcome


def finish_call(call):
    worker, outcome = call
    worker.join(timeout=5)
    assert not worker.is_alive(), "Controlled operation did not finish"
    return outcome


def arm_google(broker, source_id):
    started = time.time()
    call = start_call("arm-google", lambda: broker.codes.begin(source_id, "github-pilot", started))
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        pending = handle(broker.store, {"method": "pending"})["pending"]
        request = next((item for item in pending if item["source"] == source_id), None)
        if request:
            break
        time.sleep(.005)
    else:
        pytest.fail("Controlled Google Messages window was not published")
    base = {"source": source_id, "window": request["window"]}
    handle(broker.store, {"method": "armed", **base})
    assert finish_call(call) == {"value": None}
    return started, base


def test_delivery_cannot_restore_a_revoked_google_messages_window(env, monkeypatch):
    _, broker, _ = env
    config = pilot(broker)
    connect(broker.store, "github-pilot", config.fingerprint("github-pilot"))
    config = broker.store.config()
    source_id = config.accounts["github-pilot"].login.factor("sms").code_source
    started, base = arm_google(broker, source_id)
    original_generation = broker.store.get("source-generation:" + source_id)
    challenge = broker.store.challenge("github-pilot", "action", "browser_action_required")
    paused = threading.Event()
    release = threading.Event()
    revocation_waiting = threading.Event()
    original_put, original_lock = broker.store.put, broker.store.lock

    def put(key, value, db=None):
        if (threading.current_thread().name == "delivery" and key == "code-window:" + source_id
                and isinstance(value, dict) and value.get("incoming")):
            paused.set()
            assert release.wait(5)
        return original_put(key, value, db=db)

    @contextmanager
    def lock(key, *args, **kwargs):
        if threading.current_thread().name == "revocation" and key == "code-window:" + source_id:
            revocation_waiting.set()
        with original_lock(key, *args, **kwargs):
            yield

    monkeypatch.setattr(broker.store, "put", put)
    monkeypatch.setattr(broker.store, "lock", lock)
    delivery_call = start_call("delivery", lambda: handle(broker.store, delivery(base)))
    revoke_call = None
    try:
        assert paused.wait(5)
        revoke_call = start_call("revocation", lambda: revoke(broker.store, source_id))
        assert revocation_waiting.wait(5)
        # The current delivery owns the window; revocation has not yet committed.
        assert broker.store.get("source-generation:" + source_id) == original_generation
    finally:
        release.set()
    assert finish_call(delivery_call) == {"value": {"status": "RECEIVED"}}
    assert revoke_call is not None and finish_call(revoke_call)["value"]["status"] == "REVOKED"
    assert broker.store.get("code-window:" + source_id) is None
    revoked_generation = broker.store.get("source-generation:" + source_id)
    assert revoked_generation != original_generation
    connect(broker.store, "github-pilot", config.fingerprint("github-pilot"))
    assert broker.store.get("source-generation:" + source_id) not in {original_generation, revoked_generation}
    with pytest.raises(AccessError, match="login_code_window_missing"):
        broker.codes.resolve(source_id, started, set())
    with pytest.raises(AccessError):
        handle(broker.store, delivery(base))
    fresh_started, fresh = arm_google(broker, source_id)
    assert handle(broker.store, delivery(fresh))["status"] == "RECEIVED"
    assert broker.codes.resolve(source_id, fresh_started, set()) == "123456"
    assert [item["id"] for item in broker.store.pending("github-pilot")] == [challenge["id"]]


@pytest.mark.parametrize("phase", ["legacy_baseline", "native_before_publication", "native_baseline"])
def test_late_sms_baseline_cannot_publish_after_same_valued_reconnection(env, monkeypatch, phase):
    provider, broker, _ = env
    source_id = "controlled-sms"
    config = broker.store.config()
    config.code_sources[source_id] = CodeSource(kind="mac_messages", sender="Example", recipient="owner",
                                               template="Example login: {code}")
    broker.store.configure(config)
    enroll(broker.store, source_id, {"enabled": True})
    original_generation = broker.store.get("source-generation:" + source_id)
    paused, release = threading.Event(), threading.Event()
    if phase != "legacy_baseline":
        broker.codes.native_transport = lambda *_: pytest.fail("Baseline uses the controlled adapter")

    def baseline(*_):
        if phase != "native_before_publication" and threading.current_thread().name == "old-begin":
            paused.set()
            assert release.wait(5)
        return 42

    monkeypatch.setattr(broker.codes, "messages_baseline", baseline)
    if phase == "native_before_publication":
        original_publish = broker.codes.publish_window

        def publish(source_id, window, *, existing=False):
            if threading.current_thread().name == "old-begin" and not existing:
                paused.set()
                assert release.wait(5)
            return original_publish(source_id, window, existing=existing)

        monkeypatch.setattr(broker.codes, "publish_window", publish)
    started = time.time()
    call = start_call("old-begin", lambda: broker.codes.begin(source_id, "demo-web", started))
    try:
        assert paused.wait(5)
        if phase == "native_baseline":
            assert broker.store.get("code-window:" + source_id)["source_generation"] == original_generation
        else:
            assert broker.store.get("code-window:" + source_id) is None
        revoke(broker.store, source_id)
        enroll(broker.store, source_id, {"enabled": True})
        assert broker.store.get("source:" + source_id) == {"enabled": True}
        assert broker.store.get("source-generation:" + source_id) != original_generation
    finally:
        release.set()
    result = finish_call(call)
    assert isinstance(result.get("error"), AccessError)
    assert result["error"].reason in {"verification_source_enrollment_changed", "login_code_window_missing"}
    assert broker.store.get("code-window:" + source_id) is None
    assert provider.login_count == 0
    fresh_started = time.time()
    broker.codes.begin(source_id, "demo-web", fresh_started)
    assert broker.codes.check_window(source_id, fresh_started)[1]["after_row"] == 42


def test_repaired_phone_rejects_an_inflight_request_from_previous_pairing(env, monkeypatch):
    _, broker, _ = env
    config = broker.store.config()
    source_id = "controlled-phone"
    config.code_sources[source_id] = CodeSource(kind="phone_relay", sender="Example", recipient="owner",
                                               template="Example login: {code}")
    broker.store.configure(config)
    relay = PhoneRelay(broker.store)
    # Pairing's production authority changes run normally; this fixture needs
    # no physical phone, LAN listener, certificate or owner-network discovery.
    relay.server = SimpleNamespace(server_port=9443)
    relay.ip, relay.fingerprint = "192.168.1.2", "a" * 64
    previous = relay.pair(source_id)
    original_generation = broker.store.get("source-generation:" + source_id)
    started = time.time()
    broker.codes.begin(source_id, "demo-web", started)
    paused, release = threading.Event(), threading.Event()
    original_lock = broker.store.lock

    @contextmanager
    def lock(key, *args, **kwargs):
        if threading.current_thread().name == "previous-phone" and key == "code-window:" + source_id:
            paused.set()
            assert release.wait(5)
        with original_lock(key, *args, **kwargs):
            yield

    monkeypatch.setattr(broker.store, "lock", lock)
    message = {"id": "controlled-message", "sender": "Example", "recipient": "owner",
               "body": "Example login: 123456", "received_at": time.time()}
    call = start_call("previous-phone", lambda: deliver(broker.store, source_id, message, pair_token=previous["token"]))
    try:
        assert paused.wait(5)
        replacement = relay.pair(source_id)
        assert replacement["token"] != previous["token"]
        assert broker.store.get("source-generation:" + source_id) != original_generation
        assert broker.store.get("code-window:" + source_id) is None
        fresh_started = time.time()
        broker.codes.begin(source_id, "demo-web", fresh_started)
    finally:
        release.set()
    result = finish_call(call)
    assert isinstance(result.get("error"), AccessError) and result["error"].reason == "phone_pairing_changed"
    assert broker.store.get("code-window:" + source_id)["incoming"] == []
    assert broker.codes.resolve(source_id, fresh_started, set()) is None
    fresh = {**message, "received_at": time.time()}
    assert deliver(broker.store, source_id, fresh, pair_token=replacement["token"])["status"] == "RECEIVED"
    assert broker.codes.resolve(source_id, fresh_started, set()) == "123456"


def test_same_mailbox_password_replacement_invalidates_prior_window_but_health_check_does_not(tmp_path):
    with environment(tmp_path) as (_, broker, mailbox):
        saved = connect_mailbox(broker, mailbox_data(mailbox))
        source_id = "example-email"
        link(broker.store, source_id, saved["id"])
        started = time.time()
        broker.codes.begin(source_id, source_id, started)
        original = broker.codes.check_window(source_id, started)[2]
        assert check(broker, saved["id"])["status"] == "VERIFIED"
        assert broker.codes.check_window(source_id, started)[2] == original
        assert update_password(broker, saved["id"], mailbox_data(mailbox)["password"])["connection_check"]["status"] == "VERIFIED"
        with pytest.raises(AccessError, match="verification_source_enrollment_changed"):
            broker.codes.resolve(source_id, started, set())
        assert "generation" not in view(broker.store)[0]
        assert "password" not in view(broker.store)[0]
        assert mailbox.fetches == 0


@pytest.mark.parametrize("change", ["sender", "same_value", "sender_aba"])
def test_phone_delivery_cannot_apply_an_old_sender_match_to_a_reconfigured_source(env, monkeypatch, change):
    _, broker, _ = env
    source_id = "controlled-phone"
    config = broker.store.config()
    config.code_sources[source_id] = CodeSource(kind="phone_relay", sender="Previous service", recipient="owner",
                                               template="Example login: {code}")
    broker.store.configure(config)
    enroll(broker.store, source_id, {})
    token = "fictional-paired-phone-token"
    broker.store.put("phone-pair:" + source_id, {"token": token})
    broker.codes.begin(source_id, "demo-web", time.time())
    paused, release = threading.Event(), threading.Event()
    original_lock = broker.store.lock

    @contextmanager
    def lock(key, *args, **kwargs):
        if threading.current_thread().name == "previous-filter" and key == "code-window:" + source_id:
            paused.set()
            assert release.wait(5)
        with original_lock(key, *args, **kwargs):
            yield

    monkeypatch.setattr(broker.store, "lock", lock)
    # A controlled future-by-one-second delivery remains within the permitted
    # clock skew after the new window starts; timestamp checks alone cannot
    # distinguish these two source authorities.
    message = {"id": "controlled-old-sender", "sender": "Previous service", "recipient": "owner",
               "body": "Example login: 123456", "received_at": time.time() + 1}
    call = start_call("previous-filter", lambda: deliver(broker.store, source_id, message, pair_token=token))
    try:
        assert paused.wait(5)
        if change != "same_value":
            config = broker.store.config()
            config.code_sources[source_id].sender = "Replacement service"
            broker.store.configure(config)
        if change == "sender_aba":
            enroll(broker.store, source_id, {})
            config = broker.store.config()
            config.code_sources[source_id].sender = "Previous service"
            broker.store.configure(config)
        enroll(broker.store, source_id, {})
        fresh_started = time.time()
        broker.codes.begin(source_id, "demo-web", fresh_started)
    finally:
        release.set()
    result = finish_call(call)
    reason = "phone_message_mismatch" if change == "sender" else "verification_source_enrollment_changed"
    assert isinstance(result.get("error"), AccessError) and result["error"].reason == reason
    assert broker.store.get("code-window:" + source_id)["incoming"] == []
    sender = "Replacement service" if change == "sender" else "Previous service"
    fresh = {**message, "sender": sender, "received_at": time.time()}
    assert deliver(broker.store, source_id, fresh, pair_token=token)["status"] == "RECEIVED"
    assert broker.codes.resolve(source_id, fresh_started, set()) == "123456"


@pytest.mark.parametrize("kind", ["gmail", "imap"])
@pytest.mark.parametrize("change", ["refresh", "legacy_refresh", "reconnect", "configuration", "revoked", "invalid", "uncertain"])
def test_oauth_mailbox_window_follows_owner_authorization_and_allows_normal_refresh(env, monkeypatch, kind, change):
    _, broker, _ = env
    gmail_source(broker)
    if kind == "imap":
        config = broker.store.config()
        config.code_sources["email"] = CodeSource(kind="imap", account="demo-api", host="imap.example.test",
            sender="login@example.test", recipient="demo@example.test", subject="Sign in", template="Login: {code}")
        broker.store.configure(config)

        @contextmanager
        def mailbox(*_):
            yield Mailbox()

        monkeypatch.setattr(broker.codes, "mailbox", mailbox)
    else:
        monkeypatch.setattr("account_access.codes.get_json", lambda *_a, **_k: {})
    enroll(broker.store, "email", {"username": "demo@example.test"} if kind == "imap" else {})
    before = broker.store.get("connection:demo-api")
    if change == "legacy_refresh":
        before.pop("authorization_id")
        broker.store.put("connection:demo-api", before)
    started = time.time()
    broker.codes.begin("email", "demo-web", started)
    original = broker.codes.check_window("email", started)[1]
    if change in {"refresh", "legacy_refresh"}:
        with broker.store.lock("account:demo-api"):
            broker.oauth.token("demo-api", broker.store.config(), force=True)
        after = broker.store.get("connection:demo-api")
        assert after["generation"] != before["generation"]
        assert after["authorization_id"] == before.get("authorization_id", before["generation"])
        assert broker.codes.check_window("email", started)[1] == original
    else:
        if change == "reconnect":
            broker.oauth.save("demo-api", before["token"], broker.store.config())
            after = broker.store.get("connection:demo-api")
            assert after["token"] == before["token"]
            assert after["authorization_id"] != before["authorization_id"]
        elif change == "configuration":
            config = broker.store.config()
            config.accounts["demo-api"].authorization_params["prompt"] = "consent"
            broker.store.configure(config)
        elif change == "revoked":
            broker.revoke(account="demo-api")
        else:
            before["invalid" if change == "invalid" else "refresh_in_flight"] = True
            broker.store.put("connection:demo-api", before)
        expected = {"revoked": "connection_revoked", "invalid": "provider_grant_revoked_or_expired",
                    "uncertain": "refresh_outcome_uncertain"}.get(change, "verification_source_enrollment_changed")
        with pytest.raises(AccessError, match=expected):
            broker.codes.check_window("email", started)


def test_legacy_linked_mailbox_health_payload_is_unchanged_until_owner_replacement(tmp_path):
    from account_access.mailboxes import enrollment
    with environment(tmp_path) as (_, broker, mailbox):
        saved = connect_mailbox(broker, mailbox_data(mailbox))
        profile = broker.store.get("mailbox-profile:" + saved["id"])
        profile.pop("generation")
        broker.store.put("mailbox-profile:" + saved["id"], profile)
        link(broker.store, "example-email", saved["id"])
        effective = enrollment(broker.store, "example-email")
        assert effective == {"enabled": True, "mailbox": saved["id"],
                             "username": profile["username"], "password": profile["password"]}
        assert check(broker, saved["id"])["status"] == "VERIFIED"
        assert enrollment(broker.store, "example-email") == effective


@pytest.mark.parametrize("action", ["reenroll", "revoke", "pair"])
def test_interrupted_authority_write_preserves_the_previous_pairing_and_window_atomically(env, monkeypatch, action):
    _, broker, _ = env
    source_id = "controlled-phone"
    config = broker.store.config()
    config.code_sources[source_id] = CodeSource(kind="phone_relay", sender="Example", recipient="owner",
                                               template="Example login: {code}")
    broker.store.configure(config)
    relay = PhoneRelay(broker.store)
    relay.server, relay.ip, relay.fingerprint = SimpleNamespace(server_port=9443), "192.168.1.2", "a" * 64
    relay.pair(source_id)
    started = time.time()
    broker.codes.begin(source_id, "demo-web", started)
    keys = [prefix + source_id for prefix in ["source:", "source-generation:", "phone-pair:", "code-window:", "mailbox-health:"]]
    before = {key: broker.store.get(key) for key in keys}
    original_put = broker.store.put

    def interrupted_put(key, value, db=None):
        if key == "code-window:" + source_id and value is None:
            raise OSError("controlled storage interruption")
        return original_put(key, value, db=db)

    monkeypatch.setattr(broker.store, "put", interrupted_put)
    with pytest.raises(OSError, match="controlled storage interruption"):
        if action == "reenroll":
            enroll(broker.store, source_id, {})
        elif action == "revoke":
            revoke(broker.store, source_id)
        else:
            relay.pair(source_id)
    assert {key: broker.store.get(key) for key in keys} == before
    assert broker.codes.check_window(source_id, started)[1]["started"] == started


@pytest.mark.parametrize("change", ["revoke", "finish", "reenroll", "mailbox_account"])
def test_oauth_lock_wait_reloads_the_live_window_and_source_before_accepting(env, monkeypatch, change):
    provider, broker, _ = env
    gmail_source(broker)
    enroll(broker.store, "email", {})
    monkeypatch.setattr("account_access.codes.get_json", lambda *_a, **_k: {})
    started = time.time()
    broker.codes.begin("email", "demo-web", started)
    waiting = threading.Event()
    original_lock = broker.store.lock

    @contextmanager
    def lock(key, *args, **kwargs):
        if threading.current_thread().name == "waiting-window-check" and key == "account:demo-api":
            waiting.set()
        with original_lock(key, *args, **kwargs):
            yield

    monkeypatch.setattr(broker.store, "lock", lock)
    with original_lock("account:demo-api"):
        call = start_call("waiting-window-check", lambda: broker.codes.check_window("email", started))
        assert waiting.wait(5)
        if change == "revoke":
            revoke(broker.store, "email")
        elif change == "finish":
            broker.codes.finish("email", started)
        elif change == "reenroll":
            enroll(broker.store, "email", {})
        else:
            config = broker.store.config()
            config.accounts["secondary-api"] = config.accounts["demo-api"].model_copy(deep=True)
            config.code_sources["email"].account = "secondary-api"
            broker.store.configure(config)
    result = finish_call(call)
    reason = "login_code_source_changed" if change == "mailbox_account" else "login_code_window_missing"
    assert isinstance(result.get("error"), AccessError) and result["error"].reason == reason
    if change == "mailbox_account":
        token = broker.store.get("connection:demo-api")["token"]
        with original_lock("account:secondary-api"):
            broker.oauth.save("secondary-api", token, broker.store.config())
    enroll(broker.store, "email", {})
    fresh_started = time.time()
    broker.codes.begin("email", "demo-web", fresh_started)
    assert broker.codes.check_window("email", fresh_started)[1]["started"] == fresh_started
    assert provider.login_count == 0


def test_finishing_a_window_during_its_oauth_binding_read_cannot_return_a_stale_window(env, monkeypatch):
    _, broker, _ = env
    gmail_source(broker)
    enroll(broker.store, "email", {})
    monkeypatch.setattr("account_access.codes.get_json", lambda *_a, **_k: {})
    started = time.time()
    broker.codes.begin("email", "demo-web", started)
    paused, release = threading.Event(), threading.Event()
    original = broker.codes.mailbox_authorization

    def authorization(*args):
        if threading.current_thread().name == "binding-read":
            paused.set()
            assert release.wait(5)
        return original(*args)

    monkeypatch.setattr(broker.codes, "mailbox_authorization", authorization)
    call = start_call("binding-read", lambda: broker.codes.check_window("email", started))
    try:
        assert paused.wait(5)
        broker.codes.finish("email", started)
    finally:
        release.set()
    result = finish_call(call)
    assert isinstance(result.get("error"), AccessError) and result["error"].reason == "login_code_window_missing"
    fresh_started = time.time()
    broker.codes.begin("email", "demo-web", fresh_started)
    assert broker.codes.check_window("email", fresh_started)[1]["started"] == fresh_started
