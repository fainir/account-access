"""Checked reusable Gmail identity binding; fictional sources and local HTTP only."""

import json
import threading
import time
from contextlib import contextmanager

import httpx2 as httpx
import pytest

from account_access import mailbox_binding as binding
from account_access import mailbox_oauth as gmail
from account_access.errors import AccessError
from account_access.factors import enroll, revoke
from account_access.mailboxes import enrollment
from account_access.models import BrowserAccount, BrowserOperation, CodeSource, LoginFactor, LoginForm
from account_access.owner import make_owner_server
from test_gmail_reusable_mailbox import ADDRESS, checked, saved_google  # noqa: F401

SOURCE = "ordinary-email"
SITE = "ordinary-site"


def ordinary_source(broker):
    config = broker.store.config()
    config.code_sources[SOURCE] = CodeSource(kind="gmail", account="google", sender="login@example.test",
        recipient=ADDRESS, subject="Your sign-in code", template="Login code: {code}")
    config.accounts[SITE] = BrowserAccount(kind="browser", label="Fictional service",
        login_url="https://example.test/login", ready_selector="#signed-in",
        login=LoginForm(username_selector="#username", password_selector="#password", submit_selector="#login",
            factors={"email": LoginFactor(code_selector="#code", code_submit_selector="#confirm", code_source=SOURCE)}),
        challenge_selectors={"login": "#password", "email": "#code"},
        operations={"status": BrowserOperation(url="https://example.test/profile",
            description="Confirm the fictional username", fields={"username": "#signed-in"})})
    broker.store.configure(config)
    return config


@pytest.fixture
def connected(saved_google):  # noqa: F811
    broker, provider = saved_google
    ordinary_source(broker)
    checked(broker)
    return broker, provider


def payload(store):
    current = binding.metadata(store, SOURCE)
    return {"mailbox": gmail.profile_id("google"),
            **{key: current[key] for key in ["setup_context", "setup_revision"]}}


def grants(store):
    with store.db() as db:
        return [tuple(row) for row in db.execute("SELECT * FROM grants ORDER BY principal,account,operation")]


def test_checked_picker_and_link_change_only_selected_source_authority(connected, monkeypatch):
    broker, provider = connected
    store = broker.store
    config = store.config()
    config.code_sources["second-email"] = config.code_sources[SOURCE].model_copy(deep=True)
    store.configure(config)
    broker.grant("fixture", SITE, ["status"])
    before = store.config().model_dump(), grants(store), store.get("connection:google")
    store.put("code-window:" + SOURCE, {"fictional": "old window"})
    store.put("mailbox-health:" + SOURCE, {"status": "VERIFIED"})
    calls = provider.profiles, provider.refreshes
    monkeypatch.setattr(broker.oauth, "token", lambda *a, **k: pytest.fail("Binding must not refresh or read mail"))
    state = binding.metadata(store, SOURCE)
    assert state["mailbox_options"] == [{"id": gmail.profile_id("google"), "label": "Saved Google",
                                         "recipient": ADDRESS, "kind": "gmail"}]
    assert state["linked_mailbox"] is None
    assert "synthetic-" not in json.dumps(state)
    assert enroll(store, SOURCE, payload(store)) == {"status": "ENROLLED", "source": SOURCE, "kind": "gmail"}
    record = store.get("source:" + SOURCE)
    profile = gmail.profile(store, gmail.profile_id("google"))
    assert record == {"enabled": True, "gmail_mailbox": gmail.profile_id("google"),
                       "gmail_generation": profile["generation"], "gmail_authorization": profile["authorization_id"]}
    assert enrollment(store, SOURCE)["gmail_mailbox"] == gmail.profile_id("google")
    assert binding.metadata(store, SOURCE)["linked_mailbox"] == gmail.profile_id("google")
    assert binding.metadata(store, SOURCE)["setup_revision"] != state["setup_revision"]
    assert store.get("source:second-email") is None
    assert store.get("code-window:" + SOURCE) is None and store.get("mailbox-health:" + SOURCE) is None
    assert (store.config().model_dump(), grants(store), store.get("connection:google")) == before
    assert (provider.profiles, provider.refreshes) == calls


def test_unchecked_google_identity_is_not_offered_or_silently_adopted(saved_google):  # noqa: F811
    broker, provider = saved_google
    ordinary_source(broker)
    assert binding.metadata(broker.store, SOURCE)["mailbox_options"] == []
    with pytest.raises(AccessError, match="mailbox_not_connected"):
        enroll(broker.store, SOURCE, payload(broker.store))
    assert broker.store.get("source:" + SOURCE) is None
    # The explicit legacy path still enables its preconfigured filter; it does
    # not manufacture or adopt a checked reusable Google profile.
    enroll(broker.store, SOURCE, {})
    assert broker.store.get("source:" + SOURCE) == {"enabled": True}
    assert provider.profiles == provider.refreshes == 0


def test_picker_reads_one_consistent_authority_snapshot(connected, monkeypatch):
    broker, provider = connected
    original = broker.store.db
    connections = []

    @contextmanager
    def counted():
        with original() as db:
            connections.append(db)
            yield db

    monkeypatch.setattr(broker.store, "db", counted)
    assert binding.metadata(broker.store, SOURCE)["mailbox_options"]
    assert len(connections) == 1
    assert provider.profiles == 1 and provider.refreshes == 0


def test_picker_is_discarded_when_source_context_changes_after_snapshot(connected, monkeypatch):
    broker, _ = connected
    original = broker.store.db

    @contextmanager
    def changed():
        with original() as db:
            yield db
        config = broker.store.config()
        config.code_sources[SOURCE].subject = "Another reviewed subject"
        broker.store.configure(config)

    monkeypatch.setattr(broker.store, "db", changed)
    assert binding.metadata(broker.store, SOURCE) == {}


@pytest.mark.parametrize("value", [True, "malformed", [], 42])
def test_malformed_connection_is_not_offered_or_adopted(connected, value):
    broker, _ = connected
    store = broker.store
    before = payload(store)
    store.put("connection:google", value)
    current = binding.metadata(store, SOURCE)
    assert current["mailbox_options"] == [] and current["setup_revision"] != before["setup_revision"]
    with pytest.raises(AccessError, match="mailbox_not_connected"):
        enroll(store, SOURCE, payload(store))
    assert store.get("source:" + SOURCE) is None


@pytest.mark.parametrize("change", ["source-filter", "account", "source-revoke", "new-consent", "profile-delete",
                                    "account-revoke", "grant-invalid", "scope-loss", "connection-delete"])
def test_old_picker_cannot_enable_changed_or_revoked_authority(connected, change):
    broker, _ = connected
    store = broker.store
    data = payload(store)
    if change in {"source-filter", "account"}:
        config = store.config()
        if change == "source-filter":
            config.code_sources[SOURCE].subject = "Another exact subject"
        else:
            config.accounts[SITE].ready_selector = "#another-reviewed-marker"
        store.configure(config)
    elif change == "source-revoke":
        revoke(store, SOURCE)
    elif change == "new-consent":
        broker.oauth.save("google", store.get("connection:google")["token"], store.config())
    elif change == "profile-delete":
        store.put(gmail.PROFILE_PREFIX + gmail.profile_id("google"), None)
    elif change == "account-revoke":
        broker.revoke(account="google")
    elif change == "connection-delete":
        store.put("connection:google", None)
    else:
        connection = store.get("connection:google")
        if change == "scope-loss":
            connection["token"]["scope"] = ""
        else:
            connection["invalid"] = True
        store.put("connection:google", connection)
    before = store.get("source:" + SOURCE)
    assert binding.metadata(store, SOURCE)["setup_revision"] != data["setup_revision"]
    with pytest.raises(AccessError, match="mailbox_binding_changed"):
        enroll(store, SOURCE, data)
    assert store.get("source:" + SOURCE) == before


def test_refresh_and_repeated_identity_check_keep_picker_current(connected):
    broker, provider = connected
    store = broker.store
    data = payload(store)
    connection = store.get("connection:google")
    connection["token"]["expires_at"] = 0
    store.put("connection:google", connection)
    checked(broker)
    assert provider.refreshes == 1
    assert payload(store) == data
    assert enroll(store, SOURCE, data)["status"] == "ENROLLED"


@pytest.mark.parametrize("change", ["recipient", "different-account"])
def test_profile_must_match_exact_source_account_and_recipient(connected, change):
    broker, _ = connected
    store = broker.store
    ident = gmail.profile_id("google")
    if change == "recipient":
        config = store.config()
        config.code_sources[SOURCE].recipient = "another@example.test"
        store.configure(config)
        assert binding.metadata(store, SOURCE)["mailbox_options"] == []
    else:
        config = store.config()
        config.accounts["other-google"] = config.accounts["google"].model_copy(deep=True)
        store.configure(config)
        broker.oauth.save("other-google", store.get("connection:google")["token"], store.config())
        gmail.check(broker, "other-google", store.config().fingerprint("other-google"))
        ident = gmail.profile_id("other-google")
    data = {**payload(store), "mailbox": ident}
    with pytest.raises(AccessError, match="mailbox_source_mismatch"):
        enroll(store, SOURCE, data)
    assert store.get("source:" + SOURCE) is None


@pytest.mark.parametrize("change", ["missing-revision", "extra", "bad-context", "bad-mailbox"])
def test_malformed_link_cannot_fall_back_to_legacy_enable(connected, change):
    broker, _ = connected
    data = payload(broker.store)
    if change == "missing-revision":
        data.pop("setup_revision")
    elif change == "extra":
        data["enabled"] = True
    elif change == "bad-context":
        data["setup_context"] = "not-a-context"
    else:
        data["mailbox"] = "mailbox-" + "0" * 24
    with pytest.raises(AccessError, match="invalid_mailbox_binding"):
        enroll(broker.store, SOURCE, data)
    assert broker.store.get("source:" + SOURCE) is None


def test_owner_http_exposes_nonsecret_current_filter_and_enforces_agent_boundary(connected):
    broker, _ = connected
    store = broker.store
    agent = store.new_client("agent-fixture")
    server, owner = make_owner_server(broker, guided=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{server.server_port}"
    headers = {"Authorization": "Bearer " + owner, "Origin": base}
    try:
        with httpx.Client(base_url=base, trust_env=False) as client:
            response = client.get("/owner/state", headers=headers)
            assert response.status_code == 200
            source = next(item for item in response.json()["code_sources"] if item["id"] == SOURCE)
            assert source["sender"] == "login@example.test" and source["subject"] == "Your sign-in code"
            assert source["recipient"] == ADDRESS and source["mailbox_options"]
            assert "synthetic-" not in response.text
            request = {"source": SOURCE, "credential": payload(store)}
            for wrong in [{}, {"Authorization": "Bearer " + agent, "Origin": base},
                          {"Authorization": "Bearer " + owner, "Origin": "https://elsewhere.example.test"}]:
                assert client.post("/owner/source", json=request, headers=wrong).status_code == 403
            assert store.get("source:" + SOURCE) is None
            response = client.post("/owner/source", json=request, headers=headers)
            assert response.status_code == 200 and response.json()["status"] == "ENROLLED"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_linked_profile_revocation_stops_pending_code_window_before_message_read(connected, monkeypatch):
    broker, _ = connected
    store = broker.store
    enroll(store, SOURCE, payload(store))
    calls = []
    monkeypatch.setattr("account_access.codes.get_json", lambda *a, **k: calls.append(a[0]) or {})
    started = time.time() - 1
    broker.codes.begin(SOURCE, SITE, started)
    assert len(calls) == 1
    broker.revoke(account="google")
    with pytest.raises(AccessError, match="connection_revoked"):
        broker.codes.resolve(SOURCE, started, set())
    assert len(calls) == 1
