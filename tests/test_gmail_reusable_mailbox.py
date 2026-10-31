"""Reusable Google identities and real local HTTP fixtures, never private mail."""

import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from types import SimpleNamespace
from urllib.parse import urlsplit

import pytest

from account_access import device_email_setup as setup
from account_access import mailbox_oauth as gmail
from account_access.broker import Broker
from account_access.catalog import PYPI_ACCOUNT, PYPI_SOURCE, pypi
from account_access.errors import AccessError
from account_access.mailboxes import enrollment
from account_access.models import CodeSource, Configuration, OAuthAccount
from account_access.storage import Store
from test_pypi_device_email import device_browser, encoded  # noqa: F401

ADDRESS = "fictional@example.test"


@pytest.fixture
def saved_google(tmp_path):
    state = SimpleNamespace(status=200, profile={"emailAddress": ADDRESS, "messagesTotal": 19,
        "threadsTotal": 11, "historyId": "not-needed"}, profiles=0, refreshes=0,
        profile_delay=0, refresh_delay=0, refresh_started=threading.Event(), hook=lambda: None)

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def reply(self, status, value):
            body = json.dumps(value).encode()
            try:
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            except (BrokenPipeError, ConnectionResetError):
                pass  # A deadline test deliberately closes its own fixture socket.

        def do_GET(self):
            assert self.path == "/gmail/v1/users/me/profile"
            assert self.headers.get("Authorization", "").startswith("Bearer synthetic-")
            state.profiles += 1
            state.hook()
            time.sleep(state.profile_delay)
            self.reply(state.status, state.profile)

        def do_POST(self):
            assert self.path == "/token"
            self.rfile.read(int(self.headers["Content-Length"]))
            state.refreshes += 1
            state.refresh_started.set()
            time.sleep(state.refresh_delay)
            self.reply(200, {"access_token": "synthetic-renewed-access", "refresh_token": "synthetic-renewed-refresh",
                             "token_type": "Bearer", "expires_in": 3600, "scope": gmail.GMAIL_SCOPE})

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server.daemon_threads = True
    thread = threading.Thread(target=lambda: server.serve_forever(poll_interval=.01), daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{server.server_port}"
    store = Store(tmp_path / "fictional-state", b"k" * 32)
    store.configure(Configuration(test_mode=True, accounts={PYPI_ACCOUNT: pypi(),
        "google": OAuthAccount(kind="oauth", label="Saved Google", client_id="fictional-client",
            authorization_url=base + "/authorize", token_url=base + "/token", api_origins=[base],
            scopes=[gmail.GMAIL_SCOPE], operations={})}, code_sources={PYPI_SOURCE: CodeSource(kind="totp")}))
    broker = Broker(store)
    broker.oauth.save("google", {"access_token": "synthetic-access", "refresh_token": "synthetic-refresh",
        "token_type": "Bearer", "expires_in": 3600, "scope": gmail.GMAIL_SCOPE}, store.config())
    store.new_client("fixture")
    broker.grant("fixture", PYPI_ACCOUNT, ["status"])
    try:
        yield broker, state
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def checked(broker):
    return gmail.check(broker, "google", broker.store.config().fingerprint("google"))


def link(broker):
    result = checked(broker)
    preview = setup.preview(broker.store, PYPI_ACCOUNT,
                            broker.store.config().fingerprint(PYPI_ACCOUNT), result["id"])
    return setup.apply(broker.store, preview["id"])["source"]


def test_google_first_setup_reads_only_profile_and_does_not_grant_any_source(saved_google):
    broker, http = saved_google
    store = broker.store
    before = store.config().model_dump()
    with store.db() as db:
        grants = [tuple(row) for row in db.execute("SELECT * FROM grants")]
    result = checked(broker)
    assert result["status"] == "VERIFIED" and result["recipient"] == ADDRESS
    assert result["mailbox_identity_verified"] and not result["login_delivery_verified"]
    assert http.profiles == 1 and http.refreshes == 0
    assert store.config().model_dump() == before
    with store.db() as db:
        assert [tuple(row) for row in db.execute("SELECT * FROM grants")] == grants
        assert not db.execute("SELECT id FROM records WHERE id LIKE 'source:%'").fetchall()
    item = gmail.view(broker)[0]
    assert item["sources"] == [] and item["mailbox_identity_verified"]
    assert item["reusable_mailbox"]["id"] == result["id"]
    assert setup.view(store)[0]["mailboxes"] == [{"id": result["id"], "label": "Saved Google",
                                                 "recipient": ADDRESS, "kind": "gmail"}]
    saved = store.get(gmail.PROFILE_PREFIX + result["id"])
    assert not {"token", "access_token", "refresh_token", "messagesTotal", "threadsTotal", "historyId"} & saved.keys()
    assert "synthetic-" not in json.dumps(item) + json.dumps(setup.view(store)) + json.dumps(result)


def test_ordinary_check_and_token_refresh_preserve_bound_source_and_pending_review(saved_google):
    broker, http = saved_google
    source = link(broker)
    store = broker.store
    ident = gmail.profile_id("google")
    original = gmail.profile(store, ident)
    preview = setup.preview(store, PYPI_ACCOUNT, store.config().fingerprint(PYPI_ACCOUNT), ident)
    checked(broker)
    connection = store.get("connection:google")
    connection["token"]["expires_at"] = 0
    store.put("connection:google", connection)
    checked(broker)
    assert http.refreshes == 1 and http.profiles == 3
    assert gmail.profile(store, ident)["generation"] == original["generation"]
    assert gmail.profile(store, ident)["authorization_id"] == original["authorization_id"]
    assert enrollment(store, source)["gmail_mailbox"] == ident
    assert setup.apply(store, preview["id"])["status"] == "ENROLLED"


def test_new_consent_requires_identity_recheck_and_explicit_source_relink(saved_google):
    broker, _ = saved_google
    source = link(broker)
    store = broker.store
    ident = gmail.profile_id("google")
    generation = gmail.profile(store, ident)["generation"]
    preview = setup.preview(store, PYPI_ACCOUNT, store.config().fingerprint(PYPI_ACCOUNT), ident)
    token = store.get("connection:google")["token"]
    broker.oauth.save("google", token, store.config())  # A new owner authorization, even identical bytes.
    assert gmail.view(broker)[0]["reusable_mailbox"] is None
    with pytest.raises(AccessError, match="mailbox_identity_check_required"):
        enrollment(store, source)
    checked(broker)
    assert gmail.profile(store, ident)["generation"] != generation
    assert not setup.view(store)[0]["connected"]
    with pytest.raises(AccessError, match="device_email_mailbox_changed"):
        setup.apply(store, preview["id"])
    with pytest.raises(AccessError, match="mailbox_identity_check_required"):
        enrollment(store, source)
    value = setup.preview(store, PYPI_ACCOUNT, store.config().fingerprint(PYPI_ACCOUNT), ident)
    current = setup.apply(store, value["id"])["source"]
    assert enrollment(store, current)["gmail_mailbox"] == ident
    assert setup.view(store)[0]["connected"]


@pytest.mark.parametrize("change", ["revoke", "invalid", "refresh", "config", "delete", "scope"])
def test_changed_google_authority_is_not_selectable_or_readable_before_baseline(saved_google, monkeypatch, change):
    broker, http = saved_google
    source = link(broker)
    store = broker.store
    connection = store.get("connection:google")
    if change == "config":
        config = store.config()
        config.accounts["google"].label = "Changed publisher connection"
        store.configure(config)
    elif change == "delete":
        store.put("connection:google", None)
    else:
        if change == "scope":
            connection["token"]["scope"] += " https://www.googleapis.com/auth/drive"
        else:
            connection[{"revoke": "revoked", "invalid": "invalid", "refresh": "refresh_in_flight"}[change]] = True
        store.put("connection:google", connection)
    assert gmail.view(broker)[0]["reusable_mailbox"] is None
    assert not setup.view(store)[0]["connected"]
    monkeypatch.setattr(broker.codes, "gmail_ids", lambda *args: pytest.fail("unusable identity must stop before baseline"))
    with pytest.raises(AccessError):
        broker.codes.begin(source, PYPI_ACCOUNT, time.time())
    assert http.profiles == 1


@pytest.mark.parametrize("address", [None, [], "", "a\r\n@example.test", "missing-at", "a" * 201 + "@example.test"])
def test_invalid_identity_cannot_become_a_reusable_profile(saved_google, address):
    broker, http = saved_google
    http.profile = {"emailAddress": address, "arbitrary": "synthetic-private-detail"}
    with pytest.raises(AccessError, match="^invalid_mailbox_response$") as error:
        checked(broker)
    assert "synthetic" not in str(error.value)
    assert gmail.reusable(broker.store, "google") is None


@pytest.mark.parametrize("status,reason", [(401, "mailbox_connection_retry_required"),
                                          (403, "provider_forbidden"), (500, "provider_temporarily_unavailable")])
def test_profile_failure_preserves_consent_and_previously_verified_identity(saved_google, status, reason):
    broker, http = saved_google
    result = checked(broker)
    before = broker.store.get(gmail.PROFILE_PREFIX + result["id"])
    authorization = broker.store.get("connection:google")["authorization_id"]
    http.status = status
    http.profile = {"error": "synthetic-sensitive-server-detail"}
    with pytest.raises(AccessError, match="^" + reason + "$") as error:
        checked(broker)
    assert "synthetic" not in str(error.value)
    assert broker.store.get(gmail.PROFILE_PREFIX + result["id"]) == before
    assert broker.store.get("connection:google")["authorization_id"] == authorization
    if status == 401:
        http.status, http.profile = 200, {"emailAddress": ADDRESS}
        checked(broker)
        assert http.refreshes == 1


@pytest.mark.parametrize("change", ["config", "authorization", "revoke"])
def test_profile_result_rechecks_exact_authority_before_publication(saved_google, change):
    broker, http = saved_google
    def mutate():
        if change == "config":
            config = broker.store.config()
            config.accounts["google"].label = "Changed during profile response"
            broker.store.configure(config)
        else:
            connection = broker.store.get("connection:google")
            connection["authorization_id" if change == "authorization" else "revoked"] = "f" * 32 if change == "authorization" else True
            broker.store.put("connection:google", connection)
    http.hook = mutate
    with pytest.raises(AccessError):
        checked(broker)
    assert gmail.reusable(broker.store, "google") is None


def test_profile_has_total_deadline_without_removing_consent(saved_google, monkeypatch):
    broker, http = saved_google
    http.profile_delay = .2
    monkeypatch.setattr(gmail, "PROFILE_TIMEOUT", .05)
    started = time.monotonic()
    with pytest.raises(AccessError, match="network_unavailable"):
        checked(broker)
    assert time.monotonic() - started < 1
    assert broker.store.get("connection:google")["authorization_id"]
    assert gmail.reusable(broker.store, "google") is None


def test_explicit_refresh_budget_marks_uncertain_rotation_without_blind_retry(saved_google):
    broker, http = saved_google
    connection = broker.store.get("connection:google")
    authorization = connection["authorization_id"]
    # Wait until the local server has definitely received the refresh request
    # before allowing the deliberate read timeout to race against it.
    http.refresh_delay = .6
    result = {}
    started = time.monotonic()

    def refresh_once():
        try:
            broker.oauth.token("google", broker.store.config(), force=True, refresh_timeout=.2)
        except AccessError as exc:
            result["error"] = exc

    worker = threading.Thread(target=refresh_once)
    worker.start()
    assert http.refresh_started.wait(timeout=1), "refresh request never reached the local provider"
    worker.join(timeout=1)
    assert not worker.is_alive(), "bounded refresh did not return after its deadline"
    assert isinstance(result.get("error"), AccessError)
    assert result["error"].reason == "refresh_outcome_uncertain"
    assert time.monotonic() - started < 1
    current = broker.store.get("connection:google")
    assert current["refresh_in_flight"] and current["authorization_id"] == authorization
    with pytest.raises(AccessError, match="refresh_outcome_uncertain"):
        checked(broker)
    assert http.refreshes == 1 and http.profiles == 0


def test_google_profile_picker_real_http_device_mail_login_and_session_reuse(device_browser, monkeypatch):  # noqa: F811
    from account_access import codes
    from account_access.providers import get_json
    provider, broker, spec, state = device_browser
    parent = provider.server.RequestHandlerClass
    profile_path, messages_path = "/gmail/v1/users/me/profile", "/gmail/v1/users/me/messages"
    state["profiles"], state["gmail_lists"] = 0, 0

    class Handler(parent):
        def do_GET(self):
            path = urlsplit(self.path).path
            if path == profile_path:
                state["profiles"] += 1
                self.send(200, {"emailAddress": ADDRESS})
            elif path == messages_path:
                state["gmail_lists"] += 1
                self.send(200, {"messages": [{"id": "fresh"}]} if state["mail"] else {})
            elif path == messages_path + "/fresh":
                state["mail_reads"].append("fresh")
                self.send(200, {"id": "fresh", "internalDate": str(int(time.time() * 1000)),
                                "raw": encoded(state["mail"])})
            else:
                super().do_GET()

    provider.server.RequestHandlerClass = Handler
    config = broker.store.config()
    google = config.accounts["demo-api"].model_copy(deep=True)
    google.scopes, google.operations, google.api_origins = [gmail.GMAIL_SCOPE], {}, [provider.base]
    config.accounts["google"] = google
    broker.store.configure(config)
    token = broker.store.get("connection:demo-api")["token"]
    broker.oauth.save("google", {**token, "scope": gmail.GMAIL_SCOPE}, config)
    core = spec.model_copy(deep=True)
    core.login.device_email_source = None
    monkeypatch.setattr(setup, "pypi", lambda: core.model_copy(deep=True))
    monkeypatch.setattr(codes, "GMAIL_MESSAGES", provider.base + messages_path)
    monkeypatch.setattr(codes, "get_json", get_json)  # Real bounded HTTP, not the base fixture's message stub.
    result = checked(broker)
    review = setup.preview(broker.store, "pypi-device",
                           broker.store.config().fingerprint("pypi-device"), result["id"])
    assert state["passwords"] == state["gmail_lists"] == 0
    setup.apply(broker.store, review["id"])
    assert state["passwords"] == state["gmail_lists"] == 0
    actual = broker.run("test", "pypi-device", "status")
    assert actual["status"] == "COMPLETED", actual
    assert actual["data"] == {"username": "fictional-owner"}
    assert state["passwords"] == state["totps"] == state["confirmations"] == state["profiles"] == 1
    assert state["projects"] == 0 and state["mail_reads"] == ["fresh"]
    assert state["email_token"] not in json.dumps(actual)
    assert broker.run("test", "pypi-device", "status")["status"] == "COMPLETED"
    assert state["passwords"] == state["totps"] == state["confirmations"] == 1
    before = state["gmail_lists"]
    connection = broker.store.get("connection:google")
    connection["revoked"] = True
    broker.store.put("connection:google", connection)
    broker.store.put("connection:pypi-device", None)
    broker.store.put("login-attempt:pypi-device", 0)  # Reach source validation without a real cooldown sleep.
    blocked = broker.run("test", "pypi-device", "status")
    assert blocked["status"] == "NEEDS_USER", blocked
    # Device mail is optional until PyPI asks for it: the approved password
    # and primary TOTP can run, but revoked mail never starts a baseline/read
    # or confirmation request, and cannot claim a completed sign-in.
    assert state["passwords"] == state["totps"] == 2
    assert state["confirmations"] == 1
    assert state["gmail_lists"] == before
