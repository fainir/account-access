import json
import socket
import threading
import time
from urllib.parse import parse_qs, urlencode, urlsplit

import httpx2 as httpx
import pytest
from playwright.sync_api import sync_playwright

from account_access.errors import AccessError
from account_access.factors import enroll
from account_access.mailbox_oauth import (API_ORIGIN, AUTHORIZATION_URL, GMAIL_SCOPE, TOKEN_URL,
                                         begin, cancel, finish, prepare, view)
from account_access.models import CodeSource
from account_access.owner import make_owner_server


def configure(broker, *, production=False):
    config = broker.store.config()
    spec = config.accounts["demo-api"].model_copy(deep=True)
    spec.label = "Example Gmail connection"
    spec.operations = {}
    spec.scopes = [GMAIL_SCOPE]
    spec.authorization_params = {"access_type": "offline", "prompt": "consent"}
    if production:
        spec.authorization_url, spec.token_url = AUTHORIZATION_URL, TOKEN_URL
        spec.api_origins = [API_ORIGIN]
    config.accounts["mail"] = spec
    config.code_sources["mail-login"] = CodeSource(kind="gmail", account="mail", sender="login@example.test",
        recipient="demo@example.test", subject="Sign in", template="Login: {code}")
    broker.store.configure(config)
    return config.fingerprint("mail")


def start(broker):
    fingerprint = configure(broker)
    return begin(broker, "mail", fingerprint, "http://127.0.0.1:52781/callback/mail")


def callback(started):
    response = httpx.get(started["authorization_url"], follow_redirects=False, trust_env=False)
    assert response.status_code == 302
    return response.headers["Location"]


def test_configured_gmail_is_discovered_without_giving_an_agent_mailbox_access(env):
    provider, broker, _ = env
    before = broker.accounts("test")
    fingerprint = configure(broker, production=True)
    mailbox = view(broker)[0]
    assert mailbox["account"] == "mail" and mailbox["fingerprint"] == fingerprint
    assert mailbox["publisher_configured"] and not mailbox["connected"]
    assert mailbox["sources"] == [{"id": "mail-login", "recipient": "demo@example.test", "websites": []}]
    assert not mailbox["login_delivery_verified"]
    assert broker.accounts("test") == before
    assert provider.api_count == provider.login_count == 0


@pytest.mark.parametrize("change", ["authorization", "token", "scope", "api", "api-extra", "no-source"])
def test_consumer_cards_never_advertise_unreviewed_or_broader_google_oauth(env, change):
    _, broker, _ = env
    configure(broker, production=True)
    config = broker.store.config()
    spec = config.accounts["mail"]
    if change == "authorization":
        spec.authorization_url = "https://accounts.google.com.example.test/o/oauth2/v2/auth"
    elif change == "token":
        spec.token_url = "https://example.test/token"
    elif change == "scope":
        spec.scopes.append("https://www.googleapis.com/auth/drive")
    elif change == "api":
        spec.api_origins = ["https://example.test"]
    elif change == "api-extra":
        spec.api_origins.append("https://example.test")
    else:
        config.code_sources.pop("mail-login")
    broker.store.configure(config)
    assert view(broker) == []
    with pytest.raises(AccessError, match="mailbox_oauth_not_configured"):
        prepare(broker, "mail", config.fingerprint("mail"))


def test_google_application_secret_gate_does_not_request_a_user_password(env):
    _, broker, _ = env
    configure(broker, production=True)
    config = broker.store.config()
    config.accounts["mail"].token_auth_method = "client_secret_post"
    broker.store.configure(config)
    assert view(broker)[0]["publisher_configured"] is False
    with pytest.raises(AccessError, match="client_secret_not_configured"):
        begin(broker, "mail", config.fingerprint("mail"), "http://127.0.0.1:52781/callback/mail")
    assert broker.store.get("mailbox-oauth:mail") is None


@pytest.mark.parametrize("redirect", [
    "https://127.0.0.1:52781/callback/mail", "http://localhost:52781/callback/mail",
    "http://127.0.0.1:52781/callback/other", "http://127.0.0.1:52781/callback/mail?code=x",
    "http://127.0.0.1:52781/callback/mail#x", "http://user@127.0.0.1:52781/callback/mail",
    "http://127.0.0.1:80/callback/mail", "http://[::1]:52781/callback/mail",
    "http://127.0.0.1:052781/callback/mail", "http://127.0.0.1:99999/callback/mail", None,
])
def test_redirect_is_only_the_exact_desktop_loopback_listener(env, redirect):
    _, broker, _ = env
    fingerprint = configure(broker)
    with pytest.raises(AccessError, match="invalid_mailbox_oauth_redirect"):
        begin(broker, "mail", fingerprint, redirect)
    assert broker.store.get("oauth-pending:mail") is None


def test_owner_browser_handoff_performs_real_pkce_and_single_use_exchange(env):
    provider, broker, _ = env
    started = start(broker)
    query = parse_qs(urlsplit(started["authorization_url"]).query)
    assert 32 <= len(query["state"][0]) <= 256  # Matches the signed desktop callback contract.
    assert query["code_challenge_method"] == ["S256"] and len(query["code_challenge"][0]) == 43
    assert query["access_type"] == ["offline"]
    assert "verifier" not in json.dumps(started)
    returned = callback(started)
    result = finish(broker, "mail", started["attempt"], returned)
    assert result == {"status": "CONNECTED", "account": "mail", "mailbox_identity_verified": False,
                      "login_delivery_verified": False}
    saved = broker.store.get("connection:mail")
    assert saved["token"]["refresh_token"] and saved["authorization_id"]
    assert broker.store.get("source:mail-login") is None
    assert broker.store.get("oauth-pending:mail") is broker.store.get("mailbox-oauth:mail") is None
    assert saved["token"]["access_token"] not in json.dumps(view(broker)) + json.dumps(result)
    assert provider.login_count == provider.api_count == 0
    with pytest.raises(AccessError, match="invalid_mailbox_oauth_attempt"):
        finish(broker, "mail", started["attempt"], returned)


@pytest.mark.parametrize("change", ["state", "duplicate-state", "unicode-state", "path", "fragment", "both", "malformed"])
def test_bad_callback_keeps_the_original_attempt_available(env, change):
    _, broker, _ = env
    started = start(broker)
    returned = callback(started)
    if change == "state":
        returned = returned.replace("state=", "state=wrong")
    elif change == "duplicate-state":
        returned += "&state=other"
    elif change == "unicode-state":
        returned = returned.split("?", 1)[0] + "?code=x&state=%D7%90"
    elif change == "path":
        returned = returned.replace("/callback/mail", "/callback/other")
    elif change == "fragment":
        returned += "#unexpected"
    elif change == "both":
        returned += "&error=access_denied"
    else:
        returned = "http://[invalid"
    with pytest.raises(AccessError, match="invalid_oauth_callback"):
        finish(broker, "mail", started["attempt"], returned)
    assert broker.store.get("mailbox-oauth:mail")["attempt"] == started["attempt"]
    assert broker.store.get("oauth-pending:mail")
    cancel(broker, "mail", started["attempt"])


def test_cancel_and_provider_denial_preserve_the_existing_mailbox_connection(env):
    _, broker, _ = env
    first = start(broker)
    finish(broker, "mail", first["attempt"], callback(first))
    connection = broker.store.get("connection:mail")
    fingerprint = broker.store.config().fingerprint("mail")
    second = begin(broker, "mail", fingerprint, "http://127.0.0.1:52782/callback/mail")
    with pytest.raises(AccessError, match="mailbox_oauth_already_running"):
        begin(broker, "mail", fingerprint, "http://127.0.0.1:52783/callback/mail")
    cancel(broker, "mail", second["attempt"])
    third = begin(broker, "mail", fingerprint, "http://127.0.0.1:52783/callback/mail")
    with pytest.raises(AccessError, match="invalid_mailbox_oauth_attempt"):
        cancel(broker, "mail", second["attempt"])
    assert broker.store.get("mailbox-oauth:mail")["attempt"] == third["attempt"]
    query = parse_qs(urlsplit(third["authorization_url"]).query)
    denial = "http://127.0.0.1:52783/callback/mail?" + urlencode({"state": query["state"][0], "error": "access_denied"})
    with pytest.raises(AccessError, match="oauth_connection_declined"):
        finish(broker, "mail", third["attempt"], denial)
    assert broker.store.get("connection:mail") == connection
    assert broker.store.get("oauth-pending:mail") is broker.store.get("mailbox-oauth:mail") is None


def test_expiry_and_configuration_drift_cannot_exchange_a_code(env):
    provider, broker, _ = env
    started = start(broker)
    returned = callback(started)
    config = broker.store.config()
    config.accounts["mail"].client_id = "different-registered-client"
    broker.store.configure(config)
    before = list(provider.posted_paths)
    with pytest.raises(AccessError, match="mailbox_oauth_configuration_changed"):
        finish(broker, "mail", started["attempt"], returned)
    cancel(broker, "mail", started["attempt"])
    current = begin(broker, "mail", config.fingerprint("mail"), "http://127.0.0.1:52781/callback/mail")
    flow = broker.store.get("mailbox-oauth:mail")
    flow["expires"] = time.time() - 1
    broker.store.put("mailbox-oauth:mail", flow)
    with pytest.raises(AccessError, match="mailbox_oauth_expired"):
        finish(broker, "mail", current["attempt"], returned)
    assert provider.posted_paths == before
    assert broker.store.get("oauth-pending:mail") is broker.store.get("mailbox-oauth:mail") is None


def test_cancellation_and_replacement_wait_for_an_active_exchange(env, monkeypatch):
    _, broker, _ = env
    started = start(broker)
    returned = callback(started)
    entered, release, cancelled = threading.Event(), threading.Event(), threading.Event()
    original = broker.oauth._finish_locked
    errors = []

    def exchange(account, callback):
        entered.set()
        assert release.wait(5)
        original(account, callback)

    def finish_thread():
        try:
            finish(broker, "mail", started["attempt"], returned)
        except Exception as exc:
            errors.append(exc)

    def cancel_thread():
        try:
            cancel(broker, "mail", started["attempt"])
        except AccessError as exc:
            errors.append(exc.reason)
        finally:
            cancelled.set()

    monkeypatch.setattr(broker.oauth, "_finish_locked", exchange)
    worker = threading.Thread(target=finish_thread)
    worker.start()
    assert entered.wait(5)
    cancellation = threading.Thread(target=cancel_thread)
    cancellation.start()
    assert not cancelled.wait(.1)
    release.set()
    worker.join(5)
    cancellation.join(5)
    assert not worker.is_alive() and not cancellation.is_alive()
    assert errors == ["invalid_mailbox_oauth_attempt"]
    assert broker.store.get("connection:mail")


def test_mailbox_oauth_routes_require_owner_capability_and_preserve_agent_boundary(env):
    _, broker, token = env
    fingerprint = configure(broker)
    server, owner = make_owner_server(broker, guided=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{server.server_port}"
    headers = {"Authorization": "Bearer " + owner, "Origin": base}
    try:
        with httpx.Client(base_url=base, trust_env=False) as client:
            state = client.get("/owner/state", headers=headers).json()
            assert state["mailbox_oauth"][0]["account"] == "mail"
            body = {"account": "mail", "fingerprint": fingerprint, "redirect_uri": "http://127.0.0.1:52781/callback/mail"}
            for wrong in [{}, {"Authorization": "Bearer " + token, "Origin": base},
                          {"Authorization": "Bearer " + owner, "Origin": "https://example.test"}]:
                assert client.post("/owner/mailbox/oauth/begin", json=body, headers=wrong).status_code == 403
            started = client.post("/owner/mailbox/oauth/begin", json=body, headers=headers).json()
            returned = callback(started)
            for route in ["finish", "cancel"]:
                data = {"account": "mail", "attempt": started["attempt"]}
                if route == "finish":
                    data["callback"] = returned
                assert client.post("/owner/mailbox/oauth/" + route, json=data).status_code == 403
            result = client.post("/owner/mailbox/oauth/finish", headers=headers,
                json={"account": "mail", "attempt": started["attempt"], "callback": returned})
            assert result.status_code == 200 and result.json()["status"] == "CONNECTED"
            assert "mail" not in [item["account"] for item in broker.accounts("test")["accounts"]]
    finally:
        server.shutdown()
        server.server_close()
        thread.join(5)


def test_new_google_consent_replaces_authority_of_a_pending_login(env, monkeypatch):
    _, broker, _ = env
    first = start(broker)
    finish(broker, "mail", first["attempt"], callback(first))
    enroll(broker.store, "mail-login", {})
    monkeypatch.setattr("account_access.codes.get_json", lambda *args, **kwargs: {})
    started = time.time() - 1
    broker.codes.begin("mail-login", "demo-web", started)
    authority = broker.store.get("connection:mail")["authorization_id"]
    current = begin(broker, "mail", broker.store.config().fingerprint("mail"), "http://127.0.0.1:52782/callback/mail")
    finish(broker, "mail", current["attempt"], callback(current))
    assert broker.store.get("connection:mail")["authorization_id"] != authority
    with pytest.raises(AccessError, match="verification_source_enrollment_changed"):
        broker.codes.resolve("mail-login", started, set())


def test_isolated_worker_handoff_never_opens_the_owners_browser(env, monkeypatch):
    _, broker, _ = env
    fingerprint = configure(broker)
    monkeypatch.setattr("webbrowser.open", lambda *args: pytest.fail("The worker must not open a browser"))
    path = str(broker.store.root / "mailbox-owner.sock")
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(path)
    server, owner = make_owner_server(broker, guided=True, server_socket=listener, origin_port=8765,
                                     local_host_actions=False)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        with httpx.Client(transport=httpx.HTTPTransport(uds=path), base_url="http://127.0.0.1:8765",
                          headers={"Authorization": "Bearer " + owner, "Origin": "http://127.0.0.1:8765"},
                          trust_env=False) as client:
            state = client.get("/owner/state").json()
            assert state["mailbox_oauth"][0]["account"] == "mail" and state["local_host_actions"] is False
            assert client.post("/owner/mailbox/oauth/connect", json={"account": "mail", "fingerprint": fingerprint}).status_code == 403
            started = client.post("/owner/mailbox/oauth/begin", json={"account": "mail", "fingerprint": fingerprint,
                "redirect_uri": "http://127.0.0.1:52781/callback/mail"}).json()
            returned = callback(started)
            result = client.post("/owner/mailbox/oauth/finish", json={"account": "mail", "attempt": started["attempt"],
                "callback": returned})
            assert result.status_code == 200 and result.json()["status"] == "CONNECTED"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(5)


def test_verification_browser_starts_configured_google_connection_without_app_password(env, monkeypatch):
    provider, broker, _ = env
    configure(broker)
    monkeypatch.setattr("account_access.install.install_detected", lambda store: {"status": "INSTALLED"})
    browser_calls = []

    def open_browser(url):
        browser_calls.append(url)
        threading.Thread(target=lambda: httpx.get(url, follow_redirects=True, trust_env=False), daemon=True).start()
        return True

    monkeypatch.setattr("webbrowser.open", open_browser)
    server, owner = make_owner_server(broker, guided=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{server.server_port}"
    try:
        with sync_playwright() as pw:
            browser = pw.chromium.launch(headless=True, chromium_sandbox=True)
            try:
                page = browser.new_page()
                page.goto(base + "/#" + owner)
                page.get_by_role("button", name="Verification", exact=True).click()
                page.get_by_role("button", name="Connect with Google", exact=True).click()
                page.get_by_text("Google access is saved.", exact=False).wait_for()
                assert len(browser_calls) == 1 and browser_calls[0].startswith(provider.base + "/oauth/authorize?")
                assert broker.store.get("connection:mail") and broker.store.get("source:mail-login") is None
                assert provider.login_count == provider.api_count == 0
                assert not page.get_by_label("Application password", exact=True).is_visible()
            finally:
                browser.close()
    finally:
        server.shutdown()
        server.server_close()
        thread.join(5)


def test_existing_owner_connect_route_still_starts_its_oauth_job(env, monkeypatch):
    provider, broker, _ = env
    configure(broker)

    def open_browser(url):
        threading.Thread(target=lambda: httpx.get(url, follow_redirects=True, trust_env=False), daemon=True).start()
        return True

    monkeypatch.setattr("webbrowser.open", open_browser)
    server, owner = make_owner_server(broker, guided=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{server.server_port}"
    headers = {"Authorization": "Bearer " + owner, "Origin": base}
    try:
        with httpx.Client(base_url=base, headers=headers, trust_env=False) as client:
            started = client.post("/owner/connect", json={"account": "mail"})
            assert started.status_code == 200 and started.json()["status"] == "RUNNING"
            ident = started.json()["id"]
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline:
                job = client.get("/owner/state").json()["connection_jobs"][ident]
                if job["status"] != "RUNNING":
                    break
                time.sleep(.02)
            assert job["status"] == "CONNECTED" and broker.store.get("connection:mail")
            assert provider.login_count == provider.api_count == 0
    finally:
        server.shutdown()
        server.server_close()
        thread.join(5)
