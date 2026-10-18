"""Real browser transport with fictional credentials and concurrent source revocation."""
# ruff: noqa: F811 -- pytest consumes imported fixtures by name.

from contextlib import contextmanager
import json
import time
from types import SimpleNamespace

import pytest
from playwright.sync_api import Locator, sync_playwright

from account_access import bitwarden_source as source, password_sync
from account_access.browser import Browser, _PasswordAuthority
from account_access.demo import DEMO_PASSWORD
from account_access.errors import AccessError
from test_bitwarden_source import cli, link, setup_data  # noqa: F401


@pytest.fixture
def enrolled(env, cli, monkeypatch):
    website, broker, _ = env
    store, source_file = cli
    # The fake CLI tests stripped inheritance separately; do not start the
    # browser's own Node driver with the fixture's synthetic inspector option.
    monkeypatch.delenv("NODE_OPTIONS", raising=False)
    state = json.loads(source_file.read_text())
    state["item"]["login"]["password"] = DEMO_PASSWORD
    source_file.write_text(json.dumps(state))
    connection = source.connect(store, setup_data())
    password_sync.enroll(store, "demo-web", link(connection))
    return website, broker, connection


def disconnect(broker, connection, account="demo-web"):
    started = time.monotonic()
    source.disconnect(broker.store, connection["id"], connection["generation"])
    assert time.monotonic() - started < 5  # No navigation/code/review wait holds authority.
    assert broker.store.get("credential:" + account) is None
    assert broker.store.get("connection:" + account) is None


def blocked(result, broker, account="demo-web", reason="password_source_access_removed"):
    assert result["status"] == "NEEDS_USER"
    assert result["challenge"]["reason"] == reason
    assert broker.store.get("credential:" + account) is None
    assert broker.store.get("connection:" + account) is None


@pytest.mark.parametrize("phase", ["form", "code-baseline"])
def test_disconnect_during_preflight_prevents_any_credential_disclosure(enrolled, monkeypatch, phase):
    website, broker, connection = enrolled
    account = "demo-mfa" if phase == "code-baseline" else "demo-web"
    if account == "demo-mfa":
        password_sync.enroll(broker.store, account, link(connection))
    original_form, original_begin, original_fill = Browser.check_form, broker.codes.begin, Browser.fill_secret
    seen, disclosed = [], []

    def form(self, page, selector, config):
        value = original_form(self, page, selector, config)
        if phase == "form" and not seen and page.url == config.login_url:
            disconnect(broker, connection, account)
            seen.append(True)
        return value

    def begin(*args, **kwargs):
        value = original_begin(*args, **kwargs)
        if phase == "code-baseline" and not seen:
            disconnect(broker, connection, account)
            seen.append(True)
        return value

    def fill(*args, **kwargs):
        value = original_fill(*args, **kwargs)
        disclosed.append(True)
        return value

    monkeypatch.setattr(Browser, "check_form", form)
    monkeypatch.setattr(broker.codes, "begin", begin)
    monkeypatch.setattr(Browser, "fill_secret", fill)
    result = broker.run("test", account, "summary")
    blocked(result, broker, account)
    assert seen and not disclosed
    assert website.login_count == website.totp_count == 0


@pytest.mark.parametrize("event", ["disconnect", "reenroll", "retryable"])
def test_source_change_after_fill_prevents_password_dispatch(enrolled, monkeypatch, event):
    website, broker, connection = enrolled
    original = Browser.fill_secret
    changed = []

    def fill(self, page, selector, value):
        original(self, page, selector, value)
        if selector == broker.store.config().accounts["demo-web"].login.password_selector and not changed:
            if event == "disconnect":
                disconnect(broker, connection)
            elif event == "reenroll":
                fresh = source.connect(broker.store, setup_data())
                assert fresh["generation"] != connection["generation"]
            else:
                record = broker.store.get(source.PREFIX + connection["id"])
                record.update(status="RETRYABLE", reason="password_source_unavailable")
                source._save(broker.store, record)
            changed.append(True)

    monkeypatch.setattr(Browser, "fill_secret", fill)
    result = broker.run("test", "demo-web", "summary")
    assert changed and website.login_count == 0
    if event == "retryable":
        assert result["status"] == "RETRYABLE" and result["reason"] == "password_source_unavailable"
        assert broker.store.pending("demo-web") == []
        assert broker.store.get("connection:demo-web") is None
    else:
        blocked(result, broker, reason="bitwarden_connection_changed" if event == "reenroll" else "password_source_access_removed")


def test_disconnect_while_code_provider_is_pending_prevents_code_fill_and_post(enrolled, monkeypatch):
    website, broker, connection = enrolled
    password_sync.enroll(broker.store, "demo-mfa", link(connection))
    original_resolve, original_fill = broker.codes.resolve, Browser.fill_secret
    seen, code_disclosures = [], []

    def resolve(*args, **kwargs):
        value = original_resolve(*args, **kwargs)
        if value and not seen:
            disconnect(broker, connection, "demo-mfa")
            seen.append(True)
        return value

    def fill(self, page, selector, value):
        result = original_fill(self, page, selector, value)
        if page.url.endswith("/mfa/code"):
            code_disclosures.append(True)
        return result

    monkeypatch.setattr(broker.codes, "resolve", resolve)
    monkeypatch.setattr(Browser, "fill_secret", fill)
    result = broker.run("test", "demo-mfa", "summary")
    blocked(result, broker, "demo-mfa")
    assert seen and not code_disclosures
    assert website.login_count == 1 and website.totp_count == 0


@pytest.mark.parametrize("reused", [False, True])
def test_disconnect_before_session_publication_cannot_recreate_login(enrolled, monkeypatch, reused):
    website, broker, connection = enrolled
    if reused:
        assert broker.run("test", "demo-web", "summary")["status"] == "COMPLETED"
    original = Browser.save
    seen = []

    def save(self, account, state, *args, **kwargs):
        if not seen:
            disconnect(broker, connection)
            seen.append(True)
        return original(self, account, state, *args, **kwargs)

    monkeypatch.setattr(Browser, "save", save)
    result = broker.run("test", "demo-web", "summary")
    blocked(result, broker)
    assert seen and website.login_count == 1


def test_disconnect_during_reused_session_read_cannot_publish_late_state(enrolled, monkeypatch):
    website, broker, connection = enrolled
    assert broker.run("test", "demo-web", "summary")["status"] == "COMPLETED"
    original = Locator.inner_text
    seen = []

    def text(self, *args, **kwargs):
        value = original(self, *args, **kwargs)
        if not seen:
            disconnect(broker, connection)
            seen.append(True)
        return value

    monkeypatch.setattr(Locator, "inner_text", text)
    result = broker.run("test", "demo-web", "summary")
    blocked(result, broker)
    assert seen and website.login_count == 1


def test_disconnect_on_native_post_redirect_stops_following_credential_post(enrolled, monkeypatch):
    website, broker, connection = enrolled
    target = website.base + "/redirected-password"
    website.login_redirect = target
    config = broker.store.config()
    config.accounts["demo-web"].login_resources.append(target)
    config.accounts["demo-web"].login_post_urls.append(target)
    broker.store.configure(config)
    broker.grant("test", "demo-web", ["summary"])
    # Configuration changed before this operation: explicitly relink the same
    # approved item under the new reviewed connector fingerprint.
    broker.store.put("password-link:demo-web", None)
    password_sync.enroll(broker.store, "demo-web", link(connection))
    original = Browser.context
    seen = []

    def context(self, *args, **kwargs):
        value = original(self, *args, **kwargs)
        response = value._response_guard.response

        def received(url, method, status, *rest, **options):
            response(url, method, status, *rest, **options)
            if method == "POST" and status == 307 and not seen:
                disconnect(broker, connection)
                seen.append(True)

        value._response_guard.response = received
        return value

    monkeypatch.setattr(Browser, "context", context)
    result = broker.run("test", "demo-web", "summary")
    blocked(result, broker)
    assert seen and website.login_count == 1
    assert "/redirected-password" not in website.posted_paths


def test_same_thread_nested_browser_callback_reuses_original_authority(enrolled, monkeypatch):
    _, broker, _ = enrolled
    authorization = _PasswordAuthority(broker.store, "demo-web")
    original = source.authority
    entered = []

    @contextmanager
    def authority(*args, **kwargs):
        entered.append(True)
        with original(*args, **kwargs):
            yield

    monkeypatch.setattr(source, "authority", authority)
    with authorization.authorize():
        with authorization.authorize():  # A synchronous route callback inside fill.
            authorization.check()
    assert entered == [True]


def test_network_callbacks_are_drained_after_short_source_lock_is_released(enrolled):
    _, broker, connection = enrolled
    authorization = _PasswordAuthority(broker.store, "demo-web")
    seen = []

    def callback():
        assert authorization.local.depth == 0
        # This would fail with account_busy if a response/asset-fetch callback
        # inherited the source lock from its enclosing synchronous command.
        disconnect(broker, connection)
        seen.append(True)

    with authorization.authorize():
        assert authorization.defer(callback)
        assert not seen
    assert seen
    with pytest.raises(AccessError, match="password_source_access_removed"):
        authorization.check()


def test_disconnect_during_owner_review_stops_without_waiting_for_owner(enrolled, monkeypatch):
    website, broker, connection = enrolled
    assert broker.run("test", "demo-web", "summary")["status"] == "COMPLETED"
    website.transaction_challenge = True

    @contextmanager
    def browser():
        with sync_playwright() as pw:
            yield SimpleNamespace(chromium=SimpleNamespace(launch=lambda **kwargs:
                pw.chromium.launch(**{**kwargs, "headless": True})))

    monkeypatch.setattr("account_access.browser.sync_playwright", browser)
    seen = []

    def attention(*args):
        disconnect(broker, connection)
        seen.append(True)

    spec = broker.store.config().accounts["demo-web"]
    started = time.monotonic()
    with pytest.raises(AccessError, match="password_source_access_removed"):
        broker.browser.read("demo-web", spec.operations["summary"], spec,
                            visible=True, on_attention=attention)
    assert time.monotonic() - started < 15
    assert seen and broker.store.get("connection:demo-web") is None


def test_source_bound_child_frame_is_rejected_before_network_dispatch(enrolled):
    website, broker, connection = enrolled
    parent = website.server.RequestHandlerClass
    child_requests = []

    class Handler(parent):
        def page(self, body):
            if '<form id="password-login"' in body:
                body += '<iframe src="/source-bound-child"></iframe>'
            super().page(body)

        def do_GET(self):
            if self.path == "/source-bound-child":
                child_requests.append(True)
                self.page("<h1>Child</h1>")
            else:
                super().do_GET()

    website.server.RequestHandlerClass = Handler
    config = broker.store.config()
    for key in ["read_resources", "login_resources"]:
        getattr(config.accounts["demo-web"], key).append(website.base + "/source-bound-child")
    broker.store.configure(config)
    broker.grant("test", "demo-web", ["summary"])
    broker.store.put("password-link:demo-web", None)
    password_sync.enroll(broker.store, "demo-web", link(connection))
    result = broker.run("test", "demo-web", "summary")
    assert result["status"] == "NEEDS_USER"
    assert result["challenge"]["reason"] == "password_source_browser_surface_unsupported"
    assert not child_requests and website.login_count == 0
    assert broker.store.get("connection:demo-web") is None


def test_disconnect_before_username_first_form_prevents_identity_release(enrolled, monkeypatch):
    from test_identity_login import configure
    website, broker, connection = enrolled
    configure(website, broker)
    broker.store.put("password-link:demo-web", None)
    password_sync.enroll(broker.store, "demo-web", link(connection))
    original = Browser.check_identity_form
    seen = []

    def check(self, page, config):
        original(self, page, config)
        if not seen:
            disconnect(broker, connection)
            seen.append(True)

    monkeypatch.setattr(Browser, "check_identity_form", check)
    result = broker.run("test", "demo-web", "summary")
    blocked(result, broker)
    assert seen and website.identity_payloads == [] and website.login_count == 0


def test_unlinked_accounts_do_not_acquire_source_authority(env, monkeypatch):
    _, broker, _ = env

    def forbidden(*args, **kwargs):
        raise AssertionError("An unlinked account must retain its original behavior")

    monkeypatch.setattr(source, "authority", forbidden)
    assert broker.run("test", "demo-web", "summary")["status"] == "COMPLETED"
