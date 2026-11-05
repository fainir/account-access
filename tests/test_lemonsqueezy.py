"""Observed Lemon Squeezy forms with fictional local credentials and TOTP."""

from contextlib import contextmanager
from html import escape
import json
from urllib.parse import parse_qs

import pyotp
import pytest

from account_access.catalog import (
    LEMON_ACCOUNT, LEMON_APP, LEMON_AUTH, LEMON_SOURCE, add, include_sources, lemonsqueezy,
)
from account_access.demo import DemoProvider
from account_access.errors import AccessError
from account_access.factors import enroll, revoke
from account_access.models import CodeSource, Configuration
from account_access.password_import import apply, preview


USER = "fictional-lemon-owner@example.test"
PASSWORD = "fictional-lemon-password"
SEED = "JBSWY3DPEHPK3PXP"
CSRF = "fictional-lemon-csrf"
PRIVATE = "fixture-unreturned-payout-project-key-data"


def test_spec_is_native_totp_and_session_only_without_payment_scripts():
    spec = lemonsqueezy()
    config = Configuration(accounts={LEMON_ACCOUNT: spec}, code_sources={LEMON_SOURCE: CodeSource(kind="totp")})
    assert not spec.javascript and spec.login_assets == []
    assert spec.login.authenticator_source(config) == LEMON_SOURCE
    assert spec.login_post_urls == [LEMON_AUTH + "/login", LEMON_AUTH + "/2fa-challenge"]
    assert spec.login_resources == [LEMON_AUTH + "/2fa-challenge", LEMON_APP + "/dashboard"]
    assert list(spec.operations) == ["status"]
    assert spec.operations["status"].session_only and not spec.operations["status"].fields
    assert spec.operations["status"].url == LEMON_APP + "/dashboard"
    assert spec.ready_selector == "html"
    assert spec.ready_page.component == "App/Dashboard" and spec.ready_page.selector == "#app"
    assert spec.ready_page.url == spec.operations["status"].url
    assert all("stripe" not in url and "logout" not in url and "settings" not in url
               for url in spec.login_resources + spec.read_resources + spec.login_post_urls)


def test_selected_import_has_a_separate_unenrolled_source_and_narrow_grant(env):
    _, broker, _ = env
    add(broker.store, LEMON_ACCOUNT)
    assert broker.store.config().code_sources[LEMON_SOURCE] == CodeSource(kind="totp")
    assert broker.store.get("source:" + LEMON_SOURCE) is None
    staged = preview(broker.store, "url,username,password\n" + LEMON_AUTH + "/login," + USER + "," + PASSWORD + "\n")
    match = staged["rows"][0]["matches"][0]
    assert match["id"] == LEMON_ACCOUNT and match["authenticator_supported"]
    assert match["environment"] == "live" and match["operations"][0]["name"] == "status"
    assert PASSWORD not in json.dumps(staged)
    with pytest.raises(AccessError, match="invalid_import_selection"):
        apply(broker, staged["id"], [{"row": "0", "account": LEMON_ACCOUNT, "operations": ["payouts"]}], ["test"])
    apply(broker, staged["id"], [{"row": "0", "account": LEMON_ACCOUNT, "operations": ["status"]}], ["test"])
    assert broker.store.get("source:" + LEMON_SOURCE) is None
    assert broker.run("test", LEMON_ACCOUNT, "payouts")["status"] == "DENIED"
    assert broker.run("test", LEMON_ACCOUNT, "keys")["status"] == "DENIED"


@pytest.mark.parametrize("origin,matched", [
    (LEMON_APP, True), ("https://lemonsqueezy.com", True), ("https://www.lemonsqueezy.com", True),
    ("http://auth.lemonsqueezy.com", False), ("https://auth.lemonsqueezy.com.attacker.test", False),
    ("https://child.auth.lemonsqueezy.com", False),
])
def test_import_aliases_are_exact_and_do_not_widen_browser_authority(env, origin, matched):
    _, broker, _ = env
    staged = preview(broker.store, "url,username,password\n" + origin + "/," + USER + "," + PASSWORD + "\n")
    assert bool(staged["rows"][0]["matches"]) is matched
    assert origin + "/" not in lemonsqueezy().login_post_urls


def test_catalog_does_not_adopt_an_unrelated_seed_and_merge_is_atomic(env):
    from account_access.catalog import RTD_ACCOUNT, RTD_SOURCE, readthedocs
    _, broker, _ = env
    config = broker.store.config()
    config.code_sources[LEMON_SOURCE] = CodeSource(kind="totp")
    broker.store.configure(config)
    broker.store.put("source:" + LEMON_SOURCE, {"seed": SEED})
    before = config.model_dump()
    with pytest.raises(AccessError, match="catalog_code_source_conflict"):
        include_sources(config, {RTD_ACCOUNT: readthedocs(), LEMON_ACCOUNT: lemonsqueezy()})
    assert config.model_dump() == before and RTD_SOURCE not in config.code_sources
    assert broker.store.get("source:" + LEMON_SOURCE) == {"seed": SEED}


@contextmanager
def fixture(env, *, password_method="post", password_action=None, code_method="post", code_action=None,
            reject_password=False, reject_code=False, component="App/Dashboard", route="/dashboard",
            redirect_path="/dashboard", code_submit_extra="", application_login_bridge=False):
    auth, broker, _ = env
    app = DemoProvider().start()
    parent = auth.server.RequestHandlerClass
    attempts, requests = [], []
    live = {"valid": False}
    spec = lemonsqueezy()
    spec.login_url = auth.base + "/login"
    spec.password_import_origins = []
    spec.read_resources = [url.replace(LEMON_AUTH, auth.base) for url in spec.read_resources]
    spec.login_resources = [url.replace(LEMON_AUTH, auth.base).replace(LEMON_APP, app.base)
                            for url in spec.login_resources]
    spec.login_post_urls = [url.replace(LEMON_AUTH, auth.base) for url in spec.login_post_urls]
    spec.login.username_selector = spec.login.username_selector.replace(LEMON_AUTH, auth.base)
    spec.login.password_selector = spec.login.password_selector.replace(LEMON_AUTH, auth.base)
    spec.login.submit_selector = spec.login.submit_selector.replace(LEMON_AUTH, auth.base)
    factor = spec.login.factors["totp"]
    factor.code_selector = factor.code_selector.replace(LEMON_AUTH, auth.base)
    factor.code_submit_selector = factor.code_submit_selector.replace(LEMON_AUTH, auth.base)
    spec.challenge_selectors = {k: v.replace(LEMON_AUTH, auth.base) for k, v in spec.challenge_selectors.items()}
    spec.operations["status"].url = app.base + "/dashboard"
    spec.ready_page.url = spec.operations["status"].url

    def page_object(selected_component="App/Dashboard", selected_route="/dashboard"):
        value = json.dumps({"component": selected_component, "props": {"private": PRIVATE,
                            "decoy": {"component": "App/Dashboard", "url": "/dashboard"}},
                            "url": selected_route}, separators=(",", ":")).replace("/", r"\/")
        return "<div id='app' data-page='" + escape(value, quote=True) + "'></div>"

    class Handler(parent):
        def redirect(self, target, cookie=None):
            self.send_response(303)
            self.send_header("Location", target)
            if cookie:
                self.send_header("Set-Cookie", "lemon_fixture=" + cookie + "; Path=/; HttpOnly")
            self.send_header("Content-Length", "0")
            self.end_headers()

        def login_page(self):
            self.page(f"<form action='{password_action or spec.login_url}' method='{password_method}'>"
                      f"<input name='_token' type='hidden' value='{CSRF}'>"
                      "<input id='email' name='email' type='email'>"
                      "<input id='password' name='password' type='password'>"
                      "<input id='remember' name='remember' type='checkbox'>"
                      "<button type='submit'>Sign in</button></form>")

        def code_page(self):
            # The real prompt already has logout. Even a misleading dashboard
            # page object cannot turn the still-present code field into success.
            self.page(f"<h1>Enter your 2FA code</h1><form action='{code_action or auth.base + '/2fa-challenge'}' "
                      f"method='{code_method}'><input name='_token' type='hidden' value='{CSRF}'>"
                      "<input id='code' name='code' type='text' required>"
                      f"<button type='submit' {code_submit_extra}>Sign in</button></form>"
                      f"<form action='{auth.base}/logout' method='post'><input name='_token' type='hidden'></form>"
                      + page_object())

        def do_GET(self):
            requests.append((self.server.server_port, "GET", self.path))
            if self.server.server_port == app.server.server_port:
                if self.path == "/dashboard":
                    if not live["valid"] or self.cookie("lemon_fixture") != "connected":
                        if application_login_bridge:
                            return self.redirect(app.base + "/auth/redirect?url=" + app.base + "/dashboard")
                        return self.redirect(spec.login_url)
                    return self.page(page_object(component, route)
                                     + "<script>fetch('/settings/payouts',{method:'POST'})</script>")
                return self.send(404, "Unexpected application route")
            if self.path == "/login":
                if live["valid"] and self.cookie("lemon_fixture") == "connected":
                    return self.redirect(app.base + "/dashboard")
                return self.login_page()
            if self.path == "/2fa-challenge":
                return self.code_page()
            return self.send(404, "Unexpected authentication route")

        def do_POST(self):
            requests.append((self.server.server_port, "POST", self.path))
            fields = parse_qs(self.rfile.read(int(self.headers["Content-Length"])).decode())
            if self.server.server_port != auth.server.server_port:
                return self.send(400, "No application write is permitted")
            if self.path == "/login":
                assert fields == {"_token": [CSRF], "email": [USER], "password": [PASSWORD]}
                attempts.append("password")
                if reject_password:
                    return self.login_page()
                return self.redirect(auth.base + "/2fa-challenge", "pending")
            if self.path == "/2fa-challenge":
                assert fields["_token"] == [CSRF] and set(fields) == {"_token", "code"}
                assert pyotp.TOTP(SEED).verify(fields["code"][0], valid_window=1)
                assert self.cookie("lemon_fixture") == "pending"
                attempts.append("totp")
                if reject_code:
                    return self.code_page()
                live["valid"] = True
                return self.redirect(app.base + redirect_path, "connected")
            return self.send(400, "Unexpected authentication write")

    auth.server.RequestHandlerClass = app.server.RequestHandlerClass = Handler
    config = broker.store.config()
    config.accounts[LEMON_ACCOUNT] = spec
    config.code_sources[LEMON_SOURCE] = CodeSource(kind="totp")
    broker.store.configure(config)
    broker.store.put("credential:" + LEMON_ACCOUNT, {"username": USER, "password": PASSWORD})
    broker.grant("test", LEMON_ACCOUNT, ["status"])
    enroll(broker.store, LEMON_SOURCE, {"seed": SEED})
    try:
        yield broker, attempts, requests, live
    finally:
        app.close()


def test_real_engine_uses_password_and_totp_reuses_session_and_never_extracts_private_data(env, monkeypatch):
    from playwright.sync_api import Locator

    def no_text(*args, **kwargs):
        raise AssertionError("Status must not extract account or payment text")

    monkeypatch.setattr(Locator, "inner_text", no_text)
    with fixture(env) as (broker, attempts, requests, live):
        for _ in range(2):
            result = broker.run("test", LEMON_ACCOUNT, "status")
            assert result["status"] == "COMPLETED", result
            assert result["environment"] == "controlled-demo" and result["data"] == {"authenticated": True}
            assert all(secret not in json.dumps(result) for secret in (USER, PASSWORD, SEED, CSRF, PRIVATE))
        assert attempts == ["password", "totp"]
        live["valid"] = False
        broker.store.put("login-attempt:" + LEMON_ACCOUNT, 0)
        assert broker.run("test", LEMON_ACCOUNT, "status")["data"] == {"authenticated": True}
        assert attempts == ["password", "totp", "password", "totp"]
        assert not any("settings" in path or "?" in path for _, _, path in requests)
        assert {path for _, method, path in requests if method == "POST"} == {"/login", "/2fa-challenge"}
        revoke(broker.store, LEMON_SOURCE)
        broker.store.put("connection:" + LEMON_ACCOUNT, None)
        broker.store.put("login-attempt:" + LEMON_ACCOUNT, 0)
        assert broker.run("test", LEMON_ACCOUNT, "status")["status"] in {"DENIED", "NEEDS_USER"}
        assert len(attempts) == 4


def test_session_status_uses_reviewed_authentication_entry_without_application_bridge(env):
    with fixture(env, application_login_bridge=True) as (broker, attempts, requests, live):
        for _ in range(2):
            result = broker.run("test", LEMON_ACCOUNT, "status")
            assert result["status"] == "COMPLETED", result
            assert result["data"] == {"authenticated": True}
            assert all(secret not in json.dumps(result) for secret in (USER, PASSWORD, SEED, CSRF, PRIVATE))
        assert attempts == ["password", "totp"]
        live["valid"] = False
        broker.store.put("login-attempt:" + LEMON_ACCOUNT, 0)
        result = broker.run("test", LEMON_ACCOUNT, "status")
        assert result["status"] == "COMPLETED", result
        assert attempts == ["password", "totp", "password", "totp"]
        assert not any("/auth/redirect" in path or "?" in path for _, _, path in requests)
        assert {path for _, method, path in requests if method == "POST"} == {"/login", "/2fa-challenge"}


@pytest.mark.parametrize("disabled", [False, True])
def test_new_status_connection_reaches_missing_authenticator_without_application_bridge(env, disabled):
    with fixture(env, application_login_bridge=True) as (broker, attempts, requests, _):
        if disabled:
            revoke(broker.store, LEMON_SOURCE)
        else:
            broker.store.put("source:" + LEMON_SOURCE, None)
        result = broker.run("test", LEMON_ACCOUNT, "status")
        assert result["status"] == "NEEDS_USER", result
        assert result["reason"] == ("verification_source_disabled" if disabled else "authenticator_not_enrolled")
        assert not attempts
        assert not any("/auth/redirect" in path for _, _, path in requests)
        assert broker.store.get("connection:" + LEMON_ACCOUNT) is None


@pytest.mark.parametrize("change", [
    {"password_method": "get"}, {"password_action": "https://attacker.test/login"},
    {"code_method": "get"}, {"code_action": "https://attacker.test/2fa-challenge"},
    {"code_submit_extra": "formaction='/logout'"}, {"reject_password": True}, {"reject_code": True},
    {"component": "Auth/Login"}, {"route": "/settings/payouts"}, {"redirect_path": "/settings/payouts"},
])
def test_changed_or_rejected_authentication_never_acquires_a_session(env, change):
    with fixture(env, **change) as (broker, attempts, requests, _):
        result = broker.run("test", LEMON_ACCOUNT, "status")
        assert result["status"] in {"NEEDS_USER", "RETRYABLE"} and "data" not in result
        assert broker.store.get("connection:" + LEMON_ACCOUNT) is None
        assert all(secret not in json.dumps(result) for secret in (PASSWORD, SEED, CSRF, PRIVATE))
        assert not any("?" in path or "settings" in path for _, _, path in requests)
        if "password_method" in change or "password_action" in change:
            assert attempts == []
        elif any(key in change for key in ("code_method", "code_action", "code_submit_extra", "reject_password")):
            assert attempts == ["password"]
        else:
            assert attempts == ["password", "totp"]
