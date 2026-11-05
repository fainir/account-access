"""Betterloop-shaped native forms; no personal account or live credentials."""

from email import policy
from email.parser import BytesParser
import json

import pytest

from account_access.catalog import BETTERLOOP_ACCOUNT, BETTERLOOP_ROOT, betterloop
from account_access.password_import import apply, preview


USER = "fictional-owner@example.test"
PASSWORD = "fictional-betterloop-password"
PRIVATE_TEXT = "fixture-private-project-key-and-billing-data"


def fixture(env, *, method="post", action="/login", reject=False, redirect="/app", submit_extra=""):
    provider, broker, _ = env
    parent = provider.server.RequestHandlerClass
    spec = betterloop()
    spec.login_url = provider.base + "/login"
    spec.login_resources = [provider.base + "/app"]
    spec.read_resources = [spec.login_url]
    spec.login_post_urls = [spec.login_url]
    spec.operations["status"].url = provider.base + "/app/account"
    attempts = []
    requests = []
    live = {"valid": False}

    class Handler(parent):
        def redirect(self, target, *, cookie=False):
            self.send_response(303)
            self.send_header("Location", target)
            if cookie:
                self.send_header("Set-Cookie", "betterloop_fixture=signed-in; Path=/; HttpOnly")
            self.send_header("Content-Length", "0")
            self.end_headers()

        def login_page(self):
            # The unrelated log-out text cannot establish a session. React's
            # progressive native form carries deployment-specific action fields.
            self.page("<button>Log out</button><main><h1>Log in</h1>"
                      f"<form action='{action}' method='{method}' enctype='multipart/form-data'>"
                      "<input type='hidden' name='$ACTION_REF_1' value=''>"
                      "<input type='hidden' name='$ACTION_1:0' value='fixture-action-state'>"
                      "<input type='hidden' name='$ACTION_KEY' value='fixture-form-state'>"
                      "<label for='email'>Email</label><input id='email' name='email' type='email' required>"
                      "<label for='password'>Password</label>"
                      "<input id='password' name='password' type='password' required>"
                      f"<button type='submit' {submit_extra}>Log in</button></form></main>")

        def do_GET(self):
            requests.append(("GET", self.path))
            if self.path == "/login":
                return self.login_page()
            if self.path in {"/app", "/app/account"}:
                if not live["valid"] or self.cookie("betterloop_fixture") != "signed-in":
                    return self.redirect("/login")
                return self.page("<header><nav aria-label='Account'>"
                                 "<a href='/app/keys'>API keys</a><a href='/app/billing'>Billing</a>"
                                 "<a href='/app/account'>Account data</a>"
                                 "<span>" + USER + "</span><form method='post'>"
                                 "<button>Log out</button></form></nav></header>"
                                 "<main><h1>Account data</h1><p>" + PRIVATE_TEXT + "</p>"
                                 "<a href='/api/account/export'>Download account data</a>"
                                 "<form method='post'><button>Delete account</button></form></main>")
            return self.send(404, "Unexpected destination", content_type="text/plain")

        def do_POST(self):
            requests.append(("POST", self.path))
            if self.path != "/login":
                return self.send(400, "Unexpected action", content_type="text/plain")
            body = self.rfile.read(int(self.headers["Content-Length"]))
            message = BytesParser(policy=policy.default).parsebytes(
                ("Content-Type: " + self.headers["Content-Type"] + "\r\n\r\n").encode() + body)
            assert message.is_multipart()
            fields = {part.get_param("name", header="content-disposition"):
                      part.get_payload(decode=True).decode() for part in message.iter_parts()}
            assert fields == {"email": USER, "password": PASSWORD, "$ACTION_REF_1": "",
                              "$ACTION_1:0": "fixture-action-state", "$ACTION_KEY": "fixture-form-state"}
            attempts.append("password")
            if reject:
                return self.login_page()
            live["valid"] = True
            return self.redirect(redirect, cookie=True)

    provider.server.RequestHandlerClass = Handler
    config = broker.store.config()
    config.accounts[BETTERLOOP_ACCOUNT] = spec
    broker.store.configure(config)
    broker.store.put("credential:" + BETTERLOOP_ACCOUNT, {"username": USER, "password": PASSWORD})
    broker.grant("test", BETTERLOOP_ACCOUNT, ["status"])
    return broker, attempts, requests, live


def test_betterloop_has_only_native_password_and_boolean_status():
    spec = betterloop()
    assert spec.javascript is False and spec.login_assets == []
    assert spec.login_url == BETTERLOOP_ROOT + "/login"
    assert spec.login_post_urls == [spec.login_url]
    assert spec.login_resources == [BETTERLOOP_ROOT + "/app"]
    assert spec.read_resources == [spec.login_url]
    assert not spec.login.sources()
    assert list(spec.operations) == ["status"]
    operation = spec.operations["status"]
    assert operation.session_only is True and not operation.fields
    assert operation.url == BETTERLOOP_ROOT + "/app/account"
    assert all(value not in spec.login_resources + spec.read_resources + spec.login_post_urls
               for value in [BETTERLOOP_ROOT + "/app/keys", BETTERLOOP_ROOT + "/app/billing",
                             BETTERLOOP_ROOT + "/api/account/export", BETTERLOOP_ROOT + "/signup"])


def test_betterloop_import_is_selected_and_never_grants_page_or_billing_reads(env):
    _, broker, _ = env
    staged = preview(broker.store, "url,username,password\n"
                     + BETTERLOOP_ROOT + "/login," + USER + "," + PASSWORD + "\n"
                     + "https://betterloopai.com.attacker.example/login,wrong,not-retained\n")
    assert staged["rows"][0]["matches"][0]["id"] == BETTERLOOP_ACCOUNT
    assert staged["rows"][0]["matches"][0]["authenticator_supported"] is False
    assert not staged["rows"][1]["matches"]
    apply(broker, staged["id"], [{"row": "0", "account": BETTERLOOP_ACCOUNT,
                                "operations": ["status"]}], ["test"])
    assert broker.run("test", BETTERLOOP_ACCOUNT, "billing")["status"] == "DENIED"
    assert broker.run("test", BETTERLOOP_ACCOUNT, "keys")["status"] == "DENIED"
    assert PASSWORD not in json.dumps(staged)


def test_native_multipart_login_reuses_and_recovers_without_reading_private_text(env, monkeypatch):
    from playwright.sync_api import Locator

    def refuse_text(*args, **kwargs):
        raise AssertionError("Session status must not extract account text")

    monkeypatch.setattr(Locator, "inner_text", refuse_text)
    broker, attempts, requests, live = fixture(env)
    for _ in range(2):
        result = broker.run("test", BETTERLOOP_ACCOUNT, "status")
        assert result["status"] == "COMPLETED"
        assert result["environment"] == "controlled-demo"
        assert result["data"] == {"authenticated": True}
        assert all(value not in json.dumps(result) for value in (USER, PASSWORD, PRIVATE_TEXT))
    assert attempts == ["password"]
    live["valid"] = False
    broker.store.put("login-attempt:" + BETTERLOOP_ACCOUNT, 0)
    assert broker.run("test", BETTERLOOP_ACCOUNT, "status")["data"] == {"authenticated": True}
    assert attempts == ["password", "password"]
    assert {path for method, path in requests if method == "POST"} == {"/login"}
    assert not any(path.startswith(("/api/", "/app/keys", "/app/billing")) for _, path in requests)


@pytest.mark.parametrize("method,action", [("get", "/login"), ("post", "/signup"),
                                         ("post", "https://attacker.example/login")])
def test_changed_form_stops_without_submitting_credentials(env, method, action):
    broker, attempts, requests, _ = fixture(env, method=method, action=action)
    result = broker.run("test", BETTERLOOP_ACCOUNT, "status")
    assert result["status"] == "NEEDS_USER" and "data" not in result
    assert attempts == [] and not any(method == "POST" for method, _ in requests)
    assert all("?" not in path for _, path in requests)
    assert USER not in json.dumps(result) and PASSWORD not in json.dumps(result)


def test_rejected_password_stops_once_and_saves_no_connection(env):
    broker, attempts, _, _ = fixture(env, reject=True)
    result = broker.run("test", BETTERLOOP_ACCOUNT, "status")
    assert result["status"] == "NEEDS_USER" and "data" not in result
    assert attempts == ["password"]
    assert not broker.store.get("connection:" + BETTERLOOP_ACCOUNT)


@pytest.mark.parametrize("override", ["formaction='/signup'", "formmethod='get'"])
def test_submit_override_cannot_change_the_reviewed_form_contract(env, override):
    broker, attempts, requests, _ = fixture(env, submit_extra=override)
    result = broker.run("test", BETTERLOOP_ACCOUNT, "status")
    assert result["status"] in {"NEEDS_USER", "RETRYABLE"} and "data" not in result
    assert attempts == [] and not any(method == "POST" for method, _ in requests)
    assert all("?" not in path for _, path in requests)


def test_unreviewed_redirect_cannot_acquire_a_read_or_connection(env):
    broker, attempts, requests, _ = fixture(env, redirect="/app/keys")
    result = broker.run("test", BETTERLOOP_ACCOUNT, "status")
    assert result["status"] == "NEEDS_USER" and "data" not in result
    assert attempts == ["password"]
    assert ("GET", "/app/keys") not in requests
    assert not broker.store.get("connection:" + BETTERLOOP_ACCOUNT)
