import pytest
from playwright.sync_api import sync_playwright


@pytest.mark.parametrize("after_password", [False, True])
def test_browser_verification_stops_before_password_or_code_retries(env, monkeypatch, after_password):
    provider, broker, _ = env
    parent = provider.server.RequestHandlerClass
    # Even a misleading ready marker or password form in the response cannot
    # override the provider's explicit main-document challenge header.
    body = ('<div id="ready">Untrusted apparent success</div>'
            + parent.login_form(parent, mfa=True))

    class Handler(parent):
        def do_GET(self):
            if not after_password and self.path == "/mfa/summary":
                self.send(403, body, {"Cf-Mitigated": "challenge"}, content_type="text/html")
            else:
                super().do_GET()

        def do_POST(self):
            if after_password and self.path == "/mfa/login":
                self.rfile.read(int(self.headers.get("Content-Length", "0")))
                provider.login_count += 1
                self.send(403, body, {"Cf-Mitigated": "challenge"}, content_type="text/html")
            else:
                super().do_POST()

    provider.server.RequestHandlerClass = Handler

    def no_code(*args):
        pytest.fail("A browser verification gate must never retrieve an authentication code")

    monkeypatch.setattr(broker.codes, "resolve", no_code)
    if not after_password:
        monkeypatch.setattr(broker.codes, "begin", no_code)
    result = broker.run("test", "demo-mfa", "summary")
    assert result["status"] == "NEEDS_USER"
    assert result["challenge"]["kind"] == "captcha"
    assert result["challenge"]["reason"] == "browser_captcha_required"
    assert "cannot complete" in result["challenge"]["required_action"]
    assert provider.login_count == int(after_password)
    assert provider.totp_count == 0
    assert not broker.store.get("connection:demo-mfa")
    # A repeated agent request reuses the challenge, never another website try.
    again = broker.run("test", "demo-mfa", "summary")
    assert again["challenge"]["id"] == result["challenge"]["id"]
    assert provider.login_count == int(after_password)


@pytest.mark.parametrize("surface", ["script", "iframe"])
def test_subresource_challenge_cannot_taint_the_main_document(env, surface):
    provider, broker, _ = env
    parent = provider.server.RequestHandlerClass

    class Handler(parent):
        def do_GET(self):
            if self.path == "/site-check":
                element = ('<script src="/child-check"></script>' if surface == "script"
                           else '<iframe src="/child-check"></iframe>')
                self.page('<div id="ready">Ready</div>' + element)
            elif self.path == "/child-check":
                self.send(403, "", {"cf-mitigated": "challenge"}, content_type=(
                    "application/javascript" if surface == "script" else "text/html"))
            else:
                super().do_GET()

    provider.server.RequestHandlerClass = Handler
    spec = broker.store.config().accounts["demo-web"]
    spec.javascript = True
    spec.login_resources += [provider.base + "/site-check", provider.base + "/child-check"]
    with sync_playwright() as pw:
        browser = pw.chromium.launch(chromium_sandbox=True)
        try:
            context = broker.browser.context(browser, spec, login=True)
            page = broker.browser.page(context)
            page.goto(provider.base + "/site-check", wait_until="load")
            assert broker.browser.challenge(page, spec) is None
            broker.browser.check(page, spec)
        finally:
            browser.close()


def test_later_normal_navigation_clears_only_that_pages_verification_signal(env):
    provider, broker, _ = env
    parent = provider.server.RequestHandlerClass
    challenged = [True]

    class Handler(parent):
        def do_GET(self):
            if self.path == "/site-check":
                self.send(403 if challenged[0] else 200, '<div id="ready">Ready</div>',
                          {"cf-mitigated": "challenge"} if challenged[0] else {},
                          content_type="text/html")
            else:
                super().do_GET()

    provider.server.RequestHandlerClass = Handler
    spec = broker.store.config().accounts["demo-web"]
    spec.login_resources.append(provider.base + "/site-check")
    with sync_playwright() as pw:
        browser = pw.chromium.launch(chromium_sandbox=True)
        try:
            context = broker.browser.context(browser, spec, login=True)
            first = broker.browser.page(context)
            first.goto(provider.base + "/site-check")
            assert broker.browser.challenge(first, spec) == "captcha"
            challenged[0] = False
            second = broker.browser.page(context)
            second.goto(provider.base + "/site-check")
            assert broker.browser.challenge(second, spec) is None
            assert broker.browser.challenge(first, spec) == "captcha"
            first.reload()
            assert broker.browser.challenge(first, spec) is None
        finally:
            browser.close()


def test_confirmed_login_resolves_browser_verification_but_preserves_action_approval(env):
    _, broker, _ = env
    broker.store.challenge("demo-web", "captcha", "browser_captcha_required")
    broker.store.challenge("demo-web", "action", "browser_action_required")
    spec = broker.store.config().accounts["demo-web"]
    broker.browser.read("demo-web", spec.operations["summary"], spec)
    assert [row["kind"] for row in broker.store.pending("demo-web")] == ["action"]


def test_recognized_browser_gate_updates_the_existing_task_without_a_login_retry(env):
    from account_access.models import TaskRequest
    provider, broker, _ = env
    unknown = broker.store.challenge("demo-web", "unknown", "browser_state_unrecognized")
    task = broker.submit("test", TaskRequest(key="browser-gate", steps=[
        {"account": "demo-web", "operation": "summary"}]))
    broker.advance(task["task_id"])
    assert broker.task("test", task["task_id"])["blocked"]["challenge"]["kind"] == "unknown"
    current = broker.store.challenge("demo-web", "captcha", "browser_captcha_required")
    assert current["id"] == unknown["id"] and current["resolved"] is None
    broker.tick()
    result = broker.task("test", task["task_id"])
    assert result["status"] == "NEEDS_USER" and result["progress"] == 0
    assert result["blocked"]["challenge"]["kind"] == "captcha"
    assert result["blocked"]["challenge"]["id"] == unknown["id"]
    assert provider.login_count == 0
    # A genuine owner repair still has to pass the normal sign-in/read checks.
    # Only then can the original durable task resume using the saved session.
    spec = broker.store.config().accounts["demo-web"]
    broker.browser.read("demo-web", spec.operations["summary"], spec)
    broker.tick()
    completed = broker.task("test", task["task_id"])
    assert completed["status"] == "COMPLETED" and completed["progress"] == 1
    assert completed["task_id"] == task["task_id"]
    assert not broker.store.pending("demo-web")
    assert provider.login_count == 1
