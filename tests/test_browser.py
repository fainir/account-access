from account_access.broker import Broker


def test_browser_channel_is_explicit_reviewed_configuration(env):
    import pytest
    from pydantic import ValidationError
    from account_access.models import BrowserAccount

    _, broker, _ = env
    config = broker.store.config()
    original = config.fingerprint("demo-web")
    config.accounts["demo-web"].browser_channel = "chrome"
    assert config.fingerprint("demo-web") != original
    data = config.accounts["demo-web"].model_dump()
    data["browser_channel"] = "/tmp/untrusted-browser"
    with pytest.raises(ValidationError):
        BrowserAccount.model_validate(data)


def test_login_assets_run_only_as_scripts_or_styles_during_login(env):
    import pytest
    from playwright.sync_api import Error, sync_playwright
    provider, broker, _ = env
    parent = provider.server.RequestHandlerClass
    requests = []
    class Handler(parent):
        def do_GET(self):
            if self.path == "/approved.js":
                requests.append(self.path)
                self.send(200, "window.reviewedAssetLoaded = true", content_type="application/javascript")
            else:
                super().do_GET()
    provider.server.RequestHandlerClass = Handler
    spec = broker.store.config().accounts["demo-web"]
    spec.javascript = True
    asset = provider.base + "/approved.js"
    spec.login_assets = [asset]
    load = """url => new Promise(resolve => {
        const script = document.createElement('script'); script.src = url;
        script.onload = () => resolve(true); script.onerror = () => resolve(false);
        document.head.append(script);
    })"""
    with sync_playwright() as pw:
        browser = pw.chromium.launch(headless=True, chromium_sandbox=True)
        context = broker.browser.context(browser, spec, login=True)
        page = broker.browser.page(context)
        page.goto(spec.login_url)
        assert page.evaluate(load, asset)
        assert page.evaluate("window.reviewedAssetLoaded") is True
        assert page.evaluate("async url => {try {await fetch(url); return false} catch {return true}}", asset)
        with pytest.raises(Error):
            page.goto(asset)
        context.close()
        spec.read_resources.append(spec.login_url)
        context = broker.browser.context(browser, spec)
        page = broker.browser.page(context)
        page.goto(spec.login_url)
        assert not page.evaluate(load, asset)
        browser.close()
    assert requests == ["/approved.js"]


def test_account_discovery_does_not_claim_saved_password_is_verified_access(env):
    provider, broker, _ = env
    def account():
        return next(item for item in broker.accounts("test")["accounts"] if item["account"] == "demo-web")
    before = account()
    assert not before["connected"] and before["automatic_recovery_available"]
    assert before["connection_state"] == "login_recovery_ready" and provider.login_count == 0
    assert broker.run("test", "demo-web", "summary")["status"] == "COMPLETED"
    assert account()["connected"] and account()["connection_state"] == "saved_access"
    challenge = broker.store.challenge("demo-web", "device", "browser_device_required")
    assert not account()["connected"] and account()["connection_state"] == "needs_attention"
    assert broker.run("test", "demo-web", "summary")["challenge"]["id"] == challenge["id"]
    assert provider.login_count == 1


def test_login_cooldown_waits_without_owner_challenge_and_task_resumes(env):
    import time
    from account_access.models import TaskRequest

    provider, broker, _ = env
    broker.store.put("login-attempt:demo-web", time.time())
    task = broker.submit("test", TaskRequest(key="cooldown-recovery", steps=[
        {"account": "demo-web", "operation": "summary"}]))
    broker.advance(task["task_id"])
    waiting = broker.task("test", task["task_id"])
    assert waiting["status"] == "RETRYABLE"
    assert waiting["blocked"]["reason"] == "login_retry_cooldown"
    assert provider.login_count == 0
    assert not broker.store.pending("demo-web")
    broker.store.put("login-attempt:demo-web", 0)
    broker.advance(task["task_id"])
    assert broker.task("test", task["task_id"])["status"] == "COMPLETED"
    assert provider.login_count == 1
    assert not broker.store.pending("demo-web")


def test_browser_repeated_sessions_with_one_password_login(env):
    provider, broker, _ = env
    for _ in range(10):
        assert Broker(broker.store).run("test", "demo-web", "summary")["status"] == "COMPLETED"
    assert provider.login_count == 1
    assert not broker.store.pending("demo-web")


def test_authenticator_used_once_then_session_reused(env):
    provider, broker, _ = env
    for _ in range(5):
        assert broker.run("test", "demo-mfa", "summary")["status"] == "COMPLETED"
    assert provider.login_count == 1
    assert provider.totp_count == 1


def test_expired_browser_session_recovers_without_human(env):
    provider, broker, _ = env
    assert broker.run("test", "demo-web", "summary")["status"] == "COMPLETED"
    provider.sessions.clear()
    broker.store.put("login-attempt:demo-web", 0)
    assert broker.run("test", "demo-web", "summary")["status"] == "COMPLETED"
    assert provider.login_count == 2


def test_transaction_challenge_does_not_use_login_factor(env):
    provider, broker, _ = env
    assert broker.run("test", "demo-mfa", "summary")["status"] == "COMPLETED"
    provider.transaction_challenge = True
    result = broker.run("test", "demo-mfa", "summary")
    assert result["status"] == "NEEDS_USER"
    assert result["challenge"]["kind"] == "action"
    assert provider.totp_count == 1
    broker.store.resolve_login("demo-mfa")
    assert broker.store.pending("demo-mfa")[0]["kind"] == "action"


def test_unrecognized_page_does_not_fill_credentials(env):
    provider, broker, _ = env
    config = broker.store.config()
    config.accounts["demo-web"].challenge_selectors = {}
    broker.store.configure(config)
    broker.grant("test", "demo-web", ["summary"])
    result = broker.run("test", "demo-web", "summary")
    assert result["status"] == "NEEDS_USER"
    assert provider.login_count == 0


def test_visible_review_reports_attention_before_waiting_for_owner(env, monkeypatch):
    import threading
    import pytest
    from account_access.errors import AccessError
    from playwright.sync_api import BrowserType

    original_launch = BrowserType.launch
    def headless_fixture(browser_type, **kwargs):
        return original_launch(browser_type, **{**kwargs, "headless": True})
    monkeypatch.setattr(BrowserType, "launch", headless_fixture)

    provider, broker, _ = env
    config = broker.store.config().accounts["demo-web"]
    config.challenge_selectors = {}
    stopped = threading.Event()
    reports = []
    def attention(*metadata):
        reports.append(metadata)
        stopped.set()
    with pytest.raises(AccessError, match="browser_state_unrecognized"):
        broker.browser.read("demo-web", config.operations["summary"], config,
                            visible=True, review_stop=stopped, on_attention=attention)
    assert reports == [("NEEDS_USER", "browser_state_unrecognized", "unknown", {})]
    assert provider.login_count == 0


def test_session_import_filters_foreign_origins(env):
    _, broker, _ = env
    broker.browser.import_state("demo-web", {"cookies": [
        {"domain": "evil.example", "name": "secret", "value": "should-not-store"}],
        "origins": [{"origin": "https://evil.example", "localStorage": []}]})
    assert broker.store.get("connection:demo-web")["state"] == {"cookies": [], "origins": []}


def test_login_cannot_post_to_a_read_resource(env):
    from playwright.sync_api import sync_playwright
    provider, broker, _ = env
    config = broker.store.config().accounts["demo-web"]
    config.javascript = True
    config.login_resources.append(provider.base + "/api/summary")
    with sync_playwright() as pw:
        browser = pw.chromium.launch()
        context = broker.browser.context(browser, config, login=True)
        page = broker.browser.page(context)
        page.goto(config.login_url)
        result = page.evaluate("async url => {try {await fetch(url, {method:'POST'}); return 'sent'} catch {return 'blocked'}}", provider.base + "/api/summary")
        assert result == "blocked"
        assert "/api/summary" not in provider.posted_paths
        browser.close()


def test_async_page_markers_are_waited_for_and_action_takes_priority(env):
    from playwright.sync_api import sync_playwright
    from account_access.errors import AccessError
    import pytest

    _, broker, _ = env
    config = broker.store.config().accounts["demo-web"]
    config.javascript = True
    config.state_timeout_ms = 1000
    with sync_playwright() as pw:
        browser = pw.chromium.launch()
        page = browser.new_page()
        page.set_content("<script>setTimeout(()=>document.body.innerHTML='<div id=ready>Ready</div><div id=action-challenge>Approve payment</div>', 200)</script>")
        broker.browser.wait_state(page, config)
        with pytest.raises(AccessError, match="browser_action_required"):
            broker.browser.check(page, config)
        browser.close()


def test_provider_echoed_login_code_is_redacted_before_task_output(env):
    from account_access.models import TaskRequest

    provider, broker, _ = env
    provider.echo_login_code = True
    config = broker.store.config()
    config.accounts["demo-mfa"].operations["summary"].fields["echo"] = "#echo"
    broker.store.configure(config)
    broker.grant("test", "demo-mfa", ["summary"])
    task = broker.submit("test", TaskRequest(key="code-privacy", steps=[{"account": "demo-mfa", "operation": "summary"}]))
    broker.advance(task["task_id"])
    result = broker.task("test", task["task_id"])
    assert result["status"] == "COMPLETED"
    assert result["results"][0]["data"]["echo"] == "[REDACTED]"
    assert provider.last_login_code not in str(result)


def test_307_login_redirect_cannot_forward_password_to_unapproved_destination(env):
    provider, broker, _ = env
    provider.login_redirect = provider.base + "/api/summary"
    result = broker.run("test", "demo-web", "summary")
    assert result["status"] != "COMPLETED"
    assert provider.login_count == 1
    assert "/api/summary" not in provider.posted_paths


def test_navigation_diagnostic_does_not_expose_unreviewed_url_or_query(env):
    provider, broker, _ = env
    sensitive = "fictional-private-verification-token"
    provider.login_redirect = provider.base + "/not-reviewed/" + sensitive + "?code=123456"
    result = broker.run("test", "demo-web", "summary")
    assert result["status"] != "COMPLETED"
    with broker.store.db() as db:
        events = [dict(row) for row in db.execute("SELECT * FROM audit WHERE event='browser_navigation_failed'")]
        routes = [dict(row) for row in db.execute("SELECT * FROM audit WHERE event='browser_navigation_route'")]
    assert events
    assert any(row["reason"] == "redirect:destination:unreviewed_destination:query" for row in events)
    assert sensitive not in str(events) and "123456" not in str(events)
    assert routes and routes[-1]["reason"] == "origin_0:/?/?"
    assert sensitive not in str(routes) and "123456" not in str(routes)
    assert provider.password not in str(events) and provider.base not in str(events)
    assert not any(path.startswith("/not-reviewed/") for path in provider.posted_paths)


def test_read_redirect_cannot_leave_exact_resource_allowlist(env):
    provider, broker, _ = env
    config = broker.store.config()
    spec = config.accounts["demo-web"]
    spec.operations["summary"].url = provider.base + "/redirect"
    broker.store.configure(config)
    broker.grant("test", "demo-web", ["summary"])
    result = broker.run("test", "demo-web", "summary")
    assert result["status"] != "COMPLETED"
    assert not broker.store.get("connection:demo-web")


def test_changed_login_form_cannot_put_password_in_get_or_wrong_post(env, monkeypatch):
    provider, broker, _ = env
    original = broker.browser.check_form
    def changed(page, selector, config):
        page.locator(selector).evaluate("el => el.form.method = 'get'")
        original(page, selector, config)
    monkeypatch.setattr(broker.browser, "check_form", changed)
    result = broker.run("test", "demo-web", "summary")
    assert result["status"] == "NEEDS_USER"
    assert result["reason"] == "login_form_destination_changed"
    assert provider.login_count == 0
