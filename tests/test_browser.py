from account_access.broker import Broker


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
        page = context.new_page()
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
    assert events
    assert any(row["reason"] == "redirect:destination:unreviewed_destination:query" for row in events)
    assert sensitive not in str(events) and "123456" not in str(events)
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
