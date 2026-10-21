"""First-run authenticator enrollment through the real local page and owner routes."""

import json
import threading
from contextlib import contextmanager

import pytest
from playwright.sync_api import sync_playwright

from account_access.demo import DEMO_PASSWORD, DEMO_SEED
from account_access.errors import AccessError
from account_access.factors import enroll, totp_setup_metadata
from account_access.models import CodeSource
from account_access.owner import make_owner_server


@contextmanager
def owner_page(broker, monkeypatch):
    monkeypatch.setattr("account_access.install.install_detected", lambda store: {"status": "INSTALLED"})
    server, token = make_owner_server(broker, guided=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        with sync_playwright() as pw:
            browser = pw.chromium.launch(headless=True, chromium_sandbox=True)
            try:
                page = browser.new_page()
                page.goto(f"http://127.0.0.1:{server.server_port}/#" + token)
                page.locator("#connected .account").first.wait_for(state="attached")
                yield page
            finally:
                browser.close()
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def card(page):
    return page.locator('[data-authenticator-source="demo-totp"]')


def test_password_import_then_ui_authenticator_setup_survives_poll_and_completes_reused_reads(env, monkeypatch):
    provider, broker, _ = env
    broker.store.new_client("generic")
    broker.store.put("credential:demo-mfa", None)
    broker.store.put("source:demo-totp", None)
    login_entered, release_login = threading.Event(), threading.Event()
    enroll_entered, release_enroll = threading.Event(), threading.Event()
    real_read = broker.browser.read
    submissions = []

    def read(account, *args, **kwargs):
        if account == "demo-web":
            login_entered.set()
            assert release_login.wait(30), "Unrelated fictional owner job was not released"
            return {}
        return real_read(account, *args, **kwargs)

    def delayed_enroll(store, source, credential):
        submissions.append(source)
        result = enroll(store, source, credential)
        enroll_entered.set()
        assert release_enroll.wait(20), "Fictional source response was not released"
        return result

    monkeypatch.setattr(broker.browser, "read", read)
    monkeypatch.setattr("account_access.factors.enroll", delayed_enroll)
    try:
        with owner_page(broker, monkeypatch) as page:
            page.get_by_role("button", name="Import passwords", exact=True).click()
            export = "name,url,username,password\nFictional MFA," + broker.store.config().accounts["demo-mfa"].login_url + ",demo@example.test," + DEMO_PASSWORD + "\n"
            page.locator("#password-file").set_input_files({"name": "fictional-chrome.csv", "mimeType": "text/csv", "buffer": export.encode()})
            review = page.locator("#import-review")
            review.get_by_role("combobox").select_option("demo-mfa")
            review.get_by_role("checkbox").check()
            review.get_by_role("button", name="Import selected accounts", exact=True).click()
            page.wait_for_function("()=>state&&Object.keys(state.connection_jobs).length>0&&Object.values(state.connection_jobs).every(job=>job.status!=='RUNNING')")
            assert broker.store.get("credential:demo-mfa")["password"] == DEMO_PASSWORD
            assert broker.store.get("source:demo-totp") is None
            page.get_by_role("button", name="Verification", exact=True).click()
            page.evaluate("call('/owner/verify',{account:'demo-web'})")
            assert login_entered.wait(2)
            page.evaluate("refresh()")
            setup = card(page)
            setup.evaluate("node=>node.dataset.fixtureIdentity='same-edit'")
            seed = setup.get_by_label("Authenticator setup key or otpauth link", exact=True)
            assert seed.get_attribute("type") == "password"
            seed.fill(DEMO_SEED)
            page.evaluate("refresh()")
            assert seed.input_value() == DEMO_SEED
            assert setup.get_attribute("data-fixture-identity") == "same-edit"
            with page.expect_response(lambda response: response.url.endswith("/owner/state"), timeout=5000) as response:
                pass  # A real pending owner job self-polls every 1.2 seconds.
            response.value.finished()
            page.evaluate("() => new Promise(resolve=>requestAnimationFrame(()=>requestAnimationFrame(resolve)))")
            assert seed.input_value() == DEMO_SEED
            setup.get_by_role("button", name="Enable verification", exact=True).click()
            assert enroll_entered.wait(2)
            assert seed.input_value() == ""
            # Polling can observe our own committed generation before its POST reply.
            page.evaluate("refresh()")
            assert card(page).get_by_label("Authenticator setup key or otpauth link", exact=True).input_value() == ""
            assert card(page).get_by_role("button", name="Update verification", exact=True).is_disabled()
            card(page).locator("form").evaluate("form=>form.dispatchEvent(new Event('submit',{bubbles:true,cancelable:true}))")
            assert submissions == ["demo-totp"]
            release_enroll.set()
            page.wait_for_function("()=>state&&state.accounts.find(account=>account.account==='demo-mfa').connected===true")
            assert provider.totp_count == 1 and provider.login_count == 1
            assert broker.store.pending("demo-mfa") == []
            visible_state = page.evaluate("call('/owner/state')")
            assert seed.input_value() == ""
            release_login.set()
        # The ordinary broker opens its own synchronous browser outside the UI loop.
        first = broker.run("generic", "demo-mfa", "summary")
        second = broker.run("generic", "demo-mfa", "summary")
        assert first["status"] == second["status"] == "COMPLETED"
        assert first["data"] == second["data"]
        assert provider.totp_count == 1 and provider.login_count == 1
        assert all(secret not in json.dumps([first, second, visible_state]) for secret in [DEMO_SEED, DEMO_PASSWORD, provider.last_login_code])
    finally:
        release_enroll.set()
        release_login.set()


def test_rejected_authenticator_enrollment_clears_secret_before_reply(env, monkeypatch):
    _, broker, _ = env
    broker.store.new_client("generic")
    broker.store.put("source:demo-totp", None)
    entered, release = threading.Event(), threading.Event()

    def rejected(store, source, credential):
        entered.set()
        assert release.wait(10)
        return enroll(store, source, credential)

    monkeypatch.setattr("account_access.factors.enroll", rejected)
    try:
        with owner_page(broker, monkeypatch) as page:
            page.get_by_role("button", name="Verification", exact=True).click()
            seed = card(page).get_by_label("Authenticator setup key or otpauth link", exact=True)
            seed.fill("123456")
            card(page).get_by_role("button", name="Enable verification", exact=True).click()
            assert entered.wait(2) and seed.input_value() == ""
            release.set()
            page.locator("#message").filter(has_text="A current six-digit code cannot connect").wait_for()
            assert seed.input_value() == ""
            assert broker.store.get("source:demo-totp") is None
    finally:
        release.set()


@pytest.mark.parametrize("action", ["navigate", "cancel", "pause"])
def test_authenticator_secret_is_discarded_when_leaving_setup(env, monkeypatch, action):
    _, broker, _ = env
    broker.store.new_client("generic")
    broker.store.put("source:demo-totp", None)
    monkeypatch.setattr("account_access.supervisor.disable", lambda root: None)
    with owner_page(broker, monkeypatch) as page:
        page.on("dialog", lambda dialog: dialog.accept())
        page.get_by_role("button", name="Verification", exact=True).click()
        seed = card(page).get_by_label("Authenticator setup key or otpauth link", exact=True)
        seed.fill(DEMO_SEED)
        if action == "navigate":
            page.get_by_role("button", name="Your accounts", exact=True).click()
            assert card(page).locator('input[type="password"]').input_value() == ""
            page.get_by_role("button", name="Verification", exact=True).click()
        elif action == "cancel":
            card(page).get_by_role("button", name="Cancel authenticator setup", exact=True).click()
        else:
            page.get_by_role("button", name="Pause local service", exact=True).click()
            page.locator("#message").filter(has_text="Account Access is paused").wait_for()
        assert card(page).locator('input[type="password"]').input_value() == ""
        assert broker.store.get("source:demo-totp") is None


@pytest.mark.parametrize("change", ["generation", "account"])
def test_changed_authenticator_or_account_context_discards_typed_key(env, monkeypatch, change):
    _, broker, _ = env
    broker.store.new_client("generic")
    with owner_page(broker, monkeypatch) as page:
        page.get_by_role("button", name="Verification", exact=True).click()
        card(page).get_by_label("Authenticator setup key or otpauth link", exact=True).fill(DEMO_SEED)
        card(page).evaluate("node=>node.dataset.fixtureIdentity='old-context'")
        before = page.evaluate("state.code_sources.find(source=>source.id==='demo-totp')")
        if change == "generation":
            enroll(broker.store, "demo-totp", {"seed": DEMO_SEED})  # Another fictional owner setup.
        else:
            config = broker.store.config()
            config.accounts["demo-mfa"].operations["summary"].description = "Changed fictional read approval"
            broker.store.configure(config)
        page.evaluate("refresh()")
        assert card(page).get_attribute("data-fixture-identity") is None
        assert card(page).get_by_label("Authenticator setup key or otpauth link", exact=True).input_value() == ""
        after = page.evaluate("state.code_sources.find(source=>source.id==='demo-totp')")
        assert before["setup_revision"] != after["setup_revision"]
        assert (before["setup_context"] != after["setup_context"]) == (change == "account")


@pytest.mark.parametrize("change", ["navigate", "external_enrollment", "pause"])
def test_late_authenticator_response_cannot_start_stale_website_verification(env, monkeypatch, change):
    provider, broker, _ = env
    broker.store.new_client("generic")
    broker.store.put("source:demo-totp", None)
    entered, release = threading.Event(), threading.Event()
    monkeypatch.setattr("account_access.supervisor.disable", lambda root: None)

    def delayed(store, source, credential):
        result = enroll(store, source, credential)
        entered.set()
        assert release.wait(15)
        return result

    monkeypatch.setattr("account_access.factors.enroll", delayed)
    requests = []
    try:
        with owner_page(broker, monkeypatch) as page:
            page.on("dialog", lambda dialog: dialog.accept())
            page.on("request", lambda request: requests.append(request.url))
            page.get_by_role("button", name="Verification", exact=True).click()
            card(page).get_by_label("Authenticator setup key or otpauth link", exact=True).fill(DEMO_SEED)
            card(page).get_by_role("button", name="Enable verification", exact=True).click()
            assert entered.wait(2)
            if change == "navigate":
                page.get_by_role("button", name="Your accounts", exact=True).click()
            elif change == "pause":
                page.get_by_role("button", name="Pause local service", exact=True).click()
                page.locator("#message").filter(has_text="Account Access is paused").wait_for()
            else:
                enroll(broker.store, "demo-totp", {"seed": "JBSWY3DPEHPK3PXQ"})
                page.evaluate("refresh()")
            with page.expect_response(lambda response: response.url.endswith("/owner/source")) as response:
                release.set()
            response.value.finished()
            page.wait_for_function("()=>setupOperations.size===0")
            assert not any(url.endswith("/owner/verify") for url in requests)
            assert provider.login_count == provider.totp_count == 0
            assert card(page).locator('input[type="password"]').input_value() == ""
            if change == "pause":
                assert page.locator("button,input,select").evaluate_all("controls=>controls.every(control=>control.disabled)")
    finally:
        release.set()


def test_totp_metadata_contains_no_credential_input_and_binds_exact_generation(env):
    _, broker, _ = env
    config = broker.store.config()
    before = totp_setup_metadata(config, "demo-totp", None)
    result = enroll(broker.store, "demo-totp", {"seed": DEMO_SEED})
    metadata = totp_setup_metadata(config, "demo-totp", broker.store.get("source-generation:demo-totp"))
    assert {key: result[key] for key in metadata} == metadata
    assert before["setup_context"] == metadata["setup_context"]
    assert before["setup_revision"] != metadata["setup_revision"]
    assert all(len(value) == 64 for value in metadata.values())
    assert DEMO_SEED not in json.dumps(result)
    assert totp_setup_metadata(config, "demo-api", None) == {}


@pytest.mark.parametrize("kind", ["imap", "twilio"])
def test_generic_verification_rejection_clears_all_password_fields_before_reply(env, monkeypatch, kind):
    _, broker, _ = env
    broker.store.new_client("generic")
    config = broker.store.config()
    config.code_sources["fictional-source"] = CodeSource(
        kind=kind, host="imap.example.test" if kind == "imap" else None,
        sender="login@example.test", recipient="owner@example.test",
        subject="Fictional sign-in", template="Fictional code: {code}",
    )
    broker.store.configure(config)
    entered, release = threading.Event(), threading.Event()

    def reject(store, source, credential):
        assert source == "fictional-source"
        entered.set()
        assert release.wait(10)
        raise AccessError("DENIED", "invalid_code_source_enrollment")

    monkeypatch.setattr("account_access.factors.enroll", reject)
    try:
        with owner_page(broker, monkeypatch) as page:
            page.get_by_role("button", name="Verification", exact=True).click()
            factor = page.locator('[data-verification-source="fictional-source"]')
            if kind == "imap":
                factor.get_by_label("username", exact=True).fill("owner@example.test")
                factor.get_by_label("Mailbox application password", exact=True).fill("fictional-mail-secret")
            else:
                factor.get_by_label("sid", exact=True).fill("fictional-gateway-id")
                factor.get_by_label("auth_token", exact=True).fill("fictional-gateway-token")
            factor.get_by_role("button", name="Enable verification", exact=True).click()
            assert entered.wait(2)
            assert factor.locator('input[type="password"]').evaluate_all("fields=>fields.every(field=>field.value==='')")
            release.set()
            page.locator("#message").filter(has_text="invalid_code_source_enrollment").wait_for()
            assert factor.locator('input[type="password"]').evaluate_all("fields=>fields.every(field=>field.value==='')")
            assert broker.store.get("source:fictional-source") is None
    finally:
        release.set()


def test_owner_totp_state_does_not_wait_for_active_source_or_code_window_lock(env, monkeypatch):
    _, broker, _ = env
    broker.store.new_client("generic")
    result = enroll(broker.store, "demo-totp", {"seed": DEMO_SEED})
    with owner_page(broker, monkeypatch) as page:
        with broker.store.lock("source:demo-totp"), broker.store.lock("code-window:demo-totp"):
            state = page.evaluate("call('/owner/state')")
        source = next(item for item in state["code_sources"] if item["id"] == "demo-totp")
        assert source["setup_context"] == result["setup_context"]
        assert source["setup_revision"] == result["setup_revision"]
        assert DEMO_SEED not in json.dumps(state)
