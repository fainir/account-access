"""First-run secret cleanup and late replies on the real local owner page."""

import threading

import pytest
from playwright.sync_api import sync_playwright

from account_access.errors import AccessError
from account_access.google_messages import TEMPLATE
from account_access.models import CodeSource
from account_access.owner import make_owner_server


@pytest.fixture
def setup_page(env, monkeypatch):
    provider, broker, _ = env
    broker.store.new_client("generic")
    monkeypatch.setattr("account_access.install.install_detected", lambda store: {"status": "INSTALLED"})
    monkeypatch.setattr("account_access.supervisor.disable", lambda root: None)
    server, token = make_owner_server(broker, guided=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        with sync_playwright() as pw:
            browser = pw.chromium.launch(headless=True, chromium_sandbox=True)
            try:
                page = browser.new_page()
                page.on("dialog", lambda dialog: dialog.accept())
                page.goto(f"http://127.0.0.1:{server.server_port}/#" + token)
                page.locator("#connected .account").first.wait_for()
                yield page, broker, provider
            finally:
                browser.close()
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


@pytest.mark.parametrize("pause", [False, True])
def test_rejected_account_setup_clears_password_before_reply_and_honors_pause(
        setup_page, monkeypatch, pause):
    page, broker, provider = setup_page
    entered, release = threading.Event(), threading.Event()
    called = []
    before = broker.store.config().model_dump()

    def reject_before_connection(store, service):
        called.append(service)
        entered.set()
        assert release.wait(20)
        raise AccessError("DENIED", "account_already_added")

    monkeypatch.setattr("account_access.catalog.add", reject_before_connection)
    try:
        page.get_by_role("button", name="Add an account", exact=True).click()
        page.locator("#username").fill("fictional@example.test")
        page.locator("#password").fill("fictional-never-sent-to-website")
        page.locator("#allow").check()
        page.locator("#add").click()
        assert entered.wait(5)
        assert page.locator("#password").input_value() == ""
        page.locator("#account-form").evaluate("form=>form.dispatchEvent(new Event('submit',{bubbles:true,cancelable:true}))")
        assert len(called) == 1
        if pause:
            page.get_by_role("button", name="Pause local service", exact=True).click()
            page.locator("#message").filter(has_text="Account Access is paused").wait_for()
        with page.expect_response(lambda response: response.url.endswith("/owner/add")) as response:
            release.set()
        response.value.finished()
        page.evaluate("() => new Promise(resolve=>requestAnimationFrame(()=>requestAnimationFrame(resolve)))")
        if pause:
            assert page.locator("button,input,select").evaluate_all("fields=>fields.every(field=>field.disabled)")
            assert "Account Access is paused" in page.locator("#message").inner_text()
        else:
            page.locator("#message").filter(has_text="This account is already added").wait_for()
            assert page.locator("#add").is_enabled()
        assert page.locator("#password").input_value() == ""
        assert provider.login_count == 0
        assert broker.store.config().model_dump() == before
    finally:
        release.set()


def test_late_google_messages_preparation_cannot_reenable_paused_controls(setup_page, monkeypatch):
    page, broker, _ = setup_page
    config = broker.store.config()
    config.code_sources["demo-totp"] = CodeSource(
        kind="google_messages", sender="github-login-rotating-senders",
        recipient="paired-google-messages", template=TEMPLATE,
    )
    broker.store.configure(config)
    entered, release = threading.Event(), threading.Event()

    def delayed_preparation(store):
        entered.set()
        assert release.wait(20)
        return {"status": "PREPARED", "extension_path": "/fictional/GoogleMessagesExtension"}

    monkeypatch.setattr("account_access.google_messages_host.prepare", delayed_preparation)
    try:
        page.evaluate("refresh()")
        page.get_by_role("button", name="Verification", exact=True).click()
        card = page.get_by_label("Android SMS · Google Messages", exact=True)
        card.get_by_role("button", name="Set up Google Messages", exact=True).click()
        card.get_by_role("checkbox", name="Allow Account Access to prepare the local Google Messages bridge", exact=True).check()
        card.get_by_role("button", name="Prepare browser connection", exact=True).click()
        assert entered.wait(5)
        page.get_by_role("button", name="Pause local service", exact=True).click()
        page.locator("#message").filter(has_text="Account Access is paused").wait_for()
        with page.expect_response(lambda response: response.url.endswith("/owner/google-messages/prepare")) as response:
            release.set()
        response.value.finished()
        page.wait_for_function("()=>googleMessagesSetup?.pending===false")
        assert page.locator("button,input,select").evaluate_all("fields=>fields.every(field=>field.disabled)")
        assert "Account Access is paused" in page.locator("#message").inner_text()
        assert card.get_by_role("region", name="Add the SMS browser connection", exact=True).is_hidden()
    finally:
        release.set()


@pytest.mark.parametrize("action", ["navigate", "pause", "pagehide"])
def test_unsent_account_password_is_cleared_at_owner_lifecycle_boundary(setup_page, action):
    page, broker, provider = setup_page
    before = broker.store.config().model_dump()
    submissions = []
    page.on("request", lambda request: submissions.append(request.url)
            if request.url.endswith("/owner/add") else None)
    page.get_by_role("button", name="Add an account", exact=True).click()
    page.locator("#password").fill("fictional-unsent-account-password")
    if action == "navigate":
        page.get_by_role("button", name="Verification", exact=True).click()
        assert page.locator("#password").input_value() == ""
    elif action == "pause":
        page.get_by_role("button", name="Pause local service", exact=True).click()
        page.locator("#message").filter(has_text="Account Access is paused").wait_for()
        assert page.locator("#password").input_value() == ""
        assert page.locator("button,input,select").evaluate_all("controls=>controls.every(control=>control.disabled)")
    else:
        # Record only a Boolean after the app's pagehide listener, never a secret.
        page.evaluate("window.addEventListener('pagehide',()=>sessionStorage.setItem('fixture-masked-cleared',String([...document.querySelectorAll('input[type=password]')].every(field=>field.value===''))))")
        base = page.url.split("/#", 1)[0].rstrip("/")
        page.goto(base + "/manage")
        assert page.evaluate("sessionStorage.getItem('fixture-masked-cleared')") == "true"
    assert not submissions
    assert provider.login_count == 0
    assert broker.store.config().model_dump() == before


def test_unsent_account_password_survives_same_view_refresh_and_selection(setup_page):
    page, broker, provider = setup_page
    before = broker.store.config().model_dump()
    page.get_by_role("button", name="Add an account", exact=True).click()
    password = page.locator("#password")
    password.fill("fictional-unsent-account-password")
    page.evaluate("refresh()")
    assert password.input_value() == "fictional-unsent-account-password"
    page.get_by_role("button", name="Your accounts", exact=True).click()
    assert password.input_value() == "fictional-unsent-account-password"
    page.evaluate("refresh()")
    assert password.input_value() == "fictional-unsent-account-password"
    assert provider.login_count == 0
    assert broker.store.config().model_dump() == before
