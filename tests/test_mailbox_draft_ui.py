"""Real owner-page draft handling with fictional mailbox probes, not Gmail delivery."""

import threading

import pytest
from playwright.sync_api import sync_playwright

from account_access.errors import AccessError
from account_access.mailboxes import PREFIX, connect, remove, update_password
from account_access.owner import make_owner_server


@pytest.fixture
def mailbox_page(env, monkeypatch):
    _, broker, _ = env
    broker.store.new_client("generic")
    monkeypatch.setattr("account_access.install.install_detected", lambda store: {"status": "INSTALLED"})
    entered, release = threading.Event(), threading.Event()

    def pending_login(*args, **kwargs):
        entered.set()
        assert release.wait(40), "The unrelated fictional job was not released"
        return {"heading": "Fictional account"}

    monkeypatch.setattr(broker.browser, "read", pending_login)
    server, owner = make_owner_server(broker, guided=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        with sync_playwright() as pw:
            browser = pw.chromium.launch(headless=True, chromium_sandbox=True)
            try:
                page = browser.new_page()
                page.goto(f"http://127.0.0.1:{server.server_port}/#" + owner)
                page.get_by_role("button", name="Verification", exact=True).click()
                yield broker, page, entered, release
            finally:
                release.set()
                browser.close()
    finally:
        release.set()
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def begin_other_login(page, entered):
    page.evaluate("call('/owner/verify',{account:'demo-web'})")
    assert entered.wait(5)
    page.evaluate("refresh()")


def wait_for_self_poll(page):
    with page.expect_response(lambda response: response.url.endswith("/owner/state"), timeout=6000) as response:
        pass
    response.value.finished()
    page.evaluate("() => new Promise(resolve=>requestAnimationFrame(()=>requestAnimationFrame(resolve)))")


def new_mailbox_form(page):
    return page.locator("details").filter(has=page.get_by_text("Connect Gmail or email", exact=True))


def fill_mailbox(details, password="fictional-app-password"):
    details.get_by_text("Connect Gmail or email", exact=True).click()
    details.get_by_label("Email address", exact=True).fill("owner@example.test")
    details.get_by_label("Application password", exact=True).fill(password)


def test_new_gmail_draft_survives_polling_and_one_pending_submit(mailbox_page, monkeypatch):
    _, page, entered, _ = mailbox_page
    probes = []
    probe_entered, release_probe = threading.Event(), threading.Event()

    def probe(_broker, profile):
        assert profile["host"] == "imap.gmail.com" and profile["username"] == "owner@example.test"
        assert profile["password"] == "fictional-app-password"
        probes.append(True)
        probe_entered.set()
        assert release_probe.wait(20)
        return {"status": "VERIFIED"}

    monkeypatch.setattr("account_access.mailboxes.probe", probe)
    try:
        begin_other_login(page, entered)
        details = new_mailbox_form(page)
        fill_mailbox(details)
        details.evaluate("node=>node.dataset.fixtureIdentity='same-mailbox-draft'")
        page.evaluate("refresh()")
        wait_for_self_poll(page)
        assert details.get_attribute("data-fixture-identity") == "same-mailbox-draft"
        assert details.get_by_label("Email address", exact=True).input_value() == "owner@example.test"
        assert details.get_by_label("Application password", exact=True).input_value() == "fictional-app-password"
        assert details.get_by_label("Application password", exact=True).get_attribute("type") == "password"
        details.get_by_role("button", name="Connect mailbox", exact=True).click()
        assert probe_entered.wait(5)
        page.evaluate("refresh()")
        wait_for_self_poll(page)
        assert details.get_attribute("data-fixture-identity") == "same-mailbox-draft"
        assert details.get_by_label("Application password", exact=True).input_value() == ""
        assert details.get_by_role("button", name="Connect mailbox", exact=True).is_disabled()
        details.locator("form").evaluate("form=>form.dispatchEvent(new Event('submit',{bubbles:true,cancelable:true}))")
        assert len(probes) == 1
        release_probe.set()
        page.get_by_text("Mailbox connection checked. Website code delivery is checked separately.", exact=True).wait_for()
        assert len(probes) == 1
        assert page.locator('input[type="password"]').evaluate_all("fields=>fields.every(field=>field.value==='')")
    finally:
        release_probe.set()


def test_rejected_mailbox_submission_clears_secret_and_navigation_discards_draft(mailbox_page, monkeypatch):
    _, page, _, _ = mailbox_page
    probes = []

    def probe(_broker, profile):
        probes.append(True)
        assert profile["password"] == "fictional-rejected-password"
        raise AccessError("NEEDS_USER", "mailbox_connection_failed", "email")

    monkeypatch.setattr("account_access.mailboxes.probe", probe)
    details = new_mailbox_form(page)
    fill_mailbox(details, "fictional-rejected-password")
    details.get_by_role("button", name="Connect mailbox", exact=True).click()
    page.locator("#message").filter(has_text="The mail server did not accept this connection.").wait_for()
    assert len(probes) == 1
    assert details.get_by_label("Application password", exact=True).input_value() == ""
    assert "fictional-rejected-password" not in page.locator("body").inner_text()
    details.get_by_label("Application password", exact=True).fill("fictional-not-submitted")
    page.get_by_role("button", name="Your accounts", exact=True).click()
    page.get_by_role("button", name="Verification", exact=True).click()
    assert details.get_by_label("Application password", exact=True).input_value() == ""
    assert len(probes) == 1


@pytest.mark.parametrize("change", ["replace", "remove"])
def test_existing_mailbox_edit_survives_poll_but_is_cleared_by_external_change(
        mailbox_page, monkeypatch, change):
    broker, page, entered, _ = mailbox_page
    monkeypatch.setattr("account_access.mailboxes.probe", lambda *args: {"status": "VERIFIED"})
    saved = connect(broker, {"label": "Fictional Gmail", "host": "imap.gmail.com", "port": 993,
                             "username": "owner@example.test", "password": "fictional-original"})
    begin_other_login(page, entered)
    edit = page.get_by_label("New mailbox application password", exact=True)
    edit.fill("fictional-unsaved-replacement")
    edit.evaluate("node=>node.dataset.fixtureIdentity='same-edit'")
    page.evaluate("refresh()")
    wait_for_self_poll(page)
    assert edit.get_attribute("data-fixture-identity") == "same-edit"
    assert edit.input_value() == "fictional-unsaved-replacement"
    if change == "replace":
        update_password(broker, saved["id"], "fictional-externally-updated")
    else:
        remove(broker.store, saved["id"])
    page.evaluate("refresh()")
    assert page.locator('[data-fixture-identity="same-edit"]').count() == 0
    assert page.locator('input[type="password"]').evaluate_all("fields=>fields.every(field=>field.value==='')")
    if change == "replace":
        assert broker.store.get(PREFIX + saved["id"])["password"] == "fictional-externally-updated"
    else:
        assert broker.store.get(PREFIX + saved["id"]) is None


@pytest.mark.parametrize("existing", [False, True])
def test_late_mailbox_reply_cannot_reenable_paused_controls(mailbox_page, monkeypatch, existing):
    broker, page, _, _ = mailbox_page
    monkeypatch.setattr("account_access.supervisor.disable", lambda root: None)
    monkeypatch.setattr("account_access.mailboxes.probe", lambda *args: {"status": "VERIFIED"})
    if existing:
        connect(broker, {"label": "Fictional Gmail", "host": "imap.gmail.com", "port": 993,
                         "username": "owner@example.test", "password": "fictional-original"})
        page.evaluate("refresh()")
    entered, release = threading.Event(), threading.Event()

    def delayed_probe(*args):
        entered.set()
        assert release.wait(20)
        return {"status": "VERIFIED"}

    monkeypatch.setattr("account_access.mailboxes.probe", delayed_probe)
    try:
        if existing:
            page.get_by_label("New mailbox application password", exact=True).fill("fictional-replacement")
            page.get_by_role("button", name="Update app password", exact=True).click()
            route = "/owner/mailbox/password"
        else:
            details = new_mailbox_form(page)
            fill_mailbox(details)
            details.get_by_role("button", name="Connect mailbox", exact=True).click()
            route = "/owner/mailbox/connect"
        assert entered.wait(5)
        page.on("dialog", lambda dialog: dialog.accept())
        page.get_by_role("button", name="Pause local service", exact=True).click()
        page.locator("#message").filter(has_text="Account Access is paused").wait_for()
        with page.expect_response(lambda response: response.url.endswith(route)) as response:
            release.set()
        response.value.finished()
        page.wait_for_function("()=>setupOperations.size===0")
        assert page.locator("button,input,select").evaluate_all("fields=>fields.every(field=>field.disabled)")
        assert page.locator('input[type="password"]').evaluate_all("fields=>fields.every(field=>field.value==='')")
        assert "Account Access is paused" in page.locator("#message").inner_text()
    finally:
        release.set()
