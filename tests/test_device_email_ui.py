"""Consumer device-mail review through the real local owner API, fictional data only."""

import threading
from urllib.parse import urlsplit

import pytest
from playwright.sync_api import sync_playwright

from account_access.catalog import PYPI_ACCOUNT, PYPI_SOURCE, pypi
from account_access.demo import DEMO_PASSWORD
from account_access.mailboxes import PREFIX, connect
from account_access.models import CodeSource
from account_access.owner import make_owner_server
from account_access.verification_demo import environment


@pytest.fixture
def device_owner_ui(tmp_path, monkeypatch):
    monkeypatch.setattr("account_access.install.install_detected", lambda store: {"status": "INSTALLED"})
    with environment(tmp_path) as (provider, broker, mailbox):
        config = broker.store.config()
        config.accounts[PYPI_ACCOUNT] = pypi()
        config.code_sources[PYPI_SOURCE] = CodeSource(kind="totp")
        broker.store.configure(config)
        broker.store.new_client("generic")
        broker.grant("generic", PYPI_ACCOUNT, ["status"])
        saved = connect(broker, {"label": "Saved Gmail <img src=x>", "host": "127.0.0.1", "port": mailbox.port,
            "username": "demo@example.test", "password": DEMO_PASSWORD})
        assert saved["connection_check"]["status"] == "VERIFIED"
        server, owner = make_owner_server(broker, guided=True)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        base = f"http://127.0.0.1:{server.server_port}"
        requests = []
        try:
            with sync_playwright() as pw:
                browser = pw.chromium.launch(headless=True, chromium_sandbox=True)
                try:
                    page = browser.new_page()
                    page.on("request", lambda request: requests.append((urlsplit(request.url).path, request.post_data_json))
                            if "/owner/device-email/" in request.url else None)
                    page.goto(base + "/#" + owner)
                    page.get_by_role("button", name="Verification", exact=True).click()
                    yield page, broker, saved["id"], requests, mailbox, provider
                finally:
                    browser.close()
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)


def card(page):
    return page.locator('[aria-label="PyPI device confirmation email"]')


def test_owner_ui_reviews_cancels_and_applies_existing_mailbox_without_secret_reentry(device_owner_ui):
    page, broker, mailbox, requests, mail, provider = device_owner_ui
    panel = card(page)
    menu = panel.get_by_label("Connected mailbox for PyPI device emails", exact=True)
    assert menu.input_value() == mailbox
    assert panel.locator('input[type="password"]').count() == 0
    assert page.locator('img[src="x"]').count() == 0
    panel.get_by_role("button", name="Review email connection", exact=True).click()
    review = page.get_by_role("region", name="Review device email connection", exact=True)
    review.get_by_text("Confirm device email", exact=True).wait_for()
    assert "demo@example.test" in review.inner_text()
    assert "existing approved reads are retained" in review.inner_text()
    with page.expect_response(lambda response: response.url.endswith("/owner/device-email/discard")):
        review.get_by_role("button", name="Cancel email connection", exact=True).click()
    assert review.count() == 0
    assert broker.store.config().accounts[PYPI_ACCOUNT].login.device_email_source is None
    assert not any(path.endswith("/apply") for path, _ in requests)
    panel.get_by_role("button", name="Review email connection", exact=True).click()
    apply = review.get_by_role("button", name="Confirm email connection", exact=True)
    apply.wait_for()
    apply.evaluate("button => {button.click(); button.click();}")
    card(page).get_by_role("button", name="Disconnect device email", exact=True).wait_for()
    assert card(page).get_by_text("Setup saved · delivery unverified", exact=True).is_visible()
    current = broker.store.config()
    source = current.accounts[PYPI_ACCOUNT].login.device_email_source
    assert source and broker.store.get("source:" + source)["mailbox"] == mailbox
    assert current.code_sources[source].message_purpose == "pypi-device-confirmation"
    assert sum(path.endswith("/apply") for path, _ in requests) == 1
    assert mail.fetches == provider.login_count == 0
    assert DEMO_PASSWORD not in page.locator("body").inner_text()
    # The special source does not create a second generic password-entry form.
    assert page.locator('input[aria-label="Mailbox application password"]').count() == 1
    card(page).get_by_role("button", name="Disconnect device email", exact=True).click()
    card(page).get_by_role("button", name="Review email connection", exact=True).wait_for()
    assert broker.store.config().accounts[PYPI_ACCOUNT].login.device_email_source is None


def test_stale_mailbox_preview_stops_without_automatic_apply_replay(device_owner_ui):
    page, broker, mailbox, requests, mail, provider = device_owner_ui
    card(page).get_by_role("button", name="Review email connection", exact=True).click()
    review = page.get_by_role("region", name="Review device email connection", exact=True)
    review.get_by_role("button", name="Confirm email connection", exact=True).wait_for()
    profile = broker.store.get(PREFIX + mailbox)
    profile["generation"] = "f" * 32
    broker.store.put(PREFIX + mailbox, profile)
    review.get_by_role("button", name="Confirm email connection", exact=True).click()
    page.locator("#message").filter(has_text="mailbox changed during the review").wait_for()
    assert broker.store.config().accounts[PYPI_ACCOUNT].login.device_email_source is None
    assert sum(path.endswith("/apply") for path, _ in requests) == 1
    assert page.get_by_role("region", name="Review device email connection").count() == 0
    card(page).get_by_role("button", name="Review email connection", exact=True).wait_for()
    assert mail.fetches == provider.login_count == 0


def test_navigation_discards_review_and_missing_checked_mailbox_offers_setup(device_owner_ui):
    page, broker, mailbox, requests, _, _ = device_owner_ui
    card(page).get_by_role("button", name="Review email connection", exact=True).click()
    page.get_by_role("region", name="Review device email connection").wait_for()
    with page.expect_response(lambda response: response.url.endswith("/owner/device-email/discard")):
        page.get_by_role("button", name="Your accounts", exact=True).click()
    page.get_by_role("button", name="Verification", exact=True).click()
    assert card(page).get_by_role("button", name="Review email connection", exact=True).is_enabled()
    assert page.get_by_role("region", name="Review device email connection").count() == 0
    profile = broker.store.get(PREFIX + mailbox)
    profile["connection_check"]["status"] = "NEEDS_USER"
    broker.store.put(PREFIX + mailbox, profile)
    page.evaluate("refresh()")
    card(page).get_by_role("button", name="Connect a mailbox", exact=True).wait_for()
    assert card(page).get_by_text("One-time setup", exact=True).is_visible()
    assert card(page).get_by_role("button", name="Review email connection", exact=True).count() == 0
    card(page).get_by_role("button", name="Connect a mailbox", exact=True).click()
    assert page.locator("#factors details").evaluate("element=>element.open") is True
    assert not any(path.endswith("/apply") for path, _ in requests)


def test_missing_saved_mailbox_binding_stays_removable_without_config_editing(device_owner_ui):
    page, broker, mailbox, requests, mail, provider = device_owner_ui
    card(page).get_by_role("button", name="Review email connection", exact=True).click()
    page.get_by_role("region", name="Review device email connection").get_by_role("button", name="Confirm email connection", exact=True).click()
    card(page).get_by_role("button", name="Disconnect device email", exact=True).wait_for()
    broker.store.put(PREFIX + mailbox, None)
    page.evaluate("refresh()")
    card(page).get_by_text("Email connection needs attention", exact=True).wait_for()
    assert card(page).get_by_role("button", name="Connect a mailbox", exact=True).is_visible()
    card(page).get_by_role("button", name="Disconnect device email", exact=True).click()
    card(page).get_by_text("One-time setup", exact=True).wait_for()
    assert broker.store.config().accounts[PYPI_ACCOUNT].login.device_email_source is None
    assert sum(path.endswith("/remove") for path, _ in requests) == 1
    assert mail.fetches == provider.login_count == 0


def test_pause_clears_pending_review_without_applying_connection(device_owner_ui):
    page, broker, _, requests, _, _ = device_owner_ui
    card(page).get_by_role("button", name="Review email connection", exact=True).click()
    page.get_by_role("region", name="Review device email connection").wait_for()
    page.on("dialog", lambda dialog: dialog.accept())
    with page.expect_response(lambda response: response.url.endswith("/owner/device-email/discard")):
        page.get_by_role("button", name="Pause local service", exact=True).click()
    page.locator("#message").filter(has_text="Account Access is paused").wait_for()
    assert page.get_by_role("region", name="Review device email connection").count() == 0
    assert broker.store.config().accounts[PYPI_ACCOUNT].login.device_email_source is None
    assert not any(path.endswith("/apply") for path, _ in requests)
