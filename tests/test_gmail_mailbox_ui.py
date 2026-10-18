"""The consumer web flow uses real local HTTP and a fictional saved Google grant."""

import threading

from playwright.sync_api import sync_playwright

from account_access.mailbox_oauth import profile_id
from account_access.owner import make_owner_server
from test_gmail_reusable_mailbox import saved_google  # noqa: F401


def test_saved_google_check_repair_and_selection_need_no_password_or_reconsent(saved_google, monkeypatch):  # noqa: F811
    broker, provider = saved_google
    monkeypatch.setattr("account_access.install.install_detected", lambda store: {"status": "INSTALLED"})
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
                page.on("request", lambda request: requests.append(request.url)
                        if "/owner/mailbox/oauth/" in request.url else None)
                page.goto(base + "/#" + owner)
                page.get_by_role("button", name="Verification", exact=True).click()
                google = page.locator('[aria-label="Google mailbox connection"]')
                assert "Google access is saved" in google.inner_text()
                assert "Google mailbox checked" not in google.inner_text()
                assert google.locator('input[type="password"]').count() == 0
                google.get_by_role("button", name="Check Google connection", exact=True).click()
                google.get_by_text("Google mailbox checked.", exact=False).wait_for()
                device = page.locator('[aria-label="PyPI device confirmation email"]')
                assert device.get_by_label("Connected mailbox for PyPI device emails", exact=True).input_value() == profile_id("google")
                device.get_by_role("button", name="Review email connection", exact=True).click()
                review = page.get_by_role("region", name="Review device email connection", exact=True)
                assert "fictional@example.test" in review.inner_text()
                review.get_by_role("button", name="Confirm email connection", exact=True).click()
                device.get_by_role("button", name="Disconnect device email", exact=True).wait_for()
                assert provider.profiles == 1 and provider.refreshes == 0

                # A rejected short-lived token repairs through the saved grant.
                # The UI never opens Google consent or asks for an app password.
                provider.status = 401
                google.get_by_role("button", name="Check Google connection", exact=True).click()
                page.locator("#message").filter(has_text="Google access is saved. Try Check Google connection again").wait_for()
                provider.status = 200
                google.get_by_role("button", name="Check Google connection", exact=True).click()
                page.locator("#message").filter(has_text="Google mailbox checked. Choose it").wait_for()
                assert provider.refreshes == 1 and provider.profiles == 3
                assert all(url.endswith("/owner/mailbox/oauth/check") for url in requests)
                assert broker.store.get("oauth-pending:google") is None
                assert device.get_by_text("Setup saved · delivery unverified", exact=True).is_visible()
            finally:
                browser.close()
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
