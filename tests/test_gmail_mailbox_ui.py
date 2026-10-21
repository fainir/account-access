"""The consumer web flow uses real local HTTP and a fictional saved Google grant."""

import threading

import pytest
from playwright.sync_api import sync_playwright

from account_access.mailbox_oauth import PROFILE_PREFIX, profile_id
from account_access.owner import make_owner_server
from test_gmail_mailbox_binding import SITE, SOURCE, ordinary_source
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


@pytest.mark.parametrize("review_case", ["ready", "changed", "unchecked"])
def test_ordinary_email_picker_reuses_checked_google_and_rejects_stale_review(
        saved_google, monkeypatch, review_case):  # noqa: F811
    broker, provider = saved_google
    ordinary_source(broker)
    from account_access.mailbox_oauth import check
    if review_case != "unchecked":
        check(broker, "google", broker.store.config().fingerprint("google"))
    broker.store.challenge(SITE, "unknown", "browser_state_unrecognized")
    monkeypatch.setattr("account_access.install.install_detected", lambda store: {"status": "INSTALLED"})
    connection_checks = []

    def profile_check(url, **kwargs):
        assert url == "https://gmail.googleapis.com/gmail/v1/users/me/profile"
        connection_checks.append(url)
        return {"emailAddress": "fictional@example.test"}

    monkeypatch.setattr("account_access.mailbox_health.get_json", profile_check)
    server, owner = make_owner_server(broker, guided=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{server.server_port}"
    posts = []
    verifies = []
    try:
        with sync_playwright() as pw:
            browser = pw.chromium.launch(headless=True, chromium_sandbox=True)
            try:
                page = browser.new_page()
                page.on("request", lambda request: posts.append(request.post_data_json)
                        if request.url.endswith("/owner/source") else
                        verifies.append(request.url) if request.url.endswith("/owner/verify") else None)
                page.goto(base + "/#" + owner)
                page.get_by_role("button", name="Verification", exact=True).click()
                card = page.locator(f'[data-verification-source="{SOURCE}"]')
                if review_case == "unchecked":
                    assert card.get_by_label("Use a connected Gmail mailbox", exact=True).count() == 0
                    assert card.get_by_role("button", name="Enable verification", exact=True).is_disabled()
                    card.locator("form").evaluate("form => form.dispatchEvent(new Event('submit', {cancelable: true}))")
                    assert posts == [] and connection_checks == [] and verifies == []
                    assert broker.store.get("source:" + SOURCE) is None
                    assert provider.profiles == provider.refreshes == 0
                    return
                assert card.get_by_label("Use a connected Gmail mailbox", exact=True).input_value() == profile_id("google")
                assert card.get_by_label("Use a connected Gmail mailbox", exact=True).locator("option").count() == 1
                assert card.locator('input[type="password"]').count() == 0
                assert "login@example.test" in card.inner_text()
                assert "fictional@example.test" in card.inner_text()
                assert "Your sign-in code" in card.inner_text()
                if review_case == "changed":
                    saved = broker.store.get(PROFILE_PREFIX + profile_id("google"))
                    saved["generation"] = "f" * 32
                    broker.store.put(PROFILE_PREFIX + profile_id("google"), saved)
                with page.expect_response(lambda response: response.url.endswith("/owner/source")) as response:
                    card.get_by_role("button", name="Enable verification", exact=True).click()
                assert len(posts) == 1
                assert posts[0]["source"] == SOURCE
                assert set(posts[0]["credential"]) == {"mailbox", "setup_context", "setup_revision"}
                assert posts[0]["credential"]["mailbox"] == profile_id("google")
                if review_case == "changed":
                    assert response.value.status == 403
                    page.locator("#message").filter(has_text="website or mailbox connection changed").wait_for()
                    assert broker.store.get("source:" + SOURCE) is None
                    assert connection_checks == []
                else:
                    assert response.value.status == 200
                    card.get_by_text("Mailbox connection checked", exact=True).wait_for()
                    assert broker.store.get("source:" + SOURCE)["gmail_mailbox"] == profile_id("google")
                    assert len(connection_checks) == 1
                assert verifies == []
                assert broker.store.get("oauth-pending:google") is None
                assert provider.profiles == 1 and provider.refreshes == 0
                assert "synthetic-" not in page.locator("body").inner_text()
            finally:
                browser.close()
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
