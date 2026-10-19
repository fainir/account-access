"""Actual local owner-page SMS setup, using fictional accounts and a private HOME."""

import threading

import pytest
from playwright.sync_api import sync_playwright

from account_access.errors import AccessError
from account_access.google_messages import TEMPLATE
from account_access.google_messages_host import prepare as prepare_bridge
from account_access.models import CodeSource
from account_access.owner import make_owner_server


def sms_source(broker):
    config = broker.store.config()
    config.code_sources["demo-totp"] = CodeSource(
        kind="google_messages", sender="github-login-rotating-senders",
        recipient="paired-google-messages", template=TEMPLATE,
    )
    broker.store.configure(config)
    broker.store.put("source:demo-totp", {"enabled": True})


@pytest.mark.parametrize("existing_source", [False, True])
def test_google_messages_requires_review_then_shows_real_prepared_folder(
        env, monkeypatch, tmp_path, existing_source):
    _, broker, _ = env
    broker.store.new_client("generic")
    if existing_source:
        sms_source(broker)
    else:
        monkeypatch.setattr("account_access.sms_setup.view", lambda store: [{
            "account": "demo-mfa", "fingerprint": store.config().fingerprint("demo-mfa"),
        }])
    monkeypatch.setattr("account_access.install.install_detected", lambda store: {"status": "INSTALLED"})
    fake_home = tmp_path / "fictional-home"
    fake_home.mkdir(mode=0o700)
    preparations = []

    def prepare(store):
        preparations.append(True)
        return prepare_bridge(store, home=fake_home)

    monkeypatch.setattr("account_access.google_messages_host.prepare", prepare)
    server, token = make_owner_server(broker, guided=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    requests = []
    try:
        with sync_playwright() as pw:
            browser = pw.chromium.launch(headless=True, chromium_sandbox=True)
            try:
                page = browser.new_page()
                page.on("request", lambda request: requests.append(request.url))
                page.goto(f"http://127.0.0.1:{server.server_port}/#" + token)
                page.get_by_role("button", name="Verification", exact=True).click()
                card = page.get_by_label("Android SMS · Google Messages", exact=True)
                assert "SMS login codes" in card.inner_text()
                assert "sender identity is not independently verified" in card.inner_text()
                assert card.get_by_role("button", name="Enable verification", exact=True).count() == 0
                assert card.get_by_role("button", name="Update verification", exact=True).count() == 0
                if existing_source:
                    assert "Setup saved · delivery unverified" in card.inner_text()
                card.get_by_role("button", name="Set up Google Messages", exact=True).click()
                review = card.get_by_role("form", name="Review Google Messages preparation", exact=True)
                consent = review.get_by_role("checkbox", name="Allow Account Access to prepare the local Google Messages bridge", exact=True)
                prepare_button = review.get_by_role("button", name="Prepare browser connection", exact=True)
                assert not consent.is_checked() and prepare_button.is_disabled()
                consent.check()
                review.get_by_role("button", name="Cancel browser preparation", exact=True).click()
                assert not preparations
                card.get_by_role("button", name="Set up Google Messages", exact=True).click()
                assert not consent.is_checked() and prepare_button.is_disabled()
                consent.check()
                prepare_button.click()
                instructions = card.get_by_role("region", name="Add the SMS browser connection", exact=True)
                instructions.wait_for()
                assert len(preparations) == 1
                assert (broker.store.root / "GoogleMessagesExtension/manifest.json").is_file()
                assert list(fake_home.rglob("com.account_access.google_messages.json"))
                assert str(broker.store.root / "GoogleMessagesExtension") in instructions.inner_text()
                assert "Load unpacked" in instructions.inner_text()
                assert "Developer mode" in instructions.inner_text()
                assert "Connect GitHub login texts" in instructions.inner_text()
                assert "Browser bridge prepared · delivery unverified" in card.inner_text()
                assert card.get_by_text("Connected", exact=True).count() == 0
                assert "No website sign-in has started" in instructions.inner_text()
                assert instructions.get_by_role("link", name="Open Google Messages", exact=True).get_attribute("href") == "https://messages.google.com/web/conversations"
                page.evaluate("refresh()")
                instructions.wait_for()
                assert len(preparations) == 1
                if existing_source:
                    card.get_by_role("button", name="Disable Google Messages SMS for", exact=False).click()
                    card.get_by_text("SMS access is not enabled.", exact=False).wait_for()
                    assert broker.store.get("source:demo-totp") == {"enabled": False}
                assert not any(url.endswith("/owner/source") or url.endswith("/owner/verify") for url in requests)
                assert sum(url.endswith("/owner/google-messages/prepare") for url in requests) == 1
            finally:
                browser.close()
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def test_worker_browser_directs_to_desktop_without_forbidden_install_or_preparation(env, monkeypatch):
    _, broker, _ = env
    broker.store.new_client("generic")
    sms_source(broker)
    monkeypatch.setattr("account_access.install.install_detected", lambda store: pytest.fail("No host installation"))
    monkeypatch.setattr("account_access.google_messages_host.prepare", lambda store: pytest.fail("No host preparation"))
    server, token = make_owner_server(broker, guided=True, local_host_actions=False)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    requests = []
    try:
        with sync_playwright() as pw:
            browser = pw.chromium.launch(headless=True, chromium_sandbox=True)
            try:
                page = browser.new_page()
                page.on("request", lambda request: requests.append(request.url))
                page.goto(f"http://127.0.0.1:{server.server_port}/#" + token)
                page.get_by_role("button", name="Verification", exact=True).click()
                card = page.get_by_label("Android SMS · Google Messages", exact=True)
                card.get_by_text("Open Verification in the Account Access desktop app", exact=False).wait_for()
                assert card.get_by_role("button", name="Set up Google Messages", exact=True).count() == 0
                assert card.locator("form").count() == 0
                assert page.locator("#message").inner_text() == ""
                assert not any(url.endswith("/owner/install") or url.endswith("/owner/google-messages/prepare") for url in requests)
            finally:
                browser.close()
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


@pytest.mark.parametrize("failure", ["denied", "unexpected_status"])
def test_failed_sms_preparation_keeps_review_without_success_claim(env, monkeypatch, failure):
    _, broker, _ = env
    broker.store.new_client("generic")
    sms_source(broker)
    monkeypatch.setattr("account_access.install.install_detected", lambda store: {"status": "INSTALLED"})

    def prepare(store):
        if failure == "denied":
            raise AccessError("DENIED", "fictional-internal-detail")
        return {"status": "CONNECTED", "extension_path": "/fictional/GoogleMessagesExtension"}

    monkeypatch.setattr("account_access.google_messages_host.prepare", prepare)
    server, token = make_owner_server(broker, guided=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        with sync_playwright() as pw:
            browser = pw.chromium.launch(headless=True, chromium_sandbox=True)
            try:
                page = browser.new_page()
                page.goto(f"http://127.0.0.1:{server.server_port}/#" + token)
                page.get_by_role("button", name="Verification", exact=True).click()
                card = page.get_by_label("Android SMS · Google Messages", exact=True)
                card.get_by_role("button", name="Set up Google Messages", exact=True).click()
                consent = card.get_by_role("checkbox", name="Allow Account Access to prepare the local Google Messages bridge", exact=True)
                consent.check()
                card.get_by_role("button", name="Prepare browser connection", exact=True).click()
                page.locator("#message").filter(has_text="The browser connection could not be prepared.").wait_for()
                assert card.get_by_role("region", name="Add the SMS browser connection", exact=True).is_hidden()
                assert not consent.is_checked() and consent.is_enabled()
                assert card.get_by_role("button", name="Prepare browser connection", exact=True).is_disabled()
                assert "Browser bridge prepared" not in card.inner_text()
                assert "fictional-internal-detail" not in page.locator("body").inner_text()
            finally:
                browser.close()
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def test_sms_review_and_inflight_preparation_survive_forced_and_job_poll_refreshes(
        env, monkeypatch, tmp_path):
    _, broker, _ = env
    broker.store.new_client("generic")
    sms_source(broker)
    monkeypatch.setattr("account_access.install.install_detected", lambda store: {"status": "INSTALLED"})
    login_entered, release_login = threading.Event(), threading.Event()
    prepare_entered, release_prepare = threading.Event(), threading.Event()
    preparations = []
    fake_home = tmp_path / "fictional-home"
    fake_home.mkdir(mode=0o700)

    def pending_login(*args, **kwargs):
        login_entered.set()
        assert release_login.wait(30), "Fictional website job was not released"

    def delayed_prepare(store):
        preparations.append(True)
        prepare_entered.set()
        assert release_prepare.wait(20), "Fictional preparation was not released"
        return prepare_bridge(store, home=fake_home)

    monkeypatch.setattr(broker.browser, "read", pending_login)
    monkeypatch.setattr("account_access.google_messages_host.prepare", delayed_prepare)
    server, token = make_owner_server(broker, guided=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    requests = []
    try:
        with sync_playwright() as pw:
            browser = pw.chromium.launch(headless=True, chromium_sandbox=True)
            try:
                page = browser.new_page()
                page.on("request", lambda request: requests.append(request.url))
                page.goto(f"http://127.0.0.1:{server.server_port}/#" + token)
                page.get_by_role("button", name="Verification", exact=True).click()
                page.evaluate("call('/owner/verify',{account:'demo-web'})")
                assert login_entered.wait(2)
                page.evaluate("refresh()")
                card = page.get_by_label("Android SMS · Google Messages", exact=True)
                card.get_by_role("button", name="Set up Google Messages", exact=True).click()
                card.evaluate("node=>node.dataset.fixtureIdentity='same-card'")
                review = card.get_by_role("form", name="Review Google Messages preparation", exact=True)
                consent = review.get_by_role("checkbox", name="Allow Account Access to prepare the local Google Messages bridge", exact=True)
                consent.check()
                page.evaluate("refresh()")
                assert card.get_attribute("data-fixture-identity") == "same-card"
                assert review.is_visible() and consent.is_checked()

                def wait_for_job_poll():
                    # The real RUNNING owner job schedules refresh every 1.2 seconds.
                    with page.expect_response(lambda response: response.url.endswith("/owner/state"), timeout=5000) as response:
                        pass
                    response.value.finished()
                    page.evaluate("() => new Promise(resolve=>requestAnimationFrame(()=>requestAnimationFrame(resolve)))")

                wait_for_job_poll()
                assert card.get_attribute("data-fixture-identity") == "same-card"
                assert review.is_visible() and consent.is_checked()
                prepare_button = review.get_by_role("button", name="Prepare browser connection", exact=True)
                prepare_button.click()
                assert prepare_entered.wait(2)
                page.evaluate("refresh()")
                wait_for_job_poll()
                assert card.get_attribute("data-fixture-identity") == "same-card"
                assert consent.is_disabled() and prepare_button.is_disabled()
                assert review.get_by_role("button", name="Cancel browser preparation", exact=True).is_disabled()
                assert card.get_by_role("button", name="Set up Google Messages", exact=True).is_hidden()
                # A duplicate submit event cannot issue a second prepare while the first is pending.
                review.evaluate("form=>form.dispatchEvent(new Event('submit',{bubbles:true,cancelable:true}))")
                page.evaluate("refresh()")
                assert len(preparations) == 1
                release_prepare.set()
                instructions = card.get_by_role("region", name="Add the SMS browser connection", exact=True)
                instructions.wait_for()
                assert str(broker.store.root / "GoogleMessagesExtension") in instructions.inner_text()
                assert "Browser bridge prepared · delivery unverified" in card.inner_text()
                page.evaluate("refresh()")
                instructions.wait_for()
                assert sum(url.endswith("/owner/google-messages/prepare") for url in requests) == 1
                assert len(preparations) == 1
            finally:
                release_prepare.set()
                release_login.set()
                browser.close()
    finally:
        release_prepare.set()
        release_login.set()
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def test_source_revoke_discards_open_review_and_ignores_old_preparation_result(
        env, monkeypatch, tmp_path):
    _, broker, _ = env
    broker.store.new_client("generic")
    sms_source(broker)
    monkeypatch.setattr("account_access.install.install_detected", lambda store: {"status": "INSTALLED"})
    prepare_entered, release_prepare = threading.Event(), threading.Event()
    fake_home = tmp_path / "fictional-home"
    fake_home.mkdir(mode=0o700)
    preparations = []

    def delayed_prepare(store):
        preparations.append(True)
        prepare_entered.set()
        assert release_prepare.wait(15), "Fictional preparation was not released"
        return prepare_bridge(store, home=fake_home)

    monkeypatch.setattr("account_access.google_messages_host.prepare", delayed_prepare)
    server, token = make_owner_server(broker, guided=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        with sync_playwright() as pw:
            browser = pw.chromium.launch(headless=True, chromium_sandbox=True)
            try:
                page = browser.new_page()
                page.goto(f"http://127.0.0.1:{server.server_port}/#" + token)
                page.get_by_role("button", name="Verification", exact=True).click()
                card = page.get_by_label("Android SMS · Google Messages", exact=True)
                review = card.get_by_role("form", name="Review Google Messages preparation", exact=True)
                consent = review.get_by_role("checkbox", name="Allow Account Access to prepare the local Google Messages bridge", exact=True)
                card.get_by_role("button", name="Set up Google Messages", exact=True).click()
                card.evaluate("node=>node.dataset.fixtureIdentity='old-review'")
                consent.check()
                card.get_by_role("button", name="Disable Google Messages SMS for", exact=False).click()
                card.get_by_text("SMS access is not enabled.", exact=False).wait_for()
                assert card.get_attribute("data-fixture-identity") is None
                assert review.is_hidden()
                assert not card.locator('form[aria-label="Review Google Messages preparation"] input[type="checkbox"]').is_checked()
                assert not preparations

                # A separate fictional owner reconnection changes the context again.
                sms_source(broker)
                page.evaluate("refresh()")
                card.get_by_role("button", name="Set up Google Messages", exact=True).click()
                consent.check()
                review.get_by_role("button", name="Prepare browser connection", exact=True).click()
                assert prepare_entered.wait(2)
                card.get_by_role("button", name="Disable Google Messages SMS for", exact=False).click()
                card.get_by_text("SMS access is not enabled.", exact=False).wait_for()
                assert review.is_hidden()
                with page.expect_response(lambda response: response.url.endswith("/owner/google-messages/prepare")) as response:
                    release_prepare.set()
                response.value.finished()
                page.evaluate("() => new Promise(resolve=>requestAnimationFrame(()=>requestAnimationFrame(resolve)))")
                assert card.get_by_role("region", name="Add the SMS browser connection", exact=True).is_hidden()
                assert card.get_by_role("button", name="Set up Google Messages", exact=True).is_visible()
                assert "Browser bridge prepared" not in card.inner_text()
                assert "Google Messages SMS disabled" in page.locator("#message").inner_text()
                assert len(preparations) == 1
                assert broker.store.get("source:demo-totp") == {"enabled": False}
            finally:
                release_prepare.set()
                browser.close()
    finally:
        release_prepare.set()
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
