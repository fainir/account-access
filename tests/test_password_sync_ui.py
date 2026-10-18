"""Owner-browser setup selects a provider without exposing its saved token."""

import json
import threading

from playwright.sync_api import sync_playwright

from account_access.demo import DEMO_PASSWORD
from account_access.owner import make_owner_server


def test_owner_browser_links_service_account_without_connect_server(env, monkeypatch):
    _, broker, _ = env
    broker.store.new_client("generic")
    broker.grant("generic", "demo-web", ["summary"])
    monkeypatch.setattr("account_access.install.install_detected", lambda store: {"status": "INSTALLED"})
    observed = []

    def fetch(link, expected_origin):
        observed.append((dict(link), expected_origin))
        return {"username": "demo@example.test", "password": DEMO_PASSWORD}

    monkeypatch.setattr("account_access.onepassword_source.fetch", fetch)
    server, token = make_owner_server(broker, guided=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{server.server_port}"
    source_token = "ops_synthetic-read-only-token"
    try:
        with sync_playwright() as pw:
            browser = pw.chromium.launch(headless=True, chromium_sandbox=True)
            try:
                page = browser.new_page()
                page.goto(base + "/#" + token)
                page.get_by_role("button", name="Password sync", exact=True).click()
                provider = page.get_by_label("Password source connection", exact=True)
                assert provider.input_value() == "1Password service account"
                endpoint = page.get_by_label("Connect server HTTPS address", exact=True)
                assert endpoint.is_hidden() and endpoint.is_disabled()
                page.get_by_label("Approved account for password sync", exact=True).select_option("demo-web")
                page.get_by_label("Vault ID", exact=True).fill("a" * 26)
                page.get_by_label("Login item ID", exact=True).fill("b" * 26)
                secret = page.get_by_label("Service-account token for a read-only vault", exact=True)
                assert secret.get_attribute("type") == "password"
                secret.fill(source_token)
                provider.select_option(label="1Password Connect server")
                assert endpoint.is_visible() and endpoint.is_enabled()
                assert page.get_by_label("Read-only Connect token", exact=True).input_value() == ""
                provider.select_option(label="1Password service account")
                page.get_by_label("Service-account token for a read-only vault", exact=True).fill(source_token)
                page.get_by_role("button", name="Connect automatic updates", exact=True).click()
                page.get_by_role("button", name="Disconnect and remove saved login", exact=True).wait_for()
                assert len(observed) == 1
                assert observed[0][0] == {"provider": "onepassword-service-account", "token": source_token,
                                           "vault": "a" * 26, "item": "b" * 26}
                assert source_token not in page.locator("body").inner_text()
                assert page.get_by_label("Service-account token for a read-only vault", exact=True).input_value() == ""
                state = page.evaluate("async capability => (await fetch('/owner/state', {headers: {Authorization: 'Bearer ' + capability}})).json()", token)
                assert source_token not in json.dumps(state)
                assert state["password_sync"][0]["provider"] == "1Password service account"
            finally:
                browser.close()
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
