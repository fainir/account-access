"""Real owner-page interaction with fictional provider responses only."""

import json
import threading

from playwright.sync_api import sync_playwright

from account_access.demo import DEMO_PASSWORD
from account_access.errors import AccessError
from account_access.owner import make_owner_server
from account_access.password_import import apply, preview


ITEM = "12345678-1234-1234-1234-123456789abc"
CONNECTION = "b" * 32
GENERATION = "a" * 32


def test_local_bitwarden_setup_masks_clears_binds_imported_item_and_disconnects(env, monkeypatch):
    provider, broker, _ = env
    broker.store.new_client("generic")
    staged = preview(broker.store, json.dumps({"encrypted": False, "items": [{"id": ITEM, "type": 1,
        "login": {"username": "demo@example.test", "password": DEMO_PASSWORD,
                  "uris": [{"uri": provider.base + "/login"}]}}]}))
    row = next(row for row in staged["rows"] if any(match["id"] == "demo-web" for match in row["matches"]))
    apply(broker, staged["id"], [{"row": row["id"], "account": "demo-web", "operations": ["summary"]}], ["generic"])
    broker.grant("generic", "demo-mfa", ["summary"])
    monkeypatch.setattr("account_access.install.install_detected", lambda store: {"status": "INSTALLED"})
    runtime = [True]
    profiles, linked, observed = [], [], []
    monkeypatch.setattr("account_access.bitwarden_source.available", lambda store: runtime[0])
    monkeypatch.setattr("account_access.bitwarden_source.connections", lambda store: list(profiles))
    monkeypatch.setattr("account_access.password_sync.view", lambda store: list(linked))

    def connect(store, data):
        observed.append(("connect", dict(data)))
        if data["client_secret"] == "synthetic-rejected-secret":
            raise AccessError("DENIED", "password_source_access_removed")
        metadata = {"id": CONNECTION, "generation": GENERATION, "provider": "Bitwarden",
                    "email": "fictional@example.test", "region": data["region"], "checked": 1}
        profiles.append(metadata)
        return {"status": "CONNECTED", **metadata}

    def enroll(store_broker, account, connection):
        observed.append(("item", account, dict(connection)))
        linked.append({"account": account, "provider": "Bitwarden", "status": "SYNCED", "generation": GENERATION})
        return {"status": "LINKED", "account": account}

    def disconnect(store, identity, generation):
        observed.append(("disconnect", identity, generation))
        profiles.clear()
        linked.clear()
        return {"status": "DISCONNECTED", "id": identity}

    monkeypatch.setattr("account_access.bitwarden_source.connect", connect)
    monkeypatch.setattr("account_access.password_sync.enroll", enroll)
    monkeypatch.setattr("account_access.bitwarden_source.disconnect", disconnect)
    server, token = make_owner_server(broker, guided=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(headless=True, chromium_sandbox=True)
            try:
                page = browser.new_page()
                page.on("dialog", lambda dialog: dialog.accept())
                page.goto(f"http://127.0.0.1:{server.server_port}/#" + token)
                page.get_by_role("button", name="Password sync", exact=True).click()
                page.get_by_role("button", name="Connect Bitwarden", exact=True).click()
                for name in ["Personal API client ID", "Personal API client secret", "Bitwarden master password"]:
                    assert page.get_by_label(name, exact=True).get_attribute("type") == "password"
                consent = page.get_by_label("Allow local Bitwarden vault decryption", exact=True)
                assert not consent.is_checked()
                page.get_by_label("Personal API client ID", exact=True).fill("user." + ITEM)
                page.get_by_label("Personal API client secret", exact=True).fill("synthetic-cancelled-secret")
                page.get_by_label("Bitwarden master password", exact=True).fill("synthetic-cancelled-master")
                page.evaluate("refresh()")
                assert page.get_by_label("Bitwarden master password", exact=True).input_value() == "synthetic-cancelled-master"
                page.get_by_role("button", name="Cancel Bitwarden setup", exact=True).click()
                page.get_by_role("button", name="Connect Bitwarden", exact=True).click()
                assert page.get_by_label("Personal API client secret", exact=True).input_value() == ""
                assert page.get_by_label("Bitwarden master password", exact=True).input_value() == ""
                assert not observed

                def fill(secret):
                    page.get_by_label("Bitwarden server region", exact=True).select_option("eu")
                    page.get_by_label("Personal API client ID", exact=True).fill("user." + ITEM)
                    page.get_by_label("Personal API client secret", exact=True).fill(secret)
                    page.get_by_label("Bitwarden master password", exact=True).fill("  synthetic master 🔐  ")
                    page.get_by_label("Allow local Bitwarden vault decryption", exact=True).check()

                fill("synthetic-rejected-secret")
                page.get_by_role("button", name="Connect Bitwarden vault", exact=True).click()
                page.locator("#message").filter(has_text="Bitwarden did not accept").wait_for()
                assert page.get_by_label("Personal API client secret", exact=True).input_value() == ""
                assert page.get_by_label("Bitwarden master password", exact=True).input_value() == ""
                assert not consent.is_checked()
                assert "synthetic-rejected-secret" not in page.locator("body").inner_text()
                fill("synthetic-accepted-secret")
                page.get_by_role("button", name="Connect Bitwarden vault", exact=True).click()
                page.get_by_role("button", name="Disconnect Bitwarden vault", exact=True).wait_for()
                assert observed[-1][1] == {"region": "eu", "client_id": "user." + ITEM,
                    "client_secret": "synthetic-accepted-secret", "master_password": "  synthetic master 🔐  ", "consent_vault_access": True}
                page.get_by_label("Approved account for Bitwarden sync", exact=True).select_option("demo-web")
                item = page.get_by_label("Bitwarden login item ID (advanced)", exact=True)
                assert item.input_value() == ITEM and item.is_hidden() and item.is_disabled()
                page.get_by_label("Approved account for Bitwarden sync", exact=True).select_option("demo-mfa")
                assert item.is_visible() and item.is_enabled() and item.input_value() == ""
                page.get_by_label("Approved account for Bitwarden sync", exact=True).select_option("demo-web")
                assert item.input_value() == ITEM and item.is_hidden() and item.is_disabled()
                page.get_by_role("button", name="Connect Bitwarden automatic updates", exact=True).click()
                page.get_by_role("button", name="Disconnect and remove saved login", exact=True).wait_for()
                assert observed[-1] == ("item", "demo-web", {"provider": "bitwarden", "connection": CONNECTION,
                    "connection_generation": GENERATION, "item": ITEM})
                assert page.get_by_role("button", name="Replace token", exact=True).count() == 0
                assert page.get_by_label("Password source connection", exact=True).input_value() == "1Password service account"
                state = page.evaluate("async token => (await fetch('/owner/state', {headers:{Authorization:'Bearer '+token}})).json()", token)
                assert all(secret not in json.dumps(state) for secret in ["synthetic-accepted-secret", "  synthetic master 🔐  "])
                page.get_by_role("button", name="Disconnect Bitwarden vault", exact=True).click()
                page.get_by_role("button", name="Disconnect Bitwarden vault", exact=True).wait_for(state="detached")
                assert observed[-1] == ("disconnect", CONNECTION, GENERATION)
                runtime[0] = False
                page.evaluate("refresh()")
                page.get_by_text("Update or repair Account Access to install its protected Bitwarden component.", exact=False).wait_for()
                assert page.get_by_role("button", name="Connect Bitwarden", exact=True).count() == 0
            finally:
                browser.close()
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
