"""Fictional owner-browser import and renewal repair, with no personal accounts."""

import json
import threading

from playwright.sync_api import sync_playwright

from account_access.demo import DEMO_PASSWORD, DEMO_SEED
from account_access.owner import make_owner_server


def test_owner_browser_imports_bitwarden_json_then_uses_saved_login(env, monkeypatch):
    provider, broker, _ = env
    broker.store.new_client("generic")
    broker.store.put("source:demo-totp", None)
    monkeypatch.setattr("account_access.install.install_detected", lambda store: {"status": "INSTALLED"})
    monkeypatch.setattr("account_access.catalog.entries", lambda: {})
    export = {"encrypted": False, "items": [{
        "id": "fictional-item", "type": 1, "name": "Fictional account",
        "notes": "fictional-private-note", "fields": [{"name": "private", "value": "fictional-custom-field"}],
        "login": {"username": "demo@example.test", "password": DEMO_PASSWORD,
                  "totp": DEMO_SEED,
                  "uris": [{"uri": broker.store.config().accounts["demo-web"].login_url, "match": None}]},
    }]}
    server, token = make_owner_server(broker, guided=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{server.server_port}"
    try:
        with sync_playwright() as pw:
            browser = pw.chromium.launch(headless=True, chromium_sandbox=True)
            try:
                page = browser.new_page()
                selections = []
                previews = []
                def submitted(request):
                    if request.url == base + "/owner/import/apply":
                        selections.append(request.post_data_json)
                    elif request.url == base + "/owner/import/preview":
                        previews.append(True)
                page.on("request", submitted)
                page.goto(base + "/#" + token)
                page.locator("#connected .account").first.wait_for(state="attached")
                page.get_by_role("button", name="Import passwords", exact=True).click()
                upload = page.locator("#password-file")
                assert ".json" in upload.get_attribute("accept")
                upload.set_input_files({"name": "bitwarden.json", "mimeType": "application/json",
                                        "buffer": json.dumps(export).encode()})
                review = page.locator("#import-review")
                review.get_by_role("button", name="Import selected accounts", exact=True).wait_for()
                assert len(previews) == 1
                upload.set_input_files({"name": "broken.json", "mimeType": "application/json",
                                        "buffer": b'{"encrypted":false,"items":[],"invalid":"\xff"}'})
                page.locator("#message").filter(has_text="fresh UTF-8").wait_for()
                assert len(previews) == 1 and review.is_hidden() and upload.input_value() == ""
                upload.set_input_files({"name": "bitwarden.json", "mimeType": "application/json",
                                        "buffer": json.dumps(export).encode()})
                review.get_by_role("button", name="Import selected accounts", exact=True).wait_for()
                assert len(previews) == 2
                text = review.inner_text()
                assert all(secret not in text for secret in [DEMO_PASSWORD, DEMO_SEED,
                                                             "fictional-private-note", "fictional-custom-field"])
                authenticator = review.get_by_label("Also enroll included authenticator keys for supported login recovery")
                assert not authenticator.is_checked()
                review.get_by_role("checkbox").nth(1).check()
                review.get_by_role("button", name="Import selected accounts", exact=True).click()
                saved = page.locator("#connected .account").filter(
                    has=page.get_by_text(broker.store.config().accounts["demo-web"].label, exact=True))
                saved.get_by_text("Example connected", exact=True).wait_for()
                assert upload.input_value() == ""
                assert len(selections) == 1
                assert selections[0]["selections"][0]["include_authenticator"] is False
                assert broker.store.get("source:demo-totp") is None
            finally:
                browser.close()
        assert broker.run("generic", "demo-web", "summary")["status"] == "COMPLETED"
        assert provider.login_count == 1
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def test_owner_browser_reconnects_unusable_google_grant_without_success_claim(env, monkeypatch):
    _, broker, _ = env
    broker.store.new_client("generic")
    monkeypatch.setattr("account_access.install.install_detected", lambda store: {"status": "INSTALLED"})
    grant = {"account": "fictional-gmail", "publisher_configured": True, "connected": True,
             "renewable_access_saved": True, "connection_state": "saved_access",
             "sources": [{"recipient": "owner@example.test"}]}
    monkeypatch.setattr("account_access.mailbox_oauth.view", lambda broker: [dict(grant)])
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
                page.get_by_text("Renewable Google access is saved.", exact=False).wait_for()
                for reason in ["mailbox_oauth_renewal_unavailable", "refresh_outcome_uncertain",
                               "mailbox_scope_not_allowed", "fictional-private-reason"]:
                    grant.update(connected=False, renewable_access_saved=False,
                                 connection_state="needs_attention", reason=reason)
                    page.evaluate("refresh()")
                    assert page.get_by_role("button", name="Reconnect with Google", exact=True).is_visible()
                    body = page.locator("body").inner_text()
                    assert "Renewable Google access is saved." not in body
                    assert "fictional-private-reason" not in body
                    assert "Reconnect once" in body or "publisher must check" in body
                grant.update(connected=True)
                grant.pop("renewable_access_saved")
                grant.pop("connection_state")
                page.evaluate("refresh()")
                assert page.get_by_role("button", name="Reconnect with Google", exact=True).is_visible()
                assert "Renewable Google access is saved." not in page.locator("body").inner_text()
            finally:
                browser.close()
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
