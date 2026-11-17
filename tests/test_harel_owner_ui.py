"""Owned local UI fixtures only; never a Harel request or private profile."""

import os
from pathlib import Path
import threading

from playwright.sync_api import sync_playwright
import pytest

from account_access import catalog
from account_access.harel_login import configuration
from account_access.owner import make_owner_server


@pytest.mark.parametrize("width", [375, 1200])
def test_email_identity_fields_stay_masked_and_cannot_become_passwords(env, monkeypatch, width):
    _, broker, _ = env
    email = configuration("email")
    email.label = "Fictional Harel email UI fixture"
    password = catalog.betterloop()
    password.label = "Fictional password UI fixture"
    monkeypatch.setattr(catalog, "entries", lambda: {"fixture-email": email, "fixture-password": password})
    monkeypatch.setattr("account_access.install.install_detected", lambda store: {"status": "INSTALLED"})
    server, token = make_owner_server(broker, guided=True)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    try:
        with sync_playwright() as pw:
            browser = pw.chromium.launch()
            page = browser.new_page(viewport={"width": width, "height": 900})
            errors = []
            page.on("pageerror", lambda error: errors.append(str(error)))
            page.goto(f"http://127.0.0.1:{server.server_port}/#{token}", wait_until="domcontentloaded")
            try:
                page.locator("#service option[value='fixture-email']").wait_for(state="attached", timeout=5000)
            except Exception:
                pytest.fail("Owned fixture UI failed to load: " + page.locator("#message").inner_text() + "; " + "; ".join(errors))
            page.locator("#show-connect").click()
            page.locator("#service").select_option("fixture-email")
            assert page.locator("#username").get_attribute("type") == "password"
            assert page.locator("#password").get_attribute("type") == "password"
            assert "Identity number" in page.locator("label:has(#username)").inner_text()
            assert "Mobile number registered with the website" in page.locator("label:has(#password)").inner_text()
            page.locator("#username").fill("000000000")
            page.locator("#password").fill("0500000000")
            page.locator("#service").select_option("fixture-password")
            assert page.locator("#username").input_value() == ""
            assert page.locator("#password").input_value() == ""
            assert page.locator("#username").get_attribute("type") == "text"
            page.locator("#service").select_option("fixture-email")
            assert page.locator("#username").input_value() == ""
            assert page.evaluate("() => document.documentElement.scrollWidth <= innerWidth")
            assert not errors
            if os.environ.get("ACCOUNT_ACCESS_QA_EVIDENCE"):
                page.screenshot(path=str(Path(os.environ["ACCOUNT_ACCESS_QA_EVIDENCE"]) / f"harel-owner-{width}.png"), full_page=True)
            browser.close()
    finally:
        server.shutdown()
        server.server_close()
        worker.join(timeout=5)
