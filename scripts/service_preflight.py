"""Anonymous, credential-free preflight of reviewed consumer login forms.

This does not sign in, read an existing browser profile or prove factor delivery.
It uses the application's browser network guard and emits only fixed booleans.
"""

import json
import secrets
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from playwright.sync_api import sync_playwright

from account_access.broker import Broker
from account_access.catalog import namecheap
from account_access.models import Configuration
from account_access.storage import Store


def main():
    spec = namecheap()
    with tempfile.TemporaryDirectory(prefix="aapreflight-") as directory:
        store = Store(Path(directory), secrets.token_bytes(32))
        store.configure(Configuration(accounts={"namecheap": spec}))
        broker = Broker(store)
        with sync_playwright() as pw:
            browser = pw.chromium.launch(headless=True, chromium_sandbox=True)
            try:
                context = broker.browser.context(browser, spec, login=True)
                page = broker.browser.page(context)
                response = page.goto(spec.login_url, timeout=15000, wait_until="domcontentloaded")
                broker.browser.wait_state(page, spec)
                broker.browser.check_form(page, spec.login.password_selector, spec)
                checks = {
                    "http_ok": response.status == 200,
                    "exact_login_url": page.url == spec.login_url,
                    "login_recognized": broker.browser.challenge(page, spec) == "login",
                    "one_visible_username": page.locator(spec.login.username_selector).count() == 1
                        and page.locator(spec.login.username_selector).is_visible(),
                    "one_visible_password": page.locator(spec.login.password_selector).count() == 1
                        and page.locator(spec.login.password_selector).is_visible(),
                    "one_visible_submit": page.locator(spec.login.submit_selector).count() == 1
                        and page.locator(spec.login.submit_selector).is_visible(),
                    "not_signed_in": not page.locator(spec.ready_selector).count(),
                }
            finally:
                browser.close()
    print(json.dumps({
        "service": "namecheap", "checked_at": datetime.now(timezone.utc).isoformat(),
        "scope": "anonymous_form_preflight", "personal_login_tested": False,
        "credentials_submitted": False, "verification_delivery_tested": False,
        "checks": checks, "passed": all(checks.values()),
    }, indent=2))
    return 0 if all(checks.values()) else 1


if __name__ == "__main__":
    raise SystemExit(main())
