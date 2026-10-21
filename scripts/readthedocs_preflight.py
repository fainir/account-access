"""Credential-free public RTD form checks through the product network guard."""

from datetime import datetime, timezone
import json
from pathlib import Path
import secrets
import tempfile

from playwright.sync_api import Error as PlaywrightError, sync_playwright

from account_access.broker import Broker
from account_access.catalog import RTD_ACCOUNT, include_sources, readthedocs
from account_access.errors import AccessError
from account_access.models import Configuration
from account_access.storage import Store


def inspect():
    spec = readthedocs()
    checks = dict.fromkeys(["http_ok", "exact_login_url", "login_recognized", "native_form_destination_reviewed",
                            "one_visible_username", "one_visible_password", "one_visible_submit", "not_signed_in",
                            "no_post_or_code_request", "status_redirect_reviewed"], False)
    posts = []
    with tempfile.TemporaryDirectory(prefix="ac-rtd-preflight-") as temporary:
        store = Store(Path(temporary), secrets.token_bytes(32))
        config = Configuration(accounts={})
        include_sources(config, {RTD_ACCOUNT: spec})
        config.accounts[RTD_ACCOUNT] = spec
        store.configure(Configuration.model_validate(config.model_dump()))
        broker = Broker(store)
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(headless=True, chromium_sandbox=True)
            try:
                context = broker.browser.context(browser, spec, login=True)
                context.on("request", lambda request: posts.append(True) if request.method not in {"GET", "HEAD"} else None)
                page = broker.browser.page(context)
                response = page.goto(spec.login_url, timeout=15000, wait_until="domcontentloaded")
                checks["http_ok"] = response is not None and response.status == 200
                checks["exact_login_url"] = page.url == spec.login_url
                checks["login_recognized"] = broker.browser.challenge(page, spec) == "login"
                broker.browser.check_form(page, spec.login.password_selector, spec)
                broker.browser.check_staged_native_form(page, spec.login.password_selector,
                                                        spec.login.submit_selector, spec.login_url)
                checks["native_form_destination_reviewed"] = True
                for key, selector in [("username", spec.login.username_selector), ("password", spec.login.password_selector),
                                      ("submit", spec.login.submit_selector)]:
                    checks["one_visible_" + key] = page.locator(selector).count() == 1 and page.locator(selector).is_visible()
                checks["not_signed_in"] = page.locator(spec.ready_selector).count() == 0
                context.close()
                context = broker.browser.context(browser, spec)
                context.on("request", lambda request: posts.append(True) if request.method not in {"GET", "HEAD"} else None)
                page = broker.browser.page(context)
                page.goto(spec.operations["status"].url, timeout=15000, wait_until="domcontentloaded")
                checks["status_redirect_reviewed"] = page.url in spec.read_resources and broker.browser.challenge(page, spec) == "login"
                checks["no_post_or_code_request"] = not posts
            except (AccessError, PlaywrightError):
                pass
            finally:
                browser.close()
    return {"service": "readthedocs-community", "scope": "anonymous_form_preflight",
            "checked_at": datetime.now(timezone.utc).isoformat(),
            "primary_source_review": {"readthedocs": "9b9a4e366097f7a86f9f23b78d066b13218e2195",
                                      "dashboard": "8befc8b90cd284caf321040a294a479535ca97f7", "allauth": "65.17.0"},
            "deployed_private_templates_verified": False,
            "private_signins": 0, "credentials_submitted": False, "verification_delivery_tested": False,
            "personal_profile_used": False, "production_ready": False,
            "checks": checks, "passed": all(value is True for value in checks.values())}


def main():
    report = inspect()
    print(json.dumps(report, indent=2))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
