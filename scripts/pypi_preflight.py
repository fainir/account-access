"""One anonymous PyPI form GET, using the product's guarded fresh browser."""

from datetime import datetime, timezone
import json
from pathlib import Path
import secrets
import tempfile

from playwright.sync_api import Error as PlaywrightError, sync_playwright

from account_access.broker import Broker
from account_access.catalog import PYPI_ACCOUNT, include_sources, pypi
from account_access.errors import AccessError
from account_access.models import Configuration
from account_access.storage import Store


def inspect():
    spec = pypi()
    checks = dict.fromkeys(["http_ok", "exact_login_url", "login_recognized", "native_form_destination_reviewed",
                            "one_visible_username", "one_visible_password", "one_visible_submit", "not_signed_in",
                            "no_post_or_code_request", "deployed_source_commit_reviewed"], False)
    posts = []
    with tempfile.TemporaryDirectory(prefix="ac-pypi-preflight-") as temporary:
        store = Store(Path(temporary), secrets.token_bytes(32))
        config = Configuration(accounts={})
        include_sources(config, {PYPI_ACCOUNT: spec})
        config.accounts[PYPI_ACCOUNT] = spec
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
                source = page.locator("meta[name='source-commit']")
                checks["deployed_source_commit_reviewed"] = source.count() == 1 and source.get_attribute("content") == "f9ce83647318089c485c3d66378d559f0e7cdeed"
                checks["login_recognized"] = broker.browser.challenge(page, spec) == "login"
                broker.browser.check_staged_native_form(page, spec.login.password_selector,
                                                        spec.login.submit_selector, spec.login_url)
                checks["native_form_destination_reviewed"] = True
                for key, selector in [("username", spec.login.username_selector), ("password", spec.login.password_selector),
                                      ("submit", spec.login.submit_selector)]:
                    checks["one_visible_" + key] = page.locator(selector).count() == 1 and page.locator(selector).is_visible()
                checks["not_signed_in"] = page.locator(spec.ready_selector).count() == 0
                checks["no_post_or_code_request"] = not posts
            except (AccessError, PlaywrightError):
                pass
            finally:
                browser.close()
    return {"service": "pypi", "scope": "anonymous_form_preflight", "checked_at": datetime.now(timezone.utc).isoformat(),
            "warehouse_source_review": "f9ce83647318089c485c3d66378d559f0e7cdeed",
            "private_signins": 0, "credentials_submitted": False, "verification_delivery_tested": False,
            "personal_profile_used": False, "production_ready": False,
            "checks": checks, "passed": all(value is True for value in checks.values())}


def main():
    report = inspect()
    print(json.dumps(report, indent=2))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
