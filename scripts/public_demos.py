"""Opt-in live integration experiment using only intentionally published demo identities.

No personal accounts, signup, purchases, inbox access, or browser profiles are used.
The temporary vault is deleted on exit; reports contain neither passwords nor tokens.
"""

import argparse
import json
import secrets
import shutil
import tempfile
import time
from datetime import datetime, timezone
from importlib.metadata import version
from pathlib import Path
from urllib.parse import urljoin, urlsplit

from playwright.sync_api import Error as PlaywrightError
from playwright.sync_api import sync_playwright

from account_access.broker import Broker
from account_access.browser import Browser
from account_access.public_demo import configuration
from account_access.storage import Store


class MeasuredBrowser(Browser):
    def __init__(self, store, codes):
        super().__init__(store, codes)
        self.login_attempts = {}

    def login(self, browser, account, config, state=None, **kwargs):
        self.login_attempts[account] = self.login_attempts.get(account, 0) + 1
        return super().login(browser, account, config, state, **kwargs)


def connect_public_oauth(broker, account, user):
    """Owner-test harness for the provider's published https://notused redirect.

    The redirect is intercepted in-memory and never contacts that host. This is
    different from the application's ordinary loopback owner setup flow.
    """
    callback = []
    redirect = "https://notused"
    authorization = broker.oauth.begin(account, redirect)
    with sync_playwright() as pw:
        browser = pw.chromium.launch(headless=True, chromium_sandbox=True)
        try:
            context = browser.new_context(java_script_enabled=False, service_workers="block")

            def guard(route):
                request = route.request
                url, method, body = request.url, request.method, request.post_data_buffer
                headers = {k: v for k, v in request.all_headers().items() if k not in {"cookie", "host", "content-length"}}
                for _ in range(6):
                    parts = urlsplit(url)
                    if parts.scheme == "https" and parts.hostname == "notused":
                        callback.append(redirect + "?" + parts.query)
                        route.fulfill(status=200, content_type="text/html", body="<p>Published demo enrollment completed.</p>")
                        return
                    if parts.scheme != "https" or parts.hostname != "demo.duendesoftware.com":
                        route.abort()
                        return
                    response = route.fetch(url=url, method=method, headers=headers,
                                           post_data=body if method == "POST" else "", max_redirects=0, timeout=15000)
                    if response.status in {301, 302, 303, 307, 308} and response.headers.get("location"):
                        url = urljoin(url, response.headers["location"])
                        if response.status == 303 or (response.status in {301, 302} and method == "POST"):
                            method, body = "GET", None
                            headers.pop("content-type", None)
                    else:
                        route.fulfill(response=response)
                        return
                route.abort()

            context.route("**/*", guard)
            page = context.new_page()
            page.goto(authorization, wait_until="domcontentloaded", timeout=30000)
            page.locator("#Input_Username").fill(user)
            page.locator("#Input_Password").fill(user)
            try:
                page.locator("button[value='login']").click(timeout=15000)
            except PlaywrightError:
                if not callback:
                    raise
            deadline = time.monotonic() + 10
            consented = False
            while not callback and time.monotonic() < deadline:
                if not consented and page.locator("button[value='yes']").is_visible():
                    consented = True
                    try:
                        page.locator("button[value='yes']").click(timeout=15000)
                    except PlaywrightError:
                        if not callback:
                            raise
                page.wait_for_timeout(100)
            if len(callback) != 1:
                raise RuntimeError("published_demo_oauth_callback_missing")
            broker.oauth.finish(account, callback[0])
        finally:
            browser.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runs", type=int, default=5)
    parser.add_argument("--output", type=Path, default=Path("artifacts/public-demos.json"))
    args = parser.parse_args()
    if not 1 <= args.runs <= 30:
        parser.error("runs must be between 1 and 30")
    root = Path(tempfile.mkdtemp(prefix="aap-", dir="/tmp"))
    started = time.monotonic()
    report = {"observed_date": datetime.now(timezone.utc).date().isoformat(), "package_version": version("account-access"),
              "environment": "external-public-demo", "private_accounts_tested": 0,
              "repeated_access": [], "negative_cases": [], "session_recovery": [],
              "setup": "Owner harness enrolls intentionally published demo identities; human setup effort not measured",
              "sources": ["https://docs.saucelabs.com/web-apps/automated-testing/selenium/sample-scripts/",
                          "https://the-internet.herokuapp.com/login", "https://demo.duendesoftware.com/",
                          "https://github.com/DuendeSoftware/demo.duendesoftware.com/blob/main/src/Config.cs"],
              "limits": ["Accelerated runs, not a multi-day pilot", "Public demo accounts, no real bank/insurance/Google/Meta accounts",
                         "OAuth enrollment uses an intercepted published demo redirect; ordinary loopback enrollment is tested locally",
                         "Public JavaScript demo login does not establish server-side session security",
                         "No live SMS, Gmail, mobile or genuine biometric approval tested"]}
    try:
        key = secrets.token_bytes(32)
        store = Store(root, key)
        store.configure(configuration())
        store.new_client("public-test")
        for account, spec in store.config().accounts.items():
            Broker(store).grant("public-test", account, list(spec.operations))
        for handle, user in [("sauce-standard", "standard_user"), ("sauce-problem", "problem_user"),
                             ("sauce-locked", "locked_out_user")]:
            store.put("credential:" + handle, {"username": user, "password": "secret_sauce"})
        store.put("credential:internet-valid", {"username": "tomsmith", "password": "SuperSecretPassword!"})
        store.put("credential:internet-rejected", {"username": "tomsmith", "password": "deliberately-invalid-demo-password"})
        login_attempts = {}

        def broker_for_run():
            broker = Broker(Store(root, key))
            browser = MeasuredBrowser(broker.store, broker.codes)
            browser.login_attempts = login_attempts
            broker.browser = browser
            return broker

        for account in ["sauce-standard", "sauce-problem", "internet-valid", "duende-alice", "duende-bob"]:
            broker = broker_for_run()
            operation = next(iter(store.config().accounts[account].operations))
            item = {"account": account, "runs": args.runs, "completed": 0,
                    "human_interventions": 0, "automatic_refreshes": 0, "rotating_refreshes": 0, "outcomes": []}
            try:
                if account.startswith("duende-"):
                    connect_public_oauth(broker, account, account.split("-")[1])
                for _ in range(args.runs):
                    broker = broker_for_run()
                    before = store.get("connection:" + account) or {}
                    if account.startswith("duende-"):
                        before["token"]["expires_at"] = 0  # Accelerated real provider renewal, no token forgery.
                        store.put("connection:" + account, before)
                    result = broker.run("public-test", account, operation)
                    item["outcomes"].append({"status": result["status"], "reason": result.get("reason")})
                    if result["status"] == "COMPLETED":
                        item["completed"] += 1
                        item["last_data"] = result["data"]
                    if account.startswith("duende-") and result["status"] == "COMPLETED":
                        after = store.get("connection:" + account)
                        item["automatic_refreshes"] += after["generation"] != before["generation"]
                        item["rotating_refreshes"] += after["token"]["refresh_token"] != before["token"]["refresh_token"]
                    if result["status"] != "COMPLETED":
                        break
            except Exception as exc:
                item["setup_error_type"] = type(exc).__name__  # Never print provider content/tokens.
            item["automatic_password_attempts"] = login_attempts.get(account, 0)
            item["unique_challenges"] = len(store.pending(account))
            item["unattended_completion_fraction"] = item["completed"] / args.runs
            report["repeated_access"].append(item)
            print(json.dumps({"account": account, "completed": item["completed"], "runs": args.runs,
                              "outcomes": item["outcomes"], "setup_error_type": item.get("setup_error_type")}), flush=True)

        for account in ["sauce-standard", "internet-valid"]:
            broker = broker_for_run()
            state = store.get("connection:" + account)
            if not state:
                continue
            state["state"] = {"cookies": [], "origins": []}
            store.put("connection:" + account, state)
            store.put("login-attempt:" + account, 0)  # Explicit test simulates expiry beyond cooldown.
            before = login_attempts.get(account, 0)
            result = broker.run("public-test", account, next(iter(store.config().accounts[account].operations)))
            report["session_recovery"].append({"account": account, "status": result["status"],
                "automatic_password_attempts": login_attempts.get(account, 0) - before, "reason": result.get("reason")})
        for account in ["sauce-locked", "internet-rejected"]:
            broker = broker_for_run()
            operation = next(iter(store.config().accounts[account].operations))
            first = broker.run("public-test", account, operation)
            second = broker.run("public-test", account, operation)
            report["negative_cases"].append({"case": account, "first_status": first["status"], "second_status": second["status"],
                "shared_challenge": first.get("challenge", {}).get("id") == second.get("challenge", {}).get("id"),
                "automatic_password_attempts": login_attempts.get(account, 0), "reason": first.get("reason")})
        Broker(store).revoke(principal="public-test")
        denied = broker_for_run().run("public-test", "internet-valid", "summary")
        report["negative_cases"].append({"case": "client-revocation", "status": denied["status"], "reason": denied.get("reason")})
    finally:
        shutil.rmtree(root)
    report["elapsed_seconds"] = round(time.monotonic() - started, 3)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2))
    passed = (all(x["completed"] == args.runs for x in report["repeated_access"])
              and len(report["session_recovery"]) == 2
              and all(x["status"] == "COMPLETED" for x in report["session_recovery"])
              and all(x.get("status", x.get("first_status")) in {"NEEDS_USER", "DENIED"} for x in report["negative_cases"]))
    print(json.dumps({"report": str(args.output), "passed": passed}), flush=True)
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
