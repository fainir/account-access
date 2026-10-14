"""Bounded browser reads and owner-authorized login, using Playwright instead of a raw agent browser."""

import time
from urllib.parse import urljoin, urlsplit

from playwright.sync_api import Error as PlaywrightError
from playwright.sync_api import sync_playwright

from .errors import AccessError
from .models import origin


class Browser:
    def __init__(self, store, codes):
        self.store = store
        self.codes = codes

    def context(self, browser, config, state=None, *, login=False):
        context = browser.new_context(storage_state=state, java_script_enabled=config.javascript,
                                      service_workers="block", accept_downloads=False)
        allowed = set(config.login_resources if login else config.read_resources)
        if login:
            allowed.add(config.login_url)
        else:
            allowed.update(op.url for op in config.operations.values())

        def guard(route):
            request = route.request
            url, method = request.url, request.method
            headers = {k: v for k, v in request.all_headers().items() if k not in {"cookie", "host", "content-length"}}
            body = request.post_data_buffer
            # Playwright's route handler runs only for the first request in a redirect
            # chain. Fetch each hop ourselves so 307/308 cannot forward passwords
            # to a destination that was never checked. Fulfill the final response
            # at the requested URL; adapters must accommodate that document base.
            try:
                for _ in range(6):
                    allowed_method = method in {"GET", "HEAD"} or (
                        login and method == "POST" and url in config.login_post_urls)
                    if url not in allowed or not allowed_method:
                        route.abort("blockedbyclient")
                        return
                    response = route.fetch(url=url, method=method, headers=headers,
                                           post_data=body if method == "POST" else "",
                                           max_redirects=0, max_retries=0, timeout=15000)
                    if response.status in {301, 302, 303, 307, 308}:
                        location = response.headers.get("location")
                        if not location:
                            route.abort("blockedbyclient")
                            return
                        target = urljoin(url, location)
                        if origin(target) != origin(url):
                            headers = {k: v for k, v in headers.items() if k not in {"authorization", "origin"}}
                        if response.status == 303 or (response.status in {301, 302} and method == "POST"):
                            method, body = "GET", None
                            headers.pop("content-type", None)
                        url = target
                    else:
                        if len(response.body()) > 8_000_000:
                            route.abort("blockedbyclient")
                        else:
                            route.fulfill(response=response)
                        return
                route.abort("blockedbyclient")
            except PlaywrightError:
                route.abort("failed")
        context.route("**/*", guard)
        context.route_web_socket("**/*", lambda ws: ws.close())
        return context

    def challenge(self, page, config):
        # Action/presence challenges take priority, even if the page also has a ready marker.
        for kind in ["action", "passkey", "device", "admin", "sms", "email", "totp", "unknown", "login"]:
            selector = config.challenge_selectors.get(kind)
            if selector and page.locator(selector).first.is_visible():
                return kind
        return None

    def check(self, page, config):
        kind = self.challenge(page, config)
        if kind:
            raise AccessError("NEEDS_USER", "browser_" + kind + "_required", kind)
        if not page.locator(config.ready_selector).first.is_visible():
            raise AccessError("NEEDS_USER", "browser_state_unrecognized", "unknown")

    def wait_state(self, page, config, *, after_submit=False):
        """Wait for configured markers, including asynchronously rendered login responses."""
        deadline = time.monotonic() + config.state_timeout_ms / 1000
        while True:
            kind = self.challenge(page, config)
            if kind and (not after_submit or kind != "login"):
                return
            if page.locator(config.ready_selector).first.is_visible():
                return
            if time.monotonic() >= deadline:
                return
            page.wait_for_timeout(50)

    def read(self, account, op, config, *, secret_values=None):
        connection = self.store.get("connection:" + account)
        if connection and connection.get("revoked"):
            raise AccessError("DENIED", "connection_revoked")
        if connection and connection["fingerprint"] != self.store.config().fingerprint(account):
            raise AccessError("DENIED", "connection_configuration_changed")
        state = connection.get("state") if connection else None
        try:
            with sync_playwright() as pw:
                browser = pw.chromium.launch(headless=True, chromium_sandbox=True)
                try:
                    context = self.context(browser, config, state)
                    page = context.new_page()
                    page.goto(op.url, timeout=15000, wait_until="domcontentloaded")
                    self.wait_state(page, config)
                    try:
                        self.check(page, config)
                    except AccessError as exc:
                        if exc.kind not in {"login", "unknown"} or not config.login:
                            raise
                        # Only explicit login markers trigger automatic credential filling.
                        if self.challenge(page, config) != "login":
                            raise
                        context.close()
                        state = self.login(browser, account, config, state, secret_values=secret_values)
                        context = self.context(browser, config, state)
                        page = context.new_page()
                        page.goto(op.url, timeout=15000, wait_until="domcontentloaded")
                        self.wait_state(page, config)
                        self.check(page, config)
                    data = {name: page.locator(selector).first.inner_text(timeout=5000)[:100_000]
                            for name, selector in op.fields.items()}
                    self.save(account, context.storage_state(indexed_db=True))
                    return data
                finally:
                    browser.close()
        except PlaywrightError:
            raise AccessError("RETRYABLE", "browser_execution_failed") from None

    def login(self, browser, account, config, state=None, *, secret_values=None):
        source = config.login.code_source
        if source:
            # Two simultaneous logins must never compete for the same inbox code.
            with self.store.lock("code-login:" + source, timeout=0):
                return self._login(browser, account, config, state, secret_values=secret_values)
        return self._login(browser, account, config, state, secret_values=secret_values)

    def _login(self, browser, account, config, state=None, *, secret_values=None):
        credential = self.store.get("credential:" + account, {})
        if not credential.get("password") or not credential.get("username"):
            raise AccessError("NEEDS_USER", "password_not_connected")
        last = self.store.get("login-attempt:" + account, 0)
        if time.time() - last < 60:
            # A timed throttle needs waiting, not owner authentication. Keep the
            # rate limit while letting durable tasks retry without a false prompt.
            raise AccessError("RETRYABLE", "login_retry_cooldown")
        self.store.put("login-attempt:" + account, time.time())
        context = self.context(browser, config, state, login=True)
        started = None
        factor = None
        try:
            page = context.new_page()
            page.goto(config.login_url, timeout=15000, wait_until="domcontentloaded")
            self.wait_state(page, config)
            kind = self.challenge(page, config)
            if kind and kind not in {"login"}:
                raise AccessError("NEEDS_USER", "browser_" + kind + "_required", kind)
            if page.url != config.login_url:
                raise AccessError("NEEDS_USER", "login_destination_changed", "unknown")
            form = config.login
            page.locator(form.username_selector).fill(credential["username"])
            page.locator(form.password_selector).fill(credential["password"])
            started = time.time()
            if form.code_source:
                self.codes.begin(form.code_source, account, started)
            page.locator(form.submit_selector).click(timeout=10000)
            page.wait_for_load_state("domcontentloaded")
            self.wait_state(page, config, after_submit=True)
            kind = self.challenge(page, config)
            if kind in {"action", "passkey", "device", "admin", "unknown"}:
                raise AccessError("NEEDS_USER", "browser_" + kind + "_required", kind)
            if kind in {"sms", "email", "totp"} and form.code_source and form.code_selector and form.code_submit_selector:
                source = self.store.config().code_sources[form.code_source]
                factor = kind
                if source.kind not in {"sms": {"twilio", "mac_messages", "phone_relay"},
                                       "email": {"gmail", "imap"}, "totp": {"totp"}}[kind]:
                    raise AccessError("NEEDS_USER", "factor_type_changed", kind)
                used = set()
                code = None
                deadline = time.monotonic() + 15
                while not code and time.monotonic() < deadline:
                    code = self.codes.resolve(form.code_source, started, used)
                    if not code:
                        time.sleep(1)
                if not code:
                    raise AccessError("NEEDS_USER", "login_code_not_received", kind)
                if secret_values is not None:
                    secret_values.add(code)
                # In-memory only, one submission, never put in logs or task state.
                page.locator(form.code_selector).fill(code)
                page.locator(form.code_submit_selector).click(timeout=10000)
                page.wait_for_load_state("domcontentloaded")
                self.wait_state(page, config, after_submit=True)
            self.check(page, config)
            state = context.storage_state(indexed_db=True)
            self.save(account, state)
            self.store.resolve_login(account)
            self.store.audit("service", account, "", "login_recovered")
            if factor:
                self.store.audit("service", account, "", "login_factor_completed", factor)
            return state
        finally:
            if started and config.login.code_source:
                self.codes.finish(config.login.code_source, started)
            context.close()

    def save(self, account, state):
        config = self.store.config()
        self.store.put("connection:" + account, {"state": state,
                       "fingerprint": config.fingerprint(account), "generation": str(time.time_ns())})

    def connect(self, account, *, headless=False, complete=None):
        """Owner interactive connection. Login resources remain allowlisted; no screenshots/logs."""
        config = self.store.config().accounts[account]
        with self.store.lock("account:" + account, timeout=5):
            existing = self.store.get("connection:" + account) or {}
            with sync_playwright() as pw:
                browser = pw.chromium.launch(headless=headless, chromium_sandbox=True)
                try:
                    context = self.context(browser, config, existing.get("state"), login=True)
                    page = context.new_page()
                    page.goto(config.login_url, timeout=15000, wait_until="domcontentloaded")
                    if complete:
                        complete(page)
                    else:
                        input("Complete sign-in in the browser, then press Enter here: ")
                    self.check(page, config)
                    self.save(account, context.storage_state(indexed_db=True))
                    self.store.resolve_login(account)
                finally:
                    browser.close()

    def import_state(self, account, state):
        """Owner-only session adoption; filter every cookie and origin to configured service origins."""
        config = self.store.config().accounts[account]
        origins = {origin(config.login_url), *(origin(op.url) for op in config.operations.values())}
        hosts = {urlsplit(url).hostname for url in origins}
        filtered = {"cookies": [], "origins": []}
        for cookie in state.get("cookies", []):
            domain = cookie.get("domain", "").lstrip(".")
            if domain in hosts:
                filtered["cookies"].append(cookie)
        for item in state.get("origins", []):
            if item.get("origin") in origins:
                filtered["origins"].append(item)
        self.save(account, filtered)
        self.store.resolve_login(account)
