"""Bounded browser reads and owner-authorized login, using Playwright instead of a raw agent browser."""

import time
from contextlib import ExitStack
from urllib.parse import urljoin, urlsplit

from playwright.sync_api import Error as PlaywrightError
from playwright.sync_api import sync_playwright

from .errors import AccessError
from .browser_network import ResponseGuard
from .models import origin
from .navigation import route_hint


class Browser:
    def __init__(self, store, codes):
        self.store = store
        self.codes = codes

    def context(self, browser, config, state=None, *, login=False, account=None):
        context = browser.new_context(storage_state=state, java_script_enabled=config.javascript,
                                      service_workers="block", accept_downloads=False)
        context._login_code_request = None
        allowed = set(config.login_resources if login else config.read_resources)
        assets = set(config.login_assets) if login else set()
        asset_policy = None
        if login and config.login_asset_discovery == "github":
            from .login_assets import GithubLoginAssets
            asset_policy = GithubLoginAssets([config.login_url, *config.login_resources], assets)
        context._login_asset_policy = asset_policy
        allowed.update(assets)
        if login:
            allowed.add(config.login_url)
        else:
            allowed.update(op.url for op in config.operations.values())

        known_paths = sorted({(origin(url), urlsplit(url).path) for url in {
            config.login_url, *config.login_resources, *config.read_resources,
            *(op.url for op in config.operations.values())}})

        def record_metadata(url, method, reason, resource_type, redirected=False):
            if account is None or (resource_type != "document" and not (
                    login and method == "POST" and origin(url) == origin(config.login_url))):
                return
            # Resource indices distinguish a changed query on an already reviewed
            # path from a wholly new destination. Never log URLs, query values,
            # bodies, response text, cookies or credential-bearing error strings.
            try:
                target = (origin(url), urlsplit(url).path)
                resource = ("configured_path_" + str(known_paths.index(target))
                            if target in known_paths else "unreviewed_destination")
                detail = ":".join(["redirect" if redirected else "request", reason,
                                   resource, "query" if urlsplit(url).query else "no_query"])
                self.store.audit("service", account, "", "browser_navigation_failed", detail)
                self.store.audit("service", account, "", "browser_navigation_route",
                                 route_hint(url, (item[0] for item in known_paths)))
            except Exception:
                pass  # Diagnostics must not change the routing or credential policy.

        def record_failure(request, url, reason, redirected=False):
            record_metadata(url, request.method, reason, request.resource_type, redirected)

        def permitted(url, method, resource_type):
            if url not in allowed:
                return "destination"
            if method not in {"GET", "HEAD"} and not (
                    login and method == "POST" and url in config.login_post_urls):
                return "method"
            if url in assets and resource_type not in {"script", "stylesheet"}:
                return "resource_type"
            return None

        def response_metadata(url, method, status, resource_type, redirect=None):
            pending = context._login_code_request
            if method == "POST" and pending is not None and url == pending["url"]:
                pending["http_status"] = status
                pending["transport"] = resource_type if resource_type in {"document", "xhr", "fetch"} else "other"
                if redirect:
                    pending["redirect"] = route_hint(redirect, [origin(config.login_url)])

        def declared_assets(url, kind, body, headers, main_frame):
            declarations = asset_policy.document(url, kind, body, headers, main_frame)
            asset_policy.prefetch(declarations)
            assets.update(asset_policy.urls)
            allowed.update(asset_policy.urls)

        native = ResponseGuard(context, permitted, record_metadata, response_metadata,
                               declared_assets if asset_policy else None)
        context._response_guard = native

        def guard(route):
            request = route.request
            url, method = request.url, request.method
            reason = permitted(url, method, request.resource_type)
            if reason:
                record_failure(request, url, reason)
                route.abort("blockedbyclient")
                return
            if asset_policy and url in assets:
                try:
                    body, public_headers = asset_policy.fetch(url)
                    assets.update(asset_policy.urls)
                    allowed.update(asset_policy.urls)
                    route.fulfill(status=200, headers=public_headers,
                                  body=body if method != "HEAD" else b"")
                except AccessError:
                    route.abort("blockedbyclient")
                return
            if native.native(request):
                # The attached response guard checks every redirect before
                # Chromium follows it. Preserve real URLs, cookies, TLS and
                # browser-generated headers throughout the login transaction.
                route.continue_()
                return
            headers = {k: v for k, v in request.all_headers().items() if k not in {"cookie", "host", "content-length"}}
            body = request.post_data_buffer
            # Child frames and workers have no attached native response guard.
            # Fetch each hop separately rather than permitting an unchecked
            # native redirect in a different Chromium target.
            try:
                for hop in range(6):
                    reason = permitted(url, method, request.resource_type)
                    if reason:
                        record_failure(request, url, reason, hop > 0)
                        route.abort("blockedbyclient")
                        return
                    response = route.fetch(url=url, method=method, headers=headers,
                                           post_data=body if method == "POST" else "",
                                           max_redirects=0, max_retries=0, timeout=15000)
                    if hop == 0:
                        # Only fixed HTTP metadata, never response content or
                        # hidden page banners, establishes that a request ran.
                        location = response.headers.get("location")
                        response_metadata(url, method, response.status, request.resource_type,
                                          urljoin(url, location) if location else None)
                    if response.status >= 400:
                        record_failure(request, url, "http_" + str(response.status), hop > 0)
                    if response.status in {301, 302, 303, 307, 308}:
                        location = response.headers.get("location")
                        if not location:
                            record_failure(request, url, "missing_location", hop > 0)
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
                            record_failure(request, url, "response_size", hop > 0)
                            route.abort("blockedbyclient")
                        else:
                            route.fulfill(response=response)
                        return
                record_failure(request, url, "redirect_limit", True)
                route.abort("blockedbyclient")
            except PlaywrightError:
                record_failure(request, url, "transport")
                route.abort("failed")
        context.route("**/*", guard)
        context.route_web_socket("**/*", lambda ws: ws.close())
        return context

    def page(self, context):
        page = context.new_page()
        # Await attachment before initiating any network request. Attaching
        # during a route callback is too late for that request's response;
        # context page events are also not a synchronous attachment barrier.
        context._response_guard.attach(page)
        if page.is_closed():
            raise AccessError("RETRYABLE", "browser_guard_unavailable")
        return page

    def challenge(self, page, config):
        # Action/presence challenges take priority, even if the page also has a ready marker.
        for kind in ["action", "passkey", "device", "admin", "sms", "email", "totp",
                     "sms_request", "email_request", "method", "unknown", "login"]:
            if (kind == "method" and config.login and config.login.choice_toggle_selector
                    and page.locator(config.login.choice_toggle_selector).first.is_visible()
                    and any(page.locator(choice.selector).count() for choice in config.login.choices)):
                return kind
            if kind.endswith("_request") and config.login:
                delivery = next((item for item in config.login.code_requests if item.kind + "_request" == kind), None)
                if delivery and page.url == delivery.url and page.locator(delivery.selector).first.is_visible():
                    return kind
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

    def wait_state(self, page, config, *, after_submit=False, previous_kind=None):
        """Wait for configured markers, including asynchronously rendered login responses."""
        deadline = time.monotonic() + config.state_timeout_ms / 1000
        while True:
            kind = self.challenge(page, config)
            prior = previous_kind or ("login" if after_submit else None)
            if kind and kind != prior:
                return
            if page.locator(config.ready_selector).first.is_visible():
                return
            if time.monotonic() >= deadline:
                return
            page.wait_for_timeout(50)

    def read(self, account, op, config, *, secret_values=None, visible=False,
             setup_method=None, review_stop=None, on_code_request=None, on_attention=None):
        # Owner troubleshooting must describe this check, not an earlier routing
        # problem after the account has reached a different verification step.
        self.store.audit("service", account, "", "browser_check_started")
        connection = self.store.get("connection:" + account)
        if connection and connection.get("revoked"):
            raise AccessError("DENIED", "connection_revoked")
        if connection and connection["fingerprint"] != self.store.config().fingerprint(account):
            raise AccessError("DENIED", "connection_configuration_changed")
        state = connection.get("state") if connection else None
        try:
            with sync_playwright() as pw:
                browser = pw.chromium.launch(headless=not visible, chromium_sandbox=True,
                                             channel=config.browser_channel)
                reviewed = False

                def review_failure(page, error):
                    nonlocal reviewed
                    if reviewed:
                        return
                    reviewed = True
                    if on_attention:
                        details = {}
                        if origin(config.login_url) == "https://github.com":
                            from .sms_setup import diagnostics
                            details = diagnostics(page)
                            details["page"] = route_hint(page.url, ["https://github.com"])
                            details["progress"] = dict(getattr(page.context, "_login_progress", {}))
                        on_attention(error.status, error.reason, error.kind, details)
                    if not visible:
                        return
                    # Owner-only troubleshooting: keep the actual failed page
                    # visible briefly, without exporting its HTML or secrets.
                    try:
                        deadline = time.monotonic() + 300
                        while not page.is_closed() and time.monotonic() < deadline:
                            if review_stop and review_stop.is_set():
                                break
                            page.wait_for_timeout(100)
                    except PlaywrightError:
                        pass
                try:
                    context = self.context(browser, config, state, account=account)
                    page = self.page(context)
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
                        state = self.login(browser, account, config, state, secret_values=secret_values,
                                           review_failure=review_failure, setup_method=setup_method,
                                           on_code_request=on_code_request, review_stop=review_stop)
                        context = self.context(browser, config, state, account=account)
                        page = self.page(context)
                        page.goto(op.url, timeout=15000, wait_until="domcontentloaded")
                        self.wait_state(page, config)
                        self.check(page, config)
                    data = {name: page.locator(selector).first.inner_text(timeout=5000)[:100_000]
                            for name, selector in op.fields.items()}
                    self.save(account, context.storage_state(indexed_db=True))
                    return data
                except AccessError as exc:
                    review_failure(page, exc)
                    raise
                finally:
                    browser.close()
        except PlaywrightError:
            raise AccessError("RETRYABLE", "browser_execution_failed") from None

    def login(self, browser, account, config, state=None, *, secret_values=None, review_failure=None,
              setup_method=None, on_code_request=None, review_stop=None):
        # Lock in a stable order: accounts with several verification methods must
        # not compete for a shared inbox/SMS delivery, or deadlock each other.
        with ExitStack() as held:
            for source in sorted(config.login.sources()):
                held.enter_context(self.store.lock("code-login:" + source, timeout=0))
            return self._login(browser, account, config, state, secret_values=secret_values,
                               review_failure=review_failure, setup_method=setup_method,
                               on_code_request=on_code_request, review_stop=review_stop)

    def _login(self, browser, account, config, state=None, *, secret_values=None, review_failure=None,
               setup_method=None, on_code_request=None, review_stop=None):
        if review_stop and review_stop.is_set():
            raise AccessError("NEEDS_USER", "sms_setup_cancelled", "sms")
        from .password_sync import refresh
        refresh(self.store, account, force=True)
        credential = self.store.get("credential:" + account, {})
        credential = credential or {}
        if secret_values is not None:
            secret_values.add(credential.get("password", ""))
        if not credential.get("password") or not credential.get("username"):
            raise AccessError("NEEDS_USER", "password_not_connected")
        last = self.store.get("login-attempt:" + account, 0)
        if time.time() - last < 60:
            # A timed throttle needs waiting, not owner authentication. Keep the
            # rate limit while letting durable tasks retry without a false prompt.
            raise AccessError("RETRYABLE", "login_retry_cooldown")
        self.store.put("login-attempt:" + account, time.time())
        context = self.context(browser, config, state, login=True, account=account)
        context._login_progress = {}
        started = None
        completed = []
        source_errors = {}
        try:
            page = self.page(context)
            page.goto(config.login_url, timeout=15000, wait_until="domcontentloaded")
            self.wait_state(page, config)
            kind = self.challenge(page, config)
            if kind and kind not in {"login"}:
                raise AccessError("NEEDS_USER", "browser_" + kind + "_required", kind)
            if page.url != config.login_url:
                raise AccessError("NEEDS_USER", "login_destination_changed", "unknown")
            form = config.login
            self.check_form(page, form.password_selector, config)
            if review_stop and review_stop.is_set():
                raise AccessError("NEEDS_USER", "sms_setup_cancelled", "sms")
            page.locator(form.username_selector).fill(credential["username"])
            page.locator(form.password_selector).fill(credential["password"])
            started = time.time()
            for source_id in sorted(form.sources()):
                try:
                    # Establish freshness before the password can trigger code
                    # delivery. An unused alternative being offline must not
                    # prevent a different, enrolled method from completing.
                    self.codes.begin(source_id, account, started)
                except AccessError as exc:
                    if not form.factors:
                        raise
                    source_errors[source_id] = exc
            if not setup_method and form.sources() and form.sources() <= source_errors.keys():
                google_error = next((source_errors[source_id] for source_id in form.sources()
                                     if self.store.config().code_sources[source_id].kind == "google_messages"), None)
                if google_error:
                    # Do not submit a password when the paired SMS tab is
                    # offline and no other enrolled method is usable.
                    raise google_error
            if review_stop and review_stop.is_set():
                raise AccessError("NEEDS_USER", "sms_setup_cancelled", "sms")
            page.locator(form.submit_selector).click(timeout=10000)
            context._login_progress["password_submit_attempted"] = True
            page.wait_for_load_state("domcontentloaded")
            self.wait_state(page, config, after_submit=True)
            kind = self.challenge(page, config)
            used_by_source = {}
            choices_used = set()
            requested = set()
            while kind in {"sms", "email", "totp", "method", "sms_request", "email_request"}:
                if kind.endswith("_request"):
                    method = kind.removesuffix("_request")
                    if method in requested or method in completed:
                        raise AccessError("NEEDS_USER", "verification_code_request_repeated", method)
                    factor = form.factor(method)
                    if not factor and setup_method != method:
                        raise AccessError("NEEDS_USER", "verification_source_not_connected", method)
                    if factor and factor.code_source in source_errors:
                        raise source_errors[factor.code_source]
                    source = self.store.config().code_sources[factor.code_source] if factor else None
                    enrolled = self.store.get("source:" + factor.code_source) or {} if factor else {}
                    if factor and (source.kind not in {"sms": {"twilio", "mac_messages", "phone_relay", "google_messages"},
                                           "email": {"imap", "gmail"}}[method]
                            or not enrolled or enrolled.get("enabled") is False):
                        raise AccessError("NEEDS_USER", "verification_source_not_connected", method)
                    delivery = next(item for item in form.code_requests if item.kind == method)
                    self.check_form(page, delivery.selector, config)
                    if review_stop and review_stop.is_set():
                        raise AccessError("NEEDS_USER", "sms_setup_cancelled", method)
                    requested.add(method)
                    requested_at = time.time()
                    confirmation = {"url": delivery.url, "http_status": None}
                    context._login_code_request = confirmation
                    dispatch = page.locator(delivery.selector).first.evaluate("""el => ({
                        ajax: !!el.form?.classList.contains('js-send-auth-code'),
                        auto: !!el.form?.hasAttribute('data-autosubmit'),
                        button: (() => {
                            const text = (el.innerText || el.value || '').toLowerCase();
                            return ['recovery', 'cancel', 'send', 'confirm', 'continue'].find(word => text.includes(word)) || 'other';
                        })(),
                        fields: Array.from(el.form?.elements || []).slice(0, 32).map(field => ({
                            type: ['hidden', 'text', 'tel', 'number', 'checkbox', 'radio', 'select-one', 'submit', 'button'].includes(field.type) ? field.type : 'other',
                            required: !!field.required, checked: !!field.checked, invalid: field.matches(':invalid')
                        }))
                    })""")
                    details = {"page": route_hint(page.url, [origin(config.login_url)]), **dispatch}
                    context._login_progress["code_request"] = details
                    page.locator(delivery.selector).first.click(timeout=10000)
                    page.wait_for_load_state("domcontentloaded")
                    context._login_code_request = None
                    http_status = confirmation["http_status"]
                    details.update({key: confirmation[key] for key in ["http_status", "transport", "redirect"]
                                    if key in confirmation})
                    if http_status is None:
                        raise AccessError("NEEDS_USER", "verification_code_request_not_submitted", method)
                    self.store.audit("service", account, "", "login_code_request_result",
                                     method + ":http_" + str(http_status))
                    if not 200 <= http_status < 400:
                        raise AccessError("NEEDS_USER", "verification_code_request_rejected", method)
                    context._login_progress[method + "_requested"] = True
                    self.wait_state(page, config, previous_kind=kind)
                    if on_code_request:
                        details = {}
                        if setup_method == "sms" and origin(config.login_url) == "https://github.com":
                            from .sms_setup import diagnostics
                            details = diagnostics(page)
                        on_code_request(method, requested_at, http_status, details)
                    kind = self.challenge(page, config)
                    if kind not in {method, None, "action", "passkey", "device", "admin", method + "_request"}:
                        raise AccessError("NEEDS_USER", "verification_method_changed", "unknown")
                    continue
                if kind == "method":
                    selected = self.choose_method(page, config, source_errors, set(completed) | choices_used,
                                                  setup_method=setup_method)
                    context._login_progress["method"] = selected
                    choices_used.add(selected)
                    kind = self.challenge(page, config)
                    if kind not in {selected, selected + "_request", None, "action", "passkey", "device", "admin"}:
                        raise AccessError("NEEDS_USER", "verification_method_changed", "unknown")
                    continue
                if kind in completed:
                    raise AccessError("NEEDS_USER", "verification_code_rejected", kind)
                factor = form.factor(kind)
                if not factor:
                    raise AccessError("NEEDS_USER", "browser_" + kind + "_required", kind)
                source_id = factor.code_source
                if source_id in source_errors:
                    raise source_errors[source_id]
                source = self.store.config().code_sources[source_id]
                if source.kind not in {"sms": {"twilio", "mac_messages", "phone_relay", "google_messages"},
                                       "email": {"gmail", "imap"}, "totp": {"totp"}}[kind]:
                    raise AccessError("NEEDS_USER", "factor_type_changed", kind)
                used = used_by_source.setdefault(source_id, set())
                code = None
                deadline = time.monotonic() + min(form.code_wait_ms / 1000, max(0, started + 120 - time.time()))
                while not code and time.monotonic() < deadline:
                    code = self.codes.resolve(source_id, started, used)
                    if not code:
                        time.sleep(1)
                if not code:
                    raise AccessError("NEEDS_USER", "login_code_not_received", kind)
                if secret_values is not None:
                    secret_values.add(code)
                # The page can change while an email/SMS delivery is pending.
                # Recheck presence/action markers before putting a code into it.
                if self.challenge(page, config) != kind:
                    raise AccessError("NEEDS_USER", "verification_page_changed", "unknown")
                self.check_form(page, factor.code_selector, config)
                # Delivery can block while the owner revokes a source or the
                # login window expires. Do not submit its late response.
                self.codes.check_window(source_id, started)
                if review_stop and review_stop.is_set():
                    raise AccessError("NEEDS_USER", "sms_setup_cancelled", kind)
                # In-memory only, one submission, never put in logs or task state.
                page.locator(factor.code_selector).fill(code)
                context._login_progress[kind + "_code_filled"] = True
                context._login_progress[kind + "_submit_attempted"] = True
                page.locator(factor.code_submit_selector).click(timeout=10000)
                page.wait_for_load_state("domcontentloaded")
                self.wait_state(page, config, previous_kind=kind)
                completed.append(kind)
                kind = self.challenge(page, config)
            self.check(page, config)
            state = context.storage_state(indexed_db=True)
            self.save(account, state)
            self.store.resolve_login(account)
            self.store.audit("service", account, "", "login_recovered")
            for factor in completed:
                self.store.audit("service", account, "", "login_factor_completed", factor)
            return state
        except AccessError as exc:
            if review_failure:
                review_failure(page, exc)
            raise
        finally:
            if started:
                for source_id in config.login.sources():
                    self.codes.finish(source_id, started)
            context.close()

    def choose_method(self, page, config, source_errors, excluded, *, setup_method=None):
        """Select only an offered, reviewed GET link to an enrolled login factor.

        A connector marks an optional method picker explicitly. Presence and
        transaction markers take priority over it in challenge(); mandatory
        passkey/device/admin pages never enter this method.
        """
        toggle = config.login.choice_toggle_selector
        if toggle and not any(page.locator(choice.selector).first.is_visible() for choice in config.login.choices):
            if (page.url not in {config.login_url, *config.login_resources}
                    or self.challenge(page, config) != "method"):
                raise AccessError("NEEDS_USER", "verification_method_changed", "unknown")
            button = page.locator(toggle).first
            safe = button.evaluate("el => el.tagName === 'BUTTON' && (!el.form || el.type === 'button')")
            if not safe:
                raise AccessError("NEEDS_USER", "verification_method_destination_changed", "unknown")
            button.click(timeout=10000)
            deadline = time.monotonic() + config.state_timeout_ms / 1000
            while (time.monotonic() < deadline
                   and not any(page.locator(choice.selector).first.is_visible() for choice in config.login.choices)):
                page.wait_for_timeout(50)
        setup = None
        for choice in config.login.choices:
            if setup_method and choice.kind != setup_method:
                continue
            if choice.kind in excluded or not page.locator(choice.selector).first.is_visible():
                continue
            factor = config.login.factor(choice.kind)
            if not factor and setup_method != choice.kind:
                setup = setup or AccessError("NEEDS_USER", "verification_source_not_connected", choice.kind)
                continue
            source = self.store.config().code_sources[factor.code_source] if factor else None
            enrolled = self.store.get("source:" + factor.code_source) or {} if factor else {}
            unavailable = source_errors.get(factor.code_source) if factor else None
            if unavailable:
                setup = setup or unavailable
                continue
            if factor and (not enrolled or enrolled.get("enabled") is False or (source.kind == "totp" and not enrolled.get("seed"))):
                setup = setup or AccessError("NEEDS_USER", "authenticator_not_enrolled" if source.kind == "totp"
                                            else "verification_source_not_connected", choice.kind)
                continue
            if page.url not in {config.login_url, *config.login_resources}:
                raise AccessError("NEEDS_USER", "login_destination_changed", "unknown")
            actual = page.locator(choice.selector).first.evaluate("el => el.tagName === 'A' ? el.href : null")
            if actual != choice.url or self.challenge(page, config) != "method":
                raise AccessError("NEEDS_USER", "verification_method_destination_changed", "unknown")
            page.locator(choice.selector).first.click(timeout=10000)
            page.wait_for_load_state("domcontentloaded")
            self.wait_state(page, config, previous_kind="method")
            return choice.kind
        if setup:
            raise setup
        raise AccessError("NEEDS_USER", "verification_method_unavailable", "method")

    def check_form(self, page, selector, config):
        if page.url not in {config.login_url, *config.login_resources}:
            raise AccessError("NEEDS_USER", "login_destination_changed", "unknown")
        destination = page.locator(selector).evaluate("""el => {
            const form = el.form;
            return form ? {method: form.method.toUpperCase(), action: form.action} : null;
        }""")
        # JavaScript connectors can submit without a native form; their exact
        # request allowlist is still enforced. Native forms must never encode a
        # password/code in a GET URL, history entry or Referer header.
        if destination is None and config.javascript:
            return
        if config.javascript and not config.login_post_urls:
            # Reviewed client-side applications can preventDefault on a form
            # whose HTML method is GET. No POST or credential-bearing query is
            # allowed by the network guard in this connector mode.
            return
        if (not destination or destination["method"] != "POST"
                or destination["action"] not in config.login_post_urls):
            raise AccessError("NEEDS_USER", "login_form_destination_changed", "unknown")

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
                browser = pw.chromium.launch(headless=headless, chromium_sandbox=True,
                                             channel=config.browser_channel)
                try:
                    context = self.context(browser, config, existing.get("state"), login=True, account=account)
                    page = self.page(context)
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
