"""Bounded browser reads and owner-authorized login, using Playwright instead of a raw agent browser."""

import time
from contextlib import ExitStack, contextmanager, nullcontext
import threading
from urllib.parse import urljoin, urlsplit

from playwright.sync_api import Error as PlaywrightError
from playwright.sync_api import sync_playwright

from .errors import AccessError
from .browser_network import ResponseGuard
from .models import origin
from .navigation import route_hint


def native_form_target(action):
    """Compare the resolved native action as HTTP sends it, preserving every
    scheme, authority, path and query byte. A fragment is never sent to a server.
    Configuration and network allowlists continue to reject fragments.
    """
    if not isinstance(action, str):
        return None
    try:
        if urlsplit(action).scheme not in {"http", "https"}:
            return None
    except ValueError:
        return None
    return action.partition("#")[0]


class _PasswordAuthority:
    """An operation's exact source enrollment, not whichever link is current later.

    Only short local disclosure/dispatch/publication commands hold the source
    lock. Playwright can invoke a route callback inside a fill command, so a
    nested callback on that same thread reuses the already-held authority.
    """

    def __init__(self, store, account):
        self.store, self.account = store, account
        link = store.get("password-link:" + account) if account is not None else None
        self.link = dict(link) if isinstance(link, dict) and link.get("provider") == "bitwarden" else None
        self.error = None
        self.local = threading.local()

    @contextmanager
    def authorize(self):
        if self.error:
            raise self.error
        if self.link is None or getattr(self.local, "depth", 0):
            yield
            return
        from .bitwarden_source import authority
        try:
            with authority(self.store, self.link):
                current = self.store.get("password-link:" + self.account)
                keys = ("provider", "generation", "connection", "connection_generation", "item", "username", "fingerprint")
                if (not isinstance(current, dict)
                        or any(current.get(key) != self.link.get(key) for key in keys)):
                    raise AccessError("NEEDS_USER", "bitwarden_connection_changed")
                self.local.depth = 1
                try:
                    yield
                finally:
                    self.local.depth = 0
        except AccessError as error:
            self.error = AccessError("RETRYABLE" if error.status == "RETRYABLE" else "NEEDS_USER", error.reason)
            raise self.error from None
        finally:
            self.drain()

    def check(self):
        with self.authorize():
            pass
        if self.error:
            raise self.error

    def defer(self, callback):
        # A synchronous Playwright command can pump unrelated network events.
        # Pause those events until its short source section has fully exited;
        # response-body/public-asset fetching must not inherit the outer lock.
        if self.link is None or not getattr(self.local, "depth", 0):
            return False
        if not hasattr(self.local, "pending"):
            self.local.pending = []
        if len(self.local.pending) >= 256:
            self.error = AccessError("RETRYABLE", "browser_execution_failed")
            return True
        self.local.pending.append(callback)
        return True

    def drain(self):
        if getattr(self.local, "depth", 0) or getattr(self.local, "draining", False):
            return
        self.local.draining = True
        try:
            pending = getattr(self.local, "pending", [])
            while pending:
                callback = pending.pop(0)
                try:
                    callback()
                except PlaywrightError:
                    pass  # A closed target cannot dispatch the paused request.
        finally:
            self.local.draining = False


class Browser:
    def __init__(self, store, codes):
        self.store = store
        self.codes = codes

    def context(self, browser, config, state=None, *, login=False, account=None, secret_values=None,
                authorization=None):
        authorization = authorization or _PasswordAuthority(self.store, account)
        authorization.check()
        context = browser.new_context(storage_state=state, java_script_enabled=config.javascript,
                                      service_workers="block", accept_downloads=False)
        context._password_authority = authorization
        context._login_code_request = None
        identity = (config.login.identity_step or config.login.identity_contact) if login and config.login else None
        context._identity_pending = identity is not None
        context._identity_armed = False
        context._identity_dispatched = False
        context._identity_blocked = False
        context._identity_redirect_replay = False
        context._login_identity_request = None
        context._login_step_post_url = identity.post_url if identity else None
        context._password_blocked = False
        policy = None
        if login and config.login_challenge:
            from .pypi_challenge import PyPIChallenge
            policy = PyPIChallenge(config, test_mode=self.store.config().test_mode, secret_values=secret_values)
        context._login_challenge = policy
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
            if policy and (method == "POST" or resource_type == "document"):
                policy.block()
            if (context._identity_pending and (method == "POST" or resource_type == "document")
                    and reason in {"destination", "method", "resource_type", "redirect_limit", "missing_location", "response_size"}):
                context._identity_blocked = True
            if (not context._identity_pending and context._login_step_post_url is not None
                    and (method == "POST" or resource_type == "document")
                    and reason in {"destination", "method", "resource_type", "redirect_limit", "missing_location", "response_size"}):
                context._password_blocked = True
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

        def permitted(url, method, resource_type, **provenance):
            if policy and (method == "POST" or policy.manages(url)):
                return None if policy.permitted(url, method, resource_type, **provenance) else "method" if method == "POST" else "destination"
            if url not in allowed:
                return "destination"
            if method not in {"GET", "HEAD"} and not (
                    login and method == "POST" and url in config.login_post_urls):
                return "method"
            if method == "POST" and context._identity_pending and (
                    not context._identity_armed or url != identity.post_url or context._identity_redirect_replay):
                return "method"
            if method == "POST" and context._login_step_post_url is not None and url != context._login_step_post_url:
                return "method"
            if url in assets and resource_type not in {"script", "stylesheet"}:
                return "resource_type"
            return None

        def response_metadata(url, method, status, resource_type, redirect=None):
            identity_request = context._login_identity_request
            if method == "POST" and identity_request is not None and url == identity_request["url"]:
                identity_request["http_status"] = status
                if status in {307, 308}:
                    context._identity_redirect_replay = True
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
                               declared_assets if asset_policy else None, policy,
                               authorize=authorization.authorize, defer=authorization.defer)
        context._response_guard = native

        def guard(route):
            if authorization.defer(lambda: guard(route)):
                return
            try:
                dispatch(route)
            except AccessError:
                # Preserve the fixed source error on the operation, rather
                # than letting a callback exception escape as an internal error.
                try:
                    route.abort("blockedbyclient")
                except PlaywrightError:
                    pass  # Closing a revoked context already stops dispatch.

        def dispatch(route):
            authorization.check()
            request = route.request
            url, method = request.url, request.method
            provenance = native.provenance(request) if policy else {}
            reason = permitted(url, method, request.resource_type, **provenance)
            if reason:
                record_failure(request, url, reason)
                route.abort("blockedbyclient")
                return
            if policy:
                try:
                    policy.dispatch(url, method, provenance["attachment"], provenance["main_document"])
                except AccessError:
                    record_failure(request, url, "method")
                    route.abort("blockedbyclient")
                    return
            if method == "POST" and context._identity_pending:
                if context._identity_dispatched:
                    record_failure(request, url, "method")
                    route.abort("blockedbyclient")
                    return
                context._identity_dispatched = True
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
                with authorization.authorize():
                    route.continue_()
                return
            if authorization.link is not None:
                # A fallback fetch waits for the full network response. It
                # cannot serialize dispatch with revocation without holding a
                # source lock over that wait; source-bound reads use only the
                # attached main-frame transport (including main-frame XHR).
                authorization.error = AccessError("NEEDS_USER", "password_source_browser_surface_unsupported")
                raise authorization.error
            headers = {k: v for k, v in request.all_headers().items() if k not in {"cookie", "host", "content-length"}}
            body = request.post_data_buffer
            # Child frames and workers have no attached native response guard.
            # Fetch each hop separately rather than permitting an unchecked
            # native redirect in a different Chromium target.
            try:
                for hop in range(6):
                    reason = permitted(url, method, request.resource_type, **provenance)
                    if reason:
                        record_failure(request, url, reason, hop > 0)
                        route.abort("blockedbyclient")
                        return
                    response = route.fetch(url=url, method=method, headers=headers,
                                           post_data=body if method == "POST" else "",
                                           max_redirects=0, max_retries=0, timeout=15000)
                    locations = [item["value"] for item in response.headers_array if item["name"].lower() == "location"]
                    if len(locations) > 1:
                        record_failure(request, url, "destination", hop > 0)
                        route.abort("blockedbyclient")
                        return
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
        page._site_verification_required = False

        def response_received(response):
            # Cloudflare documents this closed header as the challenge-page
            # signal. Keep only a boolean for this page's main document, never
            # response contents, tokens, challenge URLs or cookies. A later
            # normal main-document response clears it; scripts/iframes cannot.
            if response.request.is_navigation_request() and response.frame == page.main_frame:
                page._site_verification_required = response.headers.get("cf-mitigated") == "challenge"

        page.on("response", response_received)
        # Await attachment before initiating any network request. Attaching
        # during a route callback is too late for that request's response;
        # context page events are also not a synchronous attachment barrier.
        context._response_guard.attach(page)
        if page.is_closed():
            raise AccessError("RETRYABLE", "browser_guard_unavailable")
        return page

    def challenge(self, page, config):
        # Action/presence challenges take priority, even if the page also has a ready marker.
        if getattr(page, "_site_verification_required", False):
            return "captcha"
        for kind in ["action", "recovery", "passkey", "device", "admin", "captcha", "sms", "email", "totp",
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
        self.check_authority(page)
        kind = self.challenge(page, config)
        if kind:
            raise AccessError("NEEDS_USER", "browser_" + kind + "_required", kind)
        if not page.locator(config.ready_selector).first.is_visible():
            raise AccessError("NEEDS_USER", "browser_state_unrecognized", "unknown")

    def wait_state(self, page, config, *, after_submit=False, previous_kind=None):
        """Wait for configured markers, including asynchronously rendered login responses."""
        deadline = time.monotonic() + config.state_timeout_ms / 1000
        while True:
            self.check_authority(page)
            kind = self.challenge(page, config)
            prior = previous_kind or ("login" if after_submit else None)
            if kind and kind != prior:
                return
            if page.locator(config.ready_selector).first.is_visible():
                return
            if time.monotonic() >= deadline:
                return
            page.wait_for_timeout(50)

    def check_authority(self, page):
        # Marker helpers also support standalone owner/test pages. Every
        # context created by this browser has the operation binding above.
        authorization = getattr(page.context, "_password_authority", None)
        if authorization is not None:
            authorization.check()

    def read(self, account, op, config, *, secret_values=None, visible=False,
             setup_method=None, review_stop=None, on_code_request=None, on_attention=None):
        # Owner troubleshooting must describe this check, not an earlier routing
        # problem after the account has reached a different verification step.
        self.store.audit("service", account, "", "browser_check_started")
        authorization = _PasswordAuthority(self.store, account)
        authorization.check()
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
                    authorization.check()
                    if reviewed:
                        return False
                    reviewed = True
                    if on_attention:
                        details = {}
                        if origin(config.login_url) == "https://github.com":
                            from .sms_setup import diagnostics
                            details = diagnostics(page)
                            details["page"] = route_hint(page.url, ["https://github.com"])
                            details["progress"] = dict(getattr(page.context, "_login_progress", {}))
                        elif error.status == "NEEDS_USER":
                            from .browser_diagnostics import capture
                            try:
                                details = capture(page, config)
                            except Exception:
                                pass  # A closed/changed page cannot replace the original challenge.
                        on_attention(error.status, error.reason, error.kind, details)
                    if not visible or error.status != "NEEDS_USER":
                        return False
                    # Owner-only troubleshooting: keep the actual failed page
                    # visible briefly, without exporting its HTML or secrets.
                    try:
                        page.bring_to_front()
                    except PlaywrightError:
                        pass  # Window focus cannot change the authentication result.
                    try:
                        deadline = time.monotonic() + 300
                        while not page.is_closed() and time.monotonic() < deadline:
                            authorization.check()
                            if review_stop and review_stop.is_set():
                                break
                            # Owner approval can complete on this exact reviewed
                            # page. Verify its normal success markers before
                            # saving; an attention window alone grants nothing.
                            try:
                                self.check(page, config)
                            except AccessError:
                                pass
                            else:
                                self.save(account, page.context.storage_state(indexed_db=True), authorization=authorization)
                                self.store.resolve_login(account)
                                self.store.audit("owner", account, "", "login_recovered_after_review")
                                return True
                            page.wait_for_timeout(100)
                    except PlaywrightError:
                        pass
                    return False
                try:
                    context = self.context(browser, config, state, account=account, authorization=authorization)
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
                                           on_code_request=on_code_request, review_stop=review_stop,
                                           authorization=authorization)
                        context = self.context(browser, config, state, account=account, authorization=authorization)
                        page = self.page(context)
                        page.goto(op.url, timeout=15000, wait_until="domcontentloaded")
                        self.wait_state(page, config)
                        self.check(page, config)
                    data = self.result(page, op, config)
                    self.save(account, context.storage_state(indexed_db=True), authorization=authorization)
                    return data
                except AccessError as exc:
                    if review_failure(page, exc):
                        page.goto(op.url, timeout=15000, wait_until="domcontentloaded")
                        self.wait_state(page, config)
                        self.check(page, config)
                        return self.result(page, op, config)
                    raise
                finally:
                    browser.close()
        except PlaywrightError:
            authorization.check()
            raise AccessError("RETRYABLE", "browser_execution_failed") from None

    def result(self, page, op, config):
        # A status-only operation still requires the normal authenticated marker
        # and presence/transaction checks. No page text is an agent result.
        self.check(page, config)
        if op.session_only:
            return {"authenticated": True}
        return {name: page.locator(selector).first.inner_text(timeout=5000)[:100_000]
                for name, selector in op.fields.items()}

    def login(self, browser, account, config, state=None, *, secret_values=None, review_failure=None,
              setup_method=None, on_code_request=None, review_stop=None, authorization=None):
        # Source IDs are enrollment names, not proof of separate physical
        # inboxes/phones. Conservatively serialize each message channel too,
        # including owner setup that can request a text before enrollment.
        with ExitStack() as held:
            sources = self.store.config().code_sources
            locks = {"code-login:" + source for source in config.login.sources()}
            for source in config.login.sources():
                kind = sources[source].kind
                if kind != "totp":
                    locks.add("code-delivery:" + ("email" if kind in {"imap", "gmail"} else "sms"))
            if setup_method in {"email", "sms"}:
                locks.add("code-delivery:" + setup_method)
            for key in sorted(locks):
                held.enter_context(self.store.lock(key, timeout=0))
            return self._login(browser, account, config, state, secret_values=secret_values,
                               review_failure=review_failure, setup_method=setup_method,
                               on_code_request=on_code_request, review_stop=review_stop,
                               authorization=authorization)

    def _login(self, browser, account, config, state=None, *, secret_values=None, review_failure=None,
               setup_method=None, on_code_request=None, review_stop=None, authorization=None):
        if review_stop and review_stop.is_set():
            raise AccessError("NEEDS_USER", "sms_setup_cancelled", "sms")
        from .password_sync import refresh
        form = config.login
        if not form.identity_contact:
            refresh(self.store, account, force=True)
        authorization = authorization or _PasswordAuthority(self.store, account)
        authorization.check()
        credential = self.store.get("credential:" + account, {})
        credential = credential or {}
        if not form.credential_ready(credential):
            raise AccessError("NEEDS_USER", "identity_contact_not_connected" if form.identity_contact
                              else "password_not_connected")
        if secret_values is not None:
            secret_values.update(credential[key] for key in (
                form.credential_fields() if form.identity_contact else ("password",)))
        last = self.store.get("login-attempt:" + account, 0)
        if time.time() - last < 60:
            # A timed throttle needs waiting, not owner authentication. Keep the
            # rate limit while letting durable tasks retry without a false prompt.
            raise AccessError("RETRYABLE", "login_retry_cooldown")
        context = self.context(browser, config, state, login=True, account=account, secret_values=secret_values,
                               authorization=authorization)
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
            if form.identity_contact:
                self.check_identity_contact_form(page, config)
            elif form.identity_step:
                self.check_identity_form(page, config)
            else:
                self.check_form(page, form.password_selector, config)
            if review_stop and review_stop.is_set():
                raise AccessError("NEEDS_USER", "sms_setup_cancelled", "sms")
            started = time.time()
            primary = form.sources() - ({form.device_email_source} if form.device_email_source else set())
            for required, sources in [(True, primary), (False, form.sources() - primary)]:
                for source_id in sorted(sources):
                    try:
                        # Baseline primary methods first. Optional later device
                        # mail must not make a missing primary factor usable.
                        self.codes.begin(source_id, account, started)
                    except AccessError as exc:
                        exc.source_id = source_id
                        if not form.factors:
                            raise
                        source_errors[source_id] = exc
                if required and not setup_method and primary and primary <= source_errors.keys():
                    google_error = next((source_errors[source_id] for source_id in primary
                                         if self.store.config().code_sources[source_id].kind == "google_messages"), None)
                    if google_error:
                        # Do not submit a password when the paired SMS tab is
                        # offline and no other enrolled method is usable.
                        raise google_error
                    raise source_errors[sorted(primary)[0]]
            if review_stop and review_stop.is_set():
                raise AccessError("NEEDS_USER", "sms_setup_cancelled", "sms")
            if form.identity_contact:
                self.fill_identity_contact(page, config, credential)
            elif form.identity_step:
                self.submit_identity(page, account, config, credential["username"], review_stop=review_stop)
            if not form.identity_contact:
                expected = form.identity_step.password_url if form.identity_step else config.login_url
                self.credential_page(page, config, expected)
                self.check_form(page, form.password_selector, config)
                if form.identity_step:
                    self.check_staged_native_form(page, form.password_selector, form.submit_selector,
                                                   form.identity_step.password_post_url, allow_missing=config.javascript)
                if not form.identity_step:
                    self.fill_secret(page, form.username_selector, credential["username"])
                    # Input handlers may replace the form or require presence.
                    self.credential_page(page, config, expected)
                    self.check_form(page, form.password_selector, config)
                if context._login_challenge:
                    self.check_staged_native_form(page, form.password_selector, form.submit_selector, config.login_url)
                self.fill_secret(page, form.password_selector, credential["password"])
            # Charge the password-attempt cooldown only when submission is
            # attempted. Connecting a missing mailbox/phone after preflight
            # stopped must not require another minute or user retry.
            self.store.put("login-attempt:" + account, time.time())
            if context._login_challenge:
                context._login_challenge.arm_password()
            if form.identity_contact:
                if context._identity_blocked:
                    raise AccessError("NEEDS_USER", "login_identity_navigation_changed", "unknown")
                context._login_identity_request = {"url": form.identity_contact.post_url, "http_status": None}
                context._identity_armed = True
            try:
                page.locator(form.submit_selector).click(timeout=10000)
                context._login_progress["identity_submit_attempted" if form.identity_contact
                                        else "password_submit_attempted"] = True
                page.wait_for_load_state("domcontentloaded")
                if context._login_challenge and context._login_challenge.failed:
                    raise AccessError("NEEDS_USER", "login_challenge_changed", "unknown")
                self.wait_state(page, config, after_submit=True)
            except PlaywrightError:
                if form.identity_contact and (context._identity_blocked or context._identity_redirect_replay):
                    raise AccessError("NEEDS_USER", "login_identity_navigation_changed", "unknown") from None
                if context._password_blocked:
                    raise AccessError("NEEDS_USER", "login_form_destination_changed", "unknown") from None
                raise
            if context._password_blocked:
                raise AccessError("NEEDS_USER", "login_form_destination_changed", "unknown")
            if form.identity_contact:
                if context._identity_blocked or context._identity_redirect_replay:
                    raise AccessError("NEEDS_USER", "login_identity_navigation_changed", "unknown")
                status = context._login_identity_request["http_status"]
                if status is None or not 200 <= status < 400:
                    raise AccessError("NEEDS_USER", "login_identity_not_completed", "unknown")
                context._identity_pending = False
                context._login_identity_request = None
            context._login_step_post_url = None
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
                    if kind not in {method, None, "action", "recovery", "passkey", "device", "admin", method + "_request"}:
                        raise AccessError("NEEDS_USER", "verification_method_changed", "unknown")
                    continue
                if kind == "method":
                    selected = self.choose_method(page, config, source_errors, set(completed) | choices_used,
                                                  setup_method=setup_method)
                    context._login_progress["method"] = selected
                    choices_used.add(selected)
                    kind = self.challenge(page, config)
                    if kind not in {selected, selected + "_request", None, "action", "recovery", "passkey", "device", "admin"}:
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
                    authorization.check()
                    try:
                        code = self.codes.resolve(source_id, started, used)
                    except AccessError as exc:
                        exc.source_id = source_id
                        raise
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
                if context._login_challenge:
                    destination = context._login_challenge.destination(page.url)
                    self.check_staged_native_form(page, factor.code_selector, factor.code_submit_selector, destination)
                else:
                    self.check_form(page, factor.code_selector, config)
                # Delivery can block while the owner revokes a source or the
                # login window expires. Do not submit its late response.
                self.codes.check_window(source_id, started)
                if review_stop and review_stop.is_set():
                    raise AccessError("NEEDS_USER", "sms_setup_cancelled", kind)
                if context._login_challenge:
                    context._login_challenge.arm_code(page.url)
                # In-memory only, one submission, never put in logs or task state.
                self.fill_secret(page, factor.code_selector, code)
                context._login_progress[kind + "_code_filled"] = True
                context._login_progress[kind + "_submit_attempted"] = True
                page.locator(factor.code_submit_selector).click(timeout=10000)
                page.wait_for_load_state("domcontentloaded")
                if context._login_challenge and context._login_challenge.failed:
                    raise AccessError("NEEDS_USER", "login_challenge_changed", "unknown")
                self.wait_state(page, config, previous_kind=kind)
                completed.append(kind)
                kind = self.challenge(page, config)
            if kind == "device" and context._login_challenge and form.device_email_source:
                page = self.confirm_pypi_device(page, context, config, started, source_errors, review_stop)
                completed.append("email")
            if form.identity_contact and kind is None and "sms" not in completed:
                raise AccessError("NEEDS_USER", "identity_contact_sms_not_verified", "unknown")
            self.check(page, config)
            state = context.storage_state(indexed_db=True)
            self.save(account, state, authorization=authorization)
            self.store.resolve_login(account)
            self.store.audit("service", account, "", "login_recovered")
            for factor in completed:
                self.store.audit("service", account, "", "login_factor_completed", factor)
            return state
        except PlaywrightError:
            authorization.check()
            if context._login_challenge and context._login_challenge.failed:
                raise AccessError("NEEDS_USER", "login_challenge_changed", "unknown") from None
            raise
        except AccessError as exc:
            if review_failure and review_failure(page, exc):
                self.check(page, config)
                return context.storage_state(indexed_db=True)
            raise
        finally:
            if context._login_challenge:
                context._login_challenge.clear()
            if started:
                for source_id in config.login.sources():
                    self.codes.finish(source_id, started)
            context.close()

    def confirm_pypi_device(self, page, context, config, started, source_errors, review_stop):
        policy = context._login_challenge
        source_id = config.login.device_email_source
        if not policy.live() or policy.phase != "device" or not policy.device_page_reached:
            policy.reject()
        if source_id in source_errors:
            raise source_errors[source_id]
        used, link = set(), None
        deadline = time.monotonic() + min(config.login.code_wait_ms / 1000, max(0, started + 120 - time.time()))
        while link is None and time.monotonic() < deadline:
            context._password_authority.check()
            try:
                link = self.codes.resolve(source_id, started, used, pypi_user=policy.expected_user)
            except AccessError as exc:
                exc.source_id = source_id
                raise
            if link is None:
                time.sleep(1)
        if link is None:
            raise AccessError("NEEDS_USER", "login_code_not_received", "email")
        if self.challenge(page, config) != "device":
            raise AccessError("NEEDS_USER", "verification_page_changed", "unknown")
        self.codes.check_window(source_id, started)
        if review_stop and review_stop.is_set():
            raise AccessError("NEEDS_USER", "sms_setup_cancelled", "email")
        context._password_authority.check()
        destination = policy.arm_device(page.url, link, started)
        try:
            page.goto(destination, wait_until="domcontentloaded", timeout=15000)
        except PlaywrightError:
            # Only the exact, proof-bound terminal redirect blocked by CDP may
            # finish here. All other browser failures retain their normal stop.
            if policy.phase != "confirmed" or policy.failed:
                raise
        if policy.phase != "confirmed" or policy.failed:
            policy.reject()
        # A failed top-level redirect can commit Chromium's error document after
        # goto reports failure. Close that page and use the same cookie context;
        # never race a second navigation against its pending error document.
        page.close()
        page = self.page(context)
        page.goto(config.operations["status"].url, wait_until="domcontentloaded", timeout=15000)
        self.wait_state(page, config)
        return page

    def credential_page(self, page, config, expected):
        kind = self.challenge(page, config)
        if kind and kind != "login":
            raise AccessError("NEEDS_USER", "browser_" + kind + "_required", kind)
        if page.url != expected:
            raise AccessError("NEEDS_USER", "login_destination_changed", "unknown")

    def fill_identity_contact(self, page, config, credential):
        fields = config.login.identity_contact
        controls = [(fields.identity_selector, "identity"), (fields.phone_selector, "phone")]
        for selector, key in controls:
            self.check_identity_contact_form(page, config)
            self.fill_secret(page, selector, credential[key])
        # Recheck both fields and the submit control after input handlers run.
        self.check_identity_contact_form(page, config)

    def check_identity_contact_form(self, page, config):
        self.credential_page(page, config, config.login_url)
        fields = config.login.identity_contact
        for selector in [fields.identity_selector, fields.phone_selector]:
            self.check_form(page, selector, config)
            self.check_staged_native_form(page, selector, config.login.submit_selector,
                                          fields.post_url, allow_missing=config.javascript)

    def fill_secret(self, page, selector, value):
        authorization = page.context._password_authority
        with authorization.authorize():
            if authorization.link is None:
                page.locator(selector).fill(value)
            else:
                page.locator(selector).fill(value, timeout=2000)

    def check_identity_form(self, page, config):
        self.credential_page(page, config, config.login_url)
        form, step = config.login, config.login.identity_step
        if any(page.locator(selector).count() != 1 or not page.locator(selector).is_visible()
               for selector in [form.username_selector, step.submit_selector]):
            raise AccessError("NEEDS_USER", "login_identity_form_changed", "unknown")
        if step.scripted:
            return  # The phase guard permits only the exact reviewed identity POST.
        self.check_staged_native_form(page, form.username_selector, step.submit_selector, step.post_url,
                                       reason="login_identity_form_changed")

    def check_staged_native_form(self, page, field_selector, submit_selector, post_url, *, allow_missing=False,
                                reason="login_form_destination_changed"):
        if any(page.locator(selector).count() != 1 or not page.locator(selector).is_visible()
               for selector in [field_selector, submit_selector]):
            raise AccessError("NEEDS_USER", reason, "unknown")
        field = page.locator(field_selector).element_handle()
        button = page.locator(submit_selector).element_handle()
        destination = page.evaluate("""([field, button]) => {
            const form = field?.form;
            const native = key => Object.getOwnPropertyDescriptor(HTMLFormElement.prototype, key).get.call(form);
            return form && button ? {same: form === button.form,
                method: (button.hasAttribute('formmethod') ? button.formMethod : native('method')).toUpperCase(),
                action: button.hasAttribute('formaction') ? button.formAction : native('action')} : null;
        }""", [field, button])
        if destination is None and allow_missing:
            return
        if isinstance(destination, dict):
            destination["action"] = native_form_target(destination.get("action"))
        if not destination or destination != {"same": True, "method": "POST", "action": post_url}:
            raise AccessError("NEEDS_USER", reason, "unknown")

    def submit_identity(self, page, account, config, username, *, review_stop=None):
        form, context = config.login, page.context
        step = form.identity_step
        self.check_identity_form(page, config)
        if context._identity_blocked:
            raise AccessError("NEEDS_USER", "login_identity_navigation_changed", "unknown")
        confirmation = {"url": step.post_url, "http_status": None}
        context._login_identity_request = confirmation
        context._identity_armed = True
        # Limit even a failed first-stage request. The final password submission
        # refreshes this same cooldown; missing-source preflight does not charge it.
        self.store.put("login-attempt:" + account, time.time())
        try:
            self.fill_secret(page, form.username_selector, username)
            page.locator(step.submit_selector).click(timeout=10000)
            context._login_progress["identity_submit_attempted"] = True
            page.wait_for_load_state("domcontentloaded")
        except PlaywrightError:
            if context._identity_blocked or context._identity_redirect_replay:
                raise AccessError("NEEDS_USER", "login_identity_navigation_changed", "unknown") from None
            raise AccessError("RETRYABLE", "login_identity_transport_failed") from None
        deadline = time.monotonic() + config.state_timeout_ms / 1000
        while True:
            kind = self.challenge(page, config)
            if kind and kind != "login":
                raise AccessError("NEEDS_USER", "browser_" + kind + "_required", kind)
            status = confirmation["http_status"]
            if status in {429, 500, 502, 503, 504}:
                raise AccessError("RETRYABLE", "login_identity_temporarily_unavailable")
            if status is not None and not 200 <= status < 400:
                raise AccessError("NEEDS_USER", "login_identity_rejected", "unknown")
            if context._identity_blocked or context._identity_redirect_replay:
                raise AccessError("NEEDS_USER", "login_identity_navigation_changed", "unknown")
            if review_stop and review_stop.is_set():
                raise AccessError("NEEDS_USER", "sms_setup_cancelled", "sms")
            if (status is not None and page.url == step.password_url
                    and page.locator(form.password_selector).first.is_visible()):
                context._identity_pending = False
                context._login_identity_request = None
                context._login_step_post_url = step.password_post_url
                return
            if time.monotonic() >= deadline:
                raise AccessError("NEEDS_USER", "login_identity_not_completed", "unknown")
            page.wait_for_timeout(50)

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
        # Native POST redirects can inherit the form's client fragment. Match
        # that page's actual HTTP provenance without granting a new destination.
        provenance = page.url if config.javascript else native_form_target(page.url)
        if provenance not in {config.login_url, *config.login_resources}:
            raise AccessError("NEEDS_USER", "login_destination_changed", "unknown")
        destination = page.locator(selector).evaluate("""el => {
            const form = el.form;
            const native = key => Object.getOwnPropertyDescriptor(HTMLFormElement.prototype, key).get.call(form);
            return form ? {method: native('method').toUpperCase(), action: native('action')} : null;
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
                or native_form_target(destination["action"]) not in config.login_post_urls):
            raise AccessError("NEEDS_USER", "login_form_destination_changed", "unknown")

    def save(self, account, state, db=None, *, authorization=None):
        authorization = authorization or _PasswordAuthority(self.store, account)
        config = self.store.config()
        from .bitwarden_source import _database
        database = (_database(self.store) if authorization.link is not None and db is None
                    else nullcontext(db))
        with authorization.authorize(), database as target:
            self.store.put("connection:" + account, {"state": state,
                           "fingerprint": config.fingerprint(account), "generation": str(time.time_ns())}, db=target)

    def connect(self, account, *, headless=False, complete=None):
        """Owner interactive connection. Login resources remain allowlisted; no screenshots/logs."""
        config = self.store.config().accounts[account]
        if config.login_challenge:
            raise AccessError("NEEDS_USER", "pypi_manual_setup_unavailable", "unknown")
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

    def verify_imported_state(self, account, state, username, operation):
        """Check a transferred session without password entry or changing saved access."""
        config = self.store.config().accounts[account]
        try:
            with sync_playwright() as pw:
                browser = pw.chromium.launch(headless=True, chromium_sandbox=True,
                                             channel=config.browser_channel)
                try:
                    context = self.context(browser, config, state, account=account)
                    page = self.page(context)
                    page.goto(config.operations[operation].url, timeout=15000, wait_until="domcontentloaded")
                    self.wait_state(page, config)
                    self.check(page, config)
                    identity = page.locator('meta[name="user-login"]')
                    if identity.count() != 1 or (identity.get_attribute("content") or "").lower() != username.lower():
                        raise AccessError("NEEDS_USER", "browser_session_identity_mismatch")
                    return context.storage_state(indexed_db=True)
                finally:
                    browser.close()
        except PlaywrightError:
            raise AccessError("RETRYABLE", "browser_session_verification_failed") from None

    def import_state(self, account, state):
        # Legacy direct imports never verified identity/readiness. Only the
        # short-lived owner request may adopt a verified browser session now.
        raise AccessError("DENIED", "browser_session_owner_request_required")
