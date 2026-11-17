"""Harel's fixed, status-only adapter. Native enrollment is qualified separately."""

from contextlib import ExitStack
import time

from .errors import AccessError
from .factors import source_mutation
from .harel_protocol import API, CHANNELS, ENTRY, HarelLogin
from .models import BrowserAccount, BrowserOperation, LoginFactor, LoginForm

PROTOCOL = "harel-otp-v1"
ACCOUNT = "personal-harel"
SOURCES = {"email": "personal-harel-email", "sms": "personal-harel-sms"}


def configuration(channel="email"):
    if channel not in CHANNELS:
        raise ValueError("Harel requires an explicit email or SMS channel")
    # These are protocol identifiers, not CSS selectors or an executable HTML
    # form. Browser.read dispatches this exact fixed shape before Playwright.
    return BrowserAccount(
        kind="browser", label="Harel · " + channel, login_url=ENTRY,
        ready_selector="harel-authenticated-session",
        login=LoginForm(submit_selector="harel-request-login-code",
                        identity_contact={"identity_selector": "harel-identity", "phone_selector": "harel-phone",
                                          "post_url": API + "StartProcess", "protocol": PROTOCOL},
                        factors={channel: LoginFactor(code_selector="harel-login-code",
                                                      code_submit_selector="harel-verify-login-code",
                                                      code_source=SOURCES[channel])}),
        read_resources=[ENTRY, API + "GetCurrentDetails"],
        login_resources=[API + name for name in ("ContextConfig", "StartProcess", "SCValidateOTP", "GetCurrentDetails")],
        login_post_urls=[API + name for name in ("ContextConfig", "StartProcess", "SCValidateOTP", "GetCurrentDetails")],
        operations={"status": BrowserOperation(url=API + "GetCurrentDetails", session_only=True,
                                               description="Confirm your Harel sign-in status")})


def validate_configuration(spec):
    channel = next(iter(spec.login.factors), None) if spec.login else None
    if channel not in CHANNELS or spec != configuration(channel):
        raise ValueError("Harel requires its exact reviewed status-only protocol")


def read(browser, account, operation, spec, *, state=None, secret_values=None,
         review_stop=None, on_code_request=None, setup_method=None, **kwargs):
    validate_configuration(spec)
    channel = next(iter(spec.login.factors))
    if operation != spec.operations["status"] or setup_method not in {None, channel}:
        raise AccessError("DENIED", "harel_operation_not_allowed")
    source = SOURCES[channel]
    started = None

    def cancelled():
        if review_stop and review_stop.is_set():
            raise AccessError("NEEDS_USER", "harel_setup_cancelled", channel)

    # Browser/broker callers already hold the account lock. Hold the existing
    # delivery locks too, preventing an overlapping email/SMS code window.
    with ExitStack() as held:
        for key in sorted({"code-login:" + source, "code-delivery:" + channel}):
            held.enter_context(browser.store.lock(key, timeout=0))
        with HarelLogin(channel, state=state) as session:
            cancelled()
            session.open()
            status = session.session_status()
            if status["authenticated"]:
                browser.save(account, session.storage_state())
                return status
            credential = browser.store.get("credential:" + account)
            if not spec.login.credential_ready(credential):
                raise AccessError("NEEDS_USER", "identity_contact_not_connected", "login")
            if secret_values is not None:
                secret_values.update(credential.values())
            last = browser.store.get("login-attempt:" + account, 0)
            if time.time() - last < 60:
                raise AccessError("RETRYABLE", "login_retry_cooldown")
            try:
                started = time.time()
                # Baseline and enrollment checks precede any identity-bearing
                # request. A saved mailbox check alone is not a source grant.
                browser.codes.begin(source, account, started)
                cancelled()
                session.select_channel()
                browser.codes.check_window(source, started)
                cancelled()
                browser.store.put("login-attempt:" + account, time.time())
                session.request_code(**credential)
                if on_code_request:
                    on_code_request(channel, started, 200, {})
                cancelled()
                deadline = time.monotonic() + min(spec.login.code_wait_ms / 1000, max(0, started + 120 - time.time()))
                code = None
                used = set()
                while time.monotonic() < deadline:
                    cancelled()
                    code = browser.codes.resolve(source, started, used)
                    if code:
                        break
                    time.sleep(1)
                if not code:
                    raise AccessError("NEEDS_USER", "login_code_not_received", channel)
                if secret_values is not None:
                    secret_values.add(code)
                browser.codes.check_window(source, started)
                cancelled()
                result = session.submit_code(code)
                # A mailbox/phone revocation while the provider responds must
                # prevent publishing that response and saving a new session.
                with source_mutation(browser.store, source):
                    browser.codes.check_window(source, started)
                    cancelled()
                    browser.save(account, session.storage_state())
                browser.store.resolve_login(account)
                return result
            finally:
                if started is not None:
                    browser.codes.finish(source, started)
