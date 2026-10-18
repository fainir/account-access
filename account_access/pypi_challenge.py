"""A response-derived PyPI TOTP URL, scoped to one guarded login context."""

from dataclasses import dataclass
import re
import time
from urllib.parse import urlsplit

from .errors import AccessError

POLICY = "pypi-totp-v1"
STATUS_PATH = "/_includes/authed/current-user-indicator/"
LOGIN_PATH = "/account/login/"
LOGIN_QUERY = "next=%2F_includes%2Fauthed%2Fcurrent-user-indicator%2F"
CHALLENGE_PATH = "/account/two-factor/"
DEVICE_PATH = "/account/confirm-login/"
USERNAME = "#login-form #username"
PASSWORD = "#login-form #password"
PASSWORD_SUBMIT = "#login-form input[type='submit']"
TOTP = "#totp-auth-form #totp_value"
TOTP_SUBMIT = "#totp-auth-form input[type='submit']"
READY = "#user-indicator > nav > button.dropdown__trigger:has(img.user-image)"
CHALLENGES = {
    "login": "#login-form, a[href='/account/login/']",
    "totp": "#totp-auth-form",
    "passkey": ".twofa-login:not(:has(#totp-auth-form)) #webauthn-auth-form",
    "device": "h1.page-title:has-text('Please confirm this login')",
    "recovery": "form:has(#recovery_code_value)",
    "captcha": ".g-recaptcha, .h-captcha",
}
# Deployed Warehouse uses URLSafeTimedSerializer with an SHA-512 signer.
# Optional leading dot denotes compression; the query is not key/value data.
TOKEN = re.compile(r"\.?[A-Za-z0-9_-]{1,1800}\.[A-Za-z0-9_-]{1,16}\.[A-Za-z0-9_-]{86}\Z", re.ASCII)


def origin_for(spec, test_mode=False):
    parsed = urlsplit(spec.login_url)
    origin = f"{parsed.scheme}://{parsed.netloc}"
    if origin != "https://pypi.org" and not (
            test_mode and parsed.scheme == "http" and parsed.hostname == "127.0.0.1"
            and parsed.port and parsed.netloc == "127.0.0.1:" + str(parsed.port)):
        raise ValueError("PyPI challenge requires the reviewed PyPI origin")
    return origin


def validate_configuration(spec, test_mode=False):
    root = origin_for(spec, test_mode)
    form = spec.login
    if (spec.login_challenge != POLICY or spec.login_url != root + LOGIN_PATH + "?" + LOGIN_QUERY
            or spec.javascript or not form or form.identity_step is not None
            or (form.username_selector, form.password_selector, form.submit_selector) != (USERNAME, PASSWORD, PASSWORD_SUBMIT)
            or set(form.factors) != {"totp"} or form.code_source or form.choices or form.code_requests or form.choice_toggle_selector
            or (form.factors["totp"].code_selector, form.factors["totp"].code_submit_selector) != (TOTP, TOTP_SUBMIT)
            or spec.login_post_urls != [spec.login_url]
            or set(spec.login_resources) != {root + STATUS_PATH, root + DEVICE_PATH}
            or spec.login_assets or spec.login_asset_discovery or spec.read_resources
            or spec.ready_selector != READY or set(spec.operations) != {"status"}
            or spec.challenge_selectors != CHALLENGES
            or spec.operations["status"].url != root + STATUS_PATH
            or spec.operations["status"].fields != {"username": READY}):
        raise ValueError("PyPI challenge requires the reviewed native login and username-only operation")
    return root


@dataclass(frozen=True, repr=False)
class _Proof:
    attachment: object
    frame: str
    chain: str


class PyPIChallenge:
    """Never a persisted URL pattern: one armed POST can mint one exact URL."""

    def __init__(self, spec, *, test_mode=False, secret_values=None, clock=None):
        self.origin = validate_configuration(spec, test_mode)
        self.password_url = spec.login_url
        self.clock = clock or time.monotonic
        self.secrets = secret_values
        self.clear()

    def clear(self):
        self.failed = False
        self.phase = "idle"
        self.expires = 0
        self.url = None
        self.password_proof = None
        self.code_proof = None
        self.password_dispatched = False
        self.code_dispatched = False

    def block(self):
        self.clear()
        self.phase = "closed"
        self.failed = True

    def reject(self):
        self.block()
        raise AccessError("NEEDS_USER", "login_challenge_changed", "unknown")

    def live(self):
        if self.phase in {"idle", "closed"}:
            return False
        if self.clock() >= self.expires:
            self.block()
            return False
        return True

    def arm_password(self):
        if self.phase != "idle":
            self.reject()
        self.phase = "password"
        self.expires = self.clock() + 120

    def observe(self, event, attachment, main_frame):
        request = event.get("request", {})
        if (not self.live() or event.get("frameId") != main_frame or event.get("type") != "Document"
                or request.get("method") != "POST"):
            return
        target = self.password_url if self.phase == "password" else self.url if self.phase == "code" else None
        if request.get("url") != target:
            return
        chain = event.get("requestId")
        if not isinstance(chain, str) or not chain or event.get("redirectResponse") is not None:
            self.reject()
        key = "password_proof" if self.phase == "password" else "code_proof"
        proof = _Proof(attachment, main_frame, chain)
        previous = getattr(self, key)
        if previous is not None and previous != proof:
            self.reject()
        if self.phase == "code" and attachment is not self.password_proof.attachment:
            self.reject()
        if self.phase == "code" and chain == self.password_proof.chain:
            self.reject()
        setattr(self, key, proof)

    def dispatch(self, url, method, attachment, main_document):
        if method != "POST":
            return
        if not self.live() or not main_document:
            self.reject()
        if self.phase == "password" and url == self.password_url and not self.password_dispatched:
            if self.password_proof is not None and attachment is not self.password_proof.attachment:
                self.reject()
            self.password_dispatched = True
        elif (self.phase == "code" and url == self.url and not self.code_dispatched
              and attachment is self.password_proof.attachment):
            self.code_dispatched = True
        else:
            self.reject()

    def permitted(self, url, method, kind, *, attachment=None, chain=None, main_document=False):
        if not self.live() or not main_document or kind != "document":
            return False
        if method == "POST" and self.phase == "password" and url == self.password_url:
            proof = self.password_proof
            return chain is None or (self.password_dispatched and proof is not None
                                     and proof.attachment is attachment and proof.chain == chain)
        if url != self.url or self.password_proof is None or attachment is not self.password_proof.attachment:
            return False
        if method == "GET" and self.phase == "challenge":
            return chain == self.password_proof.chain
        if method == "POST" and self.phase == "code":
            proof = self.code_proof
            return chain is None or (self.code_dispatched and proof is not None and proof.chain == chain)
        return False

    def response(self, *, url, method, status, locations, attachment, frame, chain, kind, main_document, hop):
        if not self.live():
            return
        if method == "POST" and url == self.password_url:
            proof = self.password_proof
            if (self.phase != "password" or not self.password_dispatched or proof is None
                    or proof != _Proof(attachment, frame, chain) or not main_document or kind != "document" or hop != 0):
                self.reject()
            if status not in {302, 303} or len(locations) != 1:
                self.clear()
                self.phase = "closed"
                return
            location = locations[0]
            prefixes = [CHALLENGE_PATH + "?", self.origin + CHALLENGE_PATH + "?"]
            prefix = next((value for value in prefixes if location.startswith(value)), None)
            if prefix is None:
                self.clear()
                self.phase = "closed"
                return
            token = location[len(prefix):]
            if len(token) > 2048 or not TOKEN.fullmatch(token):
                self.reject()
            self.url = self.origin + CHALLENGE_PATH + "?" + token
            self.phase = "challenge"
            if self.secrets is not None:
                self.secrets.update([token, self.url])
        elif method == "POST" and url == self.url:
            if (self.phase != "code" or not self.code_dispatched or self.code_proof != _Proof(attachment, frame, chain)
                    or not main_document or kind != "document" or hop != 0):
                self.reject()
            self.clear()
            self.phase = "closed"
        elif url == self.url and method == "GET" and status != 200:
            self.clear()
            self.phase = "closed"

    def destination(self, page_url):
        if not self.live() or self.phase != "challenge" or page_url != self.url:
            self.reject()
        return self.url

    def arm_code(self, page_url):
        self.destination(page_url)
        self.phase = "code"

