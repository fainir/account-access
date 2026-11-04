"""Closed Harel login protocol, pending native enrollment and private acceptance.

The public Scanovate component selects ContextConfig's otpChannel before
StartProcess. Its visible HTML form is GET and must never carry credentials.
This client executes only the fixed login calls, without the page's scripts,
telemetry, resends, channel switches, declarations or insurance reads.
"""

import json
import re
import time
from http.cookiejar import Cookie

import httpx2 as httpx

from .errors import AccessError

ORIGIN = "https://www.harel-group.co.il"
ENTRY = ORIGIN + "/Pages/login-page/Login.aspx?isshowlogin=true"
API = ORIGIN + "/_vti_bin/webapi/CustomersAuthentication/PostAuthenticate/"
CHANNELS = {"email": 1, "sms": 0}
MAX_RESPONSE = 256_000
MAX_ENTRY = 512_000
WINDOW_SECONDS = 120


def fail(reason="harel_login_changed", kind="unknown"):
    # No provider strings, response bodies, identity, cookie or code is an error.
    raise AccessError("NEEDS_USER", reason, kind)


def _object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON field")
        result[key] = value
    return result


def _details(raw):
    try:
        data = json.loads(raw, object_pairs_hook=_object,
                          parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
    except (ValueError, UnicodeError, RecursionError):
        fail()
    if (not isinstance(data, dict) or set(data) != {"Status", "Details"}
            or type(data["Status"]) is not int or data["Status"] != 0
            or not isinstance(data["Details"], dict)):
        fail()
    return data["Details"]


def _stop_branch(details):
    # The shared vendor dispatcher accepts many non-login continuations. We
    # support only OTPWasSent -> UserLoggedIn, never its generic Continue.
    for key in ("ProcessError", "TechnicalError", "UserInputError", "process",
                "IsPowerOfAttorney", "IsDecleration", "Activation",
                "EmailNeedsVerification", "IsShowHasatProductMsg"):
        value = details.get(key)
        if value is not None and value is not False and value != "" and not (type(value) is int and value == 0):
            fail("harel_owner_verification_required", "action")


def _inactive_mount(value):
    return value is None or value is False or type(value) is int and value == 0


def _user(details):
    current = details.get("current")
    if (not isinstance(current, dict)
            or any(not isinstance(current.get(key), str) or not 1 <= len(current[key].strip()) <= 100
                   for key in ("FirstName", "LastName"))):
        fail("harel_session_marker_changed")
    # The public header treats a populated current user as authenticated and
    # reads these two fields. They stay in memory solely to compare the OTP
    # result with the subsequent status response; they are never a result.
    return current["FirstName"], current["LastName"]


class HarelLogin:
    """One private cookie context and one code submission per login attempt.

    `transport` is an in-process testing seam, never a URL, proxy or agent input.
    The caller owns local enrollment, grants, source locks and code windows.
    Failed/uncertain sends permanently close this instance; callers must not
    replay a code request after a lost response.
    """

    def __init__(self, channel, *, state=None, transport=None):
        if not isinstance(channel, str) or channel not in CHANNELS:
            fail("harel_verification_method_required")
        self.channel = channel
        self._phase = "new"
        self._deadline = None
        self._verified_user = None
        self._restored = False
        self._client = httpx.Client(
            timeout=httpx.Timeout(15), follow_redirects=False, trust_env=False,
            transport=transport, headers={"Origin": ORIGIN, "Referer": ENTRY,
                                          "Accept": "application/json"})
        try:
            self._restore(state)
        except BaseException:
            self._client.close()
            raise

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()

    def close(self):
        self._phase = "closed"
        self._client.close()

    def _expect(self, phase):
        if self._phase != phase:
            self._phase = "failed"
            fail("harel_login_attempt_changed")

    def _window(self):
        if self._deadline is None or time.monotonic() >= self._deadline:
            self._phase = "failed"
            fail("login_code_window_expired", self.channel)

    def _request(self, endpoint=None, payload=None):
        if endpoint not in {None, "ContextConfig", "GetCurrentDetails", "StartProcess", "SCValidateOTP"}:
            self._phase = "failed"
            fail()
        url = ENTRY if endpoint is None else API + endpoint
        method = "GET" if endpoint is None else "POST"
        limit = MAX_ENTRY if endpoint is None else MAX_RESPONSE
        try:
            with self._client.stream(method, url, **({"json": payload} if payload is not None else {})) as response:
                # Never follow a 307/308 or forward identity/code/cookies to a
                # redirected destination. A retryable response is still not a
                # license to replay an uncertain identity or code request.
                if response.status_code != 200:
                    self._phase = "failed"
                    if endpoint in {"StartProcess", "SCValidateOTP"}:
                        fail("harel_request_outcome_uncertain", self.channel)
                    if response.status_code in {429, 500, 502, 503, 504}:
                        raise AccessError("RETRYABLE", "harel_temporarily_unavailable")
                    fail("harel_request_refused")
                if endpoint and response.headers.get("content-type", "").split(";", 1)[0].strip().lower() != "application/json":
                    self._phase = "failed"
                    fail()
                raw = bytearray()
                for chunk in response.iter_bytes():
                    raw.extend(chunk)
                    if len(raw) > limit:
                        self._phase = "failed"
                        fail("harel_response_too_large")
                return bytes(raw)
        except httpx.HTTPError:
            self._phase = "failed"
            if endpoint in {"StartProcess", "SCValidateOTP"}:
                fail("harel_request_outcome_uncertain", self.channel)
            raise AccessError("RETRYABLE", "harel_network_unavailable") from None

    def _restore(self, state):
        if state is None:
            return
        if (not isinstance(state, dict) or set(state) != {"harel_cookies"}
                or not isinstance(state["harel_cookies"], list) or len(state["harel_cookies"]) > 64):
            fail("harel_session_changed")
        seen = set()
        for saved in state["harel_cookies"]:
            keys = {"name", "value", "domain", "path", "secure", "expires"}
            if (not isinstance(saved, dict) or set(saved) != keys
                    or not isinstance(saved["name"], str) or re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Za-z-]{1,128}", saved["name"]) is None
                    or not isinstance(saved["value"], str) or len(saved["value"]) > 4096
                    or any(ord(char) < 32 or ord(char) >= 127 for char in saved["value"])
                    or not isinstance(saved["domain"], str)
                    or saved["domain"] not in {"www.harel-group.co.il", ".www.harel-group.co.il", ".harel-group.co.il", "harel-group.co.il"}
                    or not isinstance(saved["path"], str) or not saved["path"].startswith("/") or len(saved["path"]) > 2048
                    or any(ord(char) < 32 or ord(char) >= 127 for char in saved["path"])
                    or type(saved["secure"]) is not bool
                    or saved["expires"] is not None and (type(saved["expires"]) is not int or saved["expires"] < 0)):
                fail("harel_session_changed")
            key = saved["domain"], saved["path"], saved["name"]
            if key in seen:
                fail("harel_session_changed")
            seen.add(key)
            self._client.cookies.jar.set_cookie(Cookie(
                version=0, name=saved["name"], value=saved["value"], port=None, port_specified=False,
                domain=saved["domain"], domain_specified=True, domain_initial_dot=saved["domain"].startswith("."),
                path=saved["path"], path_specified=True, secure=saved["secure"], expires=saved["expires"],
                discard=saved["expires"] is None, comment=None, comment_url=None, rest={"HttpOnly": None}))
        self._restored = bool(state["harel_cookies"])

    def storage_state(self):
        """Private encrypted-vault state; never a public operation result."""
        self._expect("authenticated")
        state = {"harel_cookies": [
            {"name": cookie.name, "value": cookie.value, "domain": cookie.domain,
             "path": cookie.path, "secure": cookie.secure, "expires": cookie.expires}
            for cookie in self._client.cookies.jar]}
        # Validate received cookies with the same bounds used on restoration.
        self._restore(state)
        return state

    def open(self):
        self._expect("new")
        self._phase = "opening"
        self._request()
        self._phase = "public"

    def session_status(self):
        """Only a boolean, never names or other GetCurrentDetails fields."""
        if self._phase not in {"public", "verified"}:
            self._expect("public")
        verified = self._phase == "verified"
        self._phase = "checking"
        details = _details(self._request("GetCurrentDetails"))
        if verified:
            self._window()
        if set(details) != {"current", "CurrentProcess"} or type(details["CurrentProcess"]) is not int:
            fail()
        current = details["current"]
        if current is not None:
            if not verified and not self._restored:
                fail("harel_session_marker_changed")
            user = _user(details)
            if verified and user != self._verified_user:
                fail("harel_session_identity_changed")
            self._phase = "authenticated"
            return {"authenticated": True}
        if verified:
            fail("harel_session_not_authenticated")
        self._phase = "public"
        return {"authenticated": False}

    def select_channel(self):
        self._expect("public")
        self._phase = "configuring"
        details = _details(self._request("ContextConfig", {
            "ContextJson": {"LogTypCurrentPlatform": 1},
            "from": "isShowLogin", "otpChannel": CHANNELS[self.channel]}))
        if set(details) != {"CurrentProcess"} or type(details["CurrentProcess"]) is not int:
            fail()
        # CurrentProcess is an integer discriminator, not a nonce. Attempt
        # binding comes from this private cookie context and local code window.
        self._phase = "configured"

    def request_code(self, *, identity, phone):
        self._expect("configured")
        if (not isinstance(identity, str) or not re.fullmatch(r"[0-9]{5,9}", identity)
                or not isinstance(phone, str) or not re.fullmatch(r"05[0-9]{8}", phone)):
            self._phase = "failed"
            fail("invalid_identity_contact", "login")
        self._phase = "requesting"
        # Start the local deadline before any possible send, including a slow
        # successful response. Do not silently give an old code a new window.
        self._deadline = time.monotonic() + WINDOW_SECONDS
        details = _details(self._request("StartProcess", {"UserId": identity, "FullPhone": phone}))
        self._window()
        _stop_branch(details)
        extra = details.get("details")
        if (details.get("ProcessSuccess") != "OTPWasSent"
                or type(details.get("OTPChannel")) is not int
                or details["OTPChannel"] != CHANNELS[self.channel]
                or extra is not None and (not isinstance(extra, dict) or not _inactive_mount(extra.get("SendOtpOnMount")))):
            fail("harel_verification_method_changed", self.channel)
        self._phase = "code"
        return {"status": "CODE_REQUESTED", "method": self.channel}

    def submit_code(self, code):
        self._expect("code")
        self._window()
        self._phase = "submitting"
        if not isinstance(code, str) or not re.fullmatch(r"[0-9]{6}", code):
            self._phase = "failed"
            fail("invalid_login_code", self.channel)
        details = _details(self._request("SCValidateOTP", {"OTP": code}))
        self._window()
        _stop_branch(details)
        if details.get("ProcessSuccess") != "UserLoggedIn":
            fail()
        self._verified_user = _user(details)
        self._phase = "verified"
        # UserLoggedIn alone never publishes success. Read the independently
        # cookie-authenticated status endpoint before returning a boolean.
        return self.session_status()
