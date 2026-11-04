"""Controlled protocol transport only; no insurer identity, mailbox or SMS."""

import json

import httpx2 as httpx
import pytest

from account_access import harel_protocol as harel
from account_access.errors import AccessError


IDENTITY = "000000000"
PHONE = "0500000000"
CODE = "654321"
USER = {"FirstName": "Fixture", "LastName": "Account"}


class Provider:
    def __init__(self):
        self.requests = []
        self.channel = None
        self.authenticated = False
        self.replace = {}

    def __call__(self, request):
        endpoint = request.url.path.rsplit("/", 1)[-1]
        self.requests.append(request)
        assert str(request.url).startswith(harel.ORIGIN + "/")
        assert all(secret not in str(request.url) for secret in (IDENTITY, PHONE, CODE))
        if endpoint in self.replace:
            replacement = self.replace[endpoint]
            return replacement(request) if callable(replacement) else replacement
        assert request.headers["Origin"] == harel.ORIGIN
        assert request.headers["Referer"] == harel.ENTRY
        if str(request.url) == harel.ENTRY:
            assert request.method == "GET" and not request.content
            return httpx.Response(200, headers={"Content-Type": "text/html",
                                               "Set-Cookie": "HarelAttempt=fixture; Secure; HttpOnly; Path=/"},
                                  content=b"<html>Public login</html>")
        assert request.method == "POST" and "HarelAttempt=fixture" in request.headers["Cookie"]
        assert request.url.query == b""
        body = json.loads(request.content) if request.content else None
        if endpoint == "GetCurrentDetails":
            assert body is None
            details = {"CurrentProcess": 0, "current": USER if self.authenticated else None}
        elif endpoint == "ContextConfig":
            assert set(body) == {"ContextJson", "from", "otpChannel"}
            assert body["ContextJson"] == {"LogTypCurrentPlatform": 1}
            assert body["from"] == "isShowLogin"
            self.channel = body["otpChannel"]
            details = {"CurrentProcess": 0}
        elif endpoint == "StartProcess":
            assert self.channel is not None
            assert body == {"UserId": IDENTITY, "FullPhone": PHONE}
            details = {"ProcessSuccess": "OTPWasSent", "OTPChannel": self.channel}
        elif endpoint == "SCValidateOTP":
            assert body == {"OTP": CODE}
            self.authenticated = True
            details = {"ProcessSuccess": "UserLoggedIn", "current": USER}
        else:
            raise AssertionError("unreviewed endpoint")
        return response(details)


def response(details):
    return httpx.Response(200, json={"Status": 0, "Details": details})


def configured(provider, channel="email"):
    session = harel.HarelLogin(channel, transport=httpx.MockTransport(provider))
    session.open()
    assert session.session_status() == {"authenticated": False}
    session.select_channel()
    return session


def requested(provider, channel="email"):
    session = configured(provider, channel)
    assert session.request_code(identity=IDENTITY, phone=PHONE) == {"status": "CODE_REQUESTED", "method": channel}
    return session


@pytest.mark.parametrize("channel,value", [("email", 1), ("sms", 0)])
def test_fixed_channel_precedes_identity_and_code_never_uses_url(channel, value):
    provider = Provider()
    with requested(provider, channel) as session:
        assert provider.channel == value
        assert session.submit_code(CODE) == {"authenticated": True}
    endpoints = [request.url.path.rsplit("/", 1)[-1] for request in provider.requests]
    assert endpoints == ["Login.aspx", "GetCurrentDetails", "ContextConfig", "StartProcess",
                         "SCValidateOTP", "GetCurrentDetails"]
    assert "UpdateOtpChannel" not in endpoints and "CreateOTP" not in endpoints


@pytest.mark.parametrize("channel", [None, False, 0, 1, [], {}, "Email", "email&sms", "https://evil.invalid"])
def test_no_implicit_sms_or_arbitrary_channel(channel):
    with pytest.raises(AccessError, match="harel_verification_method_required"):
        harel.HarelLogin(channel)


@pytest.mark.parametrize("endpoint", ["ContextConfig", "StartProcess", "SCValidateOTP", "GetCurrentDetails"])
@pytest.mark.parametrize("status", [301, 302, 303, 307, 308, 401, 403, 429, 500, 503])
def test_redirect_error_and_uncertain_request_never_replay(endpoint, status):
    provider = Provider()
    session = harel.HarelLogin("email", transport=httpx.MockTransport(provider))
    session.open()
    if endpoint in {"StartProcess", "SCValidateOTP"}:
        session.select_channel()
    if endpoint == "SCValidateOTP":
        session.request_code(identity=IDENTITY, phone=PHONE)
    provider.replace[endpoint] = httpx.Response(status, headers={"Location": "https://evil.invalid/capture"})
    actions = {"ContextConfig": session.select_channel, "GetCurrentDetails": session.session_status,
               "StartProcess": lambda: session.request_code(identity=IDENTITY, phone=PHONE),
               "SCValidateOTP": lambda: session.submit_code(CODE)}
    with session, pytest.raises(AccessError):
        actions[endpoint]()
    count = len(provider.requests)
    with pytest.raises(AccessError):
        actions[endpoint]()
    assert len(provider.requests) == count


@pytest.mark.parametrize("field,value", [
    ("ProcessSuccess", "MustEnterIdIssueDate"), ("ProcessSuccess", "MustEnterCreditCard"),
    ("ProcessSuccess", "FullStrictIsNeeded"), ("ProcessSuccess", "MustChangePassword"),
    ("ProcessSuccess", "RegistrationSuccess"), ("ProcessError", "EmailOtpDisabled"),
    ("ProcessError", "EmailServiceFailed"), ("TechnicalError", "fixture-private-error"),
    ("process", "SwitchOTPChannel"), ("IsPowerOfAttorney", True),
    ("IsDecleration", True), ("Activation", True), ("EmailNeedsVerification", True),
    ("process", "closeWindow"), ("OTPChannel", 0), ("OTPChannel", True), ("OTPChannel", "1"),
    ("details", {"SendOtpOnMount": True}), ("details", {"SendOtpOnMount": "false"}),
    ("details", "unrecognized")])
def test_changed_channel_and_nonlogin_branch_stop_without_switch_or_code(field, value):
    provider = Provider()
    with configured(provider) as session:
        details = {"ProcessSuccess": "OTPWasSent", "OTPChannel": 1, field: value}
        provider.replace["StartProcess"] = response(details)
        with pytest.raises(AccessError) as caught:
            session.request_code(identity=IDENTITY, phone=PHONE)
        assert "fixture-private-error" not in str(caught.value)
        count = len(provider.requests)
        with pytest.raises(AccessError):
            session.submit_code(CODE)
        assert len(provider.requests) == count


@pytest.mark.parametrize("body", [
    b'null', b'[]', b'{"Status":true,"Details":{}}',
    b'{"Status":0,"Status":1,"Details":{}}',
    b'{"Status":0,"Details":{"CurrentProcess":0,"CurrentProcess":1}}',
    b'{"Status":0,"Details":{"CurrentProcess":NaN}}',
    b'{"Status":0,"Details":{"CurrentProcess":false}}',
    b'{"Status":0,"Details":{},"unexpected":"value"}', b'\xff'])
def test_invalid_or_ambiguous_json_does_not_enable_identity_request(body):
    provider = Provider()
    with harel.HarelLogin("email", transport=httpx.MockTransport(provider)) as session:
        session.open()
        provider.replace["ContextConfig"] = httpx.Response(200, headers={"Content-Type": "application/json"}, content=body)
        with pytest.raises(AccessError):
            session.select_channel()
        count = len(provider.requests)
        with pytest.raises(AccessError):
            session.request_code(identity=IDENTITY, phone=PHONE)
        assert len(provider.requests) == count


@pytest.mark.parametrize("endpoint", ["ContextConfig", "StartProcess", "SCValidateOTP"])
@pytest.mark.parametrize("failure", ["large", "html", "network"])
def test_bounded_responses_and_private_network_errors(endpoint, failure):
    provider = Provider()
    with harel.HarelLogin("email", transport=httpx.MockTransport(provider)) as session:
        session.open()
        if endpoint != "ContextConfig":
            session.select_channel()
        if endpoint == "SCValidateOTP":
            session.request_code(identity=IDENTITY, phone=PHONE)
        if failure == "network":
            def broken(request):
                raise httpx.ReadError("private " + IDENTITY + PHONE + CODE, request=request)
            replacement = broken
        else:
            replacement = httpx.Response(200, headers={"Content-Type": "application/json" if failure == "large" else "text/html"},
                                         content=b"x" * (harel.MAX_RESPONSE + 1) if failure == "large" else b"<html>private</html>")
        provider.replace[endpoint] = replacement
        actions = {"ContextConfig": session.select_channel,
                   "StartProcess": lambda: session.request_code(identity=IDENTITY, phone=PHONE),
                   "SCValidateOTP": lambda: session.submit_code(CODE)}
        with pytest.raises(AccessError) as caught:
            actions[endpoint]()
        assert all(secret not in str(caught.value) for secret in (IDENTITY, PHONE, CODE, "private"))


@pytest.mark.parametrize("current", [None, {}, True, "fixture", {"FirstName": "Fixture"},
                                      {"FirstName": "", "LastName": "Account"}])
def test_otp_success_alone_cannot_authenticate(current):
    provider = Provider()
    with requested(provider) as session:
        provider.replace["SCValidateOTP"] = response({"ProcessSuccess": "UserLoggedIn", "current": current})
        with pytest.raises(AccessError):
            session.submit_code(CODE)


@pytest.mark.parametrize("current", [None, {**USER, "LastName": "Different"}, "authenticated", {}])
def test_second_status_read_must_authenticate_the_same_session(current):
    provider = Provider()
    with requested(provider) as session:
        provider.replace["GetCurrentDetails"] = response({"current": current, "CurrentProcess": 0})
        with pytest.raises(AccessError):
            session.submit_code(CODE)


def test_code_and_identity_dispatch_are_once_only_and_window_bound(monkeypatch):
    now = [100.0]
    monkeypatch.setattr(harel.time, "monotonic", lambda: now[0])
    provider = Provider()
    with requested(provider) as session:
        now[0] += harel.WINDOW_SECONDS
        count = len(provider.requests)
        with pytest.raises(AccessError, match="login_code_window_expired"):
            session.submit_code(CODE)
        assert len(provider.requests) == count
    provider = Provider()
    with requested(provider) as session:
        assert session.submit_code(CODE) == {"authenticated": True}
        count = len(provider.requests)
        with pytest.raises(AccessError):
            session.submit_code(CODE)
        assert len(provider.requests) == count


def test_slow_code_request_does_not_extend_window(monkeypatch):
    now = [100.0]
    monkeypatch.setattr(harel.time, "monotonic", lambda: now[0])
    provider = Provider()
    with configured(provider) as session:
        def delayed(_):
            now[0] += harel.WINDOW_SECONDS
            return response({"ProcessSuccess": "OTPWasSent", "OTPChannel": 1})
        provider.replace["StartProcess"] = delayed
        with pytest.raises(AccessError, match="login_code_window_expired"):
            session.request_code(identity=IDENTITY, phone=PHONE)


@pytest.mark.parametrize("identity,phone", [(IDENTITY + "&extra=1", PHONE), ("", PHONE),
                                           (IDENTITY, PHONE + "\r\n"), (IDENTITY, None)])
def test_malformed_identity_stops_before_any_private_request(identity, phone):
    provider = Provider()
    with configured(provider) as session:
        count = len(provider.requests)
        with pytest.raises(AccessError):
            session.request_code(identity=identity, phone=phone)
        assert len(provider.requests) == count


@pytest.mark.parametrize("field,value", [("domain", "evil.invalid"), ("domain", []),
                                          ("name", "bad\r\nname"), ("value", "bad\nvalue"),
                                          ("path", "https://evil.invalid"), ("secure", "true"),
                                          ("expires", True)])
def test_stored_state_cannot_supply_arbitrary_cookies(field, value):
    cookie = {"name": "HarelAttempt", "value": "fixture", "domain": "www.harel-group.co.il",
              "path": "/", "secure": True, "expires": None, field: value}
    provider = Provider()
    with pytest.raises(AccessError, match="harel_session_changed"):
        harel.HarelLogin("email", state={"harel_cookies": [cookie]}, transport=httpx.MockTransport(provider))
    assert not provider.requests


def test_session_state_is_private_and_reusable():
    provider = Provider()
    with requested(provider) as session:
        assert session.submit_code(CODE) == {"authenticated": True}
        state = session.storage_state()
    with harel.HarelLogin("email", state=state, transport=httpx.MockTransport(provider)) as session:
        session.open()
        assert session.session_status() == {"authenticated": True}
    assert state["harel_cookies"][0]["value"] == "fixture"
    assert len([request for request in provider.requests if request.url.path.endswith("StartProcess")]) == 1


def test_populated_anonymous_status_cannot_create_an_owner_session():
    provider = Provider()
    provider.authenticated = True
    with harel.HarelLogin("email", transport=httpx.MockTransport(provider)) as session:
        session.open()
        with pytest.raises(AccessError, match="harel_session_marker_changed"):
            session.session_status()


def test_numeric_inactive_flags_and_ui_redirect_data_do_not_expand_requests():
    provider = Provider()
    provider.replace["StartProcess"] = response({"ProcessSuccess": "OTPWasSent", "OTPChannel": 1,
                                                  "details": {"SendOtpOnMount": False}, "Activation": 0})
    with requested(provider) as session:
        def verified(_):
            provider.authenticated = True
            return response({"ProcessSuccess": "UserLoggedIn", "current": USER,
                             "IsDecleration": 0, "Activation": 0, "EmailNeedsVerification": 0,
                             "redirect": True, "path": "https://unreviewed.invalid"})
        provider.replace["SCValidateOTP"] = verified
        assert session.submit_code(CODE) == {"authenticated": True}
    assert all(str(request.url).startswith(harel.ORIGIN + "/") for request in provider.requests)


@pytest.mark.parametrize("channel,method", [("email", "identity_phone_email"), ("sms", "identity_phone_sms")])
def test_owner_metadata_preserves_identity_shape_for_both_channels(channel, method):
    from account_access.account_context import describe
    from account_access.harel_login import configuration
    assert describe(configuration(channel))["login_method"] == method


@pytest.fixture
def adapter(tmp_path, monkeypatch):
    from account_access import harel_login
    from account_access.demo import DEMO_PASSWORD
    from account_access.factors import enroll
    from account_access.models import Configuration
    from account_access.verification_demo import environment

    with environment(tmp_path / "fixture") as (_, broker, mailbox):
        broker.store.new_client("test")
        provider = Provider()
        config = broker.store.config()
        config.accounts[harel_login.ACCOUNT] = harel_login.configuration("email")
        source = harel_login.SOURCES["email"]
        config.code_sources[source] = config.code_sources["example-email"].model_copy(deep=True)
        broker.store.configure(Configuration.model_validate(config.model_dump()))
        enroll(broker.store, source, {"username": "demo@example.test", "password": DEMO_PASSWORD})
        broker.store.put("credential:" + harel_login.ACCOUNT, {"identity": IDENTITY, "phone": PHONE})
        broker.grant("test", harel_login.ACCOUNT, ["status"])

        def transport(request):
            result = provider(request)
            if request.url.path.endswith("StartProcess") and result.status_code == 200:
                mailbox.deliver(CODE)
            return result

        monkeypatch.setattr(harel_login, "HarelLogin", lambda channel, state=None: harel.HarelLogin(
            channel, state=state, transport=httpx.MockTransport(transport)))
        yield broker, provider, mailbox, source


def test_guarded_adapter_reads_real_fixture_mailbox_reuses_then_recovers(adapter):
    from account_access.harel_login import ACCOUNT
    broker, provider, mailbox, source = adapter
    for attempt in range(2):
        result = broker.run("test", ACCOUNT, "status")
        assert result["status"] == "COMPLETED" and result["data"] == {"authenticated": True}
        assert all(secret not in json.dumps(result) for secret in (IDENTITY, PHONE, CODE, "Fixture"))
        assert broker.store.get("code-window:" + source) is None
        assert broker.run("test", ACCOUNT, "status")["status"] == "COMPLETED"
        assert mailbox.fetches == attempt + 1
        provider.authenticated = False
        broker.store.put("login-attempt:" + ACCOUNT, 0)
    assert len([r for r in provider.requests if r.url.path.endswith("StartProcess")]) == 2


@pytest.mark.parametrize("stage", ["before_request", "during_response"])
def test_source_revocation_refuses_private_dispatch_or_publication(adapter, stage):
    from account_access.factors import replace_source, source_mutation
    from account_access.harel_login import ACCOUNT
    broker, provider, _, source = adapter

    def revoke():
        with source_mutation(broker.store, source), broker.store.db() as db:
            replace_source(broker.store, source, {"enabled": False}, db=db)

    if stage == "before_request":
        revoke()
    else:
        def revoked_response(_):
            revoke()
            provider.authenticated = True
            return response({"ProcessSuccess": "UserLoggedIn", "current": USER})
        provider.replace["SCValidateOTP"] = revoked_response
    result = broker.run("test", ACCOUNT, "status")
    assert result["status"] == ("NEEDS_USER" if stage == "before_request" else "DENIED")
    assert broker.store.get("connection:" + ACCOUNT) is None
    assert broker.store.get("code-window:" + source) is None
    if stage == "before_request":
        assert not any(r.url.path.endswith("StartProcess") for r in provider.requests)


@pytest.mark.parametrize("mutation", ["url", "javascript", "data", "source", "post", "alias", "channel"])
def test_protocol_configuration_refuses_broader_authority(adapter, mutation):
    from pydantic import ValidationError
    from account_access.harel_login import ACCOUNT
    from account_access.models import Configuration
    broker, _, _, _ = adapter
    config = broker.store.config().model_dump()
    spec = config["accounts"][ACCOUNT]
    if mutation == "url":
        spec["login_url"] = "https://evil.invalid/login"
    elif mutation == "javascript":
        spec["javascript"] = True
    elif mutation == "data":
        spec["operations"]["status"]["session_only"] = False
        spec["operations"]["status"]["fields"] = {"policies": "body"}
    elif mutation == "source":
        spec["login"]["factors"]["email"]["code_source"] = "example-email"
    elif mutation == "post":
        spec["login_post_urls"].append(harel.API + "UpdateOtpChannel")
    elif mutation == "alias":
        spec["password_import_origins"] = [harel.ORIGIN]
    else:
        spec["login"]["factors"]["sms"] = spec["login"]["factors"]["email"]
    with pytest.raises(ValidationError):
        Configuration.model_validate(config)
