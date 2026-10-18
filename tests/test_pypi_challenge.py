"""Public provider configuration and fictional response-derived capabilities."""

from dataclasses import FrozenInstanceError
import json
from urllib.parse import parse_qs

import pyotp
from playwright.sync_api import Error as PlaywrightError, sync_playwright

import pytest

from account_access.catalog import PYPI_ACCOUNT, PYPI_SOURCE, add, include_sources, pypi
from account_access.errors import AccessError
from account_access.browser_network import ResponseGuard
from account_access.models import BrowserAccount, BrowserOperation, CodeSource, Configuration, LoginForm
from account_access import pypi_challenge as challenge


TOKEN = "eyJmaWN0aW9uYWwiOnRydWV9.ZmljdGlvbmFs." + "a" * 86
LOCATION = challenge.CHALLENGE_PATH + "?" + TOKEN


def spec_for(root="https://pypi.org"):
    spec = pypi()
    spec.login_url = spec.login_url.replace("https://pypi.org", root)
    spec.login_resources = [url.replace("https://pypi.org", root) for url in spec.login_resources]
    spec.login_post_urls = [spec.login_url]
    spec.operations["status"].url = root + challenge.STATUS_PATH
    return spec


def configuration(root="https://pypi.org"):
    return Configuration(test_mode=root.startswith("http://127.0.0.1:"),
        accounts={PYPI_ACCOUNT: spec_for(root)}, code_sources={PYPI_SOURCE: CodeSource(kind="totp")})


def observed(policy, attachment, chain="password-chain", *, frame="main", **changes):
    event = {"requestId": chain, "frameId": frame, "type": "Document",
             "request": {"url": policy.password_url, "method": "POST"}, **changes}
    policy.observe(event, attachment, "main")


def response(policy, source, **changes):
    policy.response(**{"url": policy.password_url, "method": "POST", "status": 303,
        "locations": [LOCATION], "attachment": source, "frame": "main", "chain": "password-chain",
        "kind": "document", "main_document": True, "hop": 0, **changes})


def acquired(*, clock=None):
    policy, attachment, secrets = challenge.PyPIChallenge(pypi(), secret_values=set(), clock=clock), object(), set()
    policy.secrets = secrets
    policy.arm_password()
    observed(policy, attachment)
    policy.dispatch(policy.password_url, "POST", attachment, True)
    response(policy, attachment)
    return policy, attachment, secrets


def test_reviewed_pypi_spec_allows_only_username_partial_and_native_password_totp():
    config = configuration()
    spec = config.accounts[PYPI_ACCOUNT]
    assert spec.javascript is False and spec.read_resources == []
    assert list(spec.operations) == ["status"]
    assert spec.operations["status"].url == "https://pypi.org" + challenge.STATUS_PATH
    assert spec.operations["status"].fields == {"username": challenge.READY}
    assert not any("manage/" in url for url in [*spec.login_resources, *spec.login_post_urls])
    assert spec.login.authenticator_source(config) == PYPI_SOURCE


@pytest.mark.parametrize("change", [
    lambda spec: setattr(spec, "login_url", "https://pypi.org.attacker.example" + challenge.LOGIN_PATH + "?" + challenge.LOGIN_QUERY),
    lambda spec: setattr(spec, "login_url", "http://pypi.org" + challenge.LOGIN_PATH + "?" + challenge.LOGIN_QUERY),
    lambda spec: setattr(spec, "login_url", "https://pypi.org/account/login/"),
    lambda spec: setattr(spec, "javascript", True),
    lambda spec: setattr(spec.login, "username_selector", "input"),
    lambda spec: setattr(spec.login, "submit_selector", "button"),
    lambda spec: setattr(spec.login.factors["totp"], "code_selector", "input"),
    lambda spec: spec.challenge_selectors.pop("device"),
    lambda spec: spec.login_post_urls.append("https://pypi.org/account/two-factor/"),
    lambda spec: spec.login_resources.append("https://pypi.org/manage/account/"),
    lambda spec: spec.operations["status"].fields.update(email="input[type=email]"),
    lambda spec: setattr(spec.operations["status"], "url", "https://pypi.org/manage/account/"),
])
def test_policy_cannot_be_repurposed_for_another_origin_form_factor_or_read(change):
    spec = pypi()
    change(spec)
    with pytest.raises(ValueError):
        Configuration(accounts={PYPI_ACCOUNT: spec}, code_sources={PYPI_SOURCE: CodeSource(kind="totp")})


def test_loopback_policy_requires_explicit_test_mode_and_same_reviewed_paths():
    config = configuration("http://127.0.0.1:12345")
    assert config.test_mode is True
    with pytest.raises(ValueError):
        Configuration(accounts=config.accounts, code_sources=config.code_sources)


@pytest.mark.parametrize("source", [
    CodeSource(kind="imap", host="imap.example.com", sender="login@example.com", recipient="fictional@example.com",
               subject="Login", template="Code: {code}"),
    CodeSource(kind="mac_messages", sender="12345", recipient="paired-messages", template="Code: {code}"),
])
def test_pypi_authenticator_factor_cannot_reference_mail_or_sms_source(source):
    with pytest.raises(ValueError, match="Verification method and source kind must match"):
        Configuration(accounts={PYPI_ACCOUNT: pypi()}, code_sources={PYPI_SOURCE: source})


def test_catalog_add_atomically_defines_but_does_not_enroll_enable_or_grant_source(env):
    _, broker, _ = env
    before = broker.store.config()
    add(broker.store, PYPI_ACCOUNT)
    config = broker.store.config()
    assert config.accounts.items() >= before.accounts.items()
    assert config.code_sources[PYPI_SOURCE] == CodeSource(kind="totp")
    assert broker.store.get("source:" + PYPI_SOURCE) is None
    assert broker.store.get("credential:" + PYPI_ACCOUNT) is None
    assert broker.run("test", PYPI_ACCOUNT, "status")["status"] == "DENIED"


def test_catalog_never_adopts_an_unrelated_existing_totp_source(env):
    _, broker, _ = env
    config = broker.store.config()
    config.code_sources[PYPI_SOURCE] = CodeSource(kind="totp")
    broker.store.configure(config)
    broker.store.put("source:" + PYPI_SOURCE, {"seed": "JBSWY3DPEHPK3PXP"})
    before = broker.store.config().model_dump()
    with pytest.raises(AccessError, match="catalog_code_source_conflict"):
        add(broker.store, PYPI_ACCOUNT)
    assert broker.store.config().model_dump() == before
    assert broker.store.get("source:" + PYPI_SOURCE) == {"seed": "JBSWY3DPEHPK3PXP"}


def test_catalog_preview_merge_is_local_and_existing_approved_source_keeps_definition():
    config = Configuration(accounts={})
    include_sources(config, {PYPI_ACCOUNT: pypi()})
    assert config.code_sources == {PYPI_SOURCE: CodeSource(kind="totp")}
    config.accounts[PYPI_ACCOUNT] = pypi()
    before = config.model_dump()
    include_sources(config, {PYPI_ACCOUNT: pypi()})
    assert config.model_dump() == before


def test_one_armed_response_mints_one_exact_transient_url_and_redacts_it_in_memory():
    policy, attachment, secrets = acquired()
    assert policy.url == "https://pypi.org" + LOCATION
    assert secrets == {TOKEN, policy.url}
    assert policy.permitted(policy.url, "GET", "document", attachment=attachment,
                            chain="password-chain", main_document=True)
    with pytest.raises(FrozenInstanceError):
        policy.password_proof.chain = "other"
    policy.clear()
    assert policy.url is None and policy.password_proof is None


@pytest.mark.parametrize("changes", [{"method": "GET"}, {"method": "HEAD"}, {"kind": "script"},
    {"main_document": False}, {"frame": "child"}, {"chain": "wrong-chain"}, {"attachment": object()}, {"hop": 1}])
def test_acquisition_requires_actual_attached_armed_main_document_password_chain(changes):
    policy, attachment = challenge.PyPIChallenge(pypi()), object()
    policy.arm_password()
    observed(policy, attachment)
    policy.dispatch(policy.password_url, "POST", attachment, True)
    try:
        response(policy, attachment, **changes)
    except AccessError:
        pass
    assert policy.url is None


@pytest.mark.parametrize("stage", ["unarmed", "no-network-proof", "not-dispatched"])
def test_response_alone_never_establishes_password_submission(stage):
    policy, attachment = challenge.PyPIChallenge(pypi()), object()
    if stage != "unarmed":
        policy.arm_password()
    if stage == "not-dispatched":
        observed(policy, attachment)
    if stage == "no-network-proof":
        policy.dispatch(policy.password_url, "POST", attachment, True)
    try:
        response(policy, attachment)
    except AccessError:
        pass
    assert policy.url is None


@pytest.mark.parametrize("status", [200, 301, 307, 308, 401, 500])
def test_only_302_or_303_can_create_capability(status):
    policy, attachment = challenge.PyPIChallenge(pypi()), object()
    policy.arm_password()
    observed(policy, attachment)
    policy.dispatch(policy.password_url, "POST", attachment, True)
    response(policy, attachment, status=status)
    assert policy.url is None


@pytest.mark.parametrize("location", [
    "/account/two-factor/?token=" + TOKEN, "/account/two-factor/?" + TOKEN + "&next=/",
    "/account/two-factor/?" + TOKEN + "#fragment", "/account/two-factor/?" + TOKEN + "%2f",
    "/account/two-factor/?" + TOKEN + "\n", "/account/two-factor/?" + "a" * 2049,
    "//attacker.example/account/two-factor/?" + TOKEN, "https://pypi.org.attacker.example" + LOCATION,
    "https://user:pass@pypi.org" + LOCATION, "/account/./two-factor/?" + TOKEN,
])
def test_opaque_whole_query_never_becomes_arbitrary_url_or_query_pattern(location):
    policy, attachment = challenge.PyPIChallenge(pypi()), object()
    policy.arm_password()
    observed(policy, attachment)
    policy.dispatch(policy.password_url, "POST", attachment, True)
    try:
        response(policy, attachment, locations=[location])
    except AccessError:
        pass
    assert policy.url is None


@pytest.mark.parametrize("method,kind,chain,main", [("HEAD", "document", "password-chain", True),
    ("GET", "image", "password-chain", True), ("GET", "document", "password-chain", False),
    ("GET", "document", None, True), ("GET", "document", "new-chain", True),
    ("POST", "document", "password-chain", True)])
def test_even_exact_capability_bytes_cannot_be_used_on_another_surface_or_phase(method, kind, chain, main):
    policy, attachment, _ = acquired()
    assert not policy.permitted(policy.url, method, kind, attachment=attachment, chain=chain, main_document=main)
    assert not policy.permitted(policy.url, "GET", "document", attachment=object(),
                                chain="password-chain", main_document=True)


def test_exact_code_form_gets_one_new_post_chain_and_failed_code_consumes_capability():
    policy, attachment, _ = acquired()
    url = policy.destination(policy.url)
    policy.arm_code(url)
    policy.observe({"requestId": "code-chain", "frameId": "main", "type": "Document",
                    "request": {"url": url, "method": "POST"}}, attachment, "main")
    policy.dispatch(url, "POST", attachment, True)
    assert policy.permitted(url, "POST", "document", attachment=attachment, chain="code-chain", main_document=True)
    response(policy, attachment, url=url, chain="code-chain", status=200, locations=[])
    assert policy.url is None and policy.phase == "closed"
    assert not policy.permitted(url, "POST", "document", attachment=attachment, chain="code-chain", main_document=True)


def test_expiry_clears_url_and_does_not_renew_when_code_is_armed():
    clock = [100.0]
    policy, attachment, _ = acquired(clock=lambda: clock[0])
    assert policy.expires == 220
    clock[0] = 219
    policy.arm_code(policy.url)
    assert policy.expires == 220
    clock[0] = 220
    assert not policy.permitted(policy.url, "POST", "document", attachment=attachment, main_document=True)
    assert policy.url is None


class _Session:
    def __init__(self):
        self.events, self.commands = {}, []

    def on(self, event, callback):
        self.events[event] = callback

    def send(self, command, args=None):
        self.commands.append(command)
        return ({"frameTree": {"frame": {"id": "main"}}} if command == "Page.getFrameTree"
                else {"body": "public fixture", "base64Encoded": False} if command == "Fetch.getResponseBody" else {})


def test_response_guard_records_network_chain_before_response_and_preserves_legacy_callback_contract():
    session = _Session()
    from types import SimpleNamespace
    # The real guard keys pages by identity; a simple hashable fake suffices.
    class Page:
        def on(self, *args):
            pass
    page = Page()
    policy = challenge.PyPIChallenge(pypi())
    guard = ResponseGuard(SimpleNamespace(new_cdp_session=lambda page: session),
        lambda url, method, kind, **proof: None if policy.permitted(url, method, kind, **proof) else "destination",
        lambda *args: pytest.fail("valid fixture must pass"), lambda *args: None, proof=policy)
    guard.attach(page)
    assert session.commands == ["Page.getFrameTree", "Network.enable", "Fetch.enable"]
    policy.arm_password()
    session.events["Network.requestWillBeSent"]({"requestId": "password-chain", "frameId": "main", "type": "Document",
                                                "request": {"url": policy.password_url, "method": "POST"}})
    policy.dispatch(policy.password_url, "POST", session, True)
    event = {"requestId": "paused-request", "networkId": "password-chain", "frameId": "main",
        "request": {"url": policy.password_url, "method": "POST"}, "resourceType": "Document", "responseStatusCode": 303,
        "responseHeaders": [{"name": "Location", "value": LOCATION}]}
    session.events["Fetch.requestPaused"](event)
    assert policy.url == "https://pypi.org" + LOCATION and session.commands[-1] == "Fetch.continueResponse"
    calls = []
    legacy = ResponseGuard(None, lambda url, method, kind: calls.append((url, method, kind)),
                           lambda *args: pytest.fail("legacy public response"), lambda *args: None)
    legacy.paused(session, {}, {**event, "request": {"url": "https://example.com/", "method": "GET"},
                               "responseStatusCode": 200, "responseHeaders": []})
    assert calls == [("https://example.com/", "GET", "document")]


@pytest.mark.parametrize("status", [200, 302, 303, 307])
def test_response_guard_rejects_duplicate_raw_location_headers_before_acquisition_or_follow(status):
    session, failures, responses = _Session(), [], []
    guard = ResponseGuard(None, lambda *args: None, lambda *args: failures.append(args), lambda *args: responses.append(args))
    guard.paused(session, {}, {"requestId": "paused", "request": {"url": "https://example.com/", "method": "GET"},
        "resourceType": "Document", "responseStatusCode": status,
        "responseHeaders": [{"name": "Location", "value": LOCATION}, {"name": "lOcAtIoN", "value": "/other"}]})
    assert responses == [] and session.commands == ["Fetch.failRequest"]
    assert failures == [("https://example.com/", "GET", "destination", "document", False)]


def test_non_pypi_config_and_explicit_none_have_identical_existing_fingerprint():
    spec = BrowserAccount(kind="browser", label="Example", login_url="https://example.com/login",
        ready_selector="#ready", login=LoginForm(username_selector="#u", password_selector="#p", submit_selector="#s"),
        operations={"status": BrowserOperation(description="Read status", url="https://example.com/status", fields={"status": "#ready"})})
    config = Configuration(accounts={"example": spec})
    fingerprint = config.fingerprint("example")
    # Recorded from the pre-policy model, including its legacy omitted fields.
    assert fingerprint == "07a94276f05984554cefad3354896677b410eb5859825a883bb0441360b1f925"
    value = config.model_dump()
    value["accounts"]["example"].pop("login_challenge")
    assert Configuration.model_validate(value).fingerprint("example") == fingerprint
    assert json.loads(config.model_dump_json())["accounts"]["example"]["login_challenge"] is None


@pytest.fixture
def pypi_fixture(env):
    provider, broker, _ = env
    parent = provider.server.RequestHandlerClass
    state = {"mode": "totp", "passwords": 0, "totps": 0, "challenge_gets": 0, "unexpected": []}
    seed = "JBSWY3DPEHPK3PXP"
    login_path = challenge.LOGIN_PATH + "?" + challenge.LOGIN_QUERY

    class Handler(parent):
        def do_GET(self):
            if self.path == login_path:
                override = " formaction='" + challenge.STATUS_PATH + "'" if state["mode"] == "password-override" else ""
                self.page("<form id='login-form' method='post' action='" + login_path + "'>"
                    "<input name='csrf_token' type='hidden' value='fictional-csrf'>"
                    "<input name='username' id='username'><input name='password' id='password' type='password'>"
                    "<input type='submit' value='Log in'" + override + "></form>")
            elif self.path == challenge.STATUS_PATH:
                if self.cookie("pypi_fixture") == "connected":
                    self.page("<div id='user-indicator'><nav><button class='dropdown__trigger'><img class='user-image'>fictional-owner</button>"
                              "</nav></div><p>Unselected provider data</p>")
                else:
                    self.page("<a href='/account/login/'>Log in</a>")
            elif self.path == LOCATION:
                state["challenge_gets"] += 1
                if state["mode"] == "passkey":
                    self.page("<div class='twofa-login'><form id='webauthn-auth-form'><button disabled>Authenticate</button></form></div>")
                elif state["mode"] == "recovery":
                    self.page("<form method='post'><input name='recovery_code_value' id='recovery_code_value'></form>")
                else:
                    action = login_path if state["mode"] == "code-form-changed" else LOCATION
                    self.page("<div class='twofa-login'><form id='webauthn-auth-form'><button disabled>Authenticate</button></form>"
                        "<form id='totp-auth-form' method='post' action='" + action + "'>"
                        "<input name='csrf_token' type='hidden' value='fictional-csrf'>"
                        "<input name='method' type='hidden' value='totp'>"
                        "<input name='totp_value' id='totp_value' inputmode='numeric'>"
                        "<input type='submit' value='Verify'></form></div>"
                        "<div class='twofa-recovery'><a href='/account/recovery-code/?" + TOKEN + "'>Login using recovery codes</a></div>")
            elif self.path == challenge.DEVICE_PATH:
                self.page("<h1 class='page-title'>Please confirm this login</h1><p>Fictional device confirmation.</p>")
            else:
                state["unexpected"].append(("GET", self.path))
                self.send(404, {})

        def do_POST(self):
            fields = parse_qs(self.rfile.read(int(self.headers.get("Content-Length", "0"))).decode())
            if self.path == login_path:
                state["passwords"] += 1
                assert fields == {"csrf_token": ["fictional-csrf"], "username": ["fictional-owner"], "password": ["fictional-password"]}
                if state["mode"] == "remembered":
                    self.send(303, {}, {"Location": challenge.STATUS_PATH, "Set-Cookie": "pypi_fixture=connected; Path=/; HttpOnly"})
                elif state["mode"] == "duplicate-location":
                    self.send_response(303)
                    self.send_header("Location", LOCATION)
                    self.send_header("Location", "https://attacker.example/never")
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                else:
                    location = LOCATION + "&unreviewed=yes" if state["mode"] == "bad-query" else LOCATION
                    self.send(307 if state["mode"] == "replay" else 303, {}, {"Location": location})
            elif self.path == LOCATION:
                state["totps"] += 1
                assert pyotp.TOTP(seed).verify(fields.pop("totp_value")[0], valid_window=1)
                assert fields == {"csrf_token": ["fictional-csrf"], "method": ["totp"]}
                if state["mode"] == "device":
                    self.send(303, {}, {"Location": challenge.DEVICE_PATH})
                elif state["mode"] == "rejected-code":
                    self.page("<form id='totp-auth-form' method='post' action='" + LOCATION + "'>"
                        "<input name='totp_value' id='totp_value'><input type='submit'></form>")
                else:
                    self.send(303, {}, {"Location": challenge.STATUS_PATH, "Set-Cookie": "pypi_fixture=connected; Path=/; HttpOnly"})
            else:
                state["unexpected"].append(("POST", self.path))
                self.send(400, {})

    provider.server.RequestHandlerClass = Handler
    config = broker.store.config()
    spec = spec_for(provider.base)
    spec.state_timeout_ms = 100
    config.accounts["pypi-fixture"] = spec
    config.code_sources[PYPI_SOURCE] = CodeSource(kind="totp")
    broker.store.configure(Configuration.model_validate(config.model_dump()))
    broker.store.put("credential:pypi-fixture", {"username": "fictional-owner", "password": "fictional-password"})
    broker.store.put("source:" + PYPI_SOURCE, {"seed": seed})
    broker.grant("test", "pypi-fixture", ["status"])
    return provider, broker, spec, state


@pytest.mark.parametrize("mode", ["totp", "remembered"])
def test_fictional_native_password_totp_and_saved_session_reuse(pypi_fixture, mode):
    _provider, broker, _spec, state = pypi_fixture
    state["mode"] = mode
    result = broker.run("test", "pypi-fixture", "status")
    assert result["status"] == "COMPLETED" and result["data"] == {"username": "fictional-owner"}
    assert state["passwords"] == 1 and state["totps"] == (mode == "totp")
    assert broker.run("test", "pypi-fixture", "status")["status"] == "COMPLETED"
    assert state["passwords"] == 1 and state["totps"] == (mode == "totp")
    assert state["unexpected"] == []
    assert TOKEN not in json.dumps(result)
    with broker.store.db() as db:
        events = [dict(row) for row in db.execute("SELECT * FROM audit")]
    assert TOKEN not in json.dumps(events)


@pytest.mark.parametrize("mode,kind,passwords,totps", [
    ("passkey", "passkey", 1, 0), ("recovery", "recovery", 1, 0), ("device", "device", 1, 1),
    ("code-form-changed", "unknown", 1, 0), ("password-override", "unknown", 0, 0),
    ("rejected-code", "totp", 1, 1),
])
def test_provider_presence_changed_forms_and_rejected_codes_never_become_success(pypi_fixture, mode, kind, passwords, totps):
    _provider, broker, _spec, state = pypi_fixture
    state["mode"] = mode
    result = broker.run("test", "pypi-fixture", "status")
    assert result["status"] == "NEEDS_USER" and result["challenge"]["kind"] == kind
    assert state["passwords"] == passwords and state["totps"] == totps and state["unexpected"] == []
    assert not broker.store.get("connection:pypi-fixture")
    assert TOKEN not in json.dumps(result)


@pytest.mark.parametrize("mode", ["bad-query", "duplicate-location", "replay"])
def test_invalid_redirect_query_duplicate_headers_or_password_replay_stops_before_code(pypi_fixture, mode):
    _provider, broker, _spec, state = pypi_fixture
    state["mode"] = mode
    result = broker.run("test", "pypi-fixture", "status")
    assert result["status"] == "NEEDS_USER" and result["reason"] == "login_challenge_changed"
    assert state["passwords"] == 1 and state["totps"] == 0 and state["challenge_gets"] == 0
    assert state["unexpected"] == [] and TOKEN not in json.dumps(result)


def test_no_source_means_no_password_or_identity_request(pypi_fixture):
    _provider, broker, _spec, state = pypi_fixture
    broker.store.put("source:" + PYPI_SOURCE, None)
    result = broker.run("test", "pypi-fixture", "status")
    assert result["status"] == "NEEDS_USER"
    assert state["passwords"] == state["totps"] == 0
    assert not broker.store.get("login-attempt:pypi-fixture")


def test_generic_manual_setup_refused_before_any_browser_launch(pypi_fixture, monkeypatch):
    _provider, broker, _spec, state = pypi_fixture
    monkeypatch.setattr("account_access.browser.sync_playwright", lambda: pytest.fail("unsupported setup must not launch"))
    with pytest.raises(AccessError, match="pypi_manual_setup_unavailable"):
        broker.browser.connect("pypi-fixture")
    assert state["passwords"] == state["totps"] == 0


def test_capability_cannot_be_reused_by_iframe_fetch_head_or_new_navigation(pypi_fixture):
    provider, broker, spec, state = pypi_fixture
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(chromium_sandbox=True)
        try:
            context = broker.browser.context(browser, spec, login=True)
            page = broker.browser.page(context)
            page.goto(spec.login_url)
            page.locator(challenge.USERNAME).fill("fictional-owner")
            page.locator(challenge.PASSWORD).fill("fictional-password")
            context._login_challenge.arm_password()
            page.locator(challenge.PASSWORD_SUBMIT).click()
            assert page.url == provider.base + LOCATION
            for script in [
                "url => {let frame=document.createElement('iframe');frame.src=url;document.body.append(frame)}",
                "url => fetch(url).catch(() => {})", "url => fetch(url,{method:'HEAD'}).catch(() => {})",
            ]:
                page.evaluate(script, provider.base + LOCATION)
                page.wait_for_timeout(100)
            with pytest.raises(PlaywrightError):
                page.goto(provider.base + LOCATION)
            assert state["challenge_gets"] == 1 and state["totps"] == 0 and state["unexpected"] == []
        finally:
            browser.close()

