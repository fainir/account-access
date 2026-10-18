"""Fictional PyPI device mail; no private accounts or real confirmation links."""

import base64
import json
import time
import zlib
from contextlib import contextmanager
from datetime import datetime, timezone
from email.message import EmailMessage
from urllib.parse import parse_qs

import pyotp
import pytest

from account_access import pypi_challenge as challenge
from account_access import pypi_device as device
from account_access.catalog import PYPI_SOURCE, pypi
from account_access.demo import connect_demo
from account_access.errors import AccessError
from account_access.factors import enroll
from account_access.models import CodeSource, Configuration

USER = "11111111-1111-4111-8111-111111111111"
OTHER = "22222222-2222-4222-8222-222222222222"
DEVICE = "33333333-3333-4333-8333-333333333333"
SOURCE = "pypi-device-mail"


def encoded(value):
    return base64.urlsafe_b64encode(value).decode().rstrip("=")


def token(data, *, stamp=None, compressed=False, raw=None):
    raw = json.dumps(data, separators=(",", ":")).encode() if raw is None else raw
    payload = "." + encoded(zlib.compress(raw)) if compressed else encoded(raw)
    return payload + "." + encoded(int(stamp or time.time()).to_bytes(4, "big")) + "." + "a" * 86


def confirmation(**changes):
    return {"action": "login-confirmation", "user.id": USER,
            "user.last_login": "2026-10-01 00:00:00+00:00", "unique_login_id": DEVICE, **changes}


def source(kind="gmail"):
    return CodeSource(kind=kind, message_purpose=device.PURPOSE, sender=device.SENDER,
        recipient="fictional@example.test", subject=device.SUBJECT,
        **({"account": "demo-api"} if kind == "gmail" else {"host": "imap.example.test"}))


def mail(value, **headers):
    message = EmailMessage()
    for name, item in {"From": device.SENDER, "To": "fictional@example.test", "Subject": device.SUBJECT, **headers}.items():
        message[name] = item
    message.set_content(device.PREFIX + device.CONFIRM_URL + value
        + "\n\nThis login attempt was made from:\n- IP address: 203.0.113.42"
        + "\n- Location: Fictional location\n- User agent: Fictional browser" + device.SUFFIX)
    return message.as_bytes()


@pytest.mark.parametrize("compressed", [False, True])
def test_reviewed_mail_and_token_bind_user_action_timestamp_without_claiming_signature_validation(compressed):
    started = time.time() - 1
    value = token(confirmation(), compressed=compressed)
    assert device.confirmation_link(mail(value), source(), USER, started) == device.CONFIRM_URL + value
    assert device.password_user(token({"userid": USER, "redirect_to": challenge.STATUS_PATH}, compressed=compressed)) == USER


@pytest.mark.parametrize("case", ["wrong-user", "wrong-action", "old-token", "future-token", "duplicate", "type",
                                  "extra", "bad-device", "zip-bomb", "query", "sender", "subject", "recipient", "html-only"])
def test_mail_cannot_be_a_different_account_action_message_or_unbounded_token(case):
    started = time.time() - 1
    data, changes, stamp, raw, compressed = confirmation(), {}, None, None, False
    if case == "wrong-user":
        data["user.id"] = OTHER
    if case == "wrong-action":
        data["action"] = "password-reset"
    if case in {"old-token", "future-token"}:
        stamp = time.time() + (100 if case == "future-token" else -100)
    if case == "duplicate":
        raw = ('{"action":"login-confirmation","user.id":"' + USER + '","user.id":"' + OTHER + '"}').encode()
    if case == "type":
        data["user.id"] = [USER]
    if case == "extra":
        data["unreviewed"] = "value"
    if case == "bad-device":
        data["unique_login_id"] = "1"
    if case == "zip-bomb":
        raw, compressed = b"a" * 200000, True
    for name in ["sender", "subject", "recipient"]:
        if case == name:
            changes[{"sender": "From", "subject": "Subject", "recipient": "To"}[name]] = "unreviewed@example.test"
    value = token(data, stamp=stamp, raw=raw, compressed=compressed)
    raw_mail = mail(value + "&next=/manage/account/" if case == "query" else value, **changes)
    if case == "html-only":
        message = EmailMessage()
        message["From"], message["To"], message["Subject"] = device.SENDER, "fictional@example.test", device.SUBJECT
        message.set_content("<a href='" + device.CONFIRM_URL + value + "'>Confirm</a>", subtype="html")
        raw_mail = message.as_bytes()
    assert device.confirmation_link(raw_mail, source(), USER, started) is None


@pytest.fixture
def device_browser(env, monkeypatch, request):
    provider, broker, _ = env
    parent = provider.server.RequestHandlerClass
    state = {"passwords": 0, "totps": 0, "confirmations": 0, "projects": 0, "mail": None,
             "mode": "success", "mail_reads": [], "status_reads": 0, "imap_hook": lambda event: None}
    kind = getattr(request, "param", "gmail")
    seed = "JBSWY3DPEHPK3PXP"
    login = challenge.LOGIN_PATH + "?" + challenge.LOGIN_QUERY

    class Handler(parent):
        def do_GET(self):
            if self.path == login:
                self.page("<form id='login-form' method='post' action='" + login + "'>"
                    "<input id='username' name='username'><input id='password' name='password' type='password'>"
                    "<input type='submit'></form>")
            elif self.path == challenge.STATUS_PATH:
                state["status_reads"] += 1
                if self.cookie("pypi_fixture") == "connected":
                    self.page("<div id='user-indicator'><nav><button class='dropdown__trigger'>"
                              "<img class='user-image'>fictional-owner</button></nav></div>")
                else:
                    self.page("<a href='/account/login/'>Log in</a>")
            elif self.path == state.get("totp_path"):
                self.page("<form id='totp-auth-form' method='post' action='" + self.path + "'>"
                    "<input type='hidden' name='method' value='totp'><input id='totp_value' name='totp_value'>"
                    "<input type='submit'></form>")
            elif self.path == challenge.DEVICE_PATH:
                self.page("<h1 class='page-title'>Please confirm this login</h1>")
            elif self.path.startswith(challenge.DEVICE_PATH + "?token="):
                state["confirmations"] += 1
                assert self.path == challenge.DEVICE_PATH + "?token=" + state["email_token"]
                destination = "/manage/account/" if state["mode"] == "wrong-landing" else device.PROJECTS_PATH
                self.send(307 if state["mode"] == "replay" else 303, {}, {
                    "Location": destination, "Set-Cookie": "pypi_fixture=connected; Path=/; HttpOnly"})
            elif self.path == device.PROJECTS_PATH:
                state["projects"] += 1
                self.page("<p>Must never fetch private project data</p>")
            else:
                super().do_GET()

        def do_POST(self):
            if self.path != login and self.path != state.get("totp_path"):
                return super().do_POST()
            fields = parse_qs(self.rfile.read(int(self.headers.get("Content-Length", "0"))).decode())
            if self.path == login:
                state["passwords"] += 1
                assert fields == {"username": ["fictional-owner"], "password": ["fictional-password"]}
                state["totp_path"] = challenge.CHALLENGE_PATH + "?" + token({"userid": USER, "redirect_to": challenge.STATUS_PATH})
                self.send(303, {}, {"Location": state["totp_path"]})
            elif self.path == state.get("totp_path"):
                state["totps"] += 1
                assert pyotp.TOTP(seed).verify(fields["totp_value"][0], valid_window=1)
                state["email_token"] = token(confirmation())
                state["mail"] = mail(state["email_token"])
                self.send(303, {}, {"Location": challenge.DEVICE_PATH})
            else:
                self.send(400, {})

    provider.server.RequestHandlerClass = Handler
    config = broker.store.config()
    config.accounts["demo-api"].scopes.append("https://www.googleapis.com/auth/gmail.readonly")
    spec = pypi()
    spec.login_url = spec.login_url.replace("https://pypi.org", provider.base)
    spec.login_post_urls = [spec.login_url]
    spec.login_resources = [value.replace("https://pypi.org", provider.base) for value in spec.login_resources]
    spec.operations["status"].url = provider.base + challenge.STATUS_PATH
    spec.login.device_email_source = SOURCE
    spec.login.code_wait_ms, spec.state_timeout_ms = 5000, 100
    config.accounts["pypi-device"] = spec
    config.code_sources.update({PYPI_SOURCE: CodeSource(kind="totp"), SOURCE: source(kind)})
    broker.store.configure(Configuration.model_validate(config.model_dump()))
    connect_demo(broker)
    enroll(broker.store, SOURCE, {} if kind == "gmail" else {"username": "fictional@example.test", "password": "fictional-mail-password"})
    broker.store.put("credential:pypi-device", {"username": "fictional-owner", "password": "fictional-password"})
    enroll(broker.store, PYPI_SOURCE, {"seed": seed})
    broker.grant("test", "pypi-device", ["status"])

    def get(url, **kwargs):
        if url.endswith("/messages"):
            return {"messages": [{"id": "fresh"}]} if state["mail"] else {}
        state["mail_reads"].append(url.rsplit("/", 1)[1])
        return {"id": "fresh", "internalDate": str(int(time.time() * 1000)), "raw": encoded(state["mail"])}
    monkeypatch.setattr("account_access.codes.get_json", get)
    class Mailbox:
        def response(self, name):
            state["imap_hook"](name)
            return name, [b"1" if name == "UIDVALIDITY" else b"10"]

        def uid(self, command, *args):
            if command == "SEARCH":
                return "OK", [b"10" if state["mail"] else b""]
            state["imap_hook"]("FETCH")
            state["mail_reads"].append("fresh")
            date = datetime.now(timezone.utc).strftime('%d-%b-%Y %H:%M:%S +0000')
            return "OK", [(b'1 (UID 10 INTERNALDATE "' + date.encode() + b'" BODY[] {100}', state["mail"]), b")"]

    @contextmanager
    def mailbox(*args):
        yield Mailbox()
    if kind == "imap":
        monkeypatch.setattr(broker.codes, "mailbox", mailbox)
    return provider, broker, spec, state


@pytest.mark.parametrize("device_browser", ["gmail", "imap"], indirect=True)
def test_password_totp_fresh_email_confirmation_preserves_cookie_blocks_projects_and_reuses_session(device_browser):
    _, broker, _, state = device_browser
    result = broker.run("test", "pypi-device", "status")
    assert result["status"] == "COMPLETED", result
    assert result["data"] == {"username": "fictional-owner"}
    assert state["passwords"] == state["totps"] == state["confirmations"] == 1
    assert state["projects"] == 0 and state["mail_reads"] == ["fresh"]
    assert broker.run("test", "pypi-device", "status")["status"] == "COMPLETED"
    assert state["passwords"] == state["totps"] == state["confirmations"] == 1
    assert broker.store.get("code-window:" + SOURCE) is None
    assert state["email_token"] not in json.dumps(result)


@pytest.mark.parametrize("mode", ["wrong-landing", "replay"])
def test_confirmation_cannot_follow_another_account_page_or_replay_redirect(device_browser, mode):
    _, broker, _, state = device_browser
    state["mode"] = mode
    result = broker.run("test", "pypi-device", "status")
    assert result["status"] == "NEEDS_USER", result
    assert state["projects"] == 0 and state["confirmations"] == 1
    assert state["email_token"] not in json.dumps(result)


def observed(policy, session, url, method, chain):
    policy.observe({"requestId": chain, "frameId": "main", "type": "Document",
                    "request": {"url": url, "method": method}}, session, "main")


def response(policy, session, url, method, chain, **changes):
    policy.response(**{"url": url, "method": method, "chain": chain, "attachment": session, "frame": "main",
                       "kind": "document", "main_document": True, "status": 303, "locations": [], "hop": 0, **changes})


def waiting_policy(*, clock=None):
    spec, session, secrets = pypi(), object(), set()
    spec.login.device_email_source = SOURCE
    policy = challenge.PyPIChallenge(spec, clock=clock, secret_values=secrets)
    policy.arm_password()
    observed(policy, session, policy.password_url, "POST", "password")
    policy.dispatch(policy.password_url, "POST", session, True)
    path = challenge.CHALLENGE_PATH + "?" + token({"userid": USER})
    response(policy, session, policy.password_url, "POST", "password", locations=[path])
    code_url = policy.url
    policy.arm_code(code_url)
    observed(policy, session, code_url, "POST", "code")
    policy.dispatch(code_url, "POST", session, True)
    response(policy, session, code_url, "POST", "code", locations=[challenge.DEVICE_PATH])
    response(policy, session, policy.origin + challenge.DEVICE_PATH, "GET", "code", status=200, hop=1)
    return policy, session, secrets


def terminal_policy(*, clock=None):
    policy, session, secrets = waiting_policy(clock=clock)
    value = token(confirmation())
    url = policy.arm_device(policy.origin + challenge.DEVICE_PATH, device.CONFIRM_URL + value, time.time() - 1)
    observed(policy, session, url, "GET", "email")
    policy.dispatch(url, "GET", session, True)
    response(policy, session, url, "GET", "email", locations=[device.PROJECTS_PATH])
    return policy, session, secrets, value


@pytest.mark.parametrize("change", [
    {"attachment": object()}, {"frame": "child"}, {"chain": "other"}, {"method": "POST"},
    {"main_document": False}, {"hop": 0}, {"hop": 2}, {"url": "https://pypi.org/manage/projects/?other=yes"},
])
def test_terminal_proof_never_accepts_other_session_frame_chain_verb_hop_or_url(change):
    policy, session, _, _ = terminal_policy()
    args = {"url": policy.terminal_url, "method": "GET", "attachment": session, "frame": "main",
            "chain": "email", "main_document": True, "hop": 1, **change}
    if args["url"] != policy.terminal_url:
        assert policy.intercept_terminal(**args) is False
    else:
        with pytest.raises(AccessError, match="login_challenge_changed"):
            policy.intercept_terminal(**args)
    assert policy.phase != "confirmed"


def test_unarmed_projects_request_cannot_claim_confirmation_and_terminal_proof_is_one_use():
    policy, session, _ = waiting_policy()
    args = {"url": policy.terminal_url, "method": "GET", "attachment": session, "frame": "main",
            "chain": "email", "main_document": True, "hop": 1}
    with pytest.raises(AccessError, match="login_challenge_changed"):
        policy.intercept_terminal(**args)
    policy, session, secrets, value = terminal_policy()
    args["attachment"] = session
    assert policy.intercept_terminal(**args) is True
    assert policy.phase == "confirmed" and value in secrets
    with pytest.raises(AccessError, match="login_challenge_changed"):
        policy.intercept_terminal(**args)


def test_email_step_never_extends_original_password_lifetime():
    now = [10.0]
    policy, session, _, _ = terminal_policy(clock=lambda: now[0])
    assert policy.expires == 130
    now[0] = 130
    with pytest.raises(AccessError, match="login_challenge_changed"):
        policy.intercept_terminal(url=policy.terminal_url, method="GET", attachment=session, frame="main",
                                  chain="email", main_document=True, hop=1)


@pytest.mark.parametrize("case", ["unbound-account", "numeric-resolver", "revoked", "generation", "oauth", "during-fetch"])
def test_device_mail_resolver_requires_current_bound_authority_before_and_after_delivery(device_browser, monkeypatch, case):
    _, broker, _, state = device_browser
    started = time.time() - 1
    if case == "unbound-account":
        with pytest.raises(AccessError, match="login_code_source_changed"):
            broker.codes.begin(SOURCE, "demo-web", started)
        assert state["mail_reads"] == []
        return
    broker.codes.begin(SOURCE, "pypi-device", started)
    state["mail"] = mail(token(confirmation()))
    if case == "revoked":
        broker.store.put("source:" + SOURCE, {"enabled": False})
    elif case == "generation":
        enroll(broker.store, SOURCE, {})
    elif case == "oauth":
        broker.store.put("connection:demo-api", None)
    elif case == "during-fetch":
        from account_access import codes
        original = codes.get_json
        def revoke_after_fetch(url, **kwargs):
            result = original(url, **kwargs)
            if not url.endswith("/messages"):
                broker.store.put("source:" + SOURCE, {"enabled": False})
            return result
        monkeypatch.setattr(codes, "get_json", revoke_after_fetch)
    used = set()
    with pytest.raises(AccessError):
        broker.codes.resolve(SOURCE, started, used, **({} if case == "numeric-resolver" else {"pypi_user": USER}))
    assert used == set()
    assert len(state["mail_reads"]) == (1 if case == "during-fetch" else 0)
    assert state["confirmations"] == state["projects"] == 0


def test_device_gmail_baseline_excludes_old_messages_and_stops_on_two_fresh_matches(device_browser, monkeypatch):
    _, broker, _, state = device_browser
    ids, reads = ["old"], []
    raw = mail(token(confirmation()))
    def get(url, **kwargs):
        if url.endswith("/messages"):
            return {"messages": [{"id": ident} for ident in ids]}
        ident = url.rsplit("/", 1)[1]
        reads.append(ident)
        return {"id": ident, "internalDate": str(int((time.time() + 2) * 1000)), "raw": encoded(raw)}
    monkeypatch.setattr("account_access.codes.get_json", get)
    started = time.time() - 1
    broker.codes.begin(SOURCE, "pypi-device", started)
    assert broker.codes.resolve(SOURCE, started, set(), pypi_user=USER) is None
    assert reads == []
    ids[:] = ["old", "fresh-one", "fresh-two"]
    with pytest.raises(AccessError, match="ambiguous_login_code"):
        broker.codes.resolve(SOURCE, started, set(), pypi_user=USER)
    assert reads == ["fresh-one", "fresh-two"]
    assert state["confirmations"] == state["projects"] == 0


@pytest.mark.parametrize("change", [
    {"kind": "totp"}, {"sender": "other@example.test"}, {"subject": "Verify email"},
    {"template": "Code: {code}"}, {"recipient": "fictional@example.test other"},
])
def test_source_purpose_cannot_be_a_generic_code_or_another_message(change):
    value = source().model_dump()
    value.update(change)
    with pytest.raises(ValueError):
        CodeSource.model_validate(value)


def test_explicit_device_binding_changes_only_the_selected_connector_grant(device_browser):
    _, broker, _, _ = device_browser
    config = broker.store.config()
    original = config.fingerprint("pypi-device")
    other = config.fingerprint("demo-web")
    config.accounts["pypi-device"].login.device_email_source = None
    checked = Configuration.model_validate(config.model_dump())
    assert checked.fingerprint("pypi-device") != original
    assert checked.fingerprint("demo-web") == other
    checked.accounts["demo-web"].login.device_email_source = SOURCE
    with pytest.raises(ValueError, match="bound only"):
        Configuration.model_validate(checked.model_dump())


@pytest.mark.parametrize("kind", ["gmail", "imap"])
def test_device_source_cannot_supply_a_numeric_email_factor_or_legacy_source(device_browser, kind):
    _, broker, _, _ = device_browser
    config = broker.store.config()
    config.code_sources[SOURCE] = source(kind)
    config.accounts["demo-mfa"].login.code_source = SOURCE
    with pytest.raises(ValueError, match="cannot supply a numeric code"):
        Configuration.model_validate(config.model_dump())


@pytest.mark.parametrize("device_browser", ["gmail", "imap"], indirect=True)
@pytest.mark.parametrize("stage", ["baseline", "read"])
def test_account_source_binding_change_during_mailbox_io_stops_publication_or_late_result(device_browser, monkeypatch, stage):
    _, broker, _, state = device_browser
    before = broker.store.config().code_sources[SOURCE].model_dump()
    generation = broker.store.get("source-generation:" + SOURCE)
    kind = before["kind"]
    changed = []

    def unbind():
        if changed:
            return
        config = broker.store.config()
        config.accounts["pypi-device"].login.device_email_source = None
        broker.store.configure(config)
        changed.append(True)

    if kind == "gmail":
        from account_access import codes
        original = codes.get_json
        def get(url, **kwargs):
            result = original(url, **kwargs)
            if (stage == "baseline" and url.endswith("/messages")) or (stage == "read" and not url.endswith("/messages")):
                unbind()
            return result
        monkeypatch.setattr(codes, "get_json", get)
    else:
        state["imap_hook"] = lambda event: unbind() if event == ("UIDNEXT" if stage == "baseline" else "FETCH") else None
    started, used = time.time() - 1, set()
    if stage == "baseline":
        with pytest.raises(AccessError, match="login_code_source_changed"):
            broker.codes.begin(SOURCE, "pypi-device", started)
        assert broker.store.get("code-window:" + SOURCE) is None
    else:
        broker.codes.begin(SOURCE, "pypi-device", started)
        state["mail"] = mail(token(confirmation()))
        with pytest.raises(AccessError, match="login_code_source_changed"):
            broker.codes.resolve(SOURCE, started, used, pypi_user=USER)
    assert changed == [True] and used == set()
    assert broker.store.config().code_sources[SOURCE].model_dump() == before
    assert broker.store.get("source-generation:" + SOURCE) == generation
    assert state["passwords"] == state["confirmations"] == state["projects"] == 0


@pytest.mark.parametrize("device_browser", ["gmail", "imap"], indirect=True)
def test_available_device_mail_cannot_replace_missing_totp_or_read_its_baseline(device_browser, monkeypatch):
    _, broker, _, state = device_browser
    broker.store.put("source:" + PYPI_SOURCE, None)
    def forbidden(*args, **kwargs):
        pytest.fail("Missing primary TOTP attempted optional mailbox access")
    monkeypatch.setattr(broker.codes, "gmail_reader", forbidden)
    monkeypatch.setattr(broker.codes, "mailbox", forbidden)
    result = broker.run("test", "pypi-device", "status")
    assert result["status"] == "NEEDS_USER" and result["reason"] == "authenticator_not_enrolled", result
    assert state["passwords"] == state["totps"] == state["confirmations"] == state["projects"] == 0
    assert state["mail_reads"] == [] and broker.store.get("code-window:" + SOURCE) is None
