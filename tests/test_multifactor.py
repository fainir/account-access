import hashlib
import json
import secrets
from http.cookies import SimpleCookie
from urllib.parse import parse_qs

import pyotp
import pytest
from pydantic import ValidationError

from account_access.demo import DEMO_PASSWORD, DEMO_SEED
from account_access.errors import AccessError
from account_access.factors import enroll
from account_access.models import Configuration, LoginFactor, LoginChoice, LoginCodeRequest
from account_access.verification_demo import environment


@pytest.fixture
def chain(tmp_path):
    with environment(tmp_path / "fixture") as (provider, broker, mailbox):
        parent = provider.server.RequestHandlerClass
        stages = ["email", "sms", "totp"]
        pending = {}
        delivered = {}

        class Handler(parent):
            def current(self):
                cookies = SimpleCookie(self.headers.get("Cookie", ""))
                token = cookies["chain"].value if "chain" in cookies else None
                return token, pending.get(token, [])

            def stage(self, token):
                kind = pending[token][0]
                if kind in {"email", "sms"}:
                    code = f"{secrets.randbelow(1_000_000):06d}"
                    delivered[token] = code
                    provider.delivery(kind, code)
                return "/verify/" + kind

            def do_GET(self):
                if self.path.startswith("/verify/"):
                    _, current = self.current()
                    kind = self.path.removeprefix("/verify/")
                    if current and current[0] == "choose" and kind in {"totp", "request"}:
                        current.pop(0)
                    if not current or current[0] != kind:
                        self.send(403, {})
                    elif kind == "choose":
                        target = getattr(provider, "choice_target", "/verify/totp")
                        presence = '<div id="passkey-required">Use security key</div>' if getattr(provider, "choice_presence", False) else ""
                        hidden = getattr(provider, "hidden_choices", False)
                        button_type = getattr(provider, "choice_toggle_type", "button")
                        toggle = '<button id="show-methods" type="' + button_type + '" onclick="document.querySelector(\'#method-choice\').style.display=\'block\'">More options</button>' if hidden else ""
                        if getattr(provider, "toggle_in_form", False):
                            toggle = '<form method="post" action="/verify/request">' + toggle + '</form>'
                        self.page(toggle + '<div id="method-choice"' + (' style="display:none"' if hidden else '') + '><a id="use-totp" href="' + target + '">Use authenticator app</a></div>' + presence)
                    elif kind == "action":
                        if getattr(provider, "owner_approved", False):
                            self.finish_login("/mfa/summary")
                        else:
                            polling = '<script>setTimeout(() => location.reload(), 50)</script>' if getattr(provider, "review_polling", False) else ""
                            label = "Owner approval required" if polling else "Approve a payment"
                            self.page('<div id="action-challenge">' + label + '</div>' + polling)
                    elif kind == "request":
                        action = getattr(provider, "request_action", "/verify/request")
                        button_type = ' type="button"' if getattr(provider, "request_inert", False) else ""
                        self.page('<form action="' + action + '" method="post"><button id="send-sms"' + button_type + '>Send SMS</button></form>')
                    elif kind == "recovery":
                        self.page('<form action="/verify/recovery" method="post"><input id="recovery_code" name="recovery_code"><button>Verify</button></form><div id="sms-challenge"></div>')
                    else:
                        self.page(f'<form id="{kind}-challenge" action="/verify/{kind}" method="post">'
                                  f'<input id="{kind}-code" name="code">'
                                  f'<button id="{kind}-submit">Verify</button></form>')
                else:
                    super().do_GET()

            def do_POST(self):
                if self.path != "/mfa/login" and not self.path.startswith("/verify/"):
                    super().do_POST()
                    return
                provider.posted_paths.append(self.path)
                data = parse_qs(self.rfile.read(int(self.headers.get("Content-Length", "0"))).decode())
                if self.path == "/mfa/login":
                    provider.login_count += 1
                    if data.get("username") != ["demo@example.test"] or data.get("password") != [DEMO_PASSWORD]:
                        self.page(self.login_form(mfa=True))
                        return
                    token = secrets.token_hex(16)
                    pending[token] = stages.copy()
                    self.send(303, {}, {"Location": self.stage(token),
                                       "Set-Cookie": "chain=" + token + "; HttpOnly; Path=/"})
                else:
                    token, current = self.current()
                    kind = self.path.removeprefix("/verify/")
                    if kind == "request" and current and current[0] == "request":
                        if getattr(provider, "request_rejected", False):
                            self.send(429, {})
                            return
                        provider.sms_request_count = getattr(provider, "sms_request_count", 0) + 1
                        current.pop(0)
                        self.send(303, {}, {"Location": self.stage(token)})
                        return
                    if not current or current[0] != kind or kind not in {"email", "sms", "totp"}:
                        self.send(403, {})
                        return
                    counter = {"email": "email_count", "sms": "sms_count", "totp": "totp_count"}[kind]
                    setattr(provider, counter, getattr(provider, counter) + 1)
                    code = data.get("code", [""])[0]
                    provider.last_login_code = code
                    valid = (pyotp.TOTP(DEMO_SEED).verify(code, valid_window=1) if kind == "totp"
                             else secrets.compare_digest(delivered.get(token, "missing"), code))
                    if not valid:
                        self.do_GET()
                        return
                    current.pop(0)
                    if current:
                        self.send(303, {}, {"Location": self.stage(token)})
                    else:
                        self.finish_login("/mfa/summary")

        provider.server.RequestHandlerClass = Handler
        config = broker.store.config()
        spec = config.accounts["demo-mfa"]
        spec.login.code_source = spec.login.code_selector = spec.login.code_submit_selector = None
        for kind, source in [("email", "example-email"), ("sms", "example-sms"), ("totp", "demo-totp")]:
            spec.login.factors[kind] = LoginFactor(code_source=source, code_selector="#" + kind + "-code",
                                                   code_submit_selector="#" + kind + "-submit")
            spec.challenge_selectors[kind] = "#" + kind + "-challenge"
        spec.login_resources += [provider.base + "/verify/" + kind for kind in ["email", "sms", "totp", "action", "choose", "request"]]
        spec.login_post_urls += [provider.base + "/verify/" + kind for kind in ["email", "sms", "totp"]]
        broker.store.configure(Configuration.model_validate(config.model_dump()))
        broker.store.new_client("test")
        broker.grant("test", "demo-mfa", ["summary"])
        broker.store.put("credential:demo-mfa", {"username": "demo@example.test", "password": DEMO_PASSWORD})
        enroll(broker.store, "demo-totp", {"seed": DEMO_SEED})
        enroll(broker.store, "example-email", {"username": "demo@example.test", "password": DEMO_PASSWORD})
        enroll(broker.store, "example-sms", {"enabled": True})
        yield provider, broker, mailbox, stages


@pytest.mark.parametrize("mail_format", ["plain", "html"])
def test_password_then_email_sms_and_authenticator_complete_one_browser_login(chain, monkeypatch, mail_format):
    provider, broker, mailbox, _ = chain
    if mail_format == "html":
        from email import policy
        from email.parser import BytesParser
        deliver = mailbox.deliver

        def html_delivery(code):
            deliver(code)
            with mailbox.lock:
                saved = mailbox.messages[-1]
                message = BytesParser(policy=policy.default).parsebytes(saved["raw"])
                message.set_content("<html><body><p>Example sign-in: <strong>" + code
                                    + "</strong></p></body></html>", subtype="html")
                saved["raw"] = message.as_bytes()

        monkeypatch.setattr(mailbox, "deliver", html_delivery)
    result = broker.run("test", "demo-mfa", "summary")
    assert result["status"] == "COMPLETED"
    assert provider.login_count == provider.email_count == provider.sms_count == provider.totp_count == 1
    assert mailbox.fetches == 1
    assert provider.last_login_code not in json.dumps(result)
    assert DEMO_PASSWORD not in json.dumps(result) and DEMO_SEED not in json.dumps(result)
    with broker.store.db() as db:
        events = [dict(row) for row in db.execute("SELECT * FROM audit WHERE event='login_factor_completed'")]
    assert [row["reason"] for row in events] == ["email", "sms", "totp"]
    assert provider.last_login_code not in json.dumps(events)
    for source in broker.store.config().accounts["demo-mfa"].login.sources():
        assert broker.store.get("code-window:" + source) is None
    assert broker.run("test", "demo-mfa", "summary")["status"] == "COMPLETED"
    assert provider.login_count == 1


def test_gmail_html_code_completes_browser_login_and_reuses_session(chain, monkeypatch):
    import base64
    import time
    from email.message import EmailMessage
    from account_access.demo import configuration, connect_demo
    from account_access.models import CodeSource

    provider, broker, mailbox, stages = chain
    stages[:] = ["email"]
    config = broker.store.config()
    config.accounts["mailbox"] = configuration(provider.base).accounts["demo-api"]
    config.accounts["mailbox"].scopes.append("https://www.googleapis.com/auth/gmail.readonly")
    config.code_sources["example-email"] = CodeSource(
        kind="gmail", account="mailbox", sender="login@example.test", recipient="demo@example.test",
        subject="Your example sign-in code", template="Example sign-in: {code}")
    broker.store.configure(config)
    broker.grant("test", "demo-mfa", ["summary"])
    connect_demo(broker, "mailbox")
    messages = {}
    calls = []

    def delivered(kind, code):
        assert kind == "email"
        message = EmailMessage()
        message["From"], message["To"] = "login@example.test", "demo@example.test"
        message["Subject"] = "Your example sign-in code"
        message.set_content("<p>Example sign-in: <strong>" + code + "</strong></p>", subtype="html")
        messages["fresh"] = {"id": "fresh", "internalDate": str(int(time.time() * 1000)),
                             "raw": base64.urlsafe_b64encode(message.as_bytes()).decode()}

    def gmail(url, **kwargs):
        calls.append(url)
        if url.endswith("/messages"):
            return {"messages": [{"id": ident} for ident in messages]}
        assert kwargs["params"] == {"format": "raw"}
        return messages[url.rsplit("/", 1)[1]]

    monkeypatch.setattr(provider, "delivery", delivered)
    monkeypatch.setattr("account_access.codes.get_json", gmail)
    result = broker.run("test", "demo-mfa", "summary")
    assert result["status"] == "COMPLETED", result
    assert provider.login_count == provider.email_count == 1
    assert mailbox.fetches == 0
    assert len(calls) == 3  # Pre-password list, fresh list, one raw message.
    assert provider.last_login_code not in json.dumps(result)
    assert broker.run("test", "demo-mfa", "summary")["status"] == "COMPLETED"
    assert provider.login_count == 1 and len(calls) == 3


@pytest.mark.parametrize("kind", ["email", "sms"])
def test_two_enrollment_names_cannot_compete_for_the_same_message_channel(chain, monkeypatch, kind):
    import threading
    from concurrent.futures import ThreadPoolExecutor

    provider, broker, _, stages = chain
    stages[:] = [kind]
    config = broker.store.config()
    first = config.accounts["demo-mfa"]
    first.login.factors = {kind: first.login.factors[kind]}
    second = first.model_copy(deep=True)
    config.code_sources["other-source"] = config.code_sources["example-" + kind].model_copy(deep=True)
    second.login.factors[kind].code_source = "other-source"
    config.accounts["other-account"] = second
    broker.store.configure(config)
    broker.grant("test", "demo-mfa", ["summary"])
    broker.grant("test", "other-account", ["summary"])
    broker.store.put("credential:other-account", broker.store.get("credential:demo-mfa"))
    credential = {"enabled": True} if kind == "sms" else {"username": "demo@example.test", "password": DEMO_PASSWORD}
    enroll(broker.store, "other-source", credential)
    waiting, release = threading.Event(), threading.Event()
    resolve = broker.codes.resolve

    def hold_first(source, *args):
        if source == "example-" + kind:
            waiting.set()
            assert release.wait(15)
        return resolve(source, *args)

    monkeypatch.setattr(broker.codes, "resolve", hold_first)
    with ThreadPoolExecutor(max_workers=1) as workers:
        first_run = workers.submit(broker.run, "test", "demo-mfa", "summary")
        try:
            assert waiting.wait(15)
            competing = broker.run("test", "other-account", "summary")
            assert competing["status"] == "RETRYABLE", competing
            assert provider.login_count == 1
            assert broker.store.pending("other-account") == []
        finally:
            release.set()
        assert first_run.result(timeout=15)["status"] == "COMPLETED"
    # The temporary contention needs no owner prompt or new grant. The second
    # account's later attempt baselines out the first account's old message.
    assert broker.run("test", "other-account", "summary")["status"] == "COMPLETED"
    assert provider.login_count == getattr(provider, kind + "_count") == 2


@pytest.mark.parametrize("kind", ["action", "recovery"])
def test_recovery_page_stops_before_resolving_or_submitting_any_login_code(chain, monkeypatch, kind):
    provider, broker, _, stages = chain
    stages[:] = ["recovery"]
    config = broker.store.config()
    spec = config.accounts["demo-mfa"]
    spec.login_resources.append(provider.base + "/verify/recovery")
    spec.challenge_selectors[kind] = '#recovery_code, input[name="recovery_code"]'
    broker.store.configure(config)
    broker.grant("test", "demo-mfa", ["summary"])

    def forbidden_code(*args):
        raise AssertionError("Recovery pages must not request a login code")

    monkeypatch.setattr(broker.codes, "resolve", forbidden_code)
    result = broker.run("test", "demo-mfa", "summary")
    assert result["status"] == "NEEDS_USER" and result["challenge"]["kind"] == kind
    assert provider.login_count == 1 and provider.sms_count == 0
    assert "/verify/recovery" not in provider.posted_paths
    broker.store.resolve_login("demo-mfa")
    assert bool(broker.store.pending("demo-mfa")) == (kind == "action")


@pytest.mark.parametrize("case", ["approve", "cancel", "denied", "transaction"])
def test_owner_review_saves_only_confirmed_success_and_reuses_the_session(chain, monkeypatch, case):
    import threading
    from contextlib import contextmanager
    from types import SimpleNamespace
    from playwright.sync_api import sync_playwright

    provider, broker, _, stages = chain
    stages[:] = ["action"]
    provider.review_polling = True
    config = broker.store.config()
    spec = config.accounts["demo-mfa"]
    spec.javascript = True
    spec.challenge_selectors["passkey"] = "#action-challenge"
    spec.challenge_selectors["action"] = "#transaction-challenge"
    broker.store.configure(config)
    broker.grant("test", "demo-mfa", ["summary"])
    broker.store.challenge("demo-mfa", "action" if case == "transaction" else "passkey",
                           "owner_action_required" if case == "transaction" else "browser_passkey_required")
    stop = threading.Event()
    attention = []

    @contextmanager
    def fixture_browser():
        # Exercise the real visible-review code under headless CI. The fixture
        # server's approval flag stands for the owner's external action.
        with sync_playwright() as pw:
            yield SimpleNamespace(chromium=SimpleNamespace(launch=lambda **kwargs:
                pw.chromium.launch(**{**kwargs, "headless": True})))

    monkeypatch.setattr("account_access.browser.sync_playwright", fixture_browser)
    if case == "denied":
        check = broker.browser.check

        def denied(page, config):
            try:
                check(page, config)
            except AccessError as error:
                if error.kind == "passkey":
                    raise AccessError("DENIED", "review_denied", "passkey") from None
                raise

        monkeypatch.setattr(broker.browser, "check", denied)

    def approve(status, reason, kind, diagnostics):
        attention.append(kind)
        if case == "cancel":
            stop.set()
        else:
            provider.owner_approved = True

    if case in {"cancel", "denied"}:
        with pytest.raises(AccessError, match="review_denied" if case == "denied" else "browser_passkey_required"):
            broker.browser.read("demo-mfa", spec.operations["summary"], spec, visible=True,
                                review_stop=stop, on_attention=approve)
        assert not broker.store.get("connection:demo-mfa")
        assert broker.store.pending("demo-mfa")
    else:
        data = broker.browser.read("demo-mfa", spec.operations["summary"], spec, visible=True,
                                   review_stop=stop, on_attention=approve)
        assert data == {"balance": "987.65", "currency": "ILS"}
        result = broker.run("test", "demo-mfa", "summary")
        if case == "transaction":
            assert result["status"] == "NEEDS_USER" and result["challenge"]["kind"] == "action"
        else:
            assert not broker.store.pending("demo-mfa")
            assert result["status"] == "COMPLETED"
        assert provider.login_count == 1
    assert attention == ["passkey"]
    assert provider.sms_count == provider.totp_count == provider.email_count == 0


def test_unused_offline_alternative_does_not_block_enrolled_authenticator(chain, monkeypatch):
    provider, broker, _, stages = chain
    stages[:] = ["totp"]
    begin = broker.codes.begin
    def optional(source, *args):
        if source == "example-email":
            raise AccessError("NEEDS_USER", "mailbox_not_connected", "email")
        return begin(source, *args)
    monkeypatch.setattr(broker.codes, "begin", optional)
    assert broker.run("test", "demo-mfa", "summary")["status"] == "COMPLETED"
    assert provider.totp_count == 1 and provider.email_count == provider.sms_count == 0


def test_unenrolled_authenticator_cannot_mask_an_offline_sms_source_before_password(chain, monkeypatch):
    provider, broker, _, stages = chain
    stages[:] = ["choose"]
    config = broker.store.config()
    spec = config.accounts["demo-mfa"]
    del spec.login.factors["email"]
    config.code_sources["example-sms"].kind = "google_messages"
    config.code_sources["example-sms"].sender = "github-login-rotating-senders"
    config.code_sources["example-sms"].recipient = "paired-google-messages"
    config.code_sources["example-sms"].template = "{code} is your GitHub authentication code."
    broker.store.configure(config)
    broker.store.put("source:demo-totp", None)
    begin = broker.codes.begin

    def offline(source, *args):
        if source == "example-sms":
            raise AccessError("RETRYABLE", "google_messages_tab_unavailable", "sms")
        return begin(source, *args)

    monkeypatch.setattr(broker.codes, "begin", offline)
    broker.grant("test", "demo-mfa", ["summary"])
    result = broker.run("test", "demo-mfa", "summary")
    assert result["status"] == "RETRYABLE" and result["reason"] == "google_messages_tab_unavailable"
    assert provider.login_count == 0
    assert broker.store.get("code-window:demo-totp") is None


@pytest.mark.parametrize("change,reason", [
    ("disable", "verification_source_disabled"),
    ("cancel", "login_code_window_missing"),
    ("expire", "login_code_window_missing"),
    ("source", "login_code_source_changed"),
    ("enrollment", "verification_source_enrollment_changed"),
])
def test_late_code_is_not_submitted_after_source_or_window_changes(chain, monkeypatch, change, reason):
    provider, broker, _, stages = chain
    stages[:] = ["totp"]
    resolve = broker.codes.resolve
    def changed(source, started, used):
        code = resolve(source, started, used)
        if change == "disable":
            broker.store.put("source:" + source, {"enabled": False})
        elif change == "cancel":
            broker.codes.finish(source, started)
        elif change == "expire":
            window = broker.store.get("code-window:" + source)
            window["expires"] = 0
            broker.store.put("code-window:" + source, window)
        elif change == "enrollment":
            broker.store.put("source:" + source, {"seed": pyotp.random_base32()})
        else:
            config = broker.store.config()
            config.code_sources[source].template = "Changed login: {code}"
            broker.store.configure(config)
        return code
    monkeypatch.setattr(broker.codes, "resolve", changed)
    result = broker.run("test", "demo-mfa", "summary")
    assert result["status"] in {"NEEDS_USER", "DENIED"} and result["reason"] == reason
    assert provider.login_count == 1 and provider.totp_count == 0


def test_repeated_factor_stops_after_one_submission(chain):
    provider, broker, _, stages = chain
    stages[:] = ["email", "email"]
    result = broker.run("test", "demo-mfa", "summary")
    assert result["status"] == "NEEDS_USER" and result["reason"] == "verification_code_rejected"
    assert provider.email_count == 1 and provider.sms_count == provider.totp_count == 0


def test_action_after_email_never_uses_sms_or_authenticator(chain):
    provider, broker, _, stages = chain
    stages[:] = ["email", "action", "totp"]
    result = broker.run("test", "demo-mfa", "summary")
    assert result["status"] == "NEEDS_USER" and result["challenge"]["kind"] == "action"
    assert provider.email_count == 1 and provider.sms_count == provider.totp_count == 0


def test_changed_factor_source_invalidates_existing_permissions(chain):
    provider, broker, _, _ = chain
    config = broker.store.config()
    config.code_sources["example-email"].template = "Changed login: {code}"
    broker.store.configure(config)
    assert broker.run("test", "demo-mfa", "summary")["reason"] == "owner_configuration_changed"
    assert provider.login_count == 0


def test_factor_source_must_match_the_challenge_kind(chain):
    _, broker, _, _ = chain
    raw = broker.store.config().model_dump()
    raw["accounts"]["demo-mfa"]["login"]["factors"]["email"]["code_source"] = "demo-totp"
    with pytest.raises(ValidationError, match="method and source kind"):
        Configuration.model_validate(raw)


def test_legacy_connector_fingerprint_survives_new_factor_schema(env):
    _, broker, _ = env
    config = broker.store.config()
    old = config.accounts["demo-mfa"].model_dump()
    old.pop("login_assets")
    old.pop("browser_channel")
    old.pop("login_asset_discovery")
    old.pop("password_import_origins")
    old["login"].pop("factors")
    old["login"].pop("choices")
    old["login"].pop("code_requests")
    old["login"].pop("choice_toggle_selector")
    old["login"].pop("code_wait_ms")
    old["login"].pop("identity_step")
    old["code_source_config"] = config.code_sources["demo-totp"].model_dump()
    old["code_source_config"].pop("host")
    old["code_source_config"].pop("port")
    old["test_mode"] = True
    previous = hashlib.sha256(json.dumps(old, sort_keys=True).encode()).hexdigest()
    assert config.fingerprint("demo-mfa") == previous


def choices(broker, provider):
    config = broker.store.config()
    spec = config.accounts["demo-mfa"]
    spec.challenge_selectors["method"] = "#method-choice"
    spec.challenge_selectors["passkey"] = "#passkey-required"
    spec.login.choices = [LoginChoice(kind="totp", selector="#use-totp", url=provider.base + "/verify/totp")]
    broker.store.configure(config)
    broker.grant("test", "demo-mfa", ["summary"])


@pytest.mark.parametrize("case", ["visible_choice", "mandatory_presence", "submit_button"])
def test_optional_methods_can_expand_a_reviewed_non_submitting_toggle(chain, case):
    provider, broker, _, stages = chain
    stages[:] = ["choose", "totp"]
    choices(broker, provider)
    provider.hidden_choices = True
    provider.choice_presence = case == "mandatory_presence"
    provider.toggle_in_form = case == "submit_button"
    provider.choice_toggle_type = "submit" if case == "submit_button" else "button"
    config = broker.store.config()
    spec = config.accounts["demo-mfa"]
    spec.javascript = True
    spec.login.choice_toggle_selector = "#show-methods"
    broker.store.configure(config)
    broker.grant("test", "demo-mfa", ["summary"])
    result = broker.run("test", "demo-mfa", "summary")
    if case == "visible_choice":
        assert result["status"] == "COMPLETED" and provider.totp_count == 1
    else:
        assert result["status"] == "NEEDS_USER" and provider.totp_count == 0
        assert result["reason"] == ("browser_passkey_required" if case == "mandatory_presence"
                                      else "verification_method_destination_changed")


def test_offered_authenticator_choice_completes_without_owner_intervention(chain):
    provider, broker, _, stages = chain
    stages[:] = ["choose", "totp"]
    choices(broker, provider)
    assert broker.run("test", "demo-mfa", "summary")["status"] == "COMPLETED"
    assert provider.login_count == provider.totp_count == 1
    assert provider.sms_count == provider.email_count == 0


def test_choice_cannot_replace_mandatory_presence_or_follow_a_changed_link(chain):
    provider, broker, _, stages = chain
    stages[:] = ["choose", "totp"]
    choices(broker, provider)
    provider.choice_presence = True
    result = broker.run("test", "demo-mfa", "summary")
    assert result["status"] == "NEEDS_USER" and result["challenge"]["kind"] == "passkey"
    assert provider.totp_count == 0


def test_changed_choice_link_is_not_clicked(chain):
    provider, broker, _, stages = chain
    stages[:] = ["choose", "totp"]
    choices(broker, provider)
    provider.choice_target = "/verify/sms"
    result = broker.run("test", "demo-mfa", "summary")
    assert result["reason"] == "verification_method_destination_changed"
    assert provider.totp_count == provider.sms_count == provider.email_count == 0


def test_unenrolled_choice_requests_local_setup_without_reading_a_code(chain):
    provider, broker, _, stages = chain
    stages[:] = ["choose", "totp"]
    choices(broker, provider)
    broker.store.put("source:demo-totp", None)
    result = broker.run("test", "demo-mfa", "summary")
    assert result["reason"] == "authenticator_not_enrolled"
    assert provider.totp_count == 0


def test_offered_method_without_a_configured_source_requests_its_own_setup(chain):
    provider, broker, _, stages = chain
    stages[:] = ["choose", "totp"]
    choices(broker, provider)
    config = broker.store.config()
    del config.accounts["demo-mfa"].login.factors["totp"]
    broker.store.configure(Configuration.model_validate(config.model_dump()))
    broker.grant("test", "demo-mfa", ["summary"])
    result = broker.run("test", "demo-mfa", "summary")
    assert result["status"] == "NEEDS_USER"
    assert result["reason"] == "verification_source_not_connected"
    assert result["challenge"]["kind"] == "totp"
    assert provider.totp_count == provider.sms_count == provider.email_count == 0


def configure_code_request(broker, provider):
    config = broker.store.config()
    spec = config.accounts["demo-mfa"]
    spec.login.code_requests = [LoginCodeRequest(kind="sms", selector="#send-sms", url=provider.base + "/verify/request")]
    spec.login_post_urls.append(provider.base + "/verify/request")
    spec.challenge_selectors["method"] = "#method-choice"
    spec.login.choices = [LoginChoice(kind="sms", selector="#use-totp", url=provider.base + "/verify/request")]
    provider.choice_target = "/verify/request"
    broker.store.configure(Configuration.model_validate(config.model_dump()))
    broker.grant("test", "demo-mfa", ["summary"])


def test_offered_sms_request_then_fresh_code_completes_without_owner(chain):
    provider, broker, _, stages = chain
    stages[:] = ["choose", "request", "sms"]
    configure_code_request(broker, provider)
    assert broker.run("test", "demo-mfa", "summary")["status"] == "COMPLETED"
    assert provider.sms_request_count == provider.sms_count == provider.login_count == 1


def test_delivery_redirect_diagnostics_exclude_page_content_and_code_values(chain, monkeypatch):
    provider, broker, _, stages = chain
    stages[:] = ["choose", "request", "recovery"]
    configure_code_request(broker, provider)
    config = broker.store.config()
    spec = config.accounts["demo-mfa"]
    spec.login_resources.append(provider.base + "/verify/recovery")
    spec.challenge_selectors["action"] = "#recovery_code"
    broker.store.configure(config)
    broker.grant("test", "demo-mfa", ["summary"])
    contexts = []
    original = broker.browser.context

    def capture(*args, **kwargs):
        context = original(*args, **kwargs)
        contexts.append(context)
        return context

    monkeypatch.setattr(broker.browser, "context", capture)
    result = broker.run("test", "demo-mfa", "summary")
    assert result["status"] == "NEEDS_USER"
    progress = contexts[-1]._login_progress
    assert progress["sms_requested"] is True
    assert progress["code_request"] == {"page": "origin_0:/verify/?", "ajax": False, "auto": False,
                                        "button": "send", "fields": [{"type": "submit", "required": False,
                                                                      "checked": False, "invalid": False}],
                                        "http_status": 303, "transport": "document",
                                        "redirect": "origin_0:/verify/recovery"}
    assert DEMO_PASSWORD not in json.dumps(progress) and DEMO_SEED not in json.dumps(progress)
    assert provider.sms_count == 0 and provider.sms_request_count == 1


def test_google_messages_source_can_request_reviewed_sms_delivery(chain):
    import threading
    import time
    from account_access.google_messages import handle
    from test_google_messages import source, delivery

    provider, broker, _, stages = chain
    stages[:] = ["choose", "request", "sms"]
    configure_code_request(broker, provider)
    source(broker)
    config = broker.store.config()
    config.accounts["demo-mfa"].login.factors = {
        "sms": config.accounts["demo-mfa"].login.factors["sms"].model_copy(
            update={"code_source": "google-sms"})}
    broker.store.configure(config)
    broker.grant("test", "demo-mfa", ["summary"])
    baseline = {}

    def deliver(kind, code):
        assert kind == "sms" and provider.sms_request_count == 1
        handle(broker.store, delivery(baseline, code=code))

    provider.delivery = deliver
    results = []
    worker = threading.Thread(target=lambda: results.append(broker.run("test", "demo-mfa", "summary")))
    worker.start()
    deadline = time.monotonic() + 25
    while worker.is_alive() and time.monotonic() < deadline:
        for request in handle(broker.store, {"method": "pending"})["pending"]:
            if request["phase"] == "baseline":
                assert provider.login_count == 0
                baseline.update(source=request["source"], window=request["window"])
                handle(broker.store, {"method": "armed", **baseline})
        time.sleep(0.02)
    worker.join(timeout=3)
    assert not worker.is_alive()
    assert results and results[0]["status"] == "COMPLETED", results
    assert provider.sms_request_count == provider.sms_count == provider.login_count == 1
    assert provider.last_login_code not in json.dumps(results)


@pytest.mark.parametrize("case,reason", [("request_rejected", "verification_code_request_rejected"),
                                       ("request_inert", "verification_code_request_not_submitted")])
def test_sms_setup_does_not_claim_delivery_request_without_a_successful_post(chain, case, reason):
    provider, broker, _, stages = chain
    stages[:] = ["choose", "request", "sms"]
    configure_code_request(broker, provider)
    setattr(provider, case, True)
    spec = broker.store.config().accounts["demo-mfa"]
    requested = []
    with pytest.raises(AccessError) as error:
        broker.browser.read("demo-mfa", spec.operations["summary"], spec, setup_method="sms",
                            on_code_request=lambda kind, at, status, diagnostics: requested.append((kind, at, status)))
    assert error.value.reason == reason
    assert not requested and provider.sms_count == 0
    if case == "request_rejected":
        with broker.store.db() as db:
            events = list(db.execute("SELECT reason FROM audit WHERE event='login_code_request_result'"))
        assert [row[0] for row in events] == ["sms:http_429"]


@pytest.mark.parametrize("case", ["changed_action", "repeated_request", "source_disabled"])
def test_sms_request_stops_before_unreviewed_duplicate_or_unusable_delivery(chain, case):
    provider, broker, _, stages = chain
    stages[:] = ["choose", "request", "request", "sms"] if case == "repeated_request" else ["choose", "request", "sms"]
    configure_code_request(broker, provider)
    if case == "changed_action":
        provider.request_action = "/verify/sms"
        config = broker.store.config()
        config.accounts["demo-mfa"].login_post_urls.remove(provider.base + "/verify/sms")
        broker.store.configure(config)
        broker.grant("test", "demo-mfa", ["summary"])
    elif case == "source_disabled":
        broker.store.put("source:example-sms", {"enabled": False})
    result = broker.run("test", "demo-mfa", "summary")
    assert result["status"] == "NEEDS_USER"
    assert provider.sms_count == 0
    assert getattr(provider, "sms_request_count", 0) == (1 if case == "repeated_request" else 0)


@pytest.mark.parametrize("presence", [False, True])
def test_owner_sms_setup_requests_delivery_without_retrieving_or_submitting_codes(chain, presence):
    provider, broker, _, stages = chain
    stages[:] = ["choose", "request", "sms"]
    configure_code_request(broker, provider)
    config = broker.store.config()
    spec = config.accounts["demo-mfa"]
    del spec.login.factors["sms"]
    spec.challenge_selectors["passkey"] = "#passkey-required"
    provider.choice_presence = presence
    broker.store.configure(config)
    requested = []
    with pytest.raises(AccessError) as stopped:
        broker.browser.read("demo-mfa", spec.operations["summary"], spec, setup_method="sms",
                            on_code_request=lambda kind, at, status, diagnostics: requested.append((kind, at, status)))
    assert stopped.value.kind == ("passkey" if presence else "sms")
    assert len(requested) == getattr(provider, "sms_request_count", 0) == (0 if presence else 1)
    assert provider.sms_count == 0
