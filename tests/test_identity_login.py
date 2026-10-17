import json
from pathlib import Path
import tempfile
from urllib.parse import parse_qs

from pydantic import ValidationError
import pytest

from account_access.demo import DEMO_PASSWORD, DEMO_SEED
from account_access.models import Configuration, LoginIdentityStep
from account_access.verification_demo import environment


def configure(provider, broker, account="demo-web", *, scripted=False, fault=None):
    config = broker.store.config()
    spec = config.accounts[account]
    password_post = spec.login_url
    start, identify, password = [provider.base + "/identity/" + p for p in ["start", "identify", "password"]]
    spec.login_url = start
    spec.login.identity_step = LoginIdentityStep(submit_selector="#continue", post_url=identify,
        password_url=password, password_post_url=password_post, scripted=scripted)
    spec.javascript = scripted
    spec.state_timeout_ms = 1000
    spec.login_resources += [start, identify, password, provider.base + "/identity/unexpected"]
    spec.login_post_urls += [identify]
    broker.store.configure(config)
    broker.store.put("credential:" + account, {"username": "demo@example.test", "password": DEMO_PASSWORD})
    broker.store.put("source:demo-totp", {"seed": DEMO_SEED})
    broker.store.put("source:example-email", {"username": "demo@example.test", "password": DEMO_PASSWORD})
    broker.store.put("source:example-sms", {"enabled": True})
    broker.store.new_client("test")
    broker.grant("test", account, ["summary"])
    parent = provider.server.RequestHandlerClass
    provider.identity_payloads = []
    provider.identity_baselines = []
    sources = spec.login.sources()

    class Handler(parent):
        def do_GET(self):
            if self.path == "/identity/start":
                if scripted:
                    target = password_post if fault == "wrong_script_post" else identify
                    script = ("location.href='/identity/password'" if fault == "unconfirmed" else
                        "await fetch(" + json.dumps(target) + ",{method:'POST',body:new URLSearchParams({username:document.querySelector('#username').value})});"
                        + ("await fetch(" + json.dumps(target) + ",{method:'POST',body:'username=repeat'});" if fault == "duplicate_post" else "")
                        + "location.href='/identity/password'")
                    self.page('<div id="password-login"><input id="username" name="username"><button id="continue">Next</button></div>'
                        + '<script>document.querySelector("#continue").onclick=async()=>{' + script + '};'
                        + ("fetch('/identity/identify',{method:'POST',body:'username=early'});" if fault == "early_post" else "") + '</script>')
                else:
                    override = ' formaction="' + password_post + '"' if fault == "wrong_form" else ""
                    closing = '</form><form method="post" action="/identity/identify">' if fault == "foreign_form" else ""
                    self.page('<form id="password-login" method="post" action="/identity/identify">'
                        + '<input id="username" name="username">' + closing
                        + '<button id="continue"' + override + '>Next</button></form>')
            elif self.path in {"/identity/password", "/identity/unexpected"}:
                if fault == "bad_page":
                    self.page("<h1>Unrecognized next page</h1>")
                    return
                action = identify if fault == "password_wrong_form" else password_post
                presence = '<div id="action-challenge">Approve payment</div>' if fault == "presence" else ""
                self.page('<form id="password-login" action="' + action + '" method="post">'
                    + '<input name="username" type="hidden" value="demo@example.test">'
                    + '<input id="password" name="password" type="password"><button id="login-submit">Sign in</button></form>' + presence)
            else:
                super().do_GET()

        def do_POST(self):
            if self.path != "/identity/identify":
                super().do_POST()
                return
            provider.posted_paths.append(self.path)
            data = parse_qs(self.rfile.read(int(self.headers.get("Content-Length", "0"))).decode())
            provider.identity_payloads.append(data)
            provider.identity_baselines.append(all((broker.store.get("code-window:" + s) or {}).get("started") for s in sources))
            if fault == "upstream503":
                self.send(503, {"status": "temporarily-unavailable"})
            elif fault == "replay":
                self.send(307, {}, {"Location": "/identity/identify"})
            elif scripted:
                self.send(200, {"status": "identified"})
            else:
                self.send(303, {}, {"Location": "/identity/unexpected" if fault == "wrong_page" else "/identity/password"})
    provider.server.RequestHandlerClass = Handler
    return spec


@pytest.mark.parametrize("scripted", [False, True])
@pytest.mark.parametrize("account", ["demo-web", "demo-mfa", "example-email", "example-sms"])
def test_username_first_password_and_each_factor_recover_then_reuse_session(account, scripted):
    with tempfile.TemporaryDirectory(prefix="aa-id-", dir="/tmp") as temporary:
        with environment(Path(temporary)) as (provider, broker, _):
            configure(provider, broker, account, scripted=scripted)
            for _ in range(2):
                result = broker.run("test", account, "summary")
                assert result["status"] == "COMPLETED", result
                assert result["data"] == {"balance": "987.65", "currency": "ILS"}
                assert DEMO_PASSWORD not in json.dumps(result) and DEMO_SEED not in json.dumps(result)
                if provider.last_login_code:
                    assert provider.last_login_code not in json.dumps(result)
            assert provider.identity_payloads == [{"username": ["demo@example.test"]}]
            assert provider.identity_baselines == [True] and provider.login_count == 1
            if account != "demo-web":
                counter = {"demo-mfa": "totp_count", "example-email": "email_count", "example-sms": "sms_count"}[account]
                assert getattr(provider, counter) == 1


@pytest.mark.parametrize("fault,scripted,identity_posts", [
    ("wrong_form", False, 0), ("foreign_form", False, 0),
    ("password_wrong_form", False, 1), ("presence", False, 1),
    ("bad_page", False, 1), ("wrong_page", False, 1), ("replay", False, 1),
    ("unconfirmed", True, 0), ("duplicate_post", True, 1),
    ("wrong_script_post", True, 0), ("early_post", True, 0),
])
def test_changed_or_unconfirmed_identity_flow_stops_before_password(env, fault, scripted, identity_posts):
    provider, broker, _ = env
    configure(provider, broker, scripted=scripted, fault=fault)
    result = broker.run("test", "demo-web", "summary")
    assert result["status"] == "NEEDS_USER", result
    assert provider.login_count == 0 and len(provider.identity_payloads) == identity_posts
    assert all(DEMO_PASSWORD not in json.dumps(data) for data in provider.identity_payloads)


def test_temporary_identity_failure_retries_with_cooldown_without_owner_challenge(env):
    provider, broker, _ = env
    configure(provider, broker, fault="upstream503")
    result = broker.run("test", "demo-web", "summary")
    assert result["status"] == "RETRYABLE" and result["reason"] == "login_identity_temporarily_unavailable"
    assert not broker.store.pending("demo-web")
    again = broker.run("test", "demo-web", "summary")
    assert again["reason"] == "login_retry_cooldown" and len(provider.identity_payloads) == 1


def test_missing_source_stops_before_identity_submission_without_charging_cooldown(env):
    provider, broker, _ = env
    configure(provider, broker, "demo-mfa")
    broker.store.put("source:demo-totp", {"enabled": False})
    result = broker.run("test", "demo-mfa", "summary")
    assert result["status"] == "NEEDS_USER"
    assert provider.identity_payloads == [] and provider.login_count == 0
    assert not broker.store.get("login-attempt:demo-mfa")


def test_code_preflight_and_late_presence_check_happen_before_any_credential_fill(env, monkeypatch):
    provider, broker, _ = env
    spec = broker.store.config().accounts["demo-mfa"]
    spec.javascript = True
    config = broker.store.config()
    config.accounts["demo-mfa"] = spec
    broker.store.configure(config)
    broker.grant("test", "demo-mfa", ["summary"])
    contexts, snapshots = [], []
    original_context, original_begin = broker.browser.context, broker.codes.begin
    def context(*args, **kwargs):
        value = original_context(*args, **kwargs)
        contexts.append(value)
        close = value.close
        def observe_close():
            for page in value.pages:
                if page.locator("#username").count() and page.locator("#password").count():
                    snapshots.append((page.locator("#username").input_value(), page.locator("#password").input_value()))
            close()
        monkeypatch.setattr(value, "close", observe_close)
        return value
    def begin(*args):
        page = contexts[-1].pages[-1]
        assert page.locator("#username").input_value() == page.locator("#password").input_value() == ""
        original_begin(*args)
        page.evaluate("document.body.insertAdjacentHTML('beforeend','<div id=action-challenge>Approve payment</div>')")
    monkeypatch.setattr(broker.browser, "context", context)
    monkeypatch.setattr(broker.codes, "begin", begin)
    result = broker.run("test", "demo-mfa", "summary")
    assert result["reason"] == "browser_action_required" and provider.login_count == 0
    assert snapshots and all(pair == ("", "") for pair in snapshots)


def test_identity_step_is_permission_bound_and_default_preserves_existing_grants(env):
    example = json.loads((Path(__file__).parents[1] / "examples/browser-verification.json").read_bytes())
    assert Configuration.model_validate(example).fingerprint("example-account") == "d8420e61e7ffc6b1b9da3124d47639ac2bfad2d66d185c9ffedc7f9885c7943e"
    provider, broker, _ = env
    configure(provider, broker)
    old = broker.store.config().fingerprint("demo-web")
    config = broker.store.config()
    config.accounts["demo-web"].login.identity_step.password_url = provider.base + "/identity/unexpected"
    broker.store.configure(config)
    assert config.fingerprint("demo-web") != old
    assert broker.run("test", "demo-web", "summary")["status"] == "DENIED"


def test_username_input_presence_challenge_stops_before_password_fill(env, monkeypatch):
    provider, broker, _ = env
    parent = provider.server.RequestHandlerClass
    class Handler(parent):
        def login_form(self, *args, **kwargs):
            return super().login_form(*args, **kwargs) + """<script>
                document.querySelector('#username').oninput=()=>document.body.insertAdjacentHTML(
                    'beforeend','<div id=action-challenge>Approve payment</div>');
                </script>"""
    provider.server.RequestHandlerClass = Handler
    config = broker.store.config()
    config.accounts["demo-web"].javascript = True
    broker.store.configure(config)
    broker.grant("test", "demo-web", ["summary"])
    original_context = broker.browser.context
    passwords_at_close = []
    def context(*args, **kwargs):
        value = original_context(*args, **kwargs)
        close = value.close
        def observe_close():
            for page in value.pages:
                if page.locator("#password").count():
                    passwords_at_close.append(page.locator("#password").input_value())
            close()
        monkeypatch.setattr(value, "close", observe_close)
        return value
    monkeypatch.setattr(broker.browser, "context", context)
    result = broker.run("test", "demo-web", "summary")
    assert result["reason"] == "browser_action_required" and provider.login_count == 0
    assert passwords_at_close and all(value == "" for value in passwords_at_close)


@pytest.mark.parametrize("change", ["post_origin", "password_origin", "password_post_origin", "post_permission", "password_permission", "scripted_mode"])
def test_identity_steps_require_explicit_same_origin_urls_and_script_policy(env, change):
    provider, broker, _ = env
    configure(provider, broker)
    data = broker.store.config().model_dump()
    spec = data["accounts"]["demo-web"]
    if change == "post_permission":
        spec["login_post_urls"].remove(spec["login"]["identity_step"]["post_url"])
    elif change == "password_permission":
        spec["login_resources"].remove(spec["login"]["identity_step"]["password_url"])
    elif change == "scripted_mode":
        spec["login"]["identity_step"]["scripted"] = True
    else:
        key = {"post_origin": "post_url", "password_origin": "password_url", "password_post_origin": "password_post_url"}[change]
        url = "https://other.example.test/login"
        spec["login"]["identity_step"][key] = url
        spec["login_resources"].append(url)
        spec["login_post_urls"].append(url)
    with pytest.raises(ValidationError):
        Configuration.model_validate(data)
