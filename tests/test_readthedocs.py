"""Source-reviewed RTD templates and fictional browser authentication.

These local responses exercise the real browser guard; they do not establish
private login acceptance on Read the Docs.
"""

import json
from urllib.parse import parse_qs, urlsplit

import pyotp
import pytest

from account_access.catalog import (
    RTD_ACCOUNT, RTD_LOGIN_PATH, RTD_MFA_PATH,
    RTD_ROOT, RTD_SOURCE, RTD_STATUS_PATH, RTD_USERNAME, add, include_sources, readthedocs,
)
from account_access.errors import AccessError
from account_access.factors import enroll, revoke
from account_access.models import CodeSource, Configuration
from account_access.password_import import apply, preview


SEED = "JBSWY3DPEHPK3PXP"
USER = "fictional-rtd-user"
PASSWORD = "fictional-rtd-password"
CSRF = "fictional-csrf-field"


def test_reviewed_rtd_spec_is_username_only_and_requires_an_initial_authenticator():
    spec = readthedocs()
    config = Configuration(accounts={RTD_ACCOUNT: spec}, code_sources={RTD_SOURCE: CodeSource(kind="totp")})
    assert spec.label == "Read the Docs · authenticator"
    assert spec.javascript is False and spec.login_assets == []
    assert spec.login.authenticator_source(config) == RTD_SOURCE
    assert spec.login_post_urls == [RTD_ROOT + RTD_LOGIN_PATH, RTD_ROOT + RTD_MFA_PATH]
    assert spec.login_resources == [RTD_ROOT + RTD_MFA_PATH, RTD_ROOT + "/dashboard/", RTD_ROOT + RTD_STATUS_PATH]
    assert spec.read_resources == [RTD_ROOT + RTD_LOGIN_PATH + "?next=" + RTD_STATUS_PATH]
    assert list(spec.operations) == ["status"]
    assert spec.operations["status"].fields == {"username": RTD_USERNAME}
    assert all("tokens" not in value and "delete" not in value and "projects" not in value
               for value in [*spec.read_resources, *spec.login_resources, *spec.login_post_urls])
    assert spec.login.factors["totp"].code_submit_selector.endswith(":not([form])")


def test_rtd_add_and_import_define_a_source_without_silently_enrolling_it(env):
    _, broker, _ = env
    add(broker.store, RTD_ACCOUNT)
    config = broker.store.config()
    assert config.code_sources[RTD_SOURCE] == CodeSource(kind="totp")
    assert broker.store.get("source:" + RTD_SOURCE) is None
    assert broker.run("test", RTD_ACCOUNT, "status")["status"] == "DENIED"
    staged = preview(broker.store, "url,username,password\n"
                     + RTD_ROOT + "/accounts/login/," + USER + "," + PASSWORD + "\n"
                     + "https://readthedocs.org/,old-alias,discarded-password\n"
                     + "https://app.readthedocs.org.attacker.example/,wrong,discarded-password\n")
    assert staged["rows"][0]["matches"][0]["id"] == RTD_ACCOUNT
    assert staged["rows"][0]["matches"][0]["authenticator_supported"] is True
    assert staged["rows"][1]["matches"][0]["id"] == RTD_ACCOUNT
    assert staged["rows"][2]["matches"] == []
    assert PASSWORD not in json.dumps(staged)
    selection = {"row": "0", "account": RTD_ACCOUNT, "operations": ["profile-edit"]}
    with pytest.raises(AccessError, match="invalid_import_selection"):
        apply(broker, staged["id"], [selection], ["test"])
    apply(broker, staged["id"], [{**selection, "operations": ["status"]}], ["test"])
    assert broker.store.get("credential:" + RTD_ACCOUNT) == {"username": USER, "password": PASSWORD}
    assert broker.store.get("source:" + RTD_SOURCE) is None
    assert broker.run("test", RTD_ACCOUNT, "profile-edit")["status"] == "DENIED"


def test_rtd_does_not_adopt_an_unrelated_existing_seed_and_merge_is_atomic(env):
    from account_access.catalog import PYPI_ACCOUNT, PYPI_SOURCE, pypi
    _, broker, _ = env
    config = broker.store.config()
    config.code_sources[RTD_SOURCE] = CodeSource(kind="totp")
    broker.store.configure(config)
    broker.store.put("source:" + RTD_SOURCE, {"seed": SEED})
    before = config.model_dump()
    with pytest.raises(AccessError, match="catalog_code_source_conflict"):
        include_sources(config, {PYPI_ACCOUNT: pypi(), RTD_ACCOUNT: readthedocs()})
    assert config.model_dump() == before
    assert PYPI_SOURCE not in config.code_sources
    assert broker.store.get("source:" + RTD_SOURCE) == {"seed": SEED}


def test_rtd_export_authenticator_is_imported_only_after_explicit_selection(env):
    _, broker, _ = env
    export = {"encrypted": False, "items": [{"type": 1, "login": {"username": USER, "password": PASSWORD, "totp": SEED,
                                                  "uris": [{"uri": RTD_ROOT + RTD_LOGIN_PATH}]}}]}
    staged = preview(broker.store, json.dumps(export))
    assert staged["rows"][0]["has_authenticator"] is True
    assert staged["rows"][0]["matches"][0]["authenticator_supported"] is True
    assert RTD_ACCOUNT not in broker.store.config().accounts
    assert broker.store.get("source:" + RTD_SOURCE) is None
    apply(broker, staged["id"], [{"row": staged["rows"][0]["id"], "account": RTD_ACCOUNT,
                                "operations": ["status"], "include_authenticator": True}], ["test"])
    assert broker.store.get("source:" + RTD_SOURCE) == {"seed": SEED}
    assert broker.store.get("source-generation:" + RTD_SOURCE)
    broker.permit("test", RTD_ACCOUNT, "status")
    with pytest.raises(AccessError, match="unknown_account_or_operation"):
        broker.permit("test", RTD_ACCOUNT, "tokens")


def fixture(env, *, full_name=False, altered_code_action=False, reject_code=False):
    provider, broker, _ = env
    parent = provider.server.RequestHandlerClass
    attempts = []
    spec = readthedocs()
    spec.login_url = provider.base + RTD_LOGIN_PATH
    spec.password_import_origins = []
    spec.login_resources = [value.replace(RTD_ROOT, provider.base) for value in spec.login_resources]
    spec.read_resources = [value.replace(RTD_ROOT, provider.base) for value in spec.read_resources]
    spec.login_post_urls = [value.replace(RTD_ROOT, provider.base) for value in spec.login_post_urls]
    spec.operations["status"].url = provider.base + RTD_STATUS_PATH

    def ready():
        # The mobile anonymous menu includes a logout form; it must never prove
        # readiness. The authenticated desktop menu has its own distinct parent.
        return ("<div class='ui top right pointing wide dropdown'><div class='wide menu'>"
                "<div class='header'>Navigation</div><a href='/dashboard/'>Projects</a>"
                "<div class='header'>Signed in as: " + USER + "</div>"
                "<a href='/accounts/edit/'>Settings</a></div></div>")

    class Handler(parent):
        def redirect(self, path, cookie=None):
            self.send_response(303)
            self.send_header("Location", path)
            if cookie:
                self.send_header("Set-Cookie", "rtd_fixture=" + cookie + "; Path=/; HttpOnly")
            self.send_header("Content-Length", "0")
            self.end_headers()

        def login_page(self):
            self.page("<div class='menu'><div class='header'>Signed in as: AnonymousUser</div>"
                      "<a href='/accounts/edit/'>Settings</a>"
                      "<form method='post' action='/accounts/logout/'></form></div>"
                      "<form method='post' action='/accounts/github/login/?process=login'>"
                      "<button type='submit'>Connected account</button></form>"
                      "<form method='post' action='/accounts/login/#/email'>"
                      "<input type='hidden' name='csrfmiddlewaretoken' value='" + CSRF + "'>"
                      "<input name='login' id='id_login' autocomplete='email'>"
                      "<input name='password' id='id_password' type='password' autocomplete='current-password'>"
                      "<button type='submit'>Log in</button></form>")

        def code_page(self):
            action = "/accounts/2fa/other/" if altered_code_action else RTD_MFA_PATH
            self.page("<form class='ui form' method='post' action='" + action + "'>"
                      "<input type='hidden' name='csrfmiddlewaretoken' value='" + CSRF + "'>"
                      "<input id='id_code' name='code' autocomplete='one-time-code'>"
                      "<button type='submit' form='logout-from-stage'>Cancel</button>"
                      "<button class='ui primary button' type='submit'>Verify</button></form>"
                      "<form id='logout-from-stage' method='post' action='/accounts/logout/'>"
                      "<input type='hidden' name='next' value='/accounts/login/'></form>")

        def do_GET(self):
            path = urlsplit(self.path).path
            connected = self.headers.get("Cookie") == "rtd_fixture=connected"
            if path == RTD_LOGIN_PATH:
                self.login_page()
            elif path == RTD_MFA_PATH:
                self.code_page()
            elif path == "/dashboard/":
                self.page(ready() if connected else "No session")
            elif path == RTD_STATUS_PATH:
                if not connected:
                    return self.redirect(RTD_LOGIN_PATH + "?next=" + RTD_STATUS_PATH)
                identity = ("<div class='header'>Fictional Full Name</div><div class='meta'><code>" + USER + "</code></div>"
                            if full_name else "<div class='header'>" + USER + "</div>")
                self.page(ready() + "<div id='edit-content'><div class='ui centered card'><div class='content'>"
                          + identity + "<div class='description'>Unreturned profile information</div>"
                          "</div></div><form method='post' action='.'><button>Save</button></form></div>")
            else:
                attempts.append("unexpected_get")
                self.send(404, "Unreviewed fixture destination")

        def do_POST(self):
            fields = parse_qs(self.rfile.read(int(self.headers["Content-Length"])).decode())
            if self.path == RTD_LOGIN_PATH:
                assert fields == {"login": [USER], "password": [PASSWORD], "csrfmiddlewaretoken": [CSRF]}
                attempts.append("password")
                self.redirect(RTD_MFA_PATH, "stage")
            elif self.path == RTD_MFA_PATH:
                assert self.headers.get("Cookie") == "rtd_fixture=stage"
                assert set(fields) == {"code", "csrfmiddlewaretoken"}
                assert fields["csrfmiddlewaretoken"] == [CSRF]
                assert pyotp.TOTP(SEED).verify(fields["code"][0], valid_window=1)
                attempts.append("totp")
                if reject_code:
                    self.code_page()
                else:
                    self.redirect("/dashboard/", "connected")
            else:
                attempts.append("unexpected_post")
                self.send(400, "Unreviewed fixture submission")

    provider.server.RequestHandlerClass = Handler
    config = broker.store.config()
    config.accounts[RTD_ACCOUNT] = spec
    config.code_sources[RTD_SOURCE] = CodeSource(kind="totp")
    broker.store.configure(config)
    broker.store.put("credential:" + RTD_ACCOUNT, {"username": USER, "password": PASSWORD})
    broker.grant("test", RTD_ACCOUNT, ["status"])
    enroll(broker.store, RTD_SOURCE, {"seed": SEED})
    broker._rtd_fixture_form_pages = []
    check_form = broker.browser.check_form

    def record_form_page(page, selector, config):
        parsed = urlsplit(page.url)
        broker._rtd_fixture_form_pages.append(parsed.path + ("#" + parsed.fragment if parsed.fragment else ""))
        return check_form(page, selector, config)

    broker.browser.check_form = record_form_page
    return broker, attempts


@pytest.mark.parametrize("full_name", [False, True])
def test_rtd_password_totp_session_reuse_and_source_and_grant_revocation(env, full_name):
    broker, attempts = fixture(env, full_name=full_name)
    first = broker.run("test", RTD_ACCOUNT, "status")
    assert first["status"] == "COMPLETED" and first["data"] == {"username": USER}, first
    assert attempts == ["password", "totp"]
    assert RTD_MFA_PATH + "#/email" in broker._rtd_fixture_form_pages
    assert all(value not in json.dumps(first) for value in [PASSWORD, SEED, CSRF, "Unreturned profile information"])
    assert broker.run("test", RTD_ACCOUNT, "status")["data"] == {"username": USER}
    assert attempts == ["password", "totp"]
    revoke(broker.store, RTD_SOURCE)
    # Factor revocation does not log the account out of an already valid site
    # session. After expiry, it prevents a new credential submission entirely.
    broker.store.put("connection:" + RTD_ACCOUNT, None)
    broker.store.put("login-attempt:" + RTD_ACCOUNT, 0)
    result = broker.run("test", RTD_ACCOUNT, "status")
    assert result["status"] in {"NEEDS_USER", "DENIED"}
    assert attempts == ["password", "totp"]
    assert broker.store.get("connection:" + RTD_ACCOUNT) is None
    broker.revoke(account=RTD_ACCOUNT, principal="test")
    assert broker.run("test", RTD_ACCOUNT, "status")["status"] == "DENIED"
    assert attempts == ["password", "totp"]


@pytest.mark.parametrize("failure", ["missing_seed", "changed_form", "rejected_code"])
def test_rtd_stops_on_missing_factor_changed_form_or_rejected_code(env, failure):
    broker, attempts = fixture(env, altered_code_action=failure == "changed_form", reject_code=failure == "rejected_code")
    if failure == "missing_seed":
        revoke(broker.store, RTD_SOURCE)
    result = broker.run("test", RTD_ACCOUNT, "status")
    assert result["status"] in {"NEEDS_USER", "DENIED"}
    assert broker.store.get("connection:" + RTD_ACCOUNT) is None
    assert attempts == ([] if failure == "missing_seed" else ["password"] if failure == "changed_form" else ["password", "totp"])
    assert all(value not in json.dumps(result) for value in [PASSWORD, SEED, CSRF])
