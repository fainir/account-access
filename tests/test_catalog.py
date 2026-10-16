import json

import pytest

from account_access.catalog import NAMECHEAP_LOGIN, NAMECHEAP_USER, add, namecheap
from account_access.errors import AccessError
from account_access.password_import import apply, preview


def test_namecheap_import_is_reviewed_and_does_not_approve_other_reads(env):
    _, broker, _ = env
    staged = preview(broker.store, "url,username,password\n"
                     + NAMECHEAP_LOGIN + ",fictional-user,fictional-password\n"
                     + "https://www.namecheap.com.attacker.example/,wrong,not-retained\n")
    assert staged["rows"][0]["matches"] == [{
        "id": "personal-namecheap", "label": "Namecheap", "authenticator_supported": False,
        "environment": "live", "environment_source": "connector-configuration",
        "operations": [{"name": "status", "description": "Confirm your signed-in Namecheap username"}]}]
    assert not staged["rows"][1]["matches"]
    assert "fictional-password" not in json.dumps(staged)
    assert "not-retained" not in json.dumps(broker.store.get("password-import:" + staged["id"]))
    selection = {"row": "0", "account": "personal-namecheap", "operations": ["domains"]}
    with pytest.raises(AccessError, match="invalid_import_selection"):
        apply(broker, staged["id"], [selection], ["test"])
    assert "personal-namecheap" not in broker.store.config().accounts
    apply(broker, staged["id"], [{**selection, "operations": ["status"]}], ["test"])
    spec = broker.store.config().accounts["personal-namecheap"]
    assert spec.operations["status"].fields == {"username": NAMECHEAP_USER}
    assert broker.store.get("credential:personal-namecheap")["username"] == "fictional-user"
    assert broker.run("test", "personal-namecheap", "domains")["status"] == "DENIED"


@pytest.mark.parametrize("extra_step", [False, True])
def test_namecheap_password_pilot_reuses_session_or_stops_on_unreviewed_verification(env, extra_step):
    """Provider-shaped fixture; never substitute this for a private live login."""
    provider, broker, _ = env
    parent = provider.server.RequestHandlerClass
    attempts = []
    spec = namecheap()
    spec.login_url = provider.base + "/namecheap/login/"
    spec.login_resources = [provider.base + "/namecheap/landing/"]
    spec.login_post_urls = [spec.login_url]
    spec.operations["status"].url = spec.login_url

    class Handler(parent):
        def do_GET(self):
            if self.path == "/namecheap/login/":
                if self.headers.get("Cookie") == "namecheap_fixture=connected":
                    self.page("<div id='fixture_alreadyLoggedInDiv'>"
                              "You are already logged in as "
                              "<strong id='fixture_ltUsername'>fictional-user</strong></div>")
                else:
                    self.page("<form method='post' action='/namecheap/login/'>"
                              "<div id='fixture_loginDiv'><input name='LoginUserName'>"
                              "<input type='password' name='LoginPassword'>"
                              "<input type='submit' id='fixture_LoginButton'></div></form>")
            elif self.path == "/namecheap/landing/":
                if extra_step:
                    self.page("<form method='post' action='/unreviewed-verification'>"
                              "<input name='verification-code'><button>Verify</button></form>")
                else:
                    self.page("<a href='https://www.namecheap.com/myaccount/signout'>Sign out</a>")
            else:
                super().do_GET()

        def do_POST(self):
            if self.path != "/namecheap/login/":
                attempts.append("unexpected_post")
                return self.send(400, "Unexpected request")
            from urllib.parse import parse_qs
            fields = parse_qs(self.rfile.read(int(self.headers["Content-Length"])).decode())
            assert fields == {"LoginUserName": ["fictional-user"], "LoginPassword": ["fictional-password"]}
            attempts.append("password")
            self.send_response(303)
            self.send_header("Location", "/namecheap/landing/")
            if not extra_step:
                self.send_header("Set-Cookie", "namecheap_fixture=connected; Path=/; HttpOnly")
            self.send_header("Content-Length", "0")
            self.end_headers()

    provider.server.RequestHandlerClass = Handler
    config = broker.store.config()
    config.accounts["namecheap-fixture"] = spec
    broker.store.configure(config)
    broker.store.put("credential:namecheap-fixture", {"username": "fictional-user", "password": "fictional-password"})
    broker.grant("test", "namecheap-fixture", ["status"])
    result = broker.run("test", "namecheap-fixture", "status")
    if extra_step:
        assert result["status"] == "NEEDS_USER"
        assert result["challenge"]["kind"] == "unknown"
        assert not broker.store.get("connection:namecheap-fixture")
    else:
        assert result["status"] == "COMPLETED"
        assert result["data"] == {"username": "fictional-user"}
        assert broker.run("test", "namecheap-fixture", "status")["status"] == "COMPLETED"
    assert attempts == ["password"]


def test_catalog_add_keeps_existing_connections(env):
    _, broker, _ = env
    before = broker.store.config().accounts
    add(broker.store, "personal-namecheap")
    assert broker.store.config().accounts.items() >= before.items()
    with pytest.raises(AccessError, match="account_already_added"):
        add(broker.store, "personal-namecheap")


def test_reviewed_export_alias_matches_without_widening_network_or_using_suffixes(env):
    _, broker, _ = env
    csv = ("url,username,password\n"
           "https://ap.www.namecheap.com/profile/,fictional-user,fictional-password\n"
           "https://evil.ap.www.namecheap.com/,wrong,not-retained\n"
           "http://ap.www.namecheap.com/,wrong,not-retained\n")
    staged = preview(broker.store, csv)
    assert staged["rows"][0]["matches"][0]["id"] == "personal-namecheap"
    assert not staged["rows"][1]["matches"] and not staged["rows"][2]["matches"]
    apply(broker, staged["id"], [{"row": "0", "account": "personal-namecheap", "operations": ["status"]}], ["test"])
    spec = broker.store.config().accounts["personal-namecheap"]
    assert spec.login_post_urls == [NAMECHEAP_LOGIN]
    assert not spec.read_resources
    assert all("/profile/" not in url for url in spec.login_resources)


@pytest.mark.parametrize("alias", ["https://ap.www.namecheap.com/", "https://ap.www.namecheap.com/profile",
                                   "https://ap.www.namecheap.com?secret=x", "https://user:password@ap.www.namecheap.com",
                                   "http://ap.www.namecheap.com", "https://ap.www.namecheap.com#secret"])
def test_password_import_aliases_reject_non_origins(alias):
    from pydantic import ValidationError
    from account_access.models import Configuration
    spec = namecheap()
    spec.password_import_origins = [alias]
    with pytest.raises(ValidationError):
        Configuration(accounts={"namecheap": spec})


def test_empty_alias_preserves_legacy_grants_but_new_alias_invalidates_them(env, monkeypatch):
    from account_access.models import BrowserAccount
    _, broker, _ = env
    config = broker.store.config()
    original_dump = BrowserAccount.model_dump
    actual = config.fingerprint("demo-web")

    def legacy_dump(self, **kwargs):
        data = original_dump(self, **kwargs)
        data.pop("password_import_origins", None)
        return data

    with monkeypatch.context() as legacy:
        legacy.setattr(BrowserAccount, "model_dump", legacy_dump)
        assert config.fingerprint("demo-web") == actual
    config.accounts["demo-web"].password_import_origins = ["https://reviewed.example"]
    assert config.fingerprint("demo-web") != actual
