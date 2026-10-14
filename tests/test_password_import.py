import json
import time

import pytest

from account_access.demo import DEMO_PASSWORD
from account_access.errors import AccessError
from account_access.password_import import apply, parse, preview


@pytest.mark.parametrize("header", ["name,url,username,password", "Title,URL,Username,Password",
                                    "name,login_uri,login_username,login_password"])
def test_common_exports_preserve_quoted_passwords(header):
    rows = parse(header + '\n"Example","https://example.com","person","comma,quote""password"\n')
    assert rows[0]["password"] == 'comma,quote"password'
    assert rows[0]["username"] == "person"


def test_import_is_selected_encrypted_origin_bound_and_granted(env):
    provider, broker, _ = env
    spec = broker.store.config().accounts["demo-web"]
    csv = f'url,username,password\n{spec.login_url},demo@example.test,{DEMO_PASSWORD}\nhttps://unknown.example,other,do-not-retain\n'
    staged = preview(broker.store, csv)
    assert DEMO_PASSWORD not in json.dumps(staged)
    assert staged["unsupported"] == 1
    private = broker.store.get("password-import:" + staged["id"])
    assert "do-not-retain" not in json.dumps(private)
    assert DEMO_PASSWORD.encode() not in broker.store.path.read_bytes()
    selection = {"row": "0", "account": "demo-web", "operations": ["summary"]}
    wrong = {**selection, "account": "personal-store", "operations": ["inventory"]}
    before = broker.store.config().model_dump()
    with pytest.raises(AccessError, match="password_origin_mismatch"):
        apply(broker, staged["id"], [wrong], ["test"])
    assert broker.store.config().model_dump() == before
    result = apply(broker, staged["id"], [selection], ["test"])
    assert result == {"status": "IMPORTED", "accounts": ["demo-web"]}
    assert broker.store.get("password-import:" + staged["id"]) is None
    assert broker.run("test", "demo-web", "summary")["status"] == "COMPLETED"
    assert provider.login_count == 1
    with pytest.raises(AccessError, match="password_import_expired"):
        apply(broker, staged["id"], [selection], ["test"])


def test_import_rejects_expired_duplicate_and_changed_connector(env):
    _, broker, _ = env
    spec = broker.store.config().accounts["demo-web"]
    csv = f'url,username,password\n{spec.login_url},demo@example.test,{DEMO_PASSWORD}\n'
    item = {"row": "0", "account": "demo-web", "operations": ["summary"]}
    result = preview(broker.store, csv)
    with pytest.raises(AccessError, match="invalid_import_selection"):
        apply(broker, result["id"], [item, item], ["test"])
    config = broker.store.config()
    config.accounts["demo-web"].label = "Connector changed"
    broker.store.configure(config)
    with pytest.raises(AccessError, match="import_connector_changed"):
        apply(broker, result["id"], [item], ["test"])
    value = broker.store.get("password-import:" + result["id"])
    value["expires"] = time.time() - 1
    broker.store.put("password-import:" + result["id"], value)
    with pytest.raises(AccessError, match="password_import_expired"):
        apply(broker, result["id"], [item], ["test"])


@pytest.mark.parametrize("csv", ["url,URL,username,password\nx,x,x,x", "unsupported\nx",
                                 "url,username,password\nhttps://a,x,p,extra"])
def test_invalid_exports_fail_without_credential_echo(csv):
    with pytest.raises(AccessError):
        parse(csv)


def test_authenticator_export_requires_opt_in_and_matching_login_factor(env):
    provider, broker, _ = env
    from account_access.demo import DEMO_SEED
    spec = broker.store.config().accounts["demo-mfa"]
    csv = f'URL,Username,Password,OTPAuth\n{spec.login_url},demo@example.test,{DEMO_PASSWORD},otpauth://totp/Example?secret={DEMO_SEED}\n'
    broker.store.put("source:demo-totp", None)
    staged = preview(broker.store, csv)
    assert staged["rows"][0]["has_authenticator"] is True
    assert DEMO_SEED not in json.dumps(staged)
    item = {"row": "0", "account": "demo-mfa", "operations": ["summary"]}
    apply(broker, staged["id"], [item], ["test"])
    assert broker.store.get("source:demo-totp") is None
    staged = preview(broker.store, csv)
    with pytest.raises(AccessError, match="authenticator_import_not_supported"):
        apply(broker, staged["id"], [{**item, "account": "demo-web", "include_authenticator": True}], ["test"])
    apply(broker, staged["id"], [{**item, "include_authenticator": True}], ["test"])
    assert broker.run("test", "demo-mfa", "summary")["status"] == "COMPLETED"
    assert provider.totp_count == 1
