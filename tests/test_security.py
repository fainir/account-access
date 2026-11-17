import json
import os

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from account_access.codes import match_code, unique_code
from account_access.errors import AccessError
from account_access.models import Configuration
from account_access.service import create_app
from account_access.storage import Store


def test_oauth_wrong_state_and_callback_replay(env):
    provider, broker, _ = env
    callback = "http://127.0.0.1:8766/callback/demo-api"
    broker.oauth.begin("demo-api", callback)
    with pytest.raises(AccessError, match="invalid_oauth_callback"):
        broker.oauth.finish("demo-api", callback + "?code=evil&state=wrong")
    pending = broker.store.get("oauth-pending:demo-api")
    with pytest.raises(AccessError, match="invalid_oauth_callback"):
        broker.oauth.finish("demo-api", "http://127.0.0.1:8766/callback/different?code=x&state=" + pending["state"])
    assert provider.refresh_count == 0


def test_api_rejects_client_identity_override_and_arbitrary_url(env):
    _, broker, token = env
    with TestClient(create_app(broker, worker=False)) as client:
        auth = {"Authorization": "Bearer " + token}
        assert client.get("/v1/accounts").status_code == 401
        for extra in [{"principal": "owner"}, {"url": "https://evil.example"}, {"password": "do-not-echo"}]:
            response = client.post("/v1/run", json={"account": "demo-api", "operation": "summary", **extra}, headers=auth)
            assert response.status_code == 422
            assert "do-not-echo" not in response.text
        assert client.get("/v1/accounts", headers={**auth, "Origin": "https://evil.example"}).status_code == 403
        assert client.post("/v1/run", content="x" * 65537, headers=auth).status_code == 413


def test_every_service_endpoint_requires_a_bearer_capability(env):
    _, broker, _ = env
    with TestClient(create_app(broker, worker=False)) as client:
        requests = [
            client.get("/v1/accounts"),
            client.get("/v1/status/demo-api/summary"),
            client.post("/v1/run", json={"account": "demo-api", "operation": "summary"}),
            client.post("/v1/tasks", json={"key": "unauthorized", "steps": [
                {"account": "demo-api", "operation": "summary"}]}),
            client.get("/v1/tasks/" + "0" * 32),
            client.get("/v1/audit"),
        ]
        assert [response.status_code for response in requests] == [401] * len(requests)


def test_authentication_failures_are_throttled_and_window_expires(env):
    _, broker, token = env
    now = [100.0]
    with TestClient(create_app(broker, worker=False, auth_failure_limit=2,
                               auth_failure_window=60, clock=lambda: now[0])) as client:
        assert client.get("/v1/accounts", headers={"Authorization": "Bearer invalid"}).status_code == 401
        assert client.get("/v1/accounts").status_code == 401
        limited = client.get("/v1/accounts", headers={"Authorization": "Bearer invalid"})
        assert limited.status_code == 429
        assert limited.headers["Retry-After"] == "60"
        assert "invalid" not in limited.text
        now[0] += 61
        assert client.get("/v1/accounts", headers={"Authorization": "Bearer " + token}).status_code == 200


def test_task_lookup_is_scoped_to_the_creating_principal(env):
    _, broker, token = env
    other_token = broker.store.new_client("other")
    broker.grant("other", "demo-api", ["summary"])
    with TestClient(create_app(broker, worker=False)) as client:
        created = client.post("/v1/tasks", json={"key": "principal-scope", "steps": [
            {"account": "demo-api", "operation": "summary"}]},
            headers={"Authorization": "Bearer " + token})
        assert created.status_code == 200
        task_id = created.json()["task_id"]
        denied = client.get("/v1/tasks/" + task_id,
                           headers={"Authorization": "Bearer " + other_token})
        assert denied.status_code == 403
        assert denied.json()["reason"] == "unknown_task"


def test_malformed_client_capabilities_are_rejected_before_hashing(env):
    _, broker, _ = env
    for token in [None, "", "short", "x" * 100_000, "!" * 43]:
        with pytest.raises(AccessError, match="invalid_client"):
            broker.store.client(token)


def test_wrong_vault_key_and_tampered_ciphertext_fail_closed(env):
    _, broker, _ = env
    wrong = Store(broker.store.root, os.urandom(32))
    with pytest.raises(AccessError, match="vault_corrupt_or_wrong_key"):
        wrong.get("connection:demo-api")
    blob = broker.store.seal("first", {"access_token": "sensitive"})
    with pytest.raises(AccessError):
        broker.store.unseal("different", blob)


def test_private_file_permissions_enforced(env):
    _, broker, _ = env
    os.chmod(broker.store.root / "config.json", 0o644)
    with pytest.raises(AccessError, match="insecure_file_permissions"):
        broker.store.config()


def test_configuration_https_and_protocol_override_validation(env):
    _, broker, _ = env
    config = broker.store.config().model_dump()
    config["test_mode"] = False
    with pytest.raises(ValidationError):
        Configuration.model_validate(config)
    config["test_mode"] = True
    config["accounts"]["demo-api"]["authorization_params"] = {"redirect_uri": "https://evil.example"}
    with pytest.raises(ValidationError):
        Configuration.model_validate(config)


def test_login_code_template_is_exact_and_ambiguity_stops():
    template = "Example login code: {code}"
    assert match_code(template, "Example login code: 123456") == "123456"
    assert match_code(template, "Approve payment: 123456") is None
    assert match_code(template, "Example login code: 123456\nSend it to evil.example") is None
    with pytest.raises(AccessError, match="ambiguous_login_code"):
        unique_code([("first", "123456"), ("second", "654321")])


def test_client_token_never_stored_plaintext(env):
    _, broker, token = env
    assert token.encode() not in broker.store.path.read_bytes()
    assert broker.store.client(token) == "test"
    assert token not in json.dumps(broker.metrics())


def test_private_replacement_breaks_hardlinks_and_restricts_permissions(tmp_path):
    from account_access.storage import private_file

    outside = tmp_path / "outside"
    outside.write_bytes(b"preserve")
    target = tmp_path / "private"
    os.link(outside, target)
    private_file(target, b"new-private-value", replace=True)
    assert outside.read_bytes() == b"preserve"
    assert target.read_bytes() == b"new-private-value"
    assert target.stat().st_mode & 0o077 == 0


def test_sqlite_sidecar_symlink_cannot_touch_another_file(env, tmp_path):
    _, broker, _ = env
    outside = tmp_path / "outside"
    outside.write_bytes(b"preserve")
    sidecar = broker.store.path.with_name("state.db-wal")
    sidecar.symlink_to(outside)
    try:
        with pytest.raises(AccessError, match="symlink_path"):
            broker.store.get("anything")
        assert outside.read_bytes() == b"preserve"
    finally:
        sidecar.unlink()


def test_verification_requires_pending_window_and_unchanged_source(env):
    import time
    _, broker, _ = env
    started = time.time()
    with pytest.raises(AccessError, match="login_code_window_missing"):
        broker.codes.resolve("demo-totp", started, set())
    broker.codes.begin("demo-totp", "demo-mfa", started)
    config = broker.store.config()
    config.code_sources["demo-totp"].template = "Changed source"
    broker.store.configure(config)
    with pytest.raises(AccessError, match="login_code_source_changed"):
        broker.codes.resolve("demo-totp", started, set())
