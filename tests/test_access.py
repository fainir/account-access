import concurrent.futures
import json
import time

import pytest

from account_access.broker import Broker
from account_access.demo import connect_demo
from account_access.errors import AccessError
from account_access.models import TaskRequest
from account_access.storage import Store


def expire(broker):
    state = broker.store.get("connection:demo-api")
    state["token"]["expires_at"] = time.time() - 1
    broker.store.put("connection:demo-api", state)


def test_repeated_api_refresh_and_restart(env):
    provider, broker, _ = env
    for _ in range(20):
        expire(broker)
        # Reinstantiate both broker and vault, like a restarted worker/agent process.
        broker = Broker(Store(broker.store.root, (broker.store.root / "demo.key").read_bytes()))
        assert broker.run("test", "demo-api", "summary")["status"] == "COMPLETED"
    assert provider.refresh_count == 20
    assert not broker.store.pending("demo-api")


def test_concurrent_rotating_refresh_is_singleflight(env):
    provider, broker, _ = env
    expire(broker)
    def run(_):
        other = Broker(Store(broker.store.root, (broker.store.root / "demo.key").read_bytes()))
        return other.run("test", "demo-api", "summary")
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(run, range(8)))
    assert all(r["status"] == "COMPLETED" for r in results)
    assert provider.refresh_count == 1


def test_401_renews_once(env):
    provider, broker, _ = env
    provider.access_tokens.clear()
    assert broker.run("test", "demo-api", "summary")["status"] == "COMPLETED"
    assert provider.api_count == 2
    assert provider.refresh_count == 1


def test_persistent_401_is_bounded_and_challenge_deduplicated(env):
    provider, broker, _ = env
    provider.force_401 = True
    results = [broker.run("test", "demo-api", "summary") for _ in range(10)]
    assert all(r["status"] == "NEEDS_USER" for r in results)
    assert len({r["challenge"]["id"] for r in results}) == 1
    assert provider.api_count == 2
    assert provider.refresh_count == 1


def test_revoked_refresh_stops_until_owner_reconnects(env):
    provider, broker, _ = env
    provider.refresh_tokens.clear()
    expire(broker)
    assert broker.run("test", "demo-api", "summary")["status"] == "NEEDS_USER"
    connect_demo(broker)
    assert broker.run("test", "demo-api", "summary")["status"] == "COMPLETED"


def test_lost_rotation_response_never_replays_token(env):
    provider, broker, _ = env
    provider.drop_refresh_response = True
    expire(broker)
    first = broker.run("test", "demo-api", "summary")
    assert first["status"] == "NEEDS_USER"
    assert first["reason"] == "refresh_outcome_uncertain"
    assert provider.refresh_count == 1
    second = Broker(broker.store).run("test", "demo-api", "summary")
    assert second["challenge"]["id"] == first["challenge"]["id"]
    assert provider.refresh_count == 1


def test_crashed_refresh_marker_requires_reconnection(env):
    _, broker, _ = env
    state = broker.store.get("connection:demo-api")
    state["refresh_in_flight"] = True
    broker.store.put("connection:demo-api", state)
    assert Broker(broker.store).run("test", "demo-api", "summary")["reason"] == "refresh_outcome_uncertain"


def test_transient_provider_failure_is_not_a_user_challenge(env):
    provider, broker, _ = env
    provider.temporary_failure = True
    assert broker.run("test", "demo-api", "summary")["status"] == "RETRYABLE"
    assert not broker.store.pending("demo-api")
    provider.temporary_failure = False
    assert broker.run("test", "demo-api", "summary")["status"] == "COMPLETED"


def test_grant_denial_makes_no_provider_request(env):
    provider, broker, _ = env
    before = provider.api_count
    assert broker.run("test", "demo-api", "transfer-money")["status"] == "DENIED"
    assert broker.run("unregistered", "demo-api", "summary")["status"] == "DENIED"
    assert provider.api_count == before


def test_expired_grant_denied(env):
    provider, broker, _ = env
    broker.grant("test", "demo-api", ["summary"], expires=time.time() - 1)
    assert broker.run("test", "demo-api", "summary")["reason"] == "standing_permission_expired"
    assert provider.api_count == 0


def test_configuration_change_requires_new_grant_and_connection(env):
    _, broker, _ = env
    config = broker.store.config()
    config.accounts["demo-api"].operations["summary"].fields = ["access_token"]
    broker.store.configure(config)
    assert broker.run("test", "demo-api", "summary")["reason"] == "owner_configuration_changed"
    broker.grant("test", "demo-api", ["summary"])
    assert broker.run("test", "demo-api", "summary")["reason"] == "connection_configuration_changed"


def test_provider_scope_narrowing_stops_operation(env):
    provider, broker, _ = env
    state = broker.store.get("connection:demo-api")
    state["token"]["scope"] = "different"
    broker.store.put("connection:demo-api", state)
    assert broker.run("test", "demo-api", "summary")["reason"] == "provider_scope_missing"
    assert provider.api_count == 0


def test_task_checkpoint_and_automatic_repair_resume(env):
    provider, broker, _ = env
    req = TaskRequest(key="month-end", steps=[{"account": "demo-api", "operation": "summary"},
                                             {"account": "demo-web", "operation": "summary"}])
    broker.store.put("credential:demo-web", {})
    task = broker.submit("test", req)
    broker.advance(task["task_id"])
    blocked = broker.task("test", task["task_id"])
    assert blocked["progress"] == 1
    assert blocked["status"] == "NEEDS_USER"
    reads = provider.api_count
    def owner_login(page):
        page.locator("#username").fill("demo@example.test")
        page.locator("#password").fill("controlled-demo-password-only")
        page.locator("#login-submit").click()
        page.wait_for_load_state("domcontentloaded")
    broker.browser.connect("demo-web", headless=True, complete=owner_login)
    with broker.store.db() as db:
        db.execute("UPDATE jobs SET next_at=0")
    Broker(broker.store).tick()
    final = broker.task("test", task["task_id"])
    assert final["status"] == "COMPLETED"
    assert final["progress"] == 2
    assert provider.api_count == reads


def test_idempotency_and_identity_isolation(env):
    provider, broker, _ = env
    request = TaskRequest(key="stable", steps=[{"account": "demo-api", "operation": "summary"}])
    first = broker.submit("test", request)
    assert broker.submit("test", request)["task_id"] == first["task_id"]
    changed = TaskRequest(key="stable", steps=[{"account": "demo-api", "operation": "details"}])
    with pytest.raises(AccessError, match="idempotency_key_conflict"):
        broker.submit("test", changed)
    other = broker.store.new_client("other")
    assert broker.store.client(other) == "other"
    with pytest.raises(AccessError, match="unknown_task"):
        broker.task("other", first["task_id"])
    broker.advance(first["task_id"])
    assert provider.api_count == 1
    broker.submit("test", request)
    broker.advance(first["task_id"])
    assert provider.api_count == 1


def test_client_revocation_removes_results_and_stops_work(env):
    _, broker, token = env
    task = broker.submit("test", TaskRequest(key="revoked", steps=[{"account": "demo-api", "operation": "summary"}]))
    broker.advance(task["task_id"])
    broker.revoke(principal="test")
    with pytest.raises(AccessError, match="invalid_client"):
        broker.store.client(token)
    with pytest.raises(AccessError, match="client_revoked"):
        broker.task("test", task["task_id"])


def test_secrets_encrypted_and_not_in_output_or_audit(env):
    _, broker, _ = env
    state = broker.store.get("connection:demo-api")
    config = broker.store.config()
    config.accounts["demo-api"].operations["summary"].fields.append("access_token")
    broker.store.configure(config)
    broker.grant("test", "demo-api", ["summary"])
    connect_demo(broker)
    state = broker.store.get("connection:demo-api")
    output = json.dumps(broker.run("test", "demo-api", "summary")) + json.dumps(broker.audit("test"))
    assert state["token"]["access_token"] not in output
    assert "[REDACTED]" in output
    for file in broker.store.root.glob("state.db*"):
        data = file.read_bytes()
        for secret in [state["token"]["access_token"], state["token"]["refresh_token"], "controlled-demo-password-only"]:
            assert secret.encode() not in data
