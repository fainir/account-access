import json
import threading
import time

import httpx2 as httpx
import pytest
from fastapi.testclient import TestClient
from playwright.sync_api import sync_playwright

from account_access.models import TaskRequest
from account_access.owner import make_owner_server
from account_access.service import create_app
from account_access.worker_health import WorkerHealth


def wait_for(predicate, timeout=8):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        value = predicate()
        if value:
            return value
        time.sleep(.02)
    pytest.fail("Fixture recovery deadline expired")


def test_background_fault_is_visible_without_exception_data_and_original_task_resumes(env, monkeypatch, caplog):
    provider, broker, token = env
    job = broker.submit("test", TaskRequest(key="worker-recovery", steps=[
        {"account": "demo-api", "operation": "summary"}]))
    before_api = provider.api_count
    original_tick = broker.tick
    release = threading.Event()
    failed = threading.Event()
    secret = "private-worker-exception-value-should-never-escape"

    def tick():
        if not release.is_set():
            failed.set()
            raise RuntimeError(secret)
        original_tick()

    monkeypatch.setattr(broker, "tick", tick)
    owner, owner_token = make_owner_server(broker, guided=True)
    thread = threading.Thread(target=owner.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{owner.server_port}"
    try:
        with TestClient(create_app(broker)) as client:
            assert failed.wait(3)
            wait_for(lambda: broker.worker_health.view()["status"] == "RETRYING")
            headers = {"Authorization": "Bearer " + token}
            discovery = client.get("/v1/accounts", headers=headers).json()
            waiting = client.get("/v1/tasks/" + job["task_id"], headers=headers).json()
            owner_state = httpx.get(base + "/owner/state", headers={"Authorization": "Bearer " + owner_token},
                                   trust_env=False).json()
            for payload in [discovery, waiting, owner_state]:
                assert payload["background_recovery"]["status"] == "RETRYING"
                assert payload["background_recovery"]["reason"] == "background_worker_error"
                assert secret not in json.dumps(payload)
            assert waiting["status"] == "QUEUED" and waiting["progress"] == 0
            assert provider.api_count == before_api
            assert not broker.store.pending("demo-api")
            release.set()
            completed = wait_for(lambda: (task if (task := broker.task("test", job["task_id"]))["status"] == "COMPLETED" else None))
            wait_for(lambda: broker.worker_health.view()["status"] == "RUNNING")
            assert completed["task_id"] == job["task_id"]
            assert provider.api_count == before_api + 1
            assert "background_recovery" not in completed
            recovered = client.get("/v1/accounts", headers=headers).json()["background_recovery"]
            assert recovered["consecutive_failures"] == 0 and recovered["failures_total"] >= 1
            assert recovered["last_success"] and recovered["last_failure"] and recovered["next_retry_at"] is None
            assert client.get("/v1/accounts").status_code == 401
        assert broker.worker_health.view()["status"] == "STOPPED"
        assert secret not in caplog.text
        # Health reports are transient and never persist an exception in the vault/audit.
        assert secret not in json.dumps(broker.audit("test"))
    finally:
        release.set()
        owner.shutdown()
        owner.server_close()
        thread.join(timeout=5)


def test_global_failure_backoff_is_bounded_interruptible_and_clears_on_success():
    health = WorkerHealth()
    assert health.view()["status"] == "UNKNOWN"
    health.start()
    assert [health.failure() for _ in range(8)] == [1, 2, 4, 8, 16, 30, 30, 30]
    snapshot = health.view()
    assert snapshot["consecutive_failures"] == 8 and snapshot["failures_total"] == 8
    snapshot["status"] = "forged"
    assert health.view()["status"] == "RETRYING"
    health.begin()
    assert health.view()["in_progress"] is True
    health.success()
    assert health.view()["status"] == "RUNNING" and health.view()["consecutive_failures"] == 0
    assert "reason" not in health.view()
    health.stop()
    assert health.view()["reason"] == "background_worker_stopped"


def test_service_shutdown_interrupts_backoff_and_same_app_can_restart(env, monkeypatch):
    _, broker, _ = env

    def fail():
        raise RuntimeError("not-visible")

    monkeypatch.setattr(broker, "tick", fail)
    app = create_app(broker)
    started = time.monotonic()
    with TestClient(app):
        wait_for(lambda: broker.worker_health.view()["status"] == "RETRYING")
    assert time.monotonic() - started < 3
    assert broker.worker_health.view()["status"] == "STOPPED"
    with TestClient(app):
        wait_for(lambda: broker.worker_health.view()["status"] == "RETRYING")
    assert broker.worker_health.view()["failures_total"] >= 2


def test_owner_without_attached_worker_does_not_claim_service_is_running(env):
    _, broker, _ = env
    assert broker.accounts("test")["background_recovery"]["status"] == "UNKNOWN"
    with TestClient(create_app(broker, worker=False)):
        assert broker.worker_health.view()["status"] == "UNKNOWN"


@pytest.mark.asyncio
async def test_lifespan_exception_stops_worker_and_releases_retries(env, monkeypatch):
    _, broker, _ = env
    monkeypatch.setattr(broker, "tick", lambda: None)
    app = create_app(broker)
    with pytest.raises(ValueError, match="fixture_lifespan_failure"):
        async with app.router.lifespan_context(app):
            wait_for(lambda: broker.worker_health.view()["status"] == "RUNNING")
            raise ValueError("fixture_lifespan_failure")
    assert broker.worker_health.view()["status"] == "STOPPED"


def test_owner_health_refresh_preserves_in_progress_credentials_and_hides_arbitrary_data(env, monkeypatch):
    provider, broker, _ = env
    monkeypatch.setattr("account_access.install.install_detected", lambda store: {"status": "INSTALLED"})
    broker.store.new_client("generic")
    owner, token = make_owner_server(broker, guided=True)
    thread = threading.Thread(target=owner.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{owner.server_port}"
    try:
        assert httpx.get(base + "/owner/health", trust_env=False).status_code == 401
        before = provider.api_count
        with sync_playwright() as pw:
            browser = pw.chromium.launch(headless=True, chromium_sandbox=True)
            try:
                page = browser.new_page()
                page.goto(base + "/#" + token)
                page.get_by_text("Local setup is open", exact=True).wait_for()
                page.get_by_role("button", name="Add an account", exact=True).click()
                page.locator("#password").fill("fictional-not-saved-password")
                broker.worker_health.start()
                broker.worker_health.failure()
                page.get_by_text("Retrying background recovery", exact=True).wait_for(timeout=8000)
                assert page.locator("#recovery-health").is_visible()
                assert page.locator("#password").input_value() == "fictional-not-saved-password"
                broker.worker_health.success()
                page.get_by_text("Running on your computer", exact=True).wait_for(timeout=8000)
                assert page.locator("#recovery-health").is_hidden()
                assert page.locator("#password").input_value() == "fictional-not-saved-password"
                page.evaluate("renderRecoveryHealth({status:'RETRYING',reason:'private-exception-must-not-render'})")
                assert "private-exception-must-not-render" not in page.locator("body").inner_text()
                assert provider.api_count == before
                broker.worker_health.stop()
                page.evaluate("checkRecoveryHealth()")
                page.get_by_text("Background recovery stopped", exact=True).wait_for()
                page.route("**/owner/health", lambda route: route.abort())
                page.evaluate("checkRecoveryHealth()")
                page.get_by_text("Local app unavailable", exact=True).wait_for()
            finally:
                browser.close()
    finally:
        owner.shutdown()
        owner.server_close()
        thread.join(timeout=5)
