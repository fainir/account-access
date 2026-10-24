import json
from types import SimpleNamespace

import pytest

from scripts import worker_boundary_probe as client_probe
from scripts import worker_boundary_smoke as harness


@pytest.mark.parametrize("status", ["QUEUED", "RUNNING", "RETRYABLE", "FAILED", "NEEDS_USER"])
def test_task_failure_reports_only_closed_state_and_nested_reason(status):
    result = {"status": status, "wait_timed_out": True,
              "blocked": {"reason": "login_retry_cooldown", "secret": "never-export-this"},
              "task_id": "never-export-this", "results": ["never-export-this"]}
    report = client_probe.ProbeFailure("native-sms-task-wait", result).report()
    assert report == {"status": "FAILED", "reason": "worker_boundary_probe_failed",
                      "stage": "native-sms-task-wait", "operation_status": status,
                      "operation_reason": "login_retry_cooldown", "wait_timed_out": True}


def test_unknown_fixture_values_and_truthy_timeout_are_not_exported():
    report = client_probe.ProbeFailure("private-stage", {
        "status": "private-status", "reason": "private-reason", "wait_timed_out": "true",
        "blocked": {"reason": "login_retry_cooldown"},
    }).report()
    assert report == {"status": "FAILED", "reason": "worker_boundary_probe_failed",
                      "stage": "boundary_checks", "operation_reason": "not_reported"}


@pytest.mark.parametrize("trusted", [True, False])
def test_parent_preserves_closed_task_diagnostic_without_raw_output(monkeypatch, tmp_path, trusted):
    stages = []
    result = {"status": "FAILED", "stage": "native-sms-task-wait" if trusted else "private-stage",
              "operation_status": "RUNNING" if trusted else "private-status",
              "operation_reason": "login_retry_cooldown" if trusted else "private-reason",
              "wait_timed_out": True if trusted else "true", "private": "never-export-this"}
    monkeypatch.setattr(harness, "dropped", lambda role: [])
    monkeypatch.setattr(harness.subprocess, "run", lambda *a, **k: SimpleNamespace(
        returncode=1, stdout=json.dumps(result), stderr="never-export-this"))
    monkeypatch.setattr(harness, "stage", stages.append)
    role = SimpleNamespace(pw_uid=501)
    with pytest.raises(RuntimeError, match="^fixture_boundary_probe_failed$"):
        harness.probe(tmp_path, {"agent": role, "broker": role}, SimpleNamespace(pid=123),
                      {"root": "fixture", "owner_socket": "fixture", "agent_socket": "fixture"},
                      "native-sms-recover")
    assert stages == (["probe_native-sms-task-wait", "operation_RUNNING", "login_retry_cooldown",
                       "task_wait_timed_out"] if trusted else [])
