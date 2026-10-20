"""Ordinary fixtures only; never run the installed privileged diagnostic."""

import json
import os
from pathlib import Path
import plistlib
import stat
from types import SimpleNamespace

import pytest

from macos import startup_check as check


class Fixture:
    def __init__(self, *, refusal=None, redirect=True, start=True, reason="system_broker_unavailable", reset=True):
        self.calls = []
        self.refusal = refusal
        self.redirect_ok = redirect
        self.start_ok = start
        self.reason = reason
        self.reset_ok = reset

    def require_failing(self):
        self.calls.append("require_failing")
        if self.refusal is not None:
            raise self.refusal

    def redirect(self):
        self.calls.append("redirect")
        return self.redirect_ok

    def start_without_killing(self):
        self.calls.append("start")
        return self.start_ok

    def wait_for_closed_failure(self):
        self.calls.append("wait")
        return self.reason

    def restore_default(self):
        self.calls.append("reset")
        if isinstance(self.reset_ok, Exception):
            raise self.reset_ok
        return self.reset_ok

    def cleanup(self):
        self.calls.append("cleanup")


@pytest.mark.parametrize("reason", sorted(check.FAILURE_REASONS))
def test_only_pinned_broker_failure_is_public(reason):
    assert check.closed_failure(json.dumps({"status": "FAILED", "reason": reason}).encode()) == reason


@pytest.mark.parametrize("body", [
    b'{"status":"FAILED","reason":"password=private-value"}',
    b'{"status":"FAILED","reason":"system_broker_unavailable","password":"private-value"}',
    b'{"status":"OK","reason":"system_broker_unavailable"}',
    b'{"status":"FAILED","reason":"system_broker_unavailable","reason":"system_broker_unavailable"}',
    b'[{"status":"FAILED","reason":"system_broker_unavailable"}]',
    b'{"status":"FAILED","reason":null}', b"\xff", b"x" * 4097, b"", b"{" * 100,
])
def test_malformed_ambiguous_or_arbitrary_output_is_not_a_result(body):
    assert check.closed_failure(body) is None


def test_capture_requires_known_failure_and_reset_before_cleanup():
    fixture = Fixture()
    result = check.capture(fixture)
    assert fixture.calls == ["require_failing", "redirect", "start", "wait", "reset", "cleanup"]
    assert result == {
        "status": "failure_captured", "reason": "system_broker_unavailable",
        "cleanup_pending": False, "default_stdout_requested": True, "failure_capture_consumed": True,
    }


@pytest.mark.parametrize("fixture,status,calls", [
    (Fixture(refusal=check.Refused("service_is_running")), "service_is_running", ["require_failing", "cleanup"]),
    (Fixture(redirect=False), "capture_not_permitted", ["require_failing", "redirect", "reset"]),
    (Fixture(start=False), "start_request_unavailable", ["require_failing", "redirect", "start", "reset"]),
    (Fixture(reason=None), "no_closed_failure_reported", ["require_failing", "redirect", "start", "wait", "reset"]),
    (Fixture(reset=False), "failure_captured", ["require_failing", "redirect", "start", "wait", "reset"]),
    (Fixture(reset=RuntimeError("private-value")), "failure_captured", ["require_failing", "redirect", "start", "wait", "reset"]),
])
def test_partial_operations_restore_stdout_and_preserve_pending_target(fixture, status, calls):
    result = check.capture(fixture)
    assert result["status"] == status
    assert fixture.calls == calls
    assert result["cleanup_pending"] is ("redirect" in calls)
    assert "private-value" not in json.dumps(result)


def test_backend_cannot_expand_public_vocabulary():
    for fixture in [Fixture(reason="private-value"), Fixture(refusal=check.Refused("private-value")),
                    Fixture(refusal=RuntimeError("private-value"))]:
        result = check.capture(fixture)
        assert "private-value" not in json.dumps(result)
        assert result["reason"] is None


@pytest.mark.parametrize("pid,exit_code,program,expected", [
    (None, 78, str(check.BROKER), None),
    (None, "78: EX_CONFIG", str(check.BROKER), None),
    (None, "78: UNRECOGNIZED", str(check.BROKER), "service_not_failing_with_78"),
    (123, 78, str(check.BROKER), "service_is_running"),
    (None, 0, str(check.BROKER), "service_not_failing_with_78"),
    (None, 78, "/unrelated-program", "installed_job_changed"),
])
def test_only_exact_failing_job_is_eligible(monkeypatch, pid, exit_code, program, expected):
    body = f"{check.SERVICE} = {{\n\tprogram = {program}\n\tlast exit code = {exit_code}\n"
    if pid:
        body += f"\tpid = {pid}\n"
    body += "}\n"
    monkeypatch.setattr(check, "command", lambda args: (0, body.encode()))
    if expected is None:
        check.require_failing_service()
    else:
        with pytest.raises(check.Refused, match=expected):
            check.require_failing_service()


def test_start_request_never_kills_an_already_running_process(monkeypatch):
    calls = []
    monkeypatch.setattr(check, "command", lambda args: (calls.append(args) or 0, b"123\n"))
    backend = object.__new__(check.InstalledCapture)
    assert backend.start_without_killing()
    assert calls == [["/bin/launchctl", "kickstart", "-p", check.SERVICE]]


def test_job_contract_matches_provisioner_without_installed_access(monkeypatch):
    from account_access.system_provision import Layout, plans

    signatures = {name: {"team": "WBULD6N4NQ", "identifier": "fixture", "hashes": ["a" * 40]}
                  for name in ["owner", "broker", "bootstrap"]}
    _, profile, official_job = plans(Layout.installed(), {
        "broker_uid": 450, "owner_uid": 1000, "vault_id": "fictional", "enrollment_id": "fictional",
    }, signatures, 20)
    reads = {check.BASE / "owner.json": json.dumps(profile).encode(), check.JOB: plistlib.dumps(official_job)}
    monkeypatch.setattr(check, "PINS", {})  # This case checks configuration, not file hash cryptography.
    monkeypatch.setattr(check, "public_bytes", lambda path, limit=0: reads[path])
    monkeypatch.setattr(check.pwd, "getpwuid", lambda uid: SimpleNamespace(pw_gid=20))
    monkeypatch.setattr(check, "command", lambda args: (0, b""))
    check.validate_installation()


def test_transient_startup_pid_is_observed_without_killing(monkeypatch):
    calls = []

    def state():
        calls.append("read")
        if len(calls) == 1:
            raise check.Refused("service_is_running")

    monkeypatch.setattr(check, "require_failing_service", state)
    monkeypatch.setattr(check.time, "sleep", lambda seconds: calls.append("wait"))
    check.wait_for_failing_service()
    assert calls == ["read", "wait", "read"]


def test_healthy_service_never_becomes_a_capture_target(monkeypatch):
    clock = iter([0, 0, 4])
    monkeypatch.setattr(check.time, "monotonic", lambda: next(clock))
    monkeypatch.setattr(check.time, "sleep", lambda seconds: None)

    def healthy():
        raise check.Refused("service_is_running")

    monkeypatch.setattr(check, "require_failing_service", healthy)
    with pytest.raises(check.Refused, match="service_is_running"):
        check.wait_for_failing_service()


@pytest.mark.parametrize("mode,owner,links", [
    (stat.S_IFREG | 0o666, 0, 1), (stat.S_IFREG | 0o600, 501, 1),
    (stat.S_IFREG | 0o600, 0, 2), (stat.S_IFLNK | 0o600, 0, 1),
    (stat.S_IFIFO | 0o600, 0, 1), (stat.S_IFREG | 0o4600, 0, 1),
])
def test_unsafe_capture_metadata_is_refused_before_read(monkeypatch, mode, owner, links):
    monkeypatch.setattr(check.os, "fstat", lambda fd: SimpleNamespace(st_mode=mode, st_uid=owner, st_nlink=links))
    monkeypatch.setattr(check, "no_acl", lambda fd: pytest.fail("unsafe node reached ACL check"))
    with pytest.raises(check.Refused, match="unsafe_metadata"):
        check.check_fd(3)


def test_ordinary_invocation_refuses_before_any_installed_path_access(monkeypatch, capsys):
    assert os.getuid() != 0
    monkeypatch.setattr(check, "validate_installation", lambda: pytest.fail("ordinary invocation read installed paths"))
    assert check.main() == 1
    assert json.loads(capsys.readouterr().out) == {"status": "REFUSED", "reason": "trusted_installer_context_required"}


def test_report_retains_only_public_projection(tmp_path, monkeypatch):
    monkeypatch.setattr(check, "REPORTS", Path("/Library/Logs/AccountAccessStartupChecks"))
    fd = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        result = check.capture(Fixture())
        public_path = check.publish(fd, result)
    finally:
        os.close(fd)
    report = tmp_path / Path(public_path).name
    assert stat.S_IMODE(report.stat().st_mode) == 0o644
    content = json.loads(report.read_text())
    assert content["reason"] == "system_broker_unavailable"
    assert set(content) == {"managed_by", "schema", "target_build", "target_code_sha256", *result}
