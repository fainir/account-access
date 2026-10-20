"""Ordinary fixtures only; never run the installed privileged diagnostic."""

import json
import os
from pathlib import Path
import plistlib
import stat
import sys
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
        if isinstance(self.redirect_ok, Exception):
            raise self.redirect_ok
        return self.redirect_ok

    def start_without_killing(self):
        self.calls.append("start")
        if isinstance(self.start_ok, Exception):
            raise self.start_ok
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
        "failure_stage": None, "failure_outcome": None,
        "command_outcomes": {"redirect": "success", "start": "success", "reset": "success"},
        "mode": "new_capture", "fresh_startup_verified": False,
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


@pytest.mark.parametrize("stage", ["redirect", "start", "reset"])
@pytest.mark.parametrize("outcome", ["timeout", "invocation_error", "output_too_large", "invalid_output"])
def test_each_command_failure_retains_its_closed_operation_and_outcome(stage, outcome):
    fixture = Fixture(**{stage: check.CommandFailure(outcome)})
    result = check.capture(fixture)
    assert result["failure_stage"] == stage
    assert result["failure_outcome"] == outcome
    assert result["command_outcomes"][stage] == outcome
    assert result["cleanup_pending"] is True
    assert fixture.calls.count("reset") == 1
    assert "cleanup" not in fixture.calls
    if stage != "reset":
        assert result["status"] == "diagnostic_tool_unavailable"
        assert result["reason"] is None


def test_failed_reset_does_not_hide_primary_redirect_failure():
    result = check.capture(Fixture(redirect=check.CommandFailure("timeout"),
                                   reset=check.CommandFailure("invocation_error")))
    assert result["failure_stage"] == "redirect"
    assert result["failure_outcome"] == "timeout"
    assert result["command_outcomes"] == {"redirect": "timeout", "start": "not_attempted",
                                          "reset": "invocation_error"}
    assert result["default_stdout_requested"] is False


@pytest.mark.parametrize("stage", ["redirect", "start", "reset"])
def test_nonzero_exit_is_distinct_from_invocation_failure(stage):
    result = check.capture(Fixture(**{stage: False}))
    assert result["failure_stage"] == stage
    assert result["failure_outcome"] == "nonzero"
    assert result["command_outcomes"][stage] == "nonzero"


def test_untrusted_outcome_cannot_enter_public_result():
    failure = check.CommandFailure("private-value")
    failure.outcome = ["private-value"]
    result = check.capture(Fixture(redirect=failure))
    assert result["failure_outcome"] == "invocation_error"
    assert "private-value" not in json.dumps(result)


@pytest.mark.parametrize("limit", [0, -1, True, 128 * 1024 + 1])
def test_invalid_capture_bound_refuses_before_subprocess(monkeypatch, limit):
    monkeypatch.setattr(check.subprocess, "Popen", lambda *args, **kwargs: pytest.fail("spawned"))
    with pytest.raises(check.CommandFailure) as failure:
        check.command(["unreachable"], limit=limit)
    assert failure.value.outcome == "invocation_error"


def test_command_classifies_missing_executable_without_rendering_os_error(monkeypatch):
    def unavailable(*args, **kwargs):
        raise OSError("private-value")

    monkeypatch.setattr(check.subprocess, "Popen", unavailable)
    with pytest.raises(check.CommandFailure) as failure:
        check.command(["unreachable"])
    assert failure.value.outcome == "invocation_error"
    assert failure.value.args == ("diagnostic_tool_unavailable",)


def test_command_preserves_bounded_output_and_nonzero_exit():
    assert check.command([sys.executable, "-I", "-S", "-c", "import sys; print('abc'); sys.exit(7)"],
                         limit=4) == (7, b"abc\n")


def test_missing_bytecode_flag_refuses_before_source_backed_imports():
    # A privileged diagnostic must reject a missing -B before importing ctypes
    # or any other module whose cache could be written into the managed image.
    program = """
import sys, builtins
source = open(sys.argv[1]).read()
original_import = builtins.__import__
def guarded_import(name, *args, **kwargs):
    if name != 'sys':
        raise RuntimeError('source-backed import reached before refusal')
    return original_import(name, *args, **kwargs)
builtins.__import__ = guarded_import
exec(compile(source, sys.argv[1], 'exec'), {'__name__': '__main__'})
"""
    result = check.subprocess.run(
        [sys.executable, "-I", "-S", "-c", program, str(Path(check.__file__).resolve())],
        capture_output=True, check=False, timeout=5,
    )
    assert result.returncode == 1
    assert result.stderr == b""
    assert json.loads(result.stdout) == {
        "status": "REFUSED", "reason": "trusted_installer_context_required",
    }


@pytest.mark.parametrize("outcome", ["timeout", "output_too_large"])
def test_bounded_command_reaps_only_its_own_child(monkeypatch, outcome):
    processes = []
    original = check.subprocess.Popen

    def child(*args, **kwargs):
        process = original(*args, **kwargs)
        processes.append(process)
        return process

    monkeypatch.setattr(check.subprocess, "Popen", child)
    if outcome == "timeout":
        clock = iter([0, 16])
        monkeypatch.setattr(check.time, "monotonic", lambda: next(clock))
        program = "import time; time.sleep(10)"
    else:
        program = "import os; os.write(1, b'x' * 1000000)"
    with pytest.raises(check.CommandFailure) as failure:
        check.command([sys.executable, "-I", "-S", "-c", program], limit=16)
    assert failure.value.outcome == outcome
    assert len(processes) == 1
    assert processes[0].returncode is not None
    assert processes[0].stdout.closed


def test_start_invalid_pid_output_has_closed_distinct_outcome(monkeypatch):
    monkeypatch.setattr(check, "command", lambda args: (0, b"private-value"))
    backend = object.__new__(check.InstalledCapture)
    with pytest.raises(check.CommandFailure) as failure:
        backend.start_without_killing()
    assert failure.value.outcome == "invalid_output"
    assert "private-value" not in str(failure.value)


@pytest.fixture
def ordinary_capture_metadata(monkeypatch):
    original = check.check_fd
    fixture_owner = os.getuid()
    monkeypatch.setattr(check, "no_acl", lambda fd: None)
    monkeypatch.setattr(check, "check_fd", lambda fd, directory=False:
                        original(fd, directory=directory, owner=fixture_owner))


def retained_fixture(tmp_path, data=b'{"status":"FAILED","reason":"system_broker_unavailable"}'):
    name = "capture-" + "a" * 32
    folder = tmp_path / name
    folder.mkdir(mode=0o700)
    output = folder / "stdout"
    output.write_bytes(data)
    output.chmod(0o600)
    return name, folder, output


def test_retained_inspection_reads_only_closed_old_failure(tmp_path, ordinary_capture_metadata, monkeypatch):
    name, folder, output = retained_fixture(tmp_path)
    before = (folder.stat(), output.stat(), output.read_bytes())
    monkeypatch.setattr(check, "command", lambda *args, **kwargs: pytest.fail("retained inspection ran a command"))
    parent = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        assert check.retained_capture_name(parent) == name
        result = check.inspect_retained_capture(parent, name)
        with pytest.raises(check.Refused, match="retained_capture_pending"):
            check.InstalledCapture(parent)
    finally:
        os.close(parent)
    assert result["reason"] == "system_broker_unavailable"
    assert result["mode"] == "retained_capture_inspection"
    assert result["fresh_startup_verified"] is False
    assert result["capture_is_historical"] is True
    assert result["cleanup_pending"] is True
    assert result["default_stdout_requested"] is False
    assert set(result["command_outcomes"].values()) == {"not_attempted"}
    assert set(p.name for p in tmp_path.iterdir()) == {name}
    assert set(p.name for p in folder.iterdir()) == {"stdout"}
    assert (folder.stat().st_mtime_ns, output.stat().st_mtime_ns, output.read_bytes()) == (
        before[0].st_mtime_ns, before[1].st_mtime_ns, before[2])


@pytest.mark.parametrize("data", [b"", b"private-value", b'{"status":"FAILED","reason":"private-value"}'])
def test_retained_unknown_or_empty_output_is_never_published(tmp_path, ordinary_capture_metadata, data):
    name, _, _ = retained_fixture(tmp_path, data)
    parent = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        result = check.inspect_retained_capture(parent, name)
    finally:
        os.close(parent)
    assert result["reason"] is None
    assert result["status"] == "no_closed_failure_reported"
    assert "private-value" not in json.dumps(result)


@pytest.mark.parametrize("change", ["directory_mode", "file_mode", "hardlink", "file_symlink",
                                     "directory_symlink", "extra_entry", "oversize"])
def test_retained_unsafe_metadata_refuses_before_read(tmp_path, ordinary_capture_metadata, monkeypatch, change):
    name, folder, output = retained_fixture(tmp_path)
    if change == "directory_mode":
        folder.chmod(0o755)
    elif change == "file_mode":
        output.chmod(0o640)
    elif change == "hardlink":
        os.link(output, tmp_path / "unrelated")
    elif change == "file_symlink":
        output.unlink()
        output.symlink_to(tmp_path / "unrelated")
    elif change == "directory_symlink":
        output.unlink()
        folder.rmdir()
        folder.symlink_to(tmp_path, target_is_directory=True)
    elif change == "extra_entry":
        (folder / "unrelated").write_bytes(b"private-value")
    else:
        output.write_bytes(b"x" * 4097)
    monkeypatch.setattr(check.os, "pread", lambda *args: pytest.fail("unsafe target was read"))
    parent = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        with pytest.raises(check.Refused):
            check.inspect_retained_capture(parent, name)
    finally:
        os.close(parent)


@pytest.mark.parametrize("change", ["replace_file", "grow_file", "replace_directory"])
def test_retained_changed_identity_refuses_closed_result(tmp_path, ordinary_capture_metadata, monkeypatch, change):
    name, folder, output = retained_fixture(tmp_path)
    original = os.pread

    def changed_read(fd, size, offset):
        data = original(fd, size, offset)
        if change == "replace_file":
            output.unlink()
            output.write_bytes(data)
            output.chmod(0o600)
        elif change == "grow_file":
            with output.open("ab") as stream:
                stream.write(b"x")
        else:
            folder.rename(tmp_path / "removed")
            folder.mkdir(mode=0o700)
        return data

    monkeypatch.setattr(check.os, "pread", changed_read)
    parent = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        with pytest.raises(check.Refused):
            check.inspect_retained_capture(parent, name)
    finally:
        os.close(parent)


@pytest.mark.parametrize("entries,status", [
    (["capture-" + "a" * 32, "capture-" + "b" * 32], "retained_capture_ambiguous"),
    (["capture-unrecognized"], "unknown_report_entry"),
    (["unrelated"], "unknown_report_entry"),
])
def test_retained_selection_refuses_ambiguous_or_unknown_entries(tmp_path, entries, status):
    for name in entries:
        (tmp_path / name).mkdir()
    parent = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        with pytest.raises(check.Refused, match=status):
            check.retained_capture_name(parent)
    finally:
        os.close(parent)


@pytest.fixture
def trusted_fixture_context(tmp_path, monkeypatch, ordinary_capture_metadata):
    previous_umask = os.umask(0o077)
    os.umask(previous_umask)
    tmp_path.chmod(0o755)
    monkeypatch.setattr(check.sys, "platform", "darwin")
    monkeypatch.setattr(check.sys, "executable", str(check.PYTHON))
    monkeypatch.setattr(check.sys, "flags", SimpleNamespace(isolated=True, no_site=True))
    monkeypatch.setattr(check.sys, "dont_write_bytecode", True)
    monkeypatch.setattr(check.sys, "argv", ["fixture-check", "--inspect-retained"])
    # Only the fixture's context checks are substituted; the process never elevates.
    monkeypatch.setattr(check.os, "getuid", lambda: 0)
    monkeypatch.setattr(check.os, "geteuid", lambda: 0)
    monkeypatch.setattr(check, "validate_installation", lambda: None)
    monkeypatch.setattr(check, "InstalledCapture", lambda parent: pytest.fail("inspection created a capture"))
    monkeypatch.setattr(check, "command", lambda *args, **kwargs: pytest.fail("inspection invoked a command"))
    creates = []

    def report_directory(path, *, create=False):
        assert path == check.REPORTS
        creates.append(create)
        return os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY)

    monkeypatch.setattr(check, "directory", report_directory)
    try:
        yield creates
    finally:
        os.umask(previous_umask)


@pytest.mark.parametrize("data,expected_exit", [
    (b'{"status":"FAILED","reason":"system_broker_unavailable"}', 0),
    (b"private-value", 1),
])
def test_explicit_inspection_mode_never_mutates_capture_or_falls_back(tmp_path, trusted_fixture_context,
                                                                   monkeypatch, capsys, data, expected_exit):
    name, folder, output = retained_fixture(tmp_path, data)
    old_report = tmp_path / ("result-" + "b" * 32 + ".json")
    old_report.write_bytes(b"historical-result")
    assert check.main() == expected_exit
    response = json.loads(capsys.readouterr().out)
    assert response["diagnostic_succeeded"] is (expected_exit == 0)
    assert response["fresh_startup_verified"] is False
    assert trusted_fixture_context == [False]
    assert output.read_bytes() == data
    assert old_report.read_bytes() == b"historical-result"
    report = json.loads((tmp_path / Path(response["public_report"]).name).read_text())
    assert report["mode"] == "retained_capture_inspection"
    assert "private-value" not in json.dumps(report)
    assert folder.name == name


def test_inspection_mode_without_retained_target_refuses_and_publishes_immutable_result(
        tmp_path, trusted_fixture_context, capsys):
    assert check.main() == 1
    response = json.loads(capsys.readouterr().out)
    assert response["reason"] == "retained_capture_unavailable"
    assert trusted_fixture_context == [False]
    reports = list(tmp_path.iterdir())
    assert len(reports) == 1 and reports[0].name.startswith("result-")
    result = json.loads(reports[0].read_text())
    assert result["status"] == "retained_capture_unavailable"
    assert result["reason"] is None
    assert result["mode"] == "retained_capture_inspection"
    assert result["cleanup_pending"] is True


@pytest.mark.parametrize("mode", [0o550, 0o700, 0o750])
def test_inspection_refuses_changed_report_directory_mode(tmp_path, trusted_fixture_context, capsys, mode):
    tmp_path.chmod(mode)
    assert check.main() == 1
    assert json.loads(capsys.readouterr().out)["reason"] == "unsafe_metadata"
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize("arguments", [["--inspect-retained", "/unrelated"], ["/unrelated"], ["--unknown"]])
def test_inspection_argument_cannot_select_path_or_other_mode(monkeypatch, capsys, arguments):
    monkeypatch.setattr(check.sys, "argv", ["fixture-check", *arguments])
    monkeypatch.setattr(check, "validate_installation", lambda: pytest.fail("invalid mode read installed files"))
    assert check.main() == 1
    assert json.loads(capsys.readouterr().out)["reason"] == "trusted_installer_context_required"
