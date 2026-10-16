import hashlib
import json
import os
import plistlib
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest

from macos.notarize import APP_ID, Notarization, ReleaseError, run_tool, sha256

TEAM = "EXAMPLE123"
PROFILE = "fixture publisher profile"
JOB = "11111111-1111-4111-8111-111111111111"


class AppleTools:
    """Protocol fixture, not Apple acceptance or real code signing."""
    def __init__(self):
        self.calls = []
        self.uploads = 0
        self.staples = 0
        self.apple_status = "In Progress"
        self.upload_timeout = False
        self.upload_error_with_id = False
        self.log_override = {}
        self.info_override = {}
        self.policy_fails = False
        self.signature_team = TEAM
        self.hardened = True
        self.timestamp = True
        self.staple_error_after_ticket = False

    def __call__(self, argv, timeout=60):
        self.calls.append(argv)
        text, error, code = "", "", 0
        if argv[0] == "codesign" and "--verify" not in argv:
            app = Path(argv[-1])
            arch = argv[argv.index("--arch") + 1]
            content = b"".join(path.read_bytes() for path in sorted(app.rglob("*"))
                               if path.is_file() and path.name != "fixture-notary-ticket")
            digest = hashlib.sha256(content + arch.encode()).hexdigest()[:40]
            error = (f"Identifier={APP_ID}\nTeamIdentifier={self.signature_team}\n"
                     f"Authority=Developer ID Application: Fixture\nCDHash={digest}\n"
                     + ("CodeDirectory flags=0x10000(runtime)\n" if self.hardened else "CodeDirectory flags=0x0\n")
                     + ("Timestamp=fixture timestamp\n" if self.timestamp else ""))
        elif argv[0] == "lipo":
            text = "x86_64 arm64\n"
        elif argv[0] == "ditto":
            app, target = Path(argv[-2]), Path(argv[-1])
            with zipfile.ZipFile(target, "w") as archive:
                for path in sorted(app.rglob("*")):
                    if path.is_file():
                        archive.write(path, str(Path(app.name) / path.relative_to(app)))
        elif argv[:3] == ["xcrun", "notarytool", "submit"]:
            self.uploads += 1
            self.submitted_sha = sha256(argv[3])
            if self.upload_timeout:
                raise ReleaseError("tool_unavailable_or_timed_out", "RETRYABLE")
            text = json.dumps({"id": JOB})
            if self.upload_error_with_id:
                code, error = 69, "fictional-private-credential-error"
        elif argv[:3] == ["xcrun", "notarytool", "info"]:
            text = json.dumps({"id": JOB, "status": self.apple_status, "name": "submission.zip", **self.info_override})
        elif argv[:3] == ["xcrun", "notarytool", "log"]:
            text = json.dumps({"logFormatVersion": 1, "jobId": JOB, "status": self.apple_status,
                               "statusCode": 0 if self.apple_status == "Accepted" else 4000,
                               "archiveFilename": "submission.zip", "sha256": self.submitted_sha,
                               "statusSummary": "fictional-private-log-detail", **self.log_override})
        elif argv[:3] == ["xcrun", "stapler", "validate"]:
            code = 0 if (Path(argv[-1]) / "Contents/fixture-notary-ticket").exists() else 1
        elif argv[:3] == ["xcrun", "stapler", "staple"]:
            self.staples += 1
            (Path(argv[-1]) / "Contents/fixture-notary-ticket").write_text("fixture ticket")
            if self.staple_error_after_ticket:
                self.staple_error_after_ticket = False
                code = 69
        elif argv[0] == "syspolicy_check" and self.policy_fails:
            code, error = 1, "fictional-private-policy-error"
        return subprocess.CompletedProcess(argv, code, text, error)


@pytest.fixture
def release(tmp_path):
    app = tmp_path / "input/Account Access.app"
    resources = app / "Contents/Resources"
    resources.mkdir(parents=True)
    (app / "Contents/MacOS").mkdir()
    (app / "Contents/MacOS/AccountAccess").write_bytes(b"fictional executable")
    (app / "Contents/MacOS/AccountAccess").chmod(0o755)
    (resources / "account_access.whl").write_bytes(b"fictional wheel")
    (resources / "install.sh").write_bytes(b"fictional installer")
    (app / "Contents/Info.plist").write_bytes(plistlib.dumps({
        "CFBundleIdentifier": APP_ID, "CFBundleExecutable": "AccountAccess",
        "CFBundleShortVersionString": "0.8.0", "CFBundleVersion": "56",
        "AccountAccessWheelSHA256": sha256(resources / "account_access.whl")}))
    tools = AppleTools()
    task = Notarization(tmp_path / "release", tools)
    task.prepare(app, TEAM)
    return task, tools, app


def accepted(release):
    task, tools, _ = release
    assert task.submit(PROFILE)["status"] == "SUBMITTED"
    tools.apple_status = "Accepted"
    return task, tools


def test_preparation_is_local_private_and_requires_a_signed_pinned_bundle(release):
    task, tools, app = release
    assert tools.uploads == 0
    requirement = next(arg[3:] for call in tools.calls if call[0] == "codesign" for arg in call if arg.startswith("-R="))
    assert "anchor apple generic" in requirement and TEAM in requirement
    assert "1.2.840.113635.100.6.1.13" in requirement
    assert task.load()["phase"] == "PREPARED"
    assert task.root.stat().st_mode & 0o077 == 0
    for path in [task.state_path, task.archive, task.root / "last-tool.stderr"]:
        assert path.stat().st_mode & 0o077 == 0
    assert task.prepare(app, TEAM)["status"] == "CACHED_STATE"
    assert not task.output.exists()


@pytest.mark.parametrize("change", ["team", "runtime", "timestamp", "wheel", "extra", "symlink", "nonexecutable"])
def test_invalid_package_cannot_start_an_upload(release, change):
    task, tools, app = release
    if change == "team":
        tools.signature_team = "OTHER12345"
    elif change == "runtime":
        tools.hardened = False
    elif change == "timestamp":
        tools.timestamp = False
    elif change == "wheel":
        (app / "Contents/Resources/account_access.whl").write_bytes(b"tampered")
    elif change == "extra":
        (app / "Contents/Resources/owner-passwords.csv").write_text("fictional export")
    elif change == "symlink":
        (app / "Contents/Resources/alias").symlink_to(app / "Contents/Info.plist")
    else:
        (app / "Contents/MacOS/AccountAccess").chmod(0o600)
    with pytest.raises(ReleaseError):
        task.prepare(app, TEAM)
    assert tools.uploads == 0


def test_pending_job_is_checked_again_instead_of_reuploaded(release):
    task, tools, _ = release
    task.submit(PROFILE)
    resumed = Notarization(task.root, tools)
    assert resumed.submit(PROFILE)["submission_id"] == JOB
    assert resumed.finalize(PROFILE)["apple_status"] == "In Progress"
    assert tools.uploads == 1 and tools.staples == 0
    assert not task.output.exists()


def test_timeout_is_uncertain_and_known_job_can_be_adopted_without_resubmission(release):
    task, tools, _ = release
    tools.upload_timeout = True
    with pytest.raises(ReleaseError, match="submission_outcome_uncertain"):
        task.submit(PROFILE)
    resumed = Notarization(task.root, tools)
    with pytest.raises(ReleaseError, match="submission_outcome_uncertain"):
        resumed.submit(PROFILE)
    assert tools.uploads == 1
    tools.apple_status = "Accepted"
    assert resumed.check(PROFILE, adopt=JOB)["status"] == "ACCEPTED"
    assert resumed.finalize(PROFILE)["status"] == "READY_FOR_RELEASE_REVIEW"
    assert tools.uploads == 1


def test_error_response_with_job_id_retains_handle_instead_of_reuploading(release):
    task, tools, _ = release
    tools.upload_error_with_id = True
    assert task.submit(PROFILE)["submission_id"] == JOB
    task.submit(PROFILE)
    assert tools.uploads == 1


def test_recorded_receipt_recovers_a_crash_before_main_state_commit(release, monkeypatch):
    task, tools, _ = release
    save = task.save

    def interrupted(state):
        if state["phase"] == "SUBMITTED":
            raise OSError("fictional disk interruption")
        save(state)

    monkeypatch.setattr(task, "save", interrupted)
    with pytest.raises(OSError):
        task.submit(PROFILE)
    assert task.load()["phase"] == "SUBMISSION_UNKNOWN"
    assert (task.root / "upload-receipt.json").is_file()
    resumed = Notarization(task.root, tools)
    assert resumed.submit(PROFILE)["submission_id"] == JOB
    assert tools.uploads == 1


@pytest.mark.parametrize("field,value", [
    ("sha256", "0" * 64), ("jobId", "22222222-2222-4222-8222-222222222222"),
    ("archiveFilename", "other.zip"), ("logFormatVersion", 2), ("status", "In Progress"),
])
def test_accepted_log_must_match_exact_submitted_archive_before_stapling(release, field, value):
    task, tools = accepted(release)
    tools.log_override[field] = value
    with pytest.raises(ReleaseError, match="apple_log_does_not_match_archive"):
        task.finalize(PROFILE)
    assert tools.staples == 0 and not task.output.exists()


@pytest.mark.parametrize("status", ["Invalid", "Rejected", "Unknown"])
def test_rejected_or_unknown_job_never_produces_a_release_archive(release, status):
    task, tools = accepted(release)
    tools.apple_status = status
    if status == "Unknown":
        with pytest.raises(ReleaseError, match="unrecognized_apple_status"):
            task.finalize(PROFILE)
    else:
        assert task.finalize(PROFILE)["status"] == "REJECTED"
    assert tools.staples == 0 and not task.output.exists()


def test_stapling_policy_and_final_archive_checks_are_resumable_and_input_is_untouched(release):
    task, tools = accepted(release)
    source = release[2]
    tools.staple_error_after_ticket = True
    with pytest.raises(ReleaseError, match="ticket_check_failed"):
        task.finalize(PROFILE)
    resumed = Notarization(task.root, tools)
    result = resumed.finalize(PROFILE)
    assert result["status"] == "READY_FOR_RELEASE_REVIEW"
    assert tools.uploads == tools.staples == 1
    assert result["sha256"] == sha256(task.output)
    with zipfile.ZipFile(task.output) as archive:
        assert all(name.startswith("Account Access.app/") for name in archive.namelist())
        assert any("fixture-notary-ticket" in name for name in archive.namelist())
    assert not (source / "Contents/fixture-notary-ticket").exists()
    cached = task.report(task.load(), cached=True)
    assert cached["status"] == "CACHED_STATE" and "artifact" not in cached
    assert resumed.finalize(PROFILE)["sha256"] == result["sha256"]
    task.output.write_bytes(b"tampered output")
    with pytest.raises(ReleaseError, match="release_archive_already_exists"):
        resumed.finalize(PROFILE)


def test_policy_failure_is_redacted_and_cannot_be_overridden_with_a_weaker_check(release, monkeypatch, capsys):
    import macos.notarize as module
    task, tools = accepted(release)
    tools.policy_fails = True
    monkeypatch.setattr(module, "Notarization", lambda root: task)
    monkeypatch.setattr(sys, "platform", "darwin")
    monkeypatch.setattr(sys, "argv", ["notarize.py", "finalize", "--workdir", str(task.root), "--profile", PROFILE])
    assert module.main() == 1
    report = capsys.readouterr().out
    assert "distribution_check_failed" in report and "fictional-private" not in report
    assert not task.output.exists()
    assert not any(call[0] in {"spctl", "xattr"} for call in tools.calls)


@pytest.mark.parametrize("target", ["app", "archive"])
def test_changed_prepared_input_never_reaches_apple(release, target):
    task, tools, _ = release
    (task.app / "Contents/Resources/install.sh" if target == "app" else task.archive).write_bytes(b"changed")
    with pytest.raises(ReleaseError):
        task.submit(PROFILE)
    assert tools.uploads == 0


def test_private_state_and_process_lock_prevent_conflicting_release_work(release, tmp_path):
    task, tools, _ = release
    with task.locked():
        with pytest.raises(ReleaseError, match="notarization_already_running"):
            with Notarization(task.root, tools).locked():
                pytest.fail("Concurrent publisher acquired the lock")
    task.state_path.unlink()
    outside = tmp_path / "unrelated-private-file"
    outside.write_text("fictional private value")
    os.link(outside, task.state_path)
    with pytest.raises(ReleaseError, match="unsafe_release_path"):
        task.load()
    assert outside.read_text() == "fictional private value"


def test_apple_tools_use_fixed_system_paths_without_a_shell_or_credential_arguments(monkeypatch):
    captured = []

    def execute(argv, **kwargs):
        captured.append((argv, kwargs))
        return subprocess.CompletedProcess(argv, 0, "{}", "")

    monkeypatch.setattr(subprocess, "run", execute)
    run_tool(["xcrun", "notarytool", "info", JOB, "--keychain-profile", PROFILE])
    argv, options = captured[0]
    assert argv[0] == "/usr/bin/xcrun"
    assert options["stdin"] == subprocess.DEVNULL and not options.get("shell")
    assert "--password" not in argv and "--key" not in argv


def test_partial_job_response_survives_a_tool_timeout_without_exposing_it(monkeypatch):
    def timeout(argv, **kwargs):
        raise subprocess.TimeoutExpired(argv, 1, output=json.dumps({"id": JOB}).encode(), stderr=b"fictional-private-error")

    monkeypatch.setattr(subprocess, "run", timeout)
    result = run_tool(["xcrun", "notarytool", "submit", "fixture.zip"], timeout=1)
    assert result.returncode == 124
    assert json.loads(result.stdout)["id"] == JOB


def test_work_directory_cannot_be_created_inside_input_app(release, monkeypatch, capsys):
    import macos.notarize as module
    _, _, app = release
    nested = app / "Contents/release-work"
    monkeypatch.setattr(sys, "platform", "darwin")
    monkeypatch.setattr(sys, "argv", ["notarize.py", "prepare", "--app", str(app),
                                     "--workdir", str(nested), "--team-id", TEAM])
    assert module.main() == 1
    assert "invalid_app_or_work_directory" in capsys.readouterr().out
    assert not nested.exists()


@pytest.mark.parametrize("value", [[], None, {"schema": 1, "app": []}])
def test_malformed_state_is_rejected_without_a_traceback_or_tool_call(release, value):
    task, tools, _ = release
    task.state_path.write_text(json.dumps(value))
    before = len(tools.calls)
    with pytest.raises(ReleaseError, match="invalid_release_state"):
        task.load()
    assert len(tools.calls) == before


def test_unrecognized_existing_directory_is_preserved(tmp_path):
    root = tmp_path / "other-private-work"
    root.mkdir(mode=0o700)
    unrelated = root / "last-tool.stderr"
    unrelated.write_text("unrelated private data")
    with pytest.raises(ReleaseError, match="unrecognized_release_work_directory"):
        Notarization(root)
    assert unrelated.read_text() == "unrelated private data"
    assert sorted(path.name for path in root.iterdir()) == ["last-tool.stderr"]
