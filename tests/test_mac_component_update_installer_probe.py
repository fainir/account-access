"""Pure refusal/provenance/publication contracts; no root, Installer or services."""

import copy
import importlib.util
import json
from pathlib import Path
import stat
import subprocess
from types import SimpleNamespace

import pytest

SOURCE = Path(__file__).resolve().parent.parent / "scripts/mac_component_update_installer_probe.py"
SPEC = importlib.util.spec_from_file_location("component_installer_probe", SOURCE)
probe = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(probe)
REVISION = "a" * 40
PACKAGE = "b" * 64
CI = {"GITHUB_ACTIONS": "true", "CI": "true", "RUNNER_ENVIRONMENT": "github-hosted", "RUNNER_OS": "macOS",
      "RUNNER_ARCH": "ARM64", "GITHUB_REPOSITORY": "fainir/account-access", "GITHUB_RUN_ID": "12345",
      "GITHUB_RUN_ATTEMPT": "1", "GITHUB_SHA": REVISION}
SOURCE_NAMES = ("macos/ComponentUpdate.swift", "macos/ComponentUpdatePolicies.swift", "macos/ComponentUpdateIdentity.swift",
                "macos/InstallerPayload.swift", "macos/build-component-update.py", "account_access/worker_host.py",
                "account_access/worker_bootstrap.py", "account_access/listener_binding.py")


def review():
    return {"schema": 1, "managed_by": "account-access-component-public-review-v1", "component_source_commit": REVISION,
            "base_source_commit": probe.BASE_SOURCE, "package_sha256": PACKAGE, "package_bytes": 100,
            "plan_sha256": "c" * 64,
            "scripts": {"resource-" + str(index): {"sha256": "d" * 64, "mode": 0o644, "bytes": 1}
                        for index in range(15)},
            "source_files": {name: probe.sha(name.encode()) for name in SOURCE_NAMES}}


def simulated_ci(monkeypatch):
    monkeypatch.setattr(probe.sys, "platform", "darwin")
    monkeypatch.setattr(probe.platform, "machine", lambda: "arm64")
    # Mocked return values exercise a pure guard; no privileged process is run.
    monkeypatch.setattr(probe.os, "getuid", lambda: 0)
    monkeypatch.setattr(probe.os, "geteuid", lambda: 0)
    for key, value in CI.items():
        monkeypatch.setenv(key, value)


@pytest.mark.parametrize("field,value", [("GITHUB_ACTIONS", "false"), ("CI", "false"),
    ("RUNNER_ENVIRONMENT", "self-hosted"), ("RUNNER_OS", "Linux"), ("RUNNER_ARCH", "X64"),
    ("GITHUB_REPOSITORY", "other/repo"), ("GITHUB_RUN_ID", "../1"), ("GITHUB_RUN_ID", "0"),
    ("GITHUB_RUN_ATTEMPT", "0"), ("GITHUB_SHA", "A" * 40)])
def test_context_refused_before_files_commands_or_accounts(monkeypatch, field, value):
    simulated_ci(monkeypatch)
    monkeypatch.setenv(field, value)
    monkeypatch.setattr(probe, "RootOutput", lambda *a: pytest.fail("filesystem publication must not start"))
    monkeypatch.setattr(probe.subprocess, "run", lambda *a, **k: pytest.fail("no command may run"))
    with pytest.raises(ValueError):
        probe.run(SimpleNamespace())


def test_ordinary_caller_refused_even_with_hosted_environment(monkeypatch):
    simulated_ci(monkeypatch)
    monkeypatch.setattr(probe.os, "getuid", lambda: 501)
    monkeypatch.setattr(probe.os, "geteuid", lambda: 501)
    with pytest.raises(ValueError):
        probe.guard()


def test_fixed_report_name_and_wrong_path_refuse_before_open(monkeypatch):
    expected = Path("/Library/Logs/AccountAccessComponentInstallerQA-12345/report.json")
    assert probe.report_path("12345") == expected
    monkeypatch.setattr(probe.os, "open", lambda *a, **k: pytest.fail("wrong path must not open anything"))
    for path in (Path("/tmp/report.json"), expected.parent / "other.json", Path(str(expected) + "/../report.json")):
        with pytest.raises(ValueError):
            probe.RootOutput(path, "12345")
    for value in ("../1", "01", "0", "", "1" * 21, 12345):
        with pytest.raises(ValueError):
            probe.report_path(value)


def metadata(mode=stat.S_IFDIR | 0o755, uid=0, links=2):
    return SimpleNamespace(st_mode=mode, st_uid=uid, st_nlink=links)


def test_output_anchor_metadata_requires_root_protected_directory():
    probe.protected_metadata(metadata())
    probe.protected_metadata(metadata(stat.S_IFREG | 0o644, links=1), directory=False)
    for value in (metadata(uid=501), metadata(stat.S_IFDIR | 0o775), metadata(stat.S_IFDIR | 0o777),
                  metadata(stat.S_IFLNK | 0o755), metadata(stat.S_IFDIR | 0o4755)):
        with pytest.raises(ValueError):
            probe.protected_metadata(value)
    with pytest.raises(ValueError):
        probe.protected_metadata(metadata(stat.S_IFREG | 0o644, links=2), directory=False)


def test_log_creation_is_exclusive_and_nofollow(monkeypatch):
    output = probe.RootOutput.__new__(probe.RootOutput)
    output.descriptor = 77
    monkeypatch.setattr(probe.os, "fstat", lambda fd: metadata(stat.S_IFDIR | 0o700))
    observed = []

    def blocked_open(name, flags, mode, *, dir_fd):
        observed.append((name, flags, mode, dir_fd))
        raise FileExistsError("retain prior evidence")

    monkeypatch.setattr(probe.os, "open", blocked_open)
    with pytest.raises(FileExistsError):
        output.write("expand.log", b"public")
    name, flags, mode, parent = observed.pop()
    assert name == "expand.log" and parent == 77 and mode == 0o600
    assert flags & probe.os.O_EXCL and flags & probe.os.O_NOFOLLOW
    for name in ("../report.json", "/tmp/x.log", "other.json"):
        with pytest.raises(ValueError):
            output.write(name, b"public")
    assert not observed


def test_review_has_exact_shape_and_required_source_records():
    value = review()
    assert probe.validate_review(value, REVISION, PACKAGE) == value
    for field, change in (("schema", True), ("package_bytes", True), ("plan_sha256", None),
                          ("base_source_commit", REVISION), ("extra", True), ("component_source_commit", "f" * 40)):
        wrong = review()
        wrong[field] = change
        with pytest.raises(ValueError):
            probe.validate_review(wrong, REVISION, PACKAGE)
    wrong = review()
    del wrong["source_files"][SOURCE_NAMES[0]]
    with pytest.raises(ValueError):
        probe.validate_review(wrong, REVISION, PACKAGE)


@pytest.mark.parametrize("path", ["macos/../private.py", "macos//x.py", "/macos/x.py", "secrets/x.py"])
def test_review_source_cannot_escape_public_repository_names(path):
    value = review()
    value["source_files"][path] = "a" * 64
    with pytest.raises(ValueError):
        probe.validate_review(value, REVISION, PACKAGE)


def fake_git(monkeypatch, *, mode="100644", size=None, changed=False):
    state = {}

    def result(repository, arguments, *, maximum):
        assert repository == Path("/repo")
        operation = arguments[0]
        if operation == "rev-parse":
            return b"sha1\n"
        if operation == "cat-file" and arguments[1] == "-t":
            return b"commit\n"
        if operation == "ls-tree":
            state["name"] = arguments[-1]
            return (mode + " blob " + "e" * 40 + "\t" + state["name"] + "\0").encode()
        if operation == "cat-file":
            return (str(size if size is not None else len(state["name"].encode())) + "\n").encode()
        assert arguments[:3] == ["show", "--no-ext-diff", "--no-textconv"]
        assert arguments[3] == REVISION + ":" + state["name"]
        return b"changed" if changed else state["name"].encode()

    monkeypatch.setattr(probe, "git_bytes", result)


def test_corresponding_sources_are_resolved_at_commit_not_manifest_asserted(monkeypatch):
    fake_git(monkeypatch)
    probe.bind_sources(review(), Path("/repo"), REVISION)
    wrong = review()
    wrong["source_files"][SOURCE_NAMES[0]] = "f" * 64
    with pytest.raises(ValueError):
        probe.bind_sources(wrong, Path("/repo"), REVISION)


@pytest.mark.parametrize("options", [{"mode": "120000"}, {"size": probe.MAX_SOURCE + 1}, {"changed": True}])
def test_symlinks_oversized_or_changed_committed_source_refused(monkeypatch, options):
    fake_git(monkeypatch, **options)
    with pytest.raises(ValueError):
        probe.bind_sources(review(), Path("/repo"), REVISION)


def test_git_reads_have_config_suppression_no_home_overwrite(monkeypatch):
    observed = []

    def run(arguments, **kwargs):
        observed.append((arguments, kwargs))
        return subprocess.CompletedProcess(arguments, 0, b"public", b"")

    monkeypatch.setattr(probe.subprocess, "run", run)
    assert probe.git_bytes(Path("/repo"), ["show", REVISION + ":macos/x.py"], maximum=100) == b"public"
    arguments, keywords = observed[0]
    assert "--no-replace-objects" in arguments and "--no-optional-locks" in arguments
    assert "core.fsmonitor=false" in arguments and "core.hooksPath=/dev/null" in arguments
    assert keywords["env"]["GIT_CONFIG_GLOBAL"] == keywords["env"]["GIT_CONFIG_SYSTEM"] == "/dev/null"
    assert keywords["env"]["GIT_CONFIG_NOSYSTEM"] == "1" and "HOME" not in keywords["env"]


def test_caught_failure_or_cleanup_error_can_never_become_pass():
    value = {"checks": dict.fromkeys(probe.CHECKS, True)}
    assert probe.acceptance_passed(value)
    for key in ("failure_reason", "cleanup_unverified"):
        wrong = copy.deepcopy(value)
        wrong[key] = False
        assert not probe.acceptance_passed(wrong)
    for change in (1, False):
        wrong = copy.deepcopy(value)
        wrong["checks"][next(iter(probe.CHECKS))] = change
        assert not probe.acceptance_passed(wrong)
    wrong = copy.deepcopy(value)
    wrong["checks"]["extra"] = True
    assert not probe.acceptance_passed(wrong)


@pytest.fixture
def public_archive(tmp_path, monkeypatch):
    """Ordinary files, with only metadata mocked as root anchor/archive UID731."""
    stage = tmp_path / "stage"
    stage.mkdir(mode=0o700)
    expanded = stage / "expanded"
    expanded.mkdir(mode=0o755)
    scripts = expanded / "Scripts"
    scripts.mkdir(mode=0o700)
    base = b'{"roots":{}}\n'
    target = b'{"roots":{"target":"synthetic public image"}}\n'
    plan = {"component_source_commit": REVISION, "base_manifest_sha256": probe.sha(base),
            "target_manifest_sha256": probe.sha(target)}
    files = {"ComponentPlan.json": json.dumps(plan).encode(),
             "BaseManifest.json": base, "TargetManifest.json": target,
             **{"public-" + str(index) + ".bin": b"public fixture" for index in range(12)}}
    for name, raw in files.items():
        (scripts / name).write_bytes(raw)
        (scripts / name).chmod(0o644)
    (expanded / "PackageInfo").write_text(
        '<pkg-info identifier="com.fainir.accountaccess.componentupdate76v2" version="0.1.0">'
        '<scripts><postinstall file="./postinstall"/></scripts></pkg-info>')
    (expanded / "PackageInfo").chmod(0o644)
    value = review()
    value["scripts"] = {name: {"sha256": probe.sha(raw), "mode": 0o644, "bytes": len(raw)}
                        for name, raw in files.items()}
    value["plan_sha256"] = probe.sha(files["ComponentPlan.json"])
    monkeypatch.setattr(probe, "BASE_MANIFEST_SHA256", probe.sha(base))
    monkeypatch.setattr(probe, "deny_only_acl", lambda fd: None)
    anchor = stage.stat()
    fields = ("st_dev", "st_ino", "st_mode", "st_uid", "st_gid", "st_nlink", "st_size", "st_mtime_ns", "st_ctime_ns")

    def logical_metadata(info):
        result = {name: getattr(info, name) for name in fields}
        result["st_uid"] = 0 if (info.st_dev, info.st_ino) == (anchor.st_dev, anchor.st_ino) else 731
        return SimpleNamespace(**result)

    real_fstat, real_stat = probe.os.fstat, probe.os.stat
    monkeypatch.setattr(probe.os, "fstat", lambda *a, **k: logical_metadata(real_fstat(*a, **k)))
    monkeypatch.setattr(probe.os, "stat", lambda *a, **k: logical_metadata(real_stat(*a, **k)))
    return stage, expanded, value, target


def test_archive_uid_is_data_inside_root_private_anchor_without_global_relaxation(public_archive):
    stage, expanded, value, target = public_archive
    diagnostics = {}
    scripts, plan, verified_target = probe.candidate_scripts(expanded, value, staging_anchor=stage, diagnostics=diagnostics)
    assert scripts == expanded / "Scripts" and plan["component_source_commit"] == REVISION
    assert verified_target == json.loads(target)
    metadata = diagnostics["expanded_public_metadata"]
    assert metadata["directories"]["stage"]["uid"] == 0
    assert all(row["uid"] == 731 for row in metadata["entries"]["Scripts"])
    assert all(set(row) == {"name", "type", "uid", "gid", "mode", "bytes"} for row in metadata["entries"]["Scripts"])
    with pytest.raises(ValueError):
        probe.read_file(scripts / "BaseManifest.json")  # Real installed-file contract still requires root.


@pytest.mark.parametrize("change,stage_name", [("extra_sidecar", "candidate_resource_set"),
    ("changed_bytes", "candidate_resource_bytes"), ("writable", "candidate_resource_bytes"),
    ("hardlink", "candidate_resource_bytes"), ("symlink", "candidate_resource_bytes"),
    ("payload", "candidate_top_level"), ("xml", "candidate_package_info")])
def test_archive_byte_type_mode_set_and_xml_guards_still_refuse(public_archive, tmp_path, change, stage_name):
    stage, expanded, value, _ = public_archive
    resource = expanded / "Scripts/public-0.bin"
    if change == "extra_sidecar":
        (expanded / "Scripts/._public-0.bin").write_bytes(b"public metadata")
    elif change == "changed_bytes":
        resource.write_bytes(b"different")
    elif change == "writable":
        resource.chmod(0o666)
    elif change == "hardlink":
        probe.os.link(resource, tmp_path / "retained-hardlink")
    elif change == "symlink":
        resource.unlink()
        resource.symlink_to(tmp_path / "absent")
    elif change == "payload":
        (expanded / "Payload").mkdir()
    else:
        (expanded / "PackageInfo").write_text("<wrong/>")
    diagnostics = {}
    with pytest.raises((ValueError, OSError)):
        probe.candidate_scripts(expanded, value, staging_anchor=stage, diagnostics=diagnostics)
    assert diagnostics["failure_stage"] == stage_name
    if change == "extra_sidecar":
        assert any(row["name"] == "._public-0.bin" for row in diagnostics["expanded_public_metadata"]["entries"]["Scripts"])


def test_unprotected_stage_or_symlink_archive_directory_never_adopted(public_archive, tmp_path):
    stage, expanded, value, _ = public_archive
    stage.chmod(0o755)
    diagnostics = {}
    with pytest.raises(ValueError):
        probe.candidate_scripts(expanded, value, staging_anchor=stage, diagnostics=diagnostics)
    assert diagnostics["failure_stage"] == "candidate_stage_anchor"
    stage.chmod(0o700)
    (expanded / "Scripts").rename(expanded / "SavedScripts")
    (expanded / "Scripts").symlink_to(expanded / "SavedScripts", target_is_directory=True)
    diagnostics = {}
    with pytest.raises((ValueError, OSError)):
        probe.candidate_scripts(expanded, value, staging_anchor=stage, diagnostics=diagnostics)
    assert diagnostics["failure_stage"] == "candidate_scripts_directory"
    assert diagnostics["expanded_public_metadata"]["directories"]["Scripts"]["type"] == "symlink"


def test_archive_uid_change_during_read_refused(public_archive, monkeypatch):
    stage, expanded, _, _ = public_archive
    diagnostics = {}
    archive = probe.ArchiveExpansion(stage, expanded, diagnostics)
    resource = expanded / "Scripts/public-0.bin"
    inode = resource.stat().st_ino
    original = probe.os.fstat
    observations = 0

    def changing_owner(fd):
        nonlocal observations
        info = original(fd)
        if info.st_ino == inode:
            observations += 1
            if observations > 1:
                return SimpleNamespace(**{**vars(info), "st_uid": 732})
        return info

    monkeypatch.setattr(probe.os, "fstat", changing_owner)
    try:
        with pytest.raises(ValueError):
            archive.read("Scripts", resource.name)
    finally:
        archive.close()


def test_expanded_metadata_has_fixed_entry_bound(public_archive):
    stage, expanded, value, _ = public_archive
    for index in range(50):
        (expanded / "Scripts" / ("extra-" + str(index))).touch()
    diagnostics = {}
    with pytest.raises(ValueError):
        probe.candidate_scripts(expanded, value, staging_anchor=stage, diagnostics=diagnostics)
    assert diagnostics["failure_stage"] == "candidate_expanded_metadata"
    assert diagnostics["expanded_public_metadata"]["entry_counts"]["Scripts"] == 65
    assert diagnostics["expanded_public_metadata"]["entries"]["Scripts"] == []


def test_gui_presence_is_exact_pgrep_data_not_an_application_launch():
    assert not probe.fresh_gui_present(subprocess.CompletedProcess([], 1, b"", b""))
    assert probe.fresh_gui_present(subprocess.CompletedProcess([], 0, b"123\n456\n", b""))
    for code, stdout, stderr in ((2, b"", b""), (1, b"123\n", b""), (1, b"", b"denied"),
        (0, b"", b""), (0, b"name\n", b""), (0, b"1\n", b""), (0, b"123\n123\n", b""),
        (0, b"2147483648\n", b""), (0, b"-123\n", b""), (0, b"123", b""),
        (0, b"123\n" * 9, b""), (False, b"123\n", b"")):
        with pytest.raises(ValueError):
            probe.fresh_gui_present(subprocess.CompletedProcess([], code, stdout, stderr))


def gui_commands(monkeypatch, observations):
    remaining, calls, sleeps = list(observations), [], []

    def command(arguments, **kwargs):
        calls.append((arguments, kwargs))
        if arguments[0] == "/usr/bin/pgrep":
            assert arguments == ["/usr/bin/pgrep", "-u", "501", "-x", "AccountAccess"]
            assert kwargs["check"] is False and 0 < kwargs["timeout"] <= 3
            present = remaining.pop(0)
            return subprocess.CompletedProcess(arguments, 0 if present else 1, b"123\n" if present else b"", b"")
        assert arguments == ["/bin/launchctl", "asuser", "501", "/usr/bin/sudo", "-n", "-H", "-u", "#501", "--",
            "/usr/bin/osascript", "-e", 'tell application id "com.fainir.accountaccess" to quit']
        assert kwargs["timeout"] == 30
        return subprocess.CompletedProcess(arguments, 0, b"", b"")

    monkeypatch.setattr(probe, "command", command)
    monkeypatch.setattr(probe.time, "sleep", sleeps.append)
    return calls, sleeps


def test_already_absent_gui_is_never_started_or_sent_quit(monkeypatch):
    calls, sleeps = gui_commands(monkeypatch, [False])
    report = {}
    probe.close_fresh_gui(501, report=report, output=None)
    assert len(calls) == 1 and sleeps == []
    assert report["gui_close_outcome"] == "absent_when_checked" and report["normal_quit_requested"] is False
    assert report["gui_startup_grace_is_readiness_proof"] is False


def test_present_gui_gets_bounded_startup_grace_then_can_be_observed_absent(monkeypatch):
    calls, sleeps = gui_commands(monkeypatch, [True, False])
    report = {}
    probe.close_fresh_gui(501, report=report, output=None)
    assert len(calls) == 2 and sleeps == [90]
    assert report["gui_close_outcome"] == "absent_after_startup_grace"
    assert report["normal_quit_requested"] is False and report["gui_startup_grace_is_readiness_proof"] is False


def test_normal_quit_is_followed_by_actual_absence_observation(monkeypatch):
    calls, sleeps = gui_commands(monkeypatch, [True, True, True, False])
    report = {}
    probe.close_fresh_gui(501, report=report, output=None)
    assert len(calls) == 5 and sleeps == [90, 0.25]
    assert report["normal_quit_command_succeeded"] is True
    assert report["gui_close_outcome"] == "normal_quit_and_absence_observed"


def test_successful_quit_command_without_absence_is_not_closed(monkeypatch):
    calls, sleeps = gui_commands(monkeypatch, [True] * 22)
    report = {}
    with pytest.raises(ValueError):
        probe.close_fresh_gui(501, report=report, output=None)
    assert len(calls) == 23 and sleeps[0] == 90
    assert report["normal_quit_command_succeeded"] is True and "gui_close_outcome" not in report
    assert report["failure_stage"] == "fresh_gui_absence_after_quit"


@pytest.mark.parametrize("failure", ["timeout", "invocation", "oversize"])
def test_command_failures_always_retain_bounded_closed_outcome(monkeypatch, failure):
    logs = {}

    def command(arguments, **kwargs):
        if failure == "timeout":
            raise subprocess.TimeoutExpired(arguments, kwargs["timeout"], output=b'"' * 100000, stderr=b"\x00" * 100000)
        if failure == "invocation":
            raise OSError("synthetic invocation failure")
        return subprocess.CompletedProcess(arguments, 0, b"x" * (128 * 1024 + 1), b"")

    monkeypatch.setattr(probe.subprocess, "run", command)
    report = {"logs": {}}
    output = SimpleNamespace(write=lambda name, raw: logs.setdefault(name, raw))
    with pytest.raises((subprocess.TimeoutExpired, OSError, ValueError)):
        probe.command(["public-fixture"], report=report, output=output, log="fresh-gui-normal-quit.log")
    raw = logs["fresh-gui-normal-quit.log"]
    assert len(raw) <= 256 * 1024 and report["logs"]["fresh-gui-normal-quit.log"] == probe.sha(raw)
    value = json.loads(raw)
    assert value["timed_out"] is (failure == "timeout")
    assert value["invocation_failed"] is (failure == "invocation")
    assert value["output_limited"] is (failure in {"timeout", "oversize"})
    assert report["command_failure"]["log"] == "fresh-gui-normal-quit.log"


def test_detailed_installer_failure_reason_at_end_of_output_is_retained(monkeypatch):
    reason = b'{"schema":1,"status":"REFUSED","reason":"component_base_not_verified"}'
    stdout = b"installer output begins\n" + b"x" * 40000 + b"\ninstaller output ends\n"
    stderr = b"detailed log begins\n" + b"y" * 40000 + b"\n" + reason + b"\n"
    monkeypatch.setattr(probe.subprocess, "run", lambda *a, **k: subprocess.CompletedProcess(a[0], 1, stdout, stderr))
    logs, report = {}, {"logs": {}}
    output = SimpleNamespace(write=lambda name, raw: logs.setdefault(name, raw))
    with pytest.raises(ValueError):
        probe.command(["public-installer-fixture"], report=report, output=output, log="candidate-installer.log")
    raw = logs["candidate-installer.log"]
    value = json.loads(raw)
    assert value["capture_format"] == "full_or_8k_head_tail_v1" and len(raw) <= 256 * 1024
    assert value["stdout"].startswith("installer output begins")
    assert value["stderr_tail"].endswith(reason.decode() + "\n")
    for stream, original in (("stdout", stdout), ("stderr", stderr)):
        assert len(value[stream]) == len(value[stream + "_tail"]) == 8192
        assert value[stream + "_truncated"] is True
        assert value[stream + "_bytes"] == len(original)
        assert value[stream + "_sha256"] == probe.sha(original)


@pytest.mark.parametrize("size", [0, 100, 16384, 16385])
def test_small_command_output_stays_complete_and_boundary_is_explicit(monkeypatch, size):
    stdout = b"a" * size
    monkeypatch.setattr(probe.subprocess, "run", lambda *a, **k: subprocess.CompletedProcess(a[0], 0, stdout, b""))
    logs, report = {}, {"logs": {}}
    output = SimpleNamespace(write=lambda name, raw: logs.setdefault(name, raw))
    probe.command(["public-fixture"], report=report, output=output, log="public.log")
    value = json.loads(logs["public.log"])
    if size <= 16384:
        assert value["stdout"] == stdout.decode() and value["stdout_tail"] == ""
        assert value["stdout_truncated"] is False
    else:
        assert len(value["stdout"]) == len(value["stdout_tail"]) == 8192
        assert value["stdout_truncated"] is True


@pytest.fixture
def installer_daemon_log(tmp_path, monkeypatch):
    """Ordinary synthetic tree; only metadata is represented as CI root-owned."""
    directory = tmp_path / "private/var/log"
    directory.mkdir(parents=True)
    path = directory / "install.log"
    path.write_bytes(b"older log bytes must never be captured\n")
    path.chmod(0o644)
    real_open, real_fstat, real_stat = probe.os.open, probe.os.fstat, probe.os.stat
    fields = ("st_dev", "st_ino", "st_mode", "st_uid", "st_gid", "st_nlink", "st_size", "st_mtime_ns", "st_ctime_ns")

    def logical_metadata(info):
        return SimpleNamespace(**{**{name: getattr(info, name) for name in fields}, "st_uid": 0})

    def fixed_open(name, flags, *args, **kwargs):
        if name == "/":
            name = tmp_path
        return real_open(name, flags, *args, **kwargs)

    monkeypatch.setattr(probe.os, "open", fixed_open)
    monkeypatch.setattr(probe.os, "fstat", lambda *a, **k: logical_metadata(real_fstat(*a, **k)))
    monkeypatch.setattr(probe.os, "stat", lambda *a, **k: logical_metadata(real_stat(*a, **k)))
    monkeypatch.setattr(probe, "deny_only_acl", lambda fd: None)
    return path


def capture_daemon(checkpoint):
    logs, report = {}, {"logs": {}}
    output = SimpleNamespace(write=lambda name, raw: logs.setdefault(name, raw))
    checkpoint.capture(report=report, output=output, log="candidate-daemon-install.log")
    return report["installer_daemon_logs"]["candidate-daemon-install.log"], logs, report


def test_daemon_checkpoint_reads_no_old_bytes_and_captures_only_appended_bytes(installer_daemon_log, monkeypatch):
    path = installer_daemon_log
    original = path.stat().st_size
    real_pread = probe.os.pread
    reads = []

    def pread(fd, size, offset):
        reads.append((size, offset))
        assert offset >= original
        return real_pread(fd, size, offset)

    monkeypatch.setattr(probe.os, "pread", pread)
    monkeypatch.setattr(probe.os, "read", lambda *a: pytest.fail("no old or sequential log read"))
    checkpoint = probe.InstallerLogDelta()
    assert reads == [] and checkpoint.reason is None
    raw = b'package_script_service: {"reason":"component_base_not_verified"}\n'
    with path.open("ab") as stream:
        stream.write(raw)
    value, logs, report = capture_daemon(checkpoint)
    assert reads == [(len(raw), original)]
    assert logs == {"candidate-daemon-install.log": raw}
    assert value == {"status": "captured", "reason": None, "existing_bytes_read": 0,
                     "start_offset": original, "end_offset": original + len(raw),
                     "observed_end_offset": original + len(raw), "bytes": len(raw), "sha256": probe.sha(raw)}
    assert report["logs"]["candidate-daemon-install.log"] == probe.sha(raw)
    assert checkpoint.descriptor is checkpoint.parent is None


@pytest.mark.parametrize("change", ["rotate", "truncate", "symlink", "hardlink", "writable"])
def test_daemon_rotation_truncation_and_metadata_changes_are_unavailable(installer_daemon_log, change):
    path = installer_daemon_log
    checkpoint = probe.InstallerLogDelta()
    if change == "rotate":
        path.rename(path.with_suffix(".old"))
        path.write_bytes(b"new log")
    elif change == "truncate":
        path.write_bytes(b"short")
    elif change == "symlink":
        retained = path.with_suffix(".retained")
        path.rename(retained)
        path.symlink_to(retained)
    elif change == "hardlink":
        probe.os.link(path, path.with_suffix(".link"))
    else:
        path.chmod(0o666)
    value, logs, _ = capture_daemon(checkpoint)
    assert value["status"] == "unavailable" and value["existing_bytes_read"] == 0 and not logs
    assert value["reason"] == ("log_truncated" if change == "truncate" else "capture_unavailable")
    assert checkpoint.descriptor is checkpoint.parent is None


def test_daemon_capture_accepts_further_append_during_bounded_read(installer_daemon_log, monkeypatch):
    path = installer_daemon_log
    checkpoint = probe.InstallerLogDelta()
    with path.open("ab") as stream:
        stream.write(b"candidate bytes\n")
    real_pread = probe.os.pread

    def append_after_read(*args):
        value = real_pread(*args)
        with path.open("ab") as stream:
            stream.write(b"later daemon bytes\n")
        return value

    monkeypatch.setattr(probe.os, "pread", append_after_read)
    value, logs, _ = capture_daemon(checkpoint)
    assert value["status"] == "captured" and value["observed_end_offset"] > value["end_offset"]
    assert logs["candidate-daemon-install.log"] == b"candidate bytes\n"


def test_daemon_delta_limit_refuses_without_reading_any_log_content(installer_daemon_log, monkeypatch):
    checkpoint = probe.InstallerLogDelta()
    with installer_daemon_log.open("ab") as stream:
        stream.write(b"x" * (probe.MAX_INSTALLER_DELTA + 1))
    monkeypatch.setattr(probe.os, "pread", lambda *a: pytest.fail("over-limit delta must not be read"))
    value, logs, _ = capture_daemon(checkpoint)
    assert value["status"] == "unavailable" and value["reason"] == "append_limit_exceeded" and not logs


def test_daemon_checkpoint_size_and_symlink_refuse_without_old_reads(installer_daemon_log, monkeypatch):
    monkeypatch.setattr(probe, "MAX_INSTALLER_LOG", 1)
    checkpoint = probe.InstallerLogDelta()
    value, logs, _ = capture_daemon(checkpoint)
    assert value["reason"] == "checkpoint_unavailable" and not logs
    assert checkpoint.descriptor is checkpoint.parent is None
    monkeypatch.setattr(probe, "MAX_INSTALLER_LOG", 512 * 1024 * 1024)
    path = installer_daemon_log
    retained = path.with_suffix(".retained")
    path.rename(retained)
    path.symlink_to(retained)
    checkpoint = probe.InstallerLogDelta()
    value, logs, _ = capture_daemon(checkpoint)
    assert value["reason"] == "checkpoint_unavailable" and not logs


@pytest.mark.parametrize("fails", [False, True])
def test_candidate_installer_always_captures_daemon_delta_without_masking_outcome(monkeypatch, fails):
    observed = []
    error = ValueError("original installer failure")

    class Checkpoint:
        def __init__(self):
            observed.append("checkpoint")

        def capture(self, **kwargs):
            observed.append(("capture", kwargs))

    def command(arguments, **kwargs):
        observed.append(("command", arguments, kwargs))
        if fails:
            raise error
        return "installer success"

    monkeypatch.setattr(probe, "InstallerLogDelta", Checkpoint)
    monkeypatch.setattr(probe, "command", command)
    arguments = dict(report={}, output=None, log="candidate-installer.log", daemon_log="candidate-daemon-install.log")
    if fails:
        with pytest.raises(ValueError) as caught:
            probe.candidate_install(Path("/fixed/candidate.pkg"), **arguments)
        assert caught.value is error
    else:
        assert probe.candidate_install(Path("/fixed/candidate.pkg"), **arguments) == "installer success"
    assert observed[0] == "checkpoint" and observed[1][0] == "command" and observed[2][0] == "capture"
    assert observed[1][1] == ["/usr/sbin/installer", "-dumplog", "-verboseR", "-pkg", "/fixed/candidate.pkg", "-target", "/"]
    assert observed[1][2]["timeout"] == 420


def test_daemon_capture_publication_failure_remains_diagnostic(installer_daemon_log):
    checkpoint = probe.InstallerLogDelta()
    report = {"logs": {}}

    def fail(*args):
        raise OSError("synthetic evidence write failure")

    checkpoint.capture(report=report, output=SimpleNamespace(write=fail), log="candidate-daemon-install.log")
    assert report["installer_daemon_logs"]["candidate-daemon-install.log"]["status"] == "unavailable"
    assert not report["logs"] and checkpoint.descriptor is checkpoint.parent is None


class FakeProcFunction:
    def __init__(self, callback):
        self.callback = callback

    def __call__(self, *args):
        return self.callback(*args)


@pytest.fixture
def process_reader(monkeypatch):
    state = {"pids": [12345], "list_return": 4, "list_errno": 0, "uid": 450,
             "path": "/usr/sbin/cfprefsd", "info_errno": None, "changed": False, "info_calls": 0}

    def listed(*arguments):
        buffer = arguments[-2]
        for index, pid in enumerate(state["pids"]):
            buffer[index] = pid
        probe.ctypes.set_errno(state["list_errno"])
        return state["list_return"]

    def information(pid, flavor, arg, buffer, size):
        assert flavor == 3 and arg == 0 and size == 136
        state["info_calls"] += 1
        if state["info_errno"] is not None:
            probe.ctypes.set_errno(state["info_errno"])
            return 0
        value = probe.ctypes.cast(buffer, probe.ctypes.POINTER(probe.ProcessBSDInfo)).contents
        value.pbi_pid, value.pbi_uid = pid, state["uid"]
        value.start_sec = 100 + (state["changed"] and state["info_calls"] % 2 == 0)
        value.start_usec = 5
        return size

    def executable(pid, buffer, size):
        assert size == 4096
        raw = state["path"].encode() + b"\0"
        probe.ctypes.memmove(buffer, raw, len(raw))
        return len(raw) - 1

    library = SimpleNamespace(proc_listpids=FakeProcFunction(listed), proc_listpidspath=FakeProcFunction(listed),
                              proc_pidinfo=FakeProcFunction(information), proc_pidpath=FakeProcFunction(executable))

    def load(path, **kwargs):
        assert path == "/usr/lib/libproc.dylib" and kwargs == {"use_errno": True}
        return library

    monkeypatch.setattr(probe.ctypes, "CDLL", load)
    return probe.ProcessDiagnosticReader(), state, library


def test_process_diagnostics_fixed_typed_apis_and_known_class_only(process_reader):
    reader, state, library = process_reader
    value = reader.observed(4, 450, expected_uid=450)
    assert value["count"] == value["unique_count"] == 1 and value["classes"]["cfprefsd"] == 1
    assert all(function.restype is probe.ctypes.c_int and function.argtypes for function in vars(library).values())
    raw = json.dumps(value)
    assert "12345" not in raw and "450" not in raw and "/usr/" not in raw and "pids" not in raw
    state["path"] = "/private/unknown-executable-never-published"
    value = reader.observed(4, 450, expected_uid=450)
    assert value["classes"]["unknown"] == 1 and "unknown-executable" not in json.dumps(value)


@pytest.mark.parametrize("returned,error,path,status", [(0, 0, None, "measured"), (0, 1, None, "api_failure"),
    (4, 22, None, "measured"), (0, 22, "/fixed/public", "measured"),
    (-1, 2, "/fixed/public", "api_failure"), (-1, 0, "/fixed/public", "api_failure"),
    (3, 0, None, "invalid_result"), (16384, 0, None, "invalid_result")])
def test_process_list_return_and_errno_are_retained_without_false_empty(process_reader, returned, error, path, status):
    reader, state, _ = process_reader
    state.update(list_return=returned, list_errno=error)
    value, pids = reader.listed(4 if path is None else 1, 450 if path is None else 0, path=path)
    assert value["status"] == status and value["returned_bytes"] == returned and value["errno"] == error
    if status != "measured":
        assert "count" not in value and pids == []


def test_fixed_executable_reference_counts_distinguish_execution_from_open_file(process_reader):
    reader, state, _ = process_reader
    path = str(probe.BASE / "bin/AccountAccess-broker")
    value = reader.observed(1, 0, path=path)
    assert value["other_references"] == 1 and value["execution_matches"] == 0
    state["path"] = path
    value = reader.observed(1, 0, path=path)
    assert value["execution_matches"] == 1 and value["classes"]["broker"] == 1
    assert str(probe.BASE) not in json.dumps(value)


@pytest.mark.parametrize("change", ["birth", "uid", "api"])
def test_process_identity_changes_and_api_failures_are_counts_only(process_reader, change):
    reader, state, _ = process_reader
    if change == "birth":
        state["changed"] = True
    elif change == "uid":
        state["uid"] = 451
    else:
        state["info_errno"] = 3
    value = reader.observed(4, 450, expected_uid=450)
    assert value["changed_count"] == (change != "api") and value["unavailable_count"] == (change == "api")
    assert sum(value["classes"].values()) == 0


def test_process_classification_is_bounded(process_reader):
    reader, state, _ = process_reader
    state.update(pids=list(range(1000, 1257)), list_return=257 * 4)
    value = reader.observed(4, 450, expected_uid=450)
    assert value["classification_status"] == "limit_exceeded" and state["info_calls"] == 0


def diagnostic_context():
    report = {"checks": dict.fromkeys(probe.CHECKS, True), "failure_reason": "original installer failure",
              "failure_stage": "candidate_installer"}
    install = {"managed_by": "account-access-system-install-v1", "schema": 1,
               "broker_name": "_accountaccess", "broker_uid": 450}
    return report, install


def missing_test_identity(monkeypatch):
    def absent(uid):
        assert uid == 4294967293
        raise KeyError(uid)

    monkeypatch.setattr(probe.pwd, "getpwuid", absent)


@pytest.mark.parametrize("bad", ["context", "image", "signature", "uid", "name"])
def test_quiescence_diagnostic_refuses_unbound_context_before_loading_libproc(monkeypatch, bad):
    report, install = diagnostic_context()
    monkeypatch.setattr(probe, "guard", lambda: None)
    if bad == "context":
        monkeypatch.setattr(probe, "guard", lambda: probe.require(False))
    elif bad in {"image", "signature"}:
        report["checks"]["base_public_image" if bad == "image" else "genuine_signed_helper"] = False
    else:
        install["broker_uid" if bad == "uid" else "broker_name"] = 501 if bad == "uid" else "other"
    monkeypatch.setattr(probe, "ProcessDiagnosticReader", lambda: pytest.fail("no process observation before binding"))
    probe.quiescence_diagnostics(report, install, "a" * 64)
    assert report["quiescence_diagnostics"]["status"] == "unavailable"
    assert report["failure_reason"] == "original installer failure" and report["failure_stage"] == "candidate_installer"


def test_quiescence_diagnostic_is_observational_and_preserves_original_failure(monkeypatch):
    report, install = diagnostic_context()
    original_checks = report["checks"].copy()
    calls = []

    class Reader:
        def observed(self, kind, info, **kwargs):
            calls.append((kind, info, kwargs))
            return {"status": "measured", "count": 0, "errno": 0}

    monkeypatch.setattr(probe, "guard", lambda: None)
    monkeypatch.setattr(probe, "ProcessDiagnosticReader", Reader)
    missing_test_identity(monkeypatch)

    def missing_domain(arguments, **kwargs):
        assert arguments == ["/bin/launchctl", "print", "user/4294967293"]
        assert kwargs["timeout"] == 5 and kwargs["env"] == probe.ENV
        return subprocess.CompletedProcess(arguments, 113, b"", b"fixed nonexistent domain\n")

    monkeypatch.setattr(probe.subprocess, "run", missing_domain)
    monkeypatch.setattr(probe, "read_file", lambda *a, **k: pytest.fail("no account or receipt contents read"))
    probe.quiescence_diagnostics(report, install, "a" * 64)
    assert calls == [(4, 450, {"expected_uid": 450}),
        (1, 0, {"path": str(probe.BASE / "bin/AccountAccess-broker")}),
        (1, 0, {"path": str(probe.BASE / "bin/AccountAccess-bootstrap")})]
    value = report["quiescence_diagnostics"]
    assert value["status"] == "observed" and value["diagnostic_only"] is True and value["affects_acceptance"] is False
    assert value["missing_user_domain"]["returncode"] == 113
    assert report["checks"] == original_checks and report["failure_reason"] == "original installer failure"
    assert not probe.acceptance_passed(report)
    monkeypatch.setattr(probe, "ProcessDiagnosticReader", lambda: probe.require(False))
    probe.quiescence_diagnostics(report, install, "a" * 64)
    assert report["quiescence_diagnostics"]["status"] == "unavailable" and report["checks"] == original_checks


@pytest.mark.parametrize("outcome", ["timeout", "error", "oversize"])
def test_missing_user_domain_probe_is_bounded_and_cannot_replace_process_evidence(monkeypatch, outcome):
    report, install = diagnostic_context()
    reader = SimpleNamespace(observed=lambda *a, **k: {"status": "measured", "count": 0, "errno": 0})
    monkeypatch.setattr(probe, "guard", lambda: None)
    monkeypatch.setattr(probe, "ProcessDiagnosticReader", lambda: reader)
    missing_test_identity(monkeypatch)

    def result(arguments, **kwargs):
        if outcome == "timeout":
            raise subprocess.TimeoutExpired(arguments, 5)
        if outcome == "error":
            raise OSError("not published")
        return subprocess.CompletedProcess(arguments, 1, b"", b"x" * 513)

    monkeypatch.setattr(probe.subprocess, "run", result)
    probe.quiescence_diagnostics(report, install, "a" * 64)
    value = report["quiescence_diagnostics"]
    assert value["status"] == "observed" and value["broker_identity_processes"]["count"] == 0
    assert value["missing_user_domain"]["status"] == {
        "timeout": "timeout", "error": "invocation_failed", "oversize": "output_limit"}[outcome]
    assert "stdout" not in value["missing_user_domain"] and report["failure_reason"] == "original installer failure"


def test_missing_user_domain_requires_absent_identity_before_query(monkeypatch):
    monkeypatch.setattr(probe.pwd, "getpwuid", lambda uid: SimpleNamespace())
    monkeypatch.setattr(probe.subprocess, "run", lambda *a, **k: pytest.fail("known identity must not be queried"))
    assert probe.missing_user_domain_diagnostic() == {"status": "identity_present"}


@pytest.mark.parametrize("returncode,stdout,stderr", [(0, b"", b"unexpected domain"),
    (0, b"private process metadata", b""), (113, b"unexpected text", b"private failure details")])
def test_unexpected_domain_presence_never_retains_raw_output(monkeypatch, returncode, stdout, stderr):
    missing_test_identity(monkeypatch)
    monkeypatch.setattr(probe.subprocess, "run", lambda *a, **k: subprocess.CompletedProcess(a[0], returncode, stdout, stderr))
    value = probe.missing_user_domain_diagnostic()
    assert value["status"] == "unexpected_present" and "stdout" not in value and "stderr" not in value
    assert value["stdout_bytes"] == len(stdout) and value["stderr_bytes"] == len(stderr)


def test_unknown_executable_names_are_opt_in_for_only_bound_service_uid(process_reader):
    reader, state, _ = process_reader
    state["path"] = "/fixed/public/python3.12"
    value = reader.observed(4, 450, expected_uid=450, include_unknown_names=True)
    assert value["unknown_executables"] == [{"path": state["path"], "basename": "python3.12", "count": 1}]
    assert "12345" not in json.dumps(value)
    with pytest.raises(ValueError):
        reader.observed(4, 501, expected_uid=501, include_unknown_names=True)
    state["path"] = "/untrusted/control\npath"
    assert reader.observed(4, 450, expected_uid=450, include_unknown_names=True)["unknown_executables"] == []


def test_three_unicode_executable_snapshots_fit_bounded_report(process_reader, monkeypatch):
    reader, state, _ = process_reader
    state.update(pids=list(range(1000, 1260)), list_return=256 * 4)
    monkeypatch.setattr(reader, "executable", lambda pid, **kwargs: ("measured", 0, "/" + "😀" * 125 + chr(65 + pid % 26)))
    value = reader.observed(4, 450, expected_uid=450, include_unknown_names=True)
    assert len(value["unknown_executables"]) == 8
    assert len(json.dumps({"snapshots": [value] * 3}).encode()) < 100000


def canary_context(monkeypatch):
    report, install = diagnostic_context()
    report["checks"]["actual_candidate_installer"] = False
    install["owner_uid"] = 501
    monkeypatch.setattr(probe, "guard", lambda: None)
    monkeypatch.setattr(probe.pwd, "getpwnam", lambda name: SimpleNamespace(
        pw_name="_accountaccess", pw_uid=450, pw_gid=450, pw_dir=str(probe.BASE / "home"), pw_shell="/usr/bin/false"))
    monkeypatch.setattr(probe.grp, "getgrnam", lambda name: SimpleNamespace(gr_name="_accountaccess", gr_gid=450))
    return report, install


@pytest.mark.parametrize("bad", ["owner_uid", "range", "image", "job_cleanup", "identity", "context"])
def test_domain_canary_rejects_foreign_or_unfinished_context_before_commands(monkeypatch, bad):
    report, install = canary_context(monkeypatch)
    if bad == "owner_uid":
        install["owner_uid"] = 450
    elif bad == "range":
        install["broker_uid"] = 501
    elif bad in {"image", "job_cleanup"}:
        report["checks"]["base_public_image" if bad == "image" else "created_job_stopped"] = False
    elif bad == "identity":
        monkeypatch.setattr(probe.pwd, "getpwnam", lambda name: SimpleNamespace(
            pw_name="_accountaccess", pw_uid=451, pw_gid=451, pw_dir=str(probe.BASE / "home"), pw_shell="/usr/bin/false"))
    else:
        monkeypatch.setattr(probe, "guard", lambda: probe.require(False))
    monkeypatch.setattr(probe, "ProcessDiagnosticReader", lambda: pytest.fail("no observation before context"))
    monkeypatch.setattr(probe.subprocess, "run", lambda *a, **k: pytest.fail("no command before context"))
    probe.test_vm_domain_canary(report, install, "a" * 64)
    assert report["test_vm_domain_canary"]["status"] == "refused"
    assert report["test_vm_domain_canary"]["domain_mutations_attempted"] is False


@pytest.mark.parametrize("kind", ["timeout", "invocation_failed", "output_limit"])
def test_domain_canary_refuses_uncertain_installer_completion_before_any_metadata(monkeypatch, kind):
    report, install = canary_context(monkeypatch)
    report["command_failure"] = {"kind": kind, "log": "candidate-installer.log"}
    original = copy.deepcopy(report)
    monkeypatch.setattr(probe.pwd, "getpwnam", lambda *a: pytest.fail("no identity observation after uncertain completion"))
    monkeypatch.setattr(probe, "ProcessDiagnosticReader", lambda: pytest.fail("no process observation after uncertain completion"))
    monkeypatch.setattr(probe.subprocess, "run", lambda *a, **k: pytest.fail("no domain command after uncertain completion"))
    probe.test_vm_domain_canary(report, install, "a" * 64)
    value = report.pop("test_vm_domain_canary")
    assert report == original and value["status"] == "refused" and value["domain_mutations_attempted"] is False


@pytest.mark.parametrize("fail_at", [None, "first_bootout", "bootstrap", "print", "final_bootout"])
def test_domain_canary_sequence_and_final_cleanup_never_change_candidate_failure(monkeypatch, fail_at):
    report, install = canary_context(monkeypatch)
    original = copy.deepcopy(report)
    calls, sleeps = [], []
    reader = SimpleNamespace(
        observed=lambda *a, **k: {"status": "measured", "count": 1, "classes": {"unknown": 1}},
        listed=lambda *a, **k: ({"status": "measured", "count": 0, "errno": 0}, []))
    monkeypatch.setattr(probe, "ProcessDiagnosticReader", lambda: reader)
    monkeypatch.setattr(probe.time, "sleep", sleeps.append)

    def command(action, uid):
        assert uid == 450
        calls.append(action)
        if ((fail_at == "first_bootout" and len(calls) == 1) or action == fail_at
                or fail_at == "final_bootout" and len(calls) == 6):
            return {"status": "timeout"}
        return {"status": "measured", "returncode": 0}

    monkeypatch.setattr(probe, "canary_domain_command", command)
    probe.test_vm_domain_canary(report, install, "a" * 64)
    value = report.pop("test_vm_domain_canary")
    assert report == original and calls[-1] == "bootout"
    assert value["affects_acceptance"] is False and value["domain_mutations_attempted"] is True
    if fail_at in {None, "final_bootout"}:
        assert calls == ["bootout", "bootout", "bootstrap", "bootout", "print", "bootout"] and sleeps == [1, 1]
        assert value["status"] == "observed"
    else:
        assert value["status"] == "incomplete"
    assert value["final_cleanup"]["status"] == ("unverified" if fail_at == "final_bootout" else "uid_empty")


@pytest.mark.parametrize("code,stdout,stderr", [(0, b"user/450 = {\n pid = 12345\n secret = no\n}\n", b""),
    (113, b"", b"Could not find domain for\n"), (1, b"unexpected domain", b"suppressed")])
def test_domain_command_retains_only_header_or_bounded_absence_error(monkeypatch, code, stdout, stderr):
    canary_context(monkeypatch)
    calls = []

    def run(arguments, **kwargs):
        calls.append(arguments)
        assert arguments == ["/bin/launchctl", "print", "user/450"] and kwargs["timeout"] == 15
        return subprocess.CompletedProcess(arguments, code, stdout, stderr)

    monkeypatch.setattr(probe.subprocess, "run", run)
    value = probe.canary_domain_command("print", 450)
    assert calls and "stdout" not in value and "12345" not in json.dumps(value) and "secret" not in json.dumps(value)
    assert ("stderr" in value) is (code != 0 and not stdout)
    assert value["header"] == ("user/450 = {" if code == 0 else None)


def test_uid_empty_poll_has_bounded_attempts_and_does_not_print_or_signal(monkeypatch):
    reader = SimpleNamespace(listed=lambda *a: ({"status": "measured", "count": 1, "errno": 0}, []))
    sleeps = []
    monkeypatch.setattr(probe.time, "monotonic", lambda: 0)
    monkeypatch.setattr(probe.time, "sleep", sleeps.append)
    value = probe.canary_wait_uid_empty(reader, 450)
    assert value["status"] == "not_empty" and value["attempts"] == 81 and sum(sleeps) == 20
    reader.listed = lambda *a: ({"status": "api_failure", "errno": 1}, [])
    assert probe.canary_wait_uid_empty(reader, 450)["status"] == "api_failure"
