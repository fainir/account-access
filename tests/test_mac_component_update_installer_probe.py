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
