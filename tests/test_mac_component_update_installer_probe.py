"""Pure refusal/provenance/publication contracts; no root, Installer or services."""

import copy
import importlib.util
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
