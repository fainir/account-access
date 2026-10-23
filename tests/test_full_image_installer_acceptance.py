"""Pure installer-input and refusal contracts; no downloads, root or Installer."""

import copy
import importlib.util
from pathlib import Path
from types import SimpleNamespace

import pytest


def module(name, filename):
    source = Path(__file__).resolve().parents[1] / "scripts" / filename
    spec = importlib.util.spec_from_file_location(name, source)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


downloader = module("full_image_inputs", "download_full_image_installer_inputs.py")
probe = module("full_image_installer_probe", "mac_full_image_installer_probe.py")


@pytest.mark.parametrize("cohort", [81, 82, 83, 84])
def test_installer_cohort_binds_one_committed_contract_and_package_identity(cohort):
    path, identity = probe.cohort_contract(cohort)
    assert path == downloader.COHORT_CONTRACTS[cohort]
    assert identity == f"com.fainir.accountaccess.fullimageupdate{cohort}"
    assert all(path != other for key, other in downloader.COHORT_CONTRACTS.items() if key != cohort)


@pytest.mark.parametrize("cohort", [None, True, "82", 80, 85, 82.0, "../../foreign"])
def test_installer_cohort_refuses_unreviewed_or_ambiguous_selector(cohort):
    with pytest.raises(ValueError):
        probe.cohort_contract(cohort)


PLAN = "7c80a671d8b87815db127c6e7d7e8dd9db8c023d70e891185258391b2b3f14a3"
COMPONENT_SOURCE = "213509c6bd9ff40131bd71dcb1a2967e96cd76a3"
ASSETS = {
    "base.pkg", "base-manifest.json", "base-source.tar.gz", "component.pkg",
    "component-review.json", "component-source.tar.gz", "full.pkg", "full-review.json",
    "full-scripts-inventory.json", "full-source.tar.gz",
}
CI = {
    "GITHUB_ACTIONS": "true", "CI": "true", "RUNNER_ENVIRONMENT": "github-hosted",
    "RUNNER_OS": "macOS", "RUNNER_ARCH": "ARM64", "GITHUB_REPOSITORY": "fainir/account-access",
    "GITHUB_RUN_ID": "12345", "GITHUB_RUN_ATTEMPT": "1", "GITHUB_SHA": "a" * 40,
}


def contract():
    """Real fixed public pins, fictional unpublished metadata for pure validation only.

    Passing this fixture is not asset availability or Installer acceptance. No
    actual release/asset identifiers are required for the unpublished artifacts.
    """
    base = {"id": 418292574, "tag": "qa-fbd2a73-build76-component-base",
            "source": "fbd2a733b60acde68e82fe796cb7abd971d5d625"}
    component = {"id": 100, "tag": "qa-fictional-component", "source": COMPONENT_SOURCE}
    full = {"id": 101, "tag": "qa-fictional-full", "source": "b" * 40}

    def row(identifier, checksum, size, release):
        return {"id": identifier, "sha256": checksum, "bytes": size,
                "release": copy.deepcopy(release)}

    return {
        "schema": 1, "status": "FROZEN_REVIEWED_ASSETS", "repository": "fainir/account-access",
        "component_source": COMPONENT_SOURCE,
        "target_source": "d5741bc9912aaf907fe5c52486af18818654dda5", "plan_sha256": PLAN,
        "assets": {
            "base.pkg": row(659061910,
                "e525233e74ee942a53c389babac57eee6cad25b79ea178ff9a6384b0a5c5567c", 289451807, base),
            "base-manifest.json": row(659061912,
                "5618053e6f8ed0a8720a9d2f7dde317425cecda6a970abd90c499fbfe27b43a8", 4989248, base),
            "base-source.tar.gz": row(659061965,
                "4b239336a11d702932c376fb7448f9dda6a1eda87c4fe678cadbf537ba137a37", 219113811, base),
            "component.pkg": row(10001,
                "674c5df7866477e48811d002128370aaec6385aeb0565137036880de4c626bef", 3457184, component),
            "component-review.json": row(10002, "c" * 64, 128, component),
            "component-source.tar.gz": row(10003, "d" * 64, 256, component),
            "full.pkg": row(10004, "e" * 64, 512, full),
            "full-review.json": row(10005, "f" * 64, 128, full),
            "full-scripts-inventory.json": row(10006, "1" * 64, 128, full),
            "full-source.tar.gz": row(10007, "2" * 64, 256, full),
        },
    }


@pytest.mark.parametrize("pending", ["status", "missing-asset-id"])
def test_pending_or_unpublished_candidate_cannot_validate(pending):
    value = contract()
    assert downloader.validate(value) == value
    if pending == "status":
        value["status"] = "PENDING_EXACT_BUILT_PACKAGE_AND_RELEASE_ASSETS"
    else:
        value["assets"]["full.pkg"]["id"] = None
    with pytest.raises(ValueError, match="^full_image_installer_input_contract_failed$"):
        downloader.validate(value)


@pytest.mark.parametrize("cohort", [81, 82, 83, 84])
def test_each_cohort_binds_its_app_plan_without_mutating_other_cohorts(cohort):
    value = contract()
    pins = probe.cohort_pins(cohort)
    value["target_source"], value["plan_sha256"] = pins[:2]
    assert downloader.validate(value, cohort) is value
    assert pins[:2] == (downloader.CONFIGURATION_TARGET if cohort == 84 else downloader.LEGACY_TARGET)
    assert probe.cohort_pins(81) == probe.LEGACY_PINS
    assert probe.cohort_pins(84) == probe.CONFIGURATION_PINS
    other = probe.cohort_pins(81 if cohort == 84 else 84)
    for field, replacement in zip(("target_source", "plan_sha256"), other[:2]):
        wrong = copy.deepcopy(value)
        wrong[field] = replacement
        with pytest.raises(ValueError):
            downloader.validate(wrong, cohort)


@pytest.mark.parametrize("raw", [
    b'{"status":"first","status":"second"}',
    b'{"assets":{"full.pkg":{"id":1,"id":2}}}',
])
def test_duplicate_contract_identity_refused(raw):
    with pytest.raises(ValueError, match="^full_image_installer_input_contract_failed$"):
        downloader.decode(raw)


def test_exact_asset_names_accept_real_names_and_reject_escapes():
    assert probe.ASSET_FILES == downloader.FILES == ASSETS
    assert all(probe.asset_name(name) for name in ASSETS)
    for name in (r"base\.pkg", r"full-source.tar\.gz", "../base.pkg", "/base.pkg", "other.pkg",
                 "base.pkg/", "base.PKG", "base.pkg\n", "base/pkg", None, 5):
        assert not probe.asset_name(name)


@pytest.mark.parametrize("path,value", [
    (("plan_sha256",), "8eb5193656b08e105476e0524890e206db2c23d62bc805ed62d1c94623fc06fa"),
    (("schema",), True),
    (("repository",), "other/repository"),
    (("component_source",), "a" * 40),
    (("target_source",), "a" * 40),
    (("assets", "full-source.tar.gz"), None),
    (("assets", "full.pkg", "id"), 10005),
    (("assets", "full.pkg", "id"), True),
    (("assets", "full.pkg", "bytes"), True),
    (("assets", "full.pkg", "bytes"), 1024**3 + 1),
    (("assets", "full.pkg", "sha256"), "E" * 64),
    (("assets", "full.pkg", "release", "tag"), "../qa-other"),
    (("assets", "full.pkg", "release", "id"), 102),
    (("assets", "base.pkg", "sha256"), "a" * 64),
    (("assets", "base.pkg", "release", "id"), 102),
    (("assets", "component.pkg", "sha256"), "a" * 64),
    (("assets", "component.pkg", "bytes"), 3457185),
    (("assets", "component-review.json", "release", "source"), "a" * 40),
])
def test_genuine_plan_contract_accepts_then_refuses_single_identity_mutation(path, value):
    baseline = contract()
    original = copy.deepcopy(baseline)
    assert baseline["plan_sha256"] == probe.PLAN_SHA == PLAN
    assert downloader.validate(baseline) is baseline
    assert baseline == original
    wrong = copy.deepcopy(baseline)
    target = wrong
    for name in path[:-1]:
        target = target[name]
    target[path[-1]] = value
    with pytest.raises(ValueError, match="^full_image_installer_input_contract_failed$"):
        downloader.validate(wrong)


def test_direct_helper_stage_excludes_temporary_path_aliases():
    assert probe.canonical_stage_name(Path("/private/tmp/account-access-full-image-acceptance-fixed_1"))
    for path in ("/tmp/account-access-full-image-acceptance-fixed_1",
                 "/var/tmp/account-access-full-image-acceptance-fixed_1", "/private/tmp/other",
                 "/private/tmp/account-access-full-image-acceptance-",
                 "/private/tmp/account-access-full-image-acceptance-x/child"):
        assert not probe.canonical_stage_name(Path(path))


@pytest.mark.parametrize("field,value", [
    ("uid", 501), ("euid", 501), ("platform", "linux"), ("machine", "x86_64"),
    ("GITHUB_ACTIONS", "false"), ("CI", "false"), ("RUNNER_ENVIRONMENT", "self-hosted"),
    ("RUNNER_OS", "Linux"), ("RUNNER_ARCH", "X64"), ("GITHUB_REPOSITORY", "other/repo"),
    ("GITHUB_RUN_ID", "../1"), ("GITHUB_RUN_ID", "0"), ("GITHUB_RUN_ATTEMPT", "0"),
    ("GITHUB_SHA", "A" * 40),
])
def test_root_and_host_context_refused_before_filesystem_or_process(monkeypatch, field, value):
    def forbidden(*_args, **_kwargs):
        pytest.fail("refused context touched filesystem, loaded source or launched a process")

    # These UID return values only exercise the pure predicate; no process becomes root.
    with monkeypatch.context() as guard:
        guard.setattr(probe.sys, "platform", "darwin")
        guard.setattr(probe.platform, "machine", lambda: "arm64")
        guard.setattr(probe.os, "getuid", lambda: 0)
        guard.setattr(probe.os, "geteuid", lambda: 0)
        for key, item in CI.items():
            guard.setenv(key, item)
        assert probe.guard() is None
        if field in ("uid", "euid"):
            guard.setattr(probe.os, "getuid" if field == "uid" else "geteuid", lambda: value)
        elif field == "platform":
            guard.setattr(probe.sys, "platform", value)
        elif field == "machine":
            guard.setattr(probe.platform, "machine", lambda: value)
        else:
            guard.setenv(field, value)
        for name in ("read_bytes", "open", "mkdir"):
            guard.setattr(Path, name, forbidden)
        for name in ("open", "stat", "lstat"):
            guard.setattr(probe.os, name, forbidden)
        guard.setattr(probe.runpy, "run_path", forbidden)
        for name in ("Popen", "run", "check_output"):
            guard.setattr(probe.subprocess, name, forbidden)
        with pytest.raises(ValueError, match="^full_image_installer_acceptance_failed$"):
            probe.run(SimpleNamespace())


def test_policy_expectation_changes_only_actual_two_fields_and_preserves_input(monkeypatch):
    peers = {"owner": {"hashes": ["b" * 40], "team": "WBULD6N4NQ",
                       "identifier": "com.fainir.accountaccess"},
             "broker": {"hashes": ["c" * 40]}, "bootstrap": {"hashes": ["d" * 40]}}
    before = {"install": {"payload_fingerprint": "old", "broker_uid": 470},
              "host": {"owner_hashes": ["a" * 40], "bootstrap_hashes": ["d" * 40], "owner_uid": 501},
              "owner": {"server_hashes": ["c" * 40], "owner_uid": 501}}
    original = copy.deepcopy(before)
    monkeypatch.setattr(probe, "h", SimpleNamespace(BASE=Path("/fixture/public"), LABEL="fixture.label"),
                        raising=False)
    expected = probe.expected_policies(before, peers)
    assert before == original
    assert expected["host"]["owner_hashes"] == peers["owner"]["hashes"]
    fingerprint = expected["install"]["payload_fingerprint"]
    assert len(fingerprint) == 64 and all(char in "0123456789abcdef" for char in fingerprint)
    expected["host"]["owner_hashes"] = original["host"]["owner_hashes"]
    expected["install"]["payload_fingerprint"] = original["install"]["payload_fingerprint"]
    assert expected == original


@pytest.mark.parametrize("failure", ["launch", "missed-checkpoint", "history-guard"])
def test_owned_child_failure_retains_both_bounded_logs_without_real_process(monkeypatch, tmp_path, failure):
    scripts = tmp_path / "Scripts"
    scripts.mkdir()
    stdout_body = b'fictional native refusal\n' if failure != "launch" else b""
    stderr_body = b'fictional stderr\n' if failure != "launch" else b""
    output = {}
    signals, waits, reads = [], [], []

    class Child:
        pid = 45678

        def poll(self):
            return None if failure == "history-guard" else 78

        def wait(self, *, timeout):
            waits.append(timeout)
            return 78

    def fake_popen(arguments, **options):
        assert arguments == [str(scripts / "AccountAccess-fullimageupdate")]
        assert options["env"] == probe.ENV and options["start_new_session"] is True
        if failure == "launch":
            raise ValueError("fictional launch failure")
        options["stdout"].write(stdout_body)
        options["stderr"].write(stderr_body)
        return Child()

    def read_owned_file(path, *, maximum):
        assert path.parent == tmp_path and maximum == 128 * 1024
        assert path.name in {"owned-helper.stdout", "owned-helper.stderr"}
        reads.append(path.name)
        body = path.read_bytes()
        assert len(body) <= maximum
        return body

    def fake_history(pins):
        assert pins == probe.LEGACY_PINS
        if failure == "history-guard":
            raise ValueError("fictional checkpoint history refusal")
        pytest.fail("exited fake child reached installed history")

    monkeypatch.setattr(probe.subprocess, "Popen", fake_popen)
    monkeypatch.setattr(probe.os, "killpg", lambda pid, sig: signals.append((pid, sig)))
    monkeypatch.setattr(probe, "history", fake_history)
    monkeypatch.setattr(probe, "support_root_metadata", lambda: {"fictional": True})
    monkeypatch.setattr(probe, "h", SimpleNamespace(read_file=read_owned_file), raising=False)
    report = {"logs": {}}
    with pytest.raises(ValueError):
        probe.interrupt(scripts, "interrupt-remove", report, SimpleNamespace(write=output.__setitem__))
    assert output == {"owned-helper-stdout.log": stdout_body, "owned-helper-stderr.log": stderr_body}
    assert report["logs"] == {name: probe.digest(body) for name, body in output.items()}
    assert reads == ["owned-helper.stdout", "owned-helper.stderr"] and report["owned_helper_logs_captured"] is True
    assert report["failure_stage"] == ("owned_helper_launch" if failure == "launch" else "owned_helper_checkpoint_wait")
    assert signals == ([] if failure == "launch" else [(Child.pid, probe.signal.SIGKILL)])
    assert waits == ([] if failure == "launch" else [10])


def test_predecessor_directory_metadata_records_nonzero_groups_without_normalizing(monkeypatch):
    original = Path("/Library/Application Support/Account Access Installer")
    components = Path("/Library/Application Support/Account Access Components")
    paths = [original, components, components / ("transition-" + probe.COMPONENT_PLAN)]
    seen, guards = [], []

    def fake_lstat(path):
        assert path in paths
        seen.append(path)
        index = paths.index(path)
        return SimpleNamespace(st_mode=probe.stat.S_IFDIR | 0o700, st_uid=0, st_gid=20 + index,
                               st_dev=4, st_ino=100 + index)

    monkeypatch.setattr(probe, "guard", lambda: guards.append(True))
    monkeypatch.setattr(probe, "h", SimpleNamespace(JOURNAL=original, COMPONENTS=components), raising=False)
    monkeypatch.setattr(Path, "lstat", fake_lstat)
    value = probe.predecessor_directory_metadata()
    assert seen == paths and guards == [True]
    assert value == {name: {"uid": 0, "gid": 20 + index, "mode": 0o700, "device": 4, "inode": 100 + index}
                     for index, name in enumerate(("original", "components", "transition"))}


@pytest.mark.parametrize("mode,uid", [(probe.stat.S_IFDIR | 0o755, 0), (probe.stat.S_IFLNK | 0o700, 0),
                                      (probe.stat.S_IFDIR | 0o700, 501)])
def test_predecessor_metadata_refuses_wrong_mode_symlink_or_owner_without_real_reads(monkeypatch, mode, uid):
    monkeypatch.setattr(probe, "guard", lambda: None)
    monkeypatch.setattr(probe, "h", SimpleNamespace(JOURNAL=Path("/fictional/original"),
                        COMPONENTS=Path("/fictional/components")), raising=False)
    monkeypatch.setattr(Path, "lstat", lambda _path: SimpleNamespace(st_mode=mode, st_uid=uid))
    with pytest.raises(ValueError, match="^full_image_installer_acceptance_failed$"):
        probe.predecessor_directory_metadata()


def test_predecessor_metadata_checks_vm_guard_before_paths(monkeypatch):
    def refuse():
        raise ValueError("fictional VM guard refusal")

    monkeypatch.setattr(probe, "guard", refuse)
    monkeypatch.setattr(Path, "lstat", lambda _path: pytest.fail("refused metadata touched a path"))
    with pytest.raises(ValueError, match="^fictional VM guard refusal$"):
        probe.predecessor_directory_metadata()


def stopped_metadata(scenario):
    support = {"uid": 0, "gid": 80, "mode": 0o755, "device": 4, "inode": 100, "kind": probe.stat.S_IFDIR}
    group = 80 if scenario == "interrupt-remove" else 0
    pin = {"owner": 0, "group": group, "mode": 0o755, "device": 4, "inode": 200,
           "inventorySHA256": "a" * 64}
    observed = {"uid": 0, "gid": group, "mode": 0o755, "device": 4, "inode": 200,
                "kind": probe.stat.S_IFDIR}
    return support, copy.deepcopy(support), pin, observed


@pytest.mark.parametrize("scenario", ["interrupt-remove", "interrupt-create"])
def test_stopped_optional_tree_binds_legacy_group_and_keeps_new_group_zero(scenario):
    values = stopped_metadata(scenario)
    original = copy.deepcopy(values)
    assert probe.stopped_tree_metadata(scenario, *values) == {
        name: values[2][name] for name in ("owner", "group", "mode", "device", "inode")}
    assert values == original


@pytest.mark.parametrize("scenario,side,field,value", [
    ("interrupt-remove", 1, "gid", 20),
    ("interrupt-remove", 1, "uid", 501),
    ("interrupt-remove", 1, "mode", 0o700),
    ("interrupt-remove", 1, "device", 5),
    ("interrupt-remove", 1, "inode", 101),
    ("interrupt-remove", 2, "group", 0),
    ("interrupt-remove", 2, "owner", 501),
    ("interrupt-remove", 2, "mode", 0o700),
    ("interrupt-remove", 2, "device", 5),
    ("interrupt-remove", 2, "inode", True),
    ("interrupt-remove", 3, "gid", 0),
    ("interrupt-remove", 3, "uid", 501),
    ("interrupt-remove", 3, "mode", 0o700),
    ("interrupt-remove", 3, "kind", probe.stat.S_IFLNK),
    ("interrupt-remove", 3, "device", 5),
    ("interrupt-remove", 3, "inode", 201),
    ("interrupt-create", 2, "group", 80),
    ("interrupt-create", 3, "gid", 80),
])
def test_stopped_tree_refuses_forged_pin_root_drift_or_object_metadata(scenario, side, field, value):
    values = stopped_metadata(scenario)
    values[side][field] = value
    with pytest.raises(ValueError, match="^full_image_installer_acceptance_failed$"):
        probe.stopped_tree_metadata(scenario, *values)


def test_stopped_tree_does_not_adopt_matching_forged_record_and_object_group():
    values = stopped_metadata("interrupt-remove")
    values[2]["group"] = values[3]["gid"] = 20
    with pytest.raises(ValueError, match="^full_image_installer_acceptance_failed$"):
        probe.stopped_tree_metadata("interrupt-remove", *values)


def test_support_root_group_observation_checks_vm_guard_before_open(monkeypatch):
    def refuse():
        raise ValueError("fictional VM guard refusal")

    monkeypatch.setattr(probe, "guard", refuse)
    monkeypatch.setattr(probe.os, "open", lambda *_args, **_kwargs: pytest.fail("refused context opened a path"))
    with pytest.raises(ValueError, match="^fictional VM guard refusal$"):
        probe.support_root_metadata()


@pytest.mark.parametrize("scenario", sorted(probe.SCENARIOS))
@pytest.mark.parametrize("name,log", [
    ("base.pkg", "base-installer"), ("component.pkg", "component-installer"),
    ("full.pkg", "full-installer"), ("full.pkg", "full-reapply-installer"),
])
def test_install_budget_only_changes_normal_first_upgrade_and_records_real_duration(monkeypatch, scenario, name, log):
    observed = []
    clock = iter([10.0, 408.125])
    monkeypatch.setattr(probe.time, "monotonic", lambda: next(clock))

    class Checkpoint:
        def __init__(self):
            observed.append("checkpoint")

        def capture(self, **kwargs):
            observed.append(("capture", kwargs["log"]))

    def command(arguments, **kwargs):
        observed.append(("command", arguments, kwargs["timeout"]))
        return "Installer completed"

    monkeypatch.setattr(probe, "h", SimpleNamespace(InstallerLogDelta=Checkpoint, command=command), raising=False)
    report = {}
    result = probe.install_package(Path("/fictional") / name, scenario=scenario, report=report, output=None, log=log)
    budget = 840 if scenario == "install-reapply" and log == "full-installer" else 420
    assert result == "Installer completed"
    assert observed == ["checkpoint", ("command", ["/usr/sbin/installer", "-dumplog", "-verboseR",
        "-pkg", "/fictional/" + name, "-target", "/"], budget), ("capture", log + "-daemon.log")]
    assert report["installer_attempts"][log] == {
        "budget_seconds": budget, "elapsed_seconds": 398.125, "completed_successfully": True}


def test_install_timeout_remains_failure_and_captures_duration_and_daemon_delta(monkeypatch):
    import subprocess
    error = subprocess.TimeoutExpired("fictional Installer", 840)
    clock = iter([10.0, 850.0])
    captured = []
    monkeypatch.setattr(probe.time, "monotonic", lambda: next(clock))

    def fail(*args, **kwargs):
        raise error

    monkeypatch.setattr(probe, "h", SimpleNamespace(command=fail,
        InstallerLogDelta=lambda: SimpleNamespace(capture=lambda **kwargs: captured.append(kwargs["log"]))), raising=False)
    report = {}
    with pytest.raises(subprocess.TimeoutExpired) as caught:
        probe.install_package(Path("/fictional/full.pkg"), scenario="install-reapply",
            report=report, output=None, log="full-installer")
    assert caught.value is error and captured == ["full-installer-daemon.log"]
    assert report["installer_attempts"]["full-installer"] == {
        "budget_seconds": 840, "elapsed_seconds": 840.0, "completed_successfully": False}


@pytest.mark.parametrize("scenario,name,log,existing", [
    ("other", "full.pkg", "full-installer", False),
    ("install-reapply", "unknown.pkg", "full-installer", False),
    ("install-reapply", "base.pkg", "full-installer", False),
    ("install-reapply", "full.pkg", "unknown", False),
    ("install-reapply", "full.pkg", "full-installer", True),
])
def test_invalid_or_repeated_install_phase_cannot_start_or_overwrite_evidence(monkeypatch, scenario, name, log, existing):
    def forbidden():
        pytest.fail("unrecognized phase accessed the Installer log")

    monkeypatch.setattr(probe, "h", SimpleNamespace(InstallerLogDelta=forbidden), raising=False)
    report = {"installer_attempts": {log: {"retained": True}}} if existing else {}
    before = copy.deepcopy(report)
    with pytest.raises(ValueError, match="^full_image_installer_acceptance_failed$"):
        probe.install_package(Path("/fictional") / name, scenario=scenario, report=report, output=None, log=log)
    if existing:
        assert report == before


def test_new_normal_workflow_preserves_frozen_assets_and_failed_matrix():
    import json
    import yaml
    root = Path(__file__).resolve().parents[1]
    workflow = yaml.safe_load((root / '.github/workflows/mac-full-image-normal-installer-review.yml').read_text())
    events = workflow.get('on', workflow.get(True))
    gate = 'artifacts/full-image-installer81-normal-acceptance.json'
    assert events['push']['paths'] == [gate]
    assert workflow['jobs']['actual-installer']['strategy']['matrix']['scenario'] == ['install-reapply']
    assert workflow['jobs']['actual-installer']['timeout-minutes'] == 45
    commands = '\n'.join(step.get('run', '') for step in workflow['jobs']['download-reviewed-inputs']['steps'])
    assert '--contract artifacts/full-image-installer81-recovery-inputs.json' in commands
    evidence = json.loads((root / gate).read_text())
    original = (root / evidence['unchanged_asset_contract']).read_bytes()
    assert probe.digest(original) == evidence['asset_contract_sha256']
    assert json.loads(original)['assets']['full.pkg']['sha256'] == evidence['package_sha256']
    assert evidence['prior_results']['install-reapply']['status'] == 'FAILED'
    assert evidence['actual_new_run_passed'] is False and evidence['production_ready'] is False
    assert len(probe.CHECKS) == evidence['required_checks_unchanged'] == 18


@pytest.mark.parametrize("cohort", [82, 83, 84])
def test_diagnostic_package_workflow_keeps_host_and_asset_boundaries(cohort):
    import yaml
    root = Path(__file__).resolve().parents[1]
    workflow = yaml.safe_load((root / f'.github/workflows/mac-full-image{cohort}-installer-review.yml').read_text())
    events = workflow.get('on', workflow.get(True))
    expected_paths = [f'artifacts/full-image-installer{cohort}-inputs.json']
    if cohort in (83, 84):
        expected_paths.append(f'.github/workflows/mac-full-image{cohort}-installer-review.yml')
    assert events['push']['paths'] == expected_paths
    download = workflow['jobs']['download-reviewed-inputs']
    actual = workflow['jobs']['actual-installer']
    assert [step['uses'] for step in download['steps'] if 'uses' in step] == [
        'actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1',
        'actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02',
    ]
    assert [step['uses'] for step in actual['steps'] if 'uses' in step] == [
        'actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1',
        'actions/download-artifact@634f93cb2916e3fdff6788551b99b062d0335ce0',
        'actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02',
    ]
    assert actual['strategy']['matrix']['scenario'] == ['install-reapply', 'interrupt-remove', 'interrupt-create']
    commands = '\n'.join(step.get('run', '') for step in download['steps'])
    assert f'--contract artifacts/full-image-installer{cohort}-inputs.json --cohort {cohort}' in commands
    commands = '\n'.join(step.get('run', '') for step in actual['steps'])
    assert f'--scenario "$AC_SCENARIO" --cohort {cohort}' in commands
    assert 'sudo -n /usr/bin/env -i' in commands and 'test "$RUNNER_ENVIRONMENT" = github-hosted' in commands
    assert 'GH_TOKEN' not in commands and actual['permissions'] == {'contents': 'read'}
