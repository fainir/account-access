"""Closed acceptance and host guard; no installer, root or account operations."""
from pathlib import Path
import copy
import json
import runpy
from types import SimpleNamespace

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
probe = runpy.run_path(str(ROOT / "scripts/mac_runtime_upgrade_installer_probe.py"))


@pytest.mark.parametrize("fault", [None, "worker-refused", "truthy-boolean", "stderr", "wrong-exit"])
def test_public_alias_acceptance_requires_both_real_identities(monkeypatch, fault):
    scope = probe["ordinary_runtime_aliases"].__globals__
    original_stat = scope["os"].stat
    monkeypatch.setattr(scope["os"], "stat", lambda path, *a, **k:
        SimpleNamespace(st_uid=501) if path == "/dev/console" else original_stat(path, *a, **k))
    monkeypatch.setattr(scope["pwd"], "getpwuid", lambda uid:
        SimpleNamespace(pw_gid=20 if uid == 501 else 450, pw_name="runner", pw_dir="/Users/runner"))
    def require(value):
        if not value:
            raise ValueError("fixture-refused")
    controller = SimpleNamespace(guard=lambda: None, require=require, h=SimpleNamespace(
        BASE=Path("/Library/Application Support/Account Access"),
        policies=lambda: {"install": {"owner_uid": 501, "broker_uid": 450}}))
    calls = []
    def command(argv, log, *, check):
        assert check is False
        calls.append(argv)
        value = {"schema": 1, "status": "PASSED", "aliases": 20, "ordinary_identity": True,
                 "worker_path_validator": True, "private_data_read": False}
        if fault == "worker-refused" and "#450" in argv:
            value = {"schema": 1, "status": "REFUSED", "reason": "public_runtime_alias_not_usable"}
        if fault == "truthy-boolean":
            value["ordinary_identity"] = 1
        return SimpleNamespace(returncode=78 if fault == "wrong-exit" else 0,
            stdout=json.dumps(value).encode(), stderr=b"unexpected" if fault == "stderr" else b"")
    if fault:
        with pytest.raises(ValueError):
            probe["ordinary_runtime_aliases"](controller, command, "after-upgrade")
    else:
        result = probe["ordinary_runtime_aliases"](controller, command, "after-upgrade")
        assert set(result) == {"console", "worker"} and len(calls) == 2
        assert [argv[argv.index("-u") + 1] for argv in calls] == ["#501", "#450"]
        assert all("-I" in argv and "-B" in argv and "HOME=/var/empty" in argv for argv in calls)


def test_public_alias_probe_refuses_owner_host_before_identity_or_command():
    def denied():
        raise ValueError("host-refused")
    with pytest.raises(ValueError, match="host-refused"):
        probe["ordinary_runtime_aliases"](SimpleNamespace(guard=denied), None, "after-upgrade")


def passed(scenario="install-reapply"):
    value = {"scenario": scenario, "checks": dict.fromkeys(probe["CHECKS"], True), "failure_stage": None,
             "production_ready": False, "real_account_login_tested": False, "installed_owner_machine": False}
    if scenario == "quiescence-recovery":
        value["quiescence_recovery"] = dict.fromkeys(probe["RECOVERY_CHECKS"], True)
    if scenario == "alias-recovery":
        value["alias_recovery"] = dict.fromkeys(probe["ALIAS_CHECKS"], True)
    return value


@pytest.mark.parametrize("scenario", sorted(probe["SCENARIOS"]))
def test_all_successor_scenarios_require_every_check(scenario):
    report = passed(scenario)
    assert probe["acceptance_passed"](report)
    for name in probe["CHECKS"]:
        report["checks"][name] = False
        assert not probe["acceptance_passed"](report)
        report["checks"][name] = True


@pytest.mark.parametrize("key,value", [
    ("scenario", "foreign"), ("checks", {}), ("failure_stage", "actual_installer"),
    ("production_ready", 0), ("real_account_login_tested", True), ("installed_owner_machine", True),
])
def test_optimistic_or_incomplete_result_refused(key, value):
    report = passed()
    report[key] = value
    assert not probe["acceptance_passed"](report)


def test_truthy_check_and_unknown_check_refused():
    report = passed()
    report["checks"]["fixed_inputs"] = 1
    assert not probe["acceptance_passed"](report)
    report = passed()
    report["checks"]["unknown"] = True
    assert not probe["acceptance_passed"](report)


def test_host_guard_precedes_all_paths_and_callbacks():
    class Refused(Exception):
        pass
    def guard():
        raise Refused()
    with pytest.raises(Refused):
        probe["run"](controller=SimpleNamespace(guard=guard), args=None, stage=None, report=None, output=None, command=None)
    with pytest.raises(Refused):
        probe["normalize_expansion"](SimpleNamespace(guard=guard), None)
    with pytest.raises(Refused):
        probe["reproduce_historical_cache_repair"](SimpleNamespace(guard=guard), None, None)
    with pytest.raises(Refused):
        probe["public_tree_groups"](SimpleNamespace(guard=guard), None)
    with pytest.raises(Refused):
        probe["runtime_alias_snapshot"](SimpleNamespace(guard=guard), None)
    fixture = runpy.run_path(str(ROOT / "scripts/mac_runtime_quiescence_fixture.py"))
    with pytest.raises(Refused):
        fixture["Witness"](SimpleNamespace(guard=guard), None, None, None)
    with pytest.raises(Refused):
        fixture["prepare"](controller=SimpleNamespace(guard=guard), args=None, stage=None,
                           source=None, install=None, result=None, unchanged=None)


def test_recovery_requires_both_refusals_unchanged_image_and_retained_apple_process():
    for name in probe["RECOVERY_CHECKS"]:
        for invalid in (False, None, 1):
            value = passed("quiescence-recovery")
            value["quiescence_recovery"][name] = invalid
            assert not probe["acceptance_passed"](value)
        value = passed("quiescence-recovery")
        del value["quiescence_recovery"][name]
        assert not probe["acceptance_passed"](value)
    value = passed("quiescence-recovery")
    value.pop("quiescence_recovery")
    assert not probe["acceptance_passed"](value)


def test_old_package_contract_remains_pinned_for_the_recovery_regression():
    download = runpy.run_path(str(ROOT / "scripts/download_runtime_upgrade93_inputs.py"))
    contract = json.loads((ROOT / download["CONTRACT"]).read_text())
    assert download["validate"](contract) == contract
    assert contract["assets"]["runtime-upgrade.pkg"]["sha256"] == "f5db4c6c35ca1efe62bac0b572256b500f59032d9885a7bebb7b43b6702a9b23"


def test_package94_contract_is_frozen_for_the_alias_recovery_regression():
    download = runpy.run_path(str(ROOT / "scripts/download_runtime_upgrade94_inputs.py"))
    contract = json.loads((ROOT / download["CONTRACT"]).read_text())
    assert download["validate"](contract) == contract
    assert contract["assets"]["runtime-upgrade.pkg"]["sha256"] == "1086e6eac90083489c7b85578f5267eaee77bdd6b3844b1b4a4579d89c731c3e"
    for check in probe["ALIAS_CHECKS"]:
        value = passed("alias-recovery")
        value["alias_recovery"][check] = False
        assert not probe["acceptance_passed"](value)
    value = passed("alias-recovery")
    value.pop("alias_recovery")
    assert not probe["acceptance_passed"](value)


def test_historical_cache_fixture_matches_recorded_owner_repair_exactly():
    evidence = json.loads((ROOT / "artifacts/runtime92-installed-public-groups-20261024.json").read_text())
    assert sorted(probe["CACHE_REPAIR_FILES"]) == sorted(evidence["fixed_cache_repair_files"])
    assert evidence["fixed_cache_repair_group"] == 0
    assert evidence["before_manifest_sha256"] == probe["BEFORE"]


@pytest.mark.parametrize("relative,expected", [
    ("runtime/lib/python3.12/encodings/__pycache__/aliases.cpython-312.pyc", 0),
    ("runtime/lib/python3.12/encodings/__pycache__", 80),
    ("runtime/lib/python3.12/site-packages/account_access/file.py", 0),
    ("runtime/lib/python3.12/site-packages/account_access_extra/file.py", 80),
    ("python/bin/pip3", 0), ("python/bin/python3.12", 80), ("owner.app", 0), ("browsers", 80),
])
def test_predecessor_group_projection_keeps_component_boundaries(relative, expected):
    assert probe["preceding_group"](relative, 80) == expected


def test_fixed_download_contract_refuses_every_changed_asset_identity():
    download = runpy.run_path(str(ROOT / "scripts/download_runtime_upgrade_inputs.py"))
    contract = json.loads((ROOT / download["CONTRACT"]).read_text())
    assert download["validate"](contract) == contract
    for name in download["FILES"]:
        for field in ("id", "bytes", "sha256", "release"):
            bad = copy.deepcopy(contract)
            bad["assets"][name][field] = None
            with pytest.raises(ValueError):
                download["validate"](bad)
    for field in contract:
        bad = copy.deepcopy(contract)
        del bad[field]
        with pytest.raises(ValueError):
            download["validate"](bad)


def test_runtime_report_failure_cannot_be_hidden_by_predecessor_success():
    repair = runpy.run_path(str(ROOT / "scripts/mac_broker_repair_installer_probe.py"))
    report = {"scenario": "install-reapply", "checks": dict.fromkeys(repair["CHECKS"], True),
              "personal_accounts_used": 0, "owner_GUI_qualified": False, "production_ready": False,
              "runtime_upgrade": passed()}
    assert repair["acceptance_passed"](report)
    report["runtime_upgrade"]["checks"]["actual_installer"] = False
    assert not repair["acceptance_passed"](report)


def test_hosted_workflow_uses_all_scenarios_and_separates_download_token():
    workflow = yaml.safe_load((ROOT / ".github/workflows/mac-runtime-upgrade-review.yml").read_text())
    mac = workflow["jobs"]["actual-installer"]
    assert set(mac["strategy"]["matrix"]["scenario"]) == probe["SCENARIOS"]
    assert mac["permissions"] == {"contents": "read"}
    assert "GH_TOKEN" not in str(mac)
    run = next(s["run"] for s in mac["steps"] if "run" in s)
    assert "--scenario install-reapply --cohort 91 --runtime-scenario" in run
    assert "RUNNER_ENVIRONMENT=github-hosted" in run
    assert set(mac["needs"]) == {"download-reviewed-inputs", "live-system-identities"}
    assert "--previous-runtime-upgrade" in run
    assert all(s["with"]["persist-credentials"] is False for s in mac["steps"] if "checkout@" in s.get("uses", ""))
