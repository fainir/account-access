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


def passed(scenario="install-reapply"):
    return {"scenario": scenario, "checks": dict.fromkeys(probe["CHECKS"], True), "failure_stage": None,
            "production_ready": False, "real_account_login_tested": False, "installed_owner_machine": False}


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
    assert all(s["with"]["persist-credentials"] is False for s in mac["steps"] if "checkout@" in s.get("uses", ""))
