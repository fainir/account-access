"""Scope and completion gates for the guarded actual owner Installer fixture."""

import copy
import json
from pathlib import Path
import runpy
from types import SimpleNamespace

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
PROBE = runpy.run_path(str(ROOT / "scripts/mac_owner_upgrade_installer_probe.py"))


def test_frozen_owner_assets_and_all_identity_fields():
    download = runpy.run_path(str(ROOT / "scripts/download_owner_upgrade_inputs.py"))
    value = json.loads((ROOT / download["CONTRACT"]).read_bytes())
    assert download["validate"](value) == value
    for name in download["FILES"]:
        for field in value["assets"][name]:
            bad = copy.deepcopy(value)
            bad["assets"][name][field] = None
            with pytest.raises(ValueError):
                download["validate"](bad)
    for field in value:
        bad = copy.deepcopy(value)
        del bad[field]
        with pytest.raises(ValueError):
            download["validate"](bad)


def passed(scenario="install-reapply"):
    value = {"scenario": scenario, "checks": dict.fromkeys(PROBE["CHECKS"], True),
             "runtime_predecessor_scenario": PROBE["PREDECESSOR_SCENARIOS"][scenario],
             "production_ready": False, "real_account_login_tested": False,
             "installed_owner_machine": False, "failure_stage": None}
    if scenario in PROBE["INTERRUPT_SCENARIOS"]:
        value["interruption"] = {"owned_child_only": True, "head_not_published": True,
                                 "installer_daemon_interrupted": False, "power_failure_tested": False}
    return value


@pytest.mark.parametrize("scenario", sorted(PROBE["SCENARIOS"]))
def test_every_scenario_requires_all_real_checks(scenario):
    value = passed(scenario)
    assert PROBE["acceptance_passed"](value)
    for check in PROBE["CHECKS"]:
        for invalid in (False, 1, None):
            altered = copy.deepcopy(value)
            altered["checks"][check] = invalid
            assert not PROBE["acceptance_passed"](altered)
        altered = copy.deepcopy(value)
        del altered["checks"][check]
        assert not PROBE["acceptance_passed"](altered)


@pytest.mark.parametrize("key,value", [
    ("production_ready", 0), ("installed_owner_machine", True),
    ("real_account_login_tested", True), ("failure_stage", "installer"),
    ("scenario", "owner-machine"), ("checks", {}),
])
def test_incomplete_or_optimistic_scope_refused(key, value):
    result = passed()
    result[key] = value
    assert not PROBE["acceptance_passed"](result)


def test_interrupted_child_must_be_observed_before_publication():
    for key in passed("interrupt-owner")["interruption"]:
        for invalid in (None, 1, 0):
            value = passed("interrupt-owner")
            value["interruption"][key] = invalid
            assert not PROBE["acceptance_passed"](value)
    value = passed("interrupt-host")
    del value["interruption"]
    assert not PROBE["acceptance_passed"](value)


def test_guard_precedes_every_path_and_callback():
    class Refused(Exception):
        pass

    def guard():
        raise Refused()

    with pytest.raises(Refused):
        PROBE["run"](controller=SimpleNamespace(guard=guard), args=None, stage=None,
                     report=None, output=None, command=None)
    with pytest.raises(Refused):
        PROBE["normalize_expansion"](SimpleNamespace(guard=guard), None)
    with pytest.raises(Refused):
        PROBE["namespace_snapshot"](SimpleNamespace(guard=guard), None)
    with pytest.raises(Refused):
        PROBE["require_native_refusal"](SimpleNamespace(guard=guard), None, None, None, None)
    with pytest.raises(Refused):
        PROBE["owner_runtime_aliases"](SimpleNamespace(guard=guard), None, None, None)


def test_owner_alias_observations_cannot_overwrite_predecessor_logs():
    names = []

    def require(value):
        if not value:
            raise ValueError("log-refused")

    def observe(controller, command, phase):
        for role in ("console", "worker"):
            command(["synthetic-command"], "public-alias-" + phase + "-" + role + ".log", check=False)
        return {"console": "synthetic", "worker": "synthetic"}

    def command(arguments, log, *, check):
        assert check is False and log not in names
        names.append(log)

    controller = SimpleNamespace(guard=lambda: None, require=require)
    for phase in ("after-upgrade", "after-reapply"):
        PROBE["owner_runtime_aliases"](controller, {"ordinary_runtime_aliases": observe}, command, phase)
    assert len(names) == 4 and len(set(names)) == 4
    assert all(name.startswith("owner-public-alias-") for name in names)
    with pytest.raises(ValueError, match="log-refused"):
        PROBE["owner_runtime_aliases"](controller, None, None, "foreign")


@pytest.mark.parametrize("checkpoint", ["predecessor", "journal"])
def test_negative_installer_test_requires_the_native_refusal(checkpoint):
    raw = (b'installer prefix {"schema":1,"status":"REFUSED","reason":"owner_upgrade_transition_conflict","checkpoint":"'
           + checkpoint.encode() + b'"}\n')
    assert PROBE["refusal_record"](raw, checkpoint)
    for incorrect in (b"Installer failed to start", raw.replace(b"REFUSED", b"OTHER"),
                      raw.replace(b"transition_conflict", b"unavailable"), raw.replace(checkpoint.encode(), b"context")):
        assert not PROBE["refusal_record"](incorrect, checkpoint)
    assert not PROBE["refusal_record"](raw, "foreign")


def test_requested_owner_success_cannot_be_silently_skipped():
    repair = runpy.run_path(str(ROOT / "scripts/mac_broker_repair_installer_probe.py"))
    runtime = runpy.run_path(str(ROOT / "scripts/mac_runtime_upgrade_installer_probe.py"))
    result = {"scenario": "install-reapply", "checks": dict.fromkeys(repair["CHECKS"], True),
              "personal_accounts_used": 0, "owner_GUI_qualified": False, "production_ready": False,
              "owner_upgrade_requested": True}
    assert not repair["acceptance_passed"](result)
    result["owner_upgrade"] = passed()
    assert not repair["acceptance_passed"](result)
    result["runtime_upgrade"] = {"scenario": "install-reapply", "checks": dict.fromkeys(runtime["CHECKS"], True),
        "production_ready": False, "real_account_login_tested": False, "installed_owner_machine": False,
        "failure_stage": None}
    assert repair["acceptance_passed"](result)
    result["owner_upgrade"]["checks"]["actual_installer"] = False
    assert not repair["acceptance_passed"](result)


def test_namespace_snapshot_refuses_unrelated_paths_before_open(monkeypatch):
    def require(value):
        if not value:
            raise ValueError("namespace-refused")

    def forbidden(*args, **kwargs):
        raise AssertionError("unrelated path opened")

    monkeypatch.setattr(PROBE["namespace_snapshot"].__globals__["os"], "open", forbidden)
    with pytest.raises(ValueError, match="namespace-refused"):
        PROBE["namespace_snapshot"](SimpleNamespace(guard=lambda: None,
            h=SimpleNamespace(), require=require), Path("/Users/unrelated"))


def test_hosted_workflow_separates_release_token_and_requires_live_identity_checks():
    workflow = yaml.safe_load((ROOT / ".github/workflows/mac-owner-upgrade-review.yml").read_text())
    mac = workflow["jobs"]["actual-installer"]
    assert set(mac["strategy"]["matrix"]["scenario"]) == PROBE["SCENARIOS"]
    assert set(mac["needs"]) == {"download-reviewed-inputs", "live-system-identities"}
    assert mac["permissions"] == {"contents": "read"} and "GH_TOKEN" not in str(mac)
    run = next(step["run"] for step in mac["steps"] if "run" in step)
    assert '--runtime-scenario "$AC_RUNTIME_SCENARIO" --owner-scenario' in run
    assert {row["scenario"]: row["runtime_scenario"] for row in mac["strategy"]["matrix"]["include"]} == {
        "after-alias-repair": "alias-recovery", "after-quiescence-recovery": "quiescence-recovery"}
    assert "--owner-upgrade" in run and "RUNNER_ENVIRONMENT=github-hosted" in run
    assert all(step["with"]["persist-credentials"] is False for step in mac["steps"]
               if "checkout@" in step.get("uses", ""))
