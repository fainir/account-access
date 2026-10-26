"""Completed-history acceptance is opt-in and never reaches an owner host."""
import copy
import hashlib
from pathlib import Path
import runpy
from types import SimpleNamespace

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
PROBE = runpy.run_path(str(ROOT / "scripts/mac_completed_repair_probe.py"))
REPAIR = runpy.run_path(str(ROOT / "scripts/mac_broker_repair_installer_probe.py"))


@pytest.mark.parametrize("foreign", [False, True])
def test_completion_acceptance_requires_every_observation(foreign):
    value = dict.fromkeys(PROBE["FIELDS"], True)
    value.update(production_ready=False, same_evidence_twice=not foreign, foreign_audit_refused=not foreign)
    assert PROBE["acceptance_passed"](value, foreign=foreign)
    for key in value:
        for change in [not value[key], int(value[key]), None]:
            bad = {**value, key: change}
            assert not PROBE["acceptance_passed"](bad, foreign=foreign)
        bad = copy.deepcopy(value)
        del bad[key]
        assert not PROBE["acceptance_passed"](bad, foreign=foreign)
    assert not PROBE["acceptance_passed"]({**value, "extra": True}, foreign=foreign)


def test_host_guard_precedes_all_inputs():
    class Refused(Exception):
        pass
    def guard():
        raise Refused
    with pytest.raises(Refused):
        PROBE["run"](controller=SimpleNamespace(guard=guard), args=None, stage=None,
                     scripts=None, report=None, command=None)


def test_frozen_full_image_source_pins_are_unchanged():
    assert hashlib.sha256((ROOT / PROBE["PINS"]).read_bytes()).hexdigest() == PROBE["PINS_SHA"]


def test_hosted_workflow_tests_every_repair_scenario_without_secrets():
    workflow = yaml.safe_load((ROOT / ".github/workflows/mac-completed-repair-review.yml").read_text())
    mac = workflow["jobs"]["actual-installer"]
    assert set(mac["strategy"]["matrix"]["scenario"]) == REPAIR["SCENARIOS"]
    assert mac["permissions"] == {"contents": "read"}
    assert "GH_TOKEN" not in str(mac)
    run = next(s["run"] for s in mac["steps"] if "run" in s)
    assert "--cohort 91 --verify-completed-predecessor" in run
    assert "RUNNER_ENVIRONMENT=github-hosted" in run
    assert all(s["with"]["persist-credentials"] is False for s in mac["steps"] if "checkout@" in s.get("uses", ""))


def test_repair_report_cannot_ignore_requested_proof_failure():
    value = {"scenario": "install-reapply", "checks": dict.fromkeys(REPAIR["CHECKS"], True),
             "personal_accounts_used": 0, "owner_GUI_qualified": False, "production_ready": False}
    assert REPAIR["acceptance_passed"](value)
    value["completed_predecessor"] = {"requested": True}
    assert not REPAIR["acceptance_passed"](value)
