"""Guard and fail-closed acceptance contracts; no installed state is accessed."""
import copy
import json
from pathlib import Path
import runpy
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[1]
PROBE = runpy.run_path(str(ROOT / "scripts/mac_broker_repair_installer_probe.py"))
DOWNLOAD = runpy.run_path(str(ROOT / "scripts/download_broker_repair_installer_inputs.py"))


def passing():
    return {"scenario": "install-reapply", "checks": dict.fromkeys(PROBE["CHECKS"], True),
        "personal_accounts_used": 0, "owner_GUI_qualified": False, "production_ready": False}


def test_all_checks_required():
    report = passing()
    assert PROBE["acceptance_passed"](report)
    for key in report["checks"]:
        altered = copy.deepcopy(report)
        altered["checks"][key] = False
        assert not PROBE["acceptance_passed"](altered)
        altered["checks"][key] = 1
        assert not PROBE["acceptance_passed"](altered)
        del altered["checks"][key]
        assert not PROBE["acceptance_passed"](altered)


@pytest.mark.parametrize("key,value", [("scenario", "owner-mac"), ("failure_reason", "failed"),
    ("personal_accounts_used", 1), ("owner_GUI_qualified", True), ("production_ready", True)])
def test_scope_cannot_be_upgraded(key, value):
    report = passing()
    report[key] = value
    assert not PROBE["acceptance_passed"](report)


def test_ordinary_run_refuses_before_any_path_read(monkeypatch):
    monkeypatch.setattr(PROBE["os"], "getuid", lambda: 501)
    def forbidden(*args, **kwargs):
        raise AssertionError("filesystem reached")
    monkeypatch.setattr(Path, "read_bytes", forbidden)
    with pytest.raises(ValueError, match="broker_repair_installer_acceptance_failed"):
        PROBE["run"](SimpleNamespace(scenario="install-reapply", repository=Path("/not-accessed")))


def test_publication_fixture_requires_hosted_root_before_metadata(monkeypatch):
    monkeypatch.setattr(PROBE["os"], "geteuid", lambda: 501)
    with pytest.raises(ValueError, match="broker_repair_installer_acceptance_failed"):
        PROBE["fictional_publication"]({}, {})


def contract():
    return json.loads((ROOT / DOWNLOAD["CONTRACT"]).read_bytes())


def test_exact_frozen_assets():
    value = contract()
    assert DOWNLOAD["validate"](value) == value


@pytest.mark.parametrize("mutation", ["package", "root", "source", "extra", "boolean_id", "duplicate_id", "release", "size"])
def test_asset_substitution_refused(mutation):
    value = contract()
    if mutation == "package":
        value["assets"]["repair.pkg"]["sha256"] = "a" * 64
    elif mutation == "root":
        value["assets"]["root-revalidation.pkg"]["sha256"] = "b" * 64
    elif mutation == "source":
        value["source_commit"] = "c" * 40
    elif mutation == "extra":
        value["assets"]["unexpected.pkg"] = value["assets"]["repair.pkg"]
    elif mutation == "boolean_id":
        value["assets"]["repair.pkg"]["id"] = True
    elif mutation == "duplicate_id":
        value["assets"]["repair.pkg"]["id"] = value["assets"]["root-revalidation.pkg"]["id"]
    elif mutation == "release":
        value["assets"]["repair.pkg"]["release"]["tag"] = "production"
    elif mutation == "size":
        value["assets"]["repair.pkg"]["bytes"] += 1
    with pytest.raises(ValueError, match="broker_repair_inputs_refused"):
        DOWNLOAD["validate"](value)


def test_workflow_has_no_token_on_mac_and_three_scenarios():
    import yaml
    workflow = yaml.safe_load((ROOT / ".github/workflows/mac-broker-repair86-installer-review.yml").read_text())
    mac = workflow["jobs"]["actual-installer"]
    assert mac["permissions"] == {"contents": "read"}
    assert set(mac["strategy"]["matrix"]["scenario"]) == PROBE["SCENARIOS"]
    assert "GH_TOKEN" not in json.dumps(mac)
    assert all(step.get("with", {}).get("persist-credentials") is False for step in mac["steps"] if "checkout@" in step.get("uses", ""))
