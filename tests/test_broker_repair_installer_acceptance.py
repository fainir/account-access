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


def test_foreign_binding_requires_observed_rollback_on_both_attempts():
    report = passing()
    report["scenario"] = "foreign-binding"
    assert not PROBE["acceptance_passed"](report)
    report["foreign_binding_rollback"] = {"verified_attempts": 2, "applied_per_attempt": 5,
        "restored_per_attempt": 5, "head_published": False}
    assert PROBE["acceptance_passed"](report)
    report["foreign_binding_rollback"]["verified_attempts"] = 1
    assert not PROBE["acceptance_passed"](report)


def test_rollback_evidence_cannot_be_early_refusal_or_partial_rollback():
    cycle = [{"schema": 1, "event": event, "operation": i}
        for i in range(5) for event in ("apply_intent", "applied")]
    cycle += [{"schema": 1, "event": event, "operation": i}
        for i in reversed(range(5)) for event in ("rollback_intent", "rolled_back")]
    cycle.append({"schema": 1, "event": "old_image_restored", "operation": -1})
    PROBE["verify_rollback_events"](cycle, 1)
    PROBE["verify_rollback_events"](cycle * 2, 2)
    for events in ([], cycle[:-1], list(reversed(cycle)), cycle + cycle[:-1]):
        with pytest.raises(ValueError):
            PROBE["verify_rollback_events"](events, 2)
    for index in range(len(cycle)):
        with pytest.raises(ValueError):
            PROBE["verify_rollback_events"](cycle[:index] + cycle[index + 1:], 1)
    altered = copy.deepcopy(cycle)
    altered[0]["operation"] = False
    with pytest.raises(ValueError):
        PROBE["verify_rollback_events"](altered, 1)


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


def test_closed_controller_profiles_preserve_frozen_payload_source():
    assert PROBE["profile"](87)["controller_source"] == PROBE["SOURCE"]
    selected = PROBE["profile"](88)
    assert selected["controller_source"] == "eba805729025caa1dc0754112e21d6d5592e0113"
    assert selected["identifier"] == "com.fainir.accountaccess.brokerrepair88"
    assert selected["download"] == "download_broker_repair_restart_inputs.py"
    for invalid in (True, "88", 86, 89, None, {}):
        with pytest.raises(ValueError):
            PROBE["profile"](invalid)


@pytest.mark.parametrize("cohort", [87, 88])
def test_review_separates_controller_and_unchanged_public_image(cohort):
    selected = PROBE["profile"](cohort)
    review = {"status": "BUILT_PENDING_INSTALLER_QA", "source_commit": PROBE["SOURCE"],
        "plan_sha256": PROBE["PLAN"], "before_manifest_sha256": PROBE["BEFORE"],
        "after_manifest_sha256": PROBE["AFTER"], "postinstall_timeout": 1800,
        "package_sha256": "a" * 64, "scripts_inventory_sha256": "b" * 64, "production_ready": False}
    if cohort == 88:
        with pytest.raises(ValueError):
            PROBE["verify_review_identity"](review, selected, package_sha256="a" * 64, inventory_sha256="b" * 64)
        review["controller_source_commit"] = PROBE["CONTROLLER88"]
    PROBE["verify_review_identity"](review, selected, package_sha256="a" * 64, inventory_sha256="b" * 64)
    for key in review:
        altered = {**review, key: "unreviewed"}
        with pytest.raises(ValueError):
            PROBE["verify_review_identity"](altered, selected, package_sha256="a" * 64, inventory_sha256="b" * 64)


def test_new_assets_use_their_own_closed_filename_set():
    value = contract()
    observed = []
    def measure(path, maximum):
        assert path.parent == Path("/fixture") and maximum == 1024**3
        observed.append(path.name)
        row = value["assets"][path.name]
        return row["sha256"], row["bytes"]
    PROBE["verify_assets"](Path("/fixture"), value, DOWNLOAD["FILES"], measure)
    assert set(observed) == DOWNLOAD["FILES"]
    with pytest.raises(ValueError):
        PROBE["verify_assets"](Path("/fixture"), value, {"base.pkg"}, measure)
    with pytest.raises(ValueError):
        PROBE["verify_assets"](Path("/fixture"), value, DOWNLOAD["FILES"], lambda *_: ("0" * 64, 1))


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
    workflow = yaml.safe_load((ROOT / ".github/workflows/mac-broker-repair87-installer-review.yml").read_text())
    mac = workflow["jobs"]["actual-installer"]
    assert mac["permissions"] == {"contents": "read"}
    assert set(mac["strategy"]["matrix"]["scenario"]) == PROBE["SCENARIOS"]
    assert "GH_TOKEN" not in json.dumps(mac)
    assert all(step.get("with", {}).get("persist-credentials") is False for step in mac["steps"] if "checkout@" in step.get("uses", ""))
