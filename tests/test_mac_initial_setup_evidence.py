import json

import pytest

from scripts.check_mac_initial_setup_report import CHECKS, main, validate


def report():
    return {"status": "PASSED", "platform": "macos", "environment": "controlled-demo", "production_ready": False,
            "private_signins": 0, "system_key_used": True, "actual_initial_setup_used": True,
            "consumer_deployment_verified": False, "genuine_owner_approval_verified": False,
            "synthetic_setup_approval_used": True, "controlled_initializer_gate": True, "authorization_database_changed": False,
            "fixture_key_removed": True, "publisher_signed_peers": False, "checks": dict.fromkeys(CHECKS, True)}


def test_initial_setup_requires_each_native_gate_and_production_limit(tmp_path):
    assert len(CHECKS) == 43 and validate(report())
    for name in CHECKS:
        for substitute in [False, None, 1]:
            value = report()
            value["checks"][name] = substitute
            assert not validate(value)
        value = report()
        del value["checks"][name]
        assert not validate(value)
    path = tmp_path / "report.json"
    path.write_text(json.dumps(report()))
    assert main([str(path)]) == 0


@pytest.mark.parametrize("name,value", [("production_ready", True), ("private_signins", True), ("private_signins", 1),
    ("system_key_used", False), ("actual_initial_setup_used", False), ("consumer_deployment_verified", True),
    ("genuine_owner_approval_verified", True), ("synthetic_setup_approval_used", False), ("controlled_initializer_gate", False),
    ("authorization_database_changed", True), ("fixture_key_removed", False), ("publisher_signed_peers", True), ("environment", "personal")])
def test_first_setup_cannot_claim_genuine_approval_or_hide_controlled_gate(name, value):
    value_report = report()
    value_report[name] = value
    assert not validate(value_report)


@pytest.mark.parametrize("data", [None, "", "{}", "null"])
def test_missing_initial_setup_reports_fail(tmp_path, data):
    path = tmp_path / "report.json"
    if data is not None:
        path.write_text(data)
    assert main([str(path)]) == 1
