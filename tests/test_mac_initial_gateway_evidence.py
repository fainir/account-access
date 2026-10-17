import json

import pytest

from scripts.check_mac_initial_gateway_report import CHECKS, main, validate


def report():
    return {"status": "PASSED", "platform": "macos", "environment": "controlled-demo", "production_ready": False,
            "private_signins": 0, "actual_system_entrypoint_used": True, "actual_native_xpc_used": True,
            "consumer_deployment_verified": False, "genuine_owner_approval_verified": False,
            "positive_enrollment_verified": False, "authorization_database_changed": True,
            "fixture_policy_removed": True, "publisher_signed_peers": False, "checks": dict.fromkeys(CHECKS, True)}


def test_initial_gateway_requires_each_actual_peer_and_no_key_check(tmp_path):
    assert len(CHECKS) == 15 and validate(report())
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
    ("actual_system_entrypoint_used", False), ("actual_native_xpc_used", False), ("consumer_deployment_verified", True),
    ("genuine_owner_approval_verified", True), ("positive_enrollment_verified", True), ("authorization_database_changed", False),
    ("fixture_policy_removed", False), ("publisher_signed_peers", True), ("environment", "personal")])
def test_waiting_gateway_cannot_claim_positive_or_consumer_enrollment(name, value):
    value_report = report()
    value_report[name] = value
    assert not validate(value_report)


@pytest.mark.parametrize("data", [None, "", "{}", "null"])
def test_missing_initial_gateway_reports_fail(tmp_path, data):
    path = tmp_path / "report.json"
    if data is not None:
        path.write_text(data)
    assert main([str(path)]) == 1
