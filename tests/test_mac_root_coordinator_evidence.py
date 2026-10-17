import json

import pytest

from scripts.check_mac_root_coordinator_report import CHECKS, main, validate


def report():
    return {"status": "PASSED", "platform": "macos", "environment": "controlled-demo", "production_ready": False,
            "private_signins": 0, "system_key_used": True, "actual_worker_used": True, "consumer_deployment_verified": False,
            "actual_root_composition_verified": True, "parent_daemon_recovery_verified": True, "machine_reboot_verified": False,
            "genuine_owner_approval_verified": False, "authorization_database_changed": True, "fixture_policy_removed": True,
            "fixture_key_removed": True, "publisher_signed_peers": False, "checks": dict.fromkeys(CHECKS, True)}


def test_coordinator_requires_each_real_os_lifecycle_and_native_channel_assertion(tmp_path):
    assert len(CHECKS) == 31 and validate(report())
    for name in CHECKS:
        for replacement in [False, None, 1]:
            value = report()
            value["checks"][name] = replacement
            assert not validate(value)
        value = report()
        del value["checks"][name]
        assert not validate(value)
    path = tmp_path / "report.json"
    path.write_text(json.dumps(report()))
    assert main([str(path)]) == 0


@pytest.mark.parametrize("name,value", [("production_ready", True), ("private_signins", True), ("private_signins", 1),
    ("system_key_used", False), ("actual_worker_used", False), ("actual_root_composition_verified", False),
    ("parent_daemon_recovery_verified", False), ("machine_reboot_verified", True), ("consumer_deployment_verified", True),
    ("genuine_owner_approval_verified", True), ("publisher_signed_peers", True), ("authorization_database_changed", False),
    ("fixture_policy_removed", False), ("fixture_key_removed", False), ("environment", "personal")])
def test_coordinator_cannot_claim_consumer_private_or_reboot_coverage(name, value):
    value_report = report()
    value_report[name] = value
    assert not validate(value_report)


@pytest.mark.parametrize("data", [None, "", "{}", "null"])
def test_missing_coordinator_reports_fail(tmp_path, data):
    path = tmp_path / "report.json"
    if data is not None:
        path.write_text(data)
    assert main([str(path)]) == 1
