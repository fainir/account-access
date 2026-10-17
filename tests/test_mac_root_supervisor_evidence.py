import json

import pytest

from scripts.check_mac_root_supervisor_report import CHECKS, main, validate


def report():
    return {"status": "PASSED", "platform": "macos", "environment": "controlled-demo", "production_ready": False,
            "private_signins": 0, "system_key_used": True, "actual_worker_used": True, "consumer_deployment_verified": False,
            "parent_daemon_recovery_verified": False, "genuine_owner_approval_verified": False,
            "owner_session_checks": "synthetic-in-process", "controlled_monotonic_clock": True,
            "fixture_key_removed": True, "checks": dict.fromkeys(CHECKS, True)}


def test_supervisor_requires_each_native_lifecycle_assertion(tmp_path):
    assert len(CHECKS) == 19 and validate(report())
    for name in CHECKS:
        for replacement in [False, None, 1]:
            changed = report()
            changed["checks"][name] = replacement
            assert not validate(changed)
        changed = report()
        del changed["checks"][name]
        assert not validate(changed)
    path = tmp_path / "report.json"
    path.write_text(json.dumps(report()))
    assert main([str(path)]) == 0


@pytest.mark.parametrize("name,value", [("production_ready", True), ("private_signins", True), ("private_signins", 1),
    ("system_key_used", False), ("actual_worker_used", False), ("consumer_deployment_verified", True),
    ("parent_daemon_recovery_verified", True), ("genuine_owner_approval_verified", True),
    ("owner_session_checks", "native-xpc"), ("controlled_monotonic_clock", False), ("fixture_key_removed", False),
    ("environment", "personal")])
def test_supervisor_cannot_claim_private_enrollment_or_parent_daemon_recovery(name, value):
    changed = report()
    changed[name] = value
    assert not validate(changed)


@pytest.mark.parametrize("data", [None, "", "{}", "null"])
def test_missing_supervisor_reports_fail(tmp_path, data):
    path = tmp_path / "report.json"
    if data is not None:
        path.write_text(data)
    assert main([str(path)]) == 1
