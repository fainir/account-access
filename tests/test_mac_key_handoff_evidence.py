import json

import pytest

from scripts.check_mac_key_handoff_report import CHECKS, main, validate


def report():
    return {"status": "PASSED", "platform": "macos", "environment": "controlled-demo", "production_ready": False,
            "private_signins": 0, "system_key_used": True, "production_python_reader_used": True,
            "consumer_deployment_verified": False, "production_supervision_verified": False,
            "actual_worker_store_handoff_verified": False, "fixture_key_removed": True, "checks": dict.fromkeys(CHECKS, True)}


def test_handoff_requires_each_cross_identity_protocol_and_lifecycle_assertion(tmp_path):
    assert len(CHECKS) == 10 and validate(report())
    for key in CHECKS:
        for replacement in [False, None, 1]:
            value = report()
            value["checks"][key] = replacement
            assert not validate(value)
        value = report()
        del value["checks"][key]
        assert not validate(value)
    path = tmp_path / "report.json"
    path.write_text(json.dumps(report()))
    assert main([str(path)]) == 0


@pytest.mark.parametrize("name,value", [("production_ready", True), ("private_signins", True), ("private_signins", 1),
    ("system_key_used", False), ("production_python_reader_used", False), ("fixture_key_removed", False),
    ("consumer_deployment_verified", True), ("production_supervision_verified", True),
    ("actual_worker_store_handoff_verified", True), ("environment", "personal")])
def test_reader_probe_cannot_claim_a_consumer_deployment_or_enrolled_worker_store(name, value):
    changed = report()
    changed[name] = value
    assert not validate(changed)


@pytest.mark.parametrize("data", [None, "", "{}", "null"])
def test_missing_handoff_reports_fail(tmp_path, data):
    path = tmp_path / "report.json"
    if data is not None:
        path.write_text(data)
    assert main([str(path)]) == 1
