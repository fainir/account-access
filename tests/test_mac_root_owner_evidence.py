import copy
import json

import pytest

from scripts.check_mac_root_owner_report import CHECKS, main, validate


def report():
    return {"status": "PASSED", "environment": "controlled-demo", "platform": "macos", "production_ready": False,
            "private_signins": 0, "root_service_installed": True, "consumer_deployment_verified": False,
            "real_owner_auth_approval_tested": False, "authorization_database_changed": False,
            "publisher_signed_peers": False, "checks": dict.fromkeys(CHECKS, True)}


def test_root_service_evidence_requires_every_actual_assertion(tmp_path):
    value = report()
    assert len(CHECKS) == 24 and validate(value)
    for name in CHECKS:
        for replacement in [False, 1, None]:
            broken = copy.deepcopy(value)
            broken["checks"][name] = replacement
            assert not validate(broken)
        broken = copy.deepcopy(value)
        del broken["checks"][name]
        assert not validate(broken)
    target = tmp_path / "evidence.json"
    target.write_text(json.dumps(value))
    assert main([str(target)]) == 0


@pytest.mark.parametrize("name,value", [("production_ready", True), ("private_signins", 1), ("private_signins", False),
    ("real_owner_auth_approval_tested", True), ("consumer_deployment_verified", True),
    ("authorization_database_changed", True), ("publisher_signed_peers", True), ("root_service_installed", False),
    ("platform", "linux"), ("environment", "personal")])
def test_ci_root_host_cannot_claim_consumer_or_private_acceptance(name, value):
    changed = report()
    changed[name] = value
    assert not validate(changed)


@pytest.mark.parametrize("data", [None, "", "{}", "null", "not-json"])
def test_missing_empty_or_failed_root_reports_fail_ci(tmp_path, data):
    path = tmp_path / "report.json"
    if data is not None:
        path.write_text(data)
    assert main([str(path)]) == 1
