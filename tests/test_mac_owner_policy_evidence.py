import copy
import json

import pytest

from scripts.check_mac_owner_policy_report import CHECKS, main, validate


def report():
    return {"status": "PASSED", "platform": "macos", "environment": "controlled-demo", "production_ready": False,
            "private_signins": 0, "authorization_database_changed": True, "fixture_namespace": True,
            "fixture_right_removed": True, "synthetic_permissive_rule_used": True,
            "real_owner_auth_approval_tested": False, "consumer_deployment_verified": False,
            "checks": dict.fromkeys(CHECKS, True)}


def test_policy_evidence_requires_each_provisioning_and_fail_closed_check(tmp_path):
    assert len(CHECKS) == 16 and validate(report())
    for check in CHECKS:
        for replacement in [False, 1, None]:
            value = report()
            value["checks"][check] = replacement
            assert not validate(value)
        value = report()
        del value["checks"][check]
        assert not validate(value)
    path = tmp_path / "report.json"
    path.write_text(json.dumps(report()))
    assert main([str(path)]) == 0


@pytest.mark.parametrize("name,value", [("production_ready", True), ("private_signins", True), ("private_signins", 1),
    ("authorization_database_changed", False), ("fixture_right_removed", False), ("fixture_namespace", False),
    ("synthetic_permissive_rule_used", False), ("real_owner_auth_approval_tested", True),
    ("consumer_deployment_verified", True), ("environment", "personal")])
def test_synthetic_rule_proof_cannot_claim_genuine_owner_or_consumer_acceptance(name, value):
    changed = copy.deepcopy(report())
    changed[name] = value
    assert not validate(changed)


@pytest.mark.parametrize("data", [None, "", "{}", "null"])
def test_missing_policy_evidence_fails(tmp_path, data):
    path = tmp_path / "report.json"
    if data is not None:
        path.write_text(data)
    assert main([str(path)]) == 1
