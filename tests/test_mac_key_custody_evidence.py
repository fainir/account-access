import copy
import json

import pytest

from scripts.check_mac_key_custody_report import CHECKS, main, validate


def report():
    return {"status": "PASSED", "platform": "macos", "environment": "controlled-demo", "production_ready": False,
            "private_signins": 0, "personal_keychain_used": False, "consumer_deployment_verified": False,
            "fixture_namespace": True, "fixture_key_removed": True, "direct_read_status": -25308,
            "checks": dict.fromkeys(CHECKS, True)}


def test_key_custody_requires_all_persistence_and_denial_assertions(tmp_path):
    value = report()
    assert len(CHECKS) == 18 and validate(value)
    for name in CHECKS:
        for replacement in [False, 1, None]:
            changed = copy.deepcopy(value)
            changed["checks"][name] = replacement
            assert not validate(changed)
        changed = copy.deepcopy(value)
        del changed["checks"][name]
        assert not validate(changed)
    target = tmp_path / "evidence.json"
    target.write_text(json.dumps(value))
    assert main([str(target)]) == 0


@pytest.mark.parametrize("status", [-50, -25291, 0, None, True, "-25308"])
def test_invalid_queries_and_unavailable_keychains_are_not_access_denial_proof(status):
    value = report()
    value["direct_read_status"] = status
    assert not validate(value)


@pytest.mark.parametrize("name,value", [("production_ready", True), ("private_signins", True), ("private_signins", 1),
    ("personal_keychain_used", True), ("fixture_key_removed", False), ("fixture_namespace", False),
    ("consumer_deployment_verified", True), ("environment", "personal")])
def test_fixture_key_store_cannot_claim_consumer_or_private_acceptance(name, value):
    changed = report()
    changed[name] = value
    assert not validate(changed)


@pytest.mark.parametrize("data", [None, "", "{}", "null"])
def test_empty_or_partial_key_custody_reports_fail_ci(tmp_path, data):
    path = tmp_path / "report.json"
    if data is not None:
        path.write_text(data)
    assert main([str(path)]) == 1
