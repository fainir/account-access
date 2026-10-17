import copy

import pytest

from scripts.mac_owner_gateway_smoke import NATIVE_CHECKS, validate_report


def report():
    return {"status": "PASSED", "environment": "controlled-demo", "platform": "macos", "private_signins": 0,
            "production_ready": False, "publisher_signed_peers": False, "real_owner_auth_approval_tested": False,
            "root_service_installed": False, "checks": dict.fromkeys(NATIVE_CHECKS, True)}


@pytest.mark.parametrize("value", [None, {}, [], {"status": "PASSED"}, "passed"])
def test_incomplete_native_reports_are_not_acceptance(value):
    assert not validate_report(value, publisher=False)


def test_each_native_check_is_required_and_not_just_truthy():
    value = report()
    assert validate_report(value, publisher=False)
    for name in NATIVE_CHECKS:
        changed = copy.deepcopy(value)
        del changed["checks"][name]
        assert not validate_report(changed, publisher=False)
        for substitute in [False, 1, "true", None]:
            changed = copy.deepcopy(value)
            changed["checks"][name] = substitute
            assert not validate_report(changed, publisher=False)


@pytest.mark.parametrize("name,value", [("production_ready", True), ("private_signins", True),
    ("private_signins", 1), ("real_owner_auth_approval_tested", True), ("root_service_installed", True),
    ("publisher_signed_peers", True), ("platform", "linux")])
def test_native_component_cannot_claim_untested_deployment_or_signing(name, value):
    changed = report()
    changed[name] = value
    assert not validate_report(changed, publisher=False)


def test_publisher_proof_is_explicit_and_separate_from_adhoc_ci():
    value = report()
    assert not validate_report(value, publisher=True)
    value["publisher_signed_peers"] = True
    assert validate_report(value, publisher=True)
    assert not validate_report(value, publisher=False)
