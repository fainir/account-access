import json

import pytest

from scripts.check_mac_provisioning_report import CHECKS, main, validate


def report():
    return {
        "status": "PASSED",
        "platform": "macos",
        "environment": "controlled-demo",
        "production_ready": False,
        "private_signins": 0,
        "actual_provisioner_used": True,
        "actual_system_entrypoint_used": True,
        "actual_native_xpc_used": True,
        "consumer_package_verified": False,
        "genuine_owner_approval_verified": False,
        "publisher_signed_peers": False,
        "fixture_identity_removed": True,
        "checks": dict.fromkeys(CHECKS, True),
    }


def test_every_provisioning_boundary_is_required(tmp_path):
    assert len(CHECKS) == 34 and validate(report())
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


@pytest.mark.parametrize(
    "name,value",
    [
        ("production_ready", True),
        ("private_signins", True),
        ("private_signins", 1),
        ("actual_provisioner_used", False),
        ("actual_system_entrypoint_used", False),
        ("actual_native_xpc_used", False),
        ("consumer_package_verified", True),
        ("genuine_owner_approval_verified", True),
        ("publisher_signed_peers", True),
        ("fixture_identity_removed", False),
        ("environment", "personal"),
    ],
)
def test_generated_installation_cannot_claim_consumer_or_private_coverage(name, value):
    data = report()
    data[name] = value
    assert not validate(data)


@pytest.mark.parametrize("text", [None, "", "{}", "null"])
def test_missing_or_invalid_evidence_fails(tmp_path, text):
    path = tmp_path / "report.json"
    if text is not None:
        path.write_text(text)
    assert main([str(path)]) == 1
