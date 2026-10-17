import pytest
from scripts.check_mac_native_messages_report import CHECKS, validate


def report():
    return {
        "status": "PASSED",
        "environment": "controlled-demo",
        "production_ready": False,
        "private_signins": 0,
        "actual_separate_owner_uid_reader": True,
        "real_messages_database_used": False,
        "physical_sms_delivery_verified": False,
        "full_worker_browser_sms_journey_verified": False,
        "genuine_full_disk_access_verified": False,
        "checks": dict.fromkeys(CHECKS, True),
    }


def test_all_native_process_checks_are_required():
    assert len(CHECKS) == 13 and validate(report())
    for key in CHECKS:
        for replacement in [False, None, 1]:
            value = report()
            value["checks"][key] = replacement
            assert not validate(value)
        value = report()
        del value["checks"][key]
        assert not validate(value)


@pytest.mark.parametrize(
    "name,value",
    [
        ("production_ready", True),
        ("private_signins", True),
        ("private_signins", 1),
        ("actual_separate_owner_uid_reader", False),
        ("real_messages_database_used", True),
        ("physical_sms_delivery_verified", True),
        ("full_worker_browser_sms_journey_verified", True),
        ("genuine_full_disk_access_verified", True),
        ("environment", "live"),
    ],
)
def test_fixture_cannot_claim_private_or_complete_journey_acceptance(name, value):
    data = report()
    data[name] = value
    assert not validate(data)
