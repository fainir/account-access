import pytest
from scripts.check_mac_native_browser_report import CHECKS, validate
from scripts.mac_native_sms_fixture import NativeSMSFixture, native_account


def report():
    return dict(
        status="PASSED",
        platform="macos",
        environment="controlled-demo",
        production_ready=False,
        private_signins=0,
        full_worker_browser_sms_journey_verified=True,
        actual_native_collector_used=True,
        actual_distinct_uids=True,
        real_messages_database_used=False,
        physical_sms_delivery_verified=False,
        genuine_full_disk_access_verified=False,
        system_key_used=False,
        checks=dict.fromkeys(CHECKS, True),
    )


def test_every_native_browser_assertion_is_required():
    assert len(CHECKS) == 10 and validate(report())
    for key in CHECKS:
        for value in [False, 1, None, "true"]:
            changed = report()
            changed["checks"][key] = value
            assert not validate(changed)
        changed = report()
        del changed["checks"][key]
        assert not validate(changed)


@pytest.mark.parametrize(
    "key,value",
    [
        ("production_ready", True),
        ("environment", "personal"),
        ("private_signins", True),
        ("private_signins", 1),
        ("actual_distinct_uids", False),
        ("actual_native_collector_used", False),
        ("full_worker_browser_sms_journey_verified", False),
        ("real_messages_database_used", True),
        ("physical_sms_delivery_verified", True),
        ("genuine_full_disk_access_verified", True),
        ("system_key_used", True),
    ],
)
def test_native_browser_fixture_cannot_claim_physical_or_consumer_acceptance(key, value):
    changed = report()
    changed[key] = value
    assert not validate(changed)


def test_fixture_cannot_mutate_an_ordinary_machine(tmp_path):
    with pytest.raises(RuntimeError, match="native_browser_requires_disposable_mac_ci"):
        NativeSMSFixture(tmp_path, None)
    assert not list(tmp_path.iterdir())


def test_native_browser_fixture_uses_only_its_reviewed_sms_site():
    spec = native_account("http://127.0.0.1:12345")
    assert spec.login.sources() == {"native-sms"}
    assert spec.challenge_selectors == {
        "login": "#password-login",
        "action": "#action-challenge",
        "sms": "#sms-challenge",
    }
    assert spec.login_post_urls == [
        "http://127.0.0.1:12345/sms/login",
        "http://127.0.0.1:12345/sms/code",
    ]
    assert spec.operations["summary"].url == "http://127.0.0.1:12345/sms/summary"
