import pytest
from scripts.check_mac_native_system_browser_report import CHECKS, validate
from scripts.mac_native_system_fixture import exercise_native_system
from scripts.mac_key_handoff_probe import seed_native_host_fixture


def report():
    return dict(
        status="PASSED",
        platform="macos",
        environment="controlled-demo",
        production_ready=False,
        private_signins=0,
        system_key_used=True,
        production_composed_host_used=True,
        actual_native_collector_used=True,
        actual_distinct_uids=True,
        full_worker_browser_sms_journey_verified=True,
        real_messages_database_used=False,
        physical_sms_delivery_verified=False,
        genuine_owner_approval_verified=False,
        genuine_full_disk_access_verified=False,
        consumer_deployment_verified=False,
        publisher_signed_peers=False,
        checks=dict.fromkeys(CHECKS, True),
    )


def test_all_system_native_journey_checks_are_required():
    assert len(CHECKS) == 16 and validate(report())
    for key in CHECKS:
        for value in [False, None, 1, "true"]:
            broken = report()
            broken["checks"][key] = value
            assert not validate(broken)
        broken = report()
        del broken["checks"][key]
        assert not validate(broken)


@pytest.mark.parametrize(
    "key,value",
    [
        ("system_key_used", False),
        ("production_composed_host_used", False),
        ("actual_native_collector_used", False),
        ("actual_distinct_uids", 1),
        ("full_worker_browser_sms_journey_verified", False),
        ("private_signins", True),
        ("private_signins", 1),
        ("production_ready", True),
        ("environment", "personal"),
        ("real_messages_database_used", True),
        ("physical_sms_delivery_verified", True),
        ("genuine_owner_approval_verified", True),
        ("genuine_full_disk_access_verified", True),
        ("consumer_deployment_verified", True),
        ("publisher_signed_peers", True),
    ],
)
def test_system_fixture_cannot_hide_a_missing_component_or_claim_consumer_qa(key, value):
    changed = report()
    changed[key] = value
    assert not validate(changed)


def test_system_journey_cannot_mutate_an_ordinary_mac(tmp_path):
    with pytest.raises(RuntimeError, match="native_system_requires_disposable_mac_ci"):
        exercise_native_system(tmp_path, None, None, None, "", None, None, None)
    assert not list(tmp_path.iterdir())


def test_fixture_seed_refuses_existing_account_configuration(env):
    _, broker, _ = env
    before = broker.store.config().model_dump()
    with pytest.raises(ValueError, match="invalid_native_host_fixture"):
        seed_native_host_fixture(
            broker.store, {"provider_url": "http://127.0.0.1:1234", "client_digest": "a" * 64}
        )
    assert broker.store.config().model_dump() == before
