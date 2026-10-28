from pathlib import Path
import tempfile

import pytest

from account_access.demo import DEMO_PASSWORD
from account_access.models import Configuration
from account_access.verification_demo import environment
from scripts.mac_native_sms_fixture import identity_provider, native_account


@pytest.mark.parametrize("identity", [False, True])
def test_native_sms_fixture_keeps_single_page_and_system_host_identity_flows(identity):
    # Ordinary-user browser fixture only. Root/System-key composition runs in CI.
    with tempfile.TemporaryDirectory(prefix="aa-native-id-", dir="/tmp") as temporary:
        with environment(Path(temporary)) as (provider, broker, _):
            if identity:
                identity_provider(provider)
            config = broker.store.config()
            account = native_account(provider.base, identity=identity)
            account.login.factors["sms"].code_source = "example-sms"
            config.accounts["example-sms"] = account
            broker.store.configure(Configuration.model_validate(config.model_dump()))
            broker.store.put("credential:example-sms", {
                "username": "demo@example.test", "password": DEMO_PASSWORD,
            })
            broker.store.put("source:example-sms", {"enabled": True})
            broker.store.new_client("test")
            broker.grant("test", "example-sms", ["summary"])
            for _ in range(2):
                result = broker.run("test", "example-sms", "summary")
                assert result["status"] == "COMPLETED", result
                assert result["data"] == {"balance": "987.65", "currency": "ILS"}
            assert provider.login_count == provider.sms_count == 1
            if identity:
                assert provider.identity_count == 1
                assert provider.posted_paths == ["/sms/identify", "/sms/login", "/sms/code"]
