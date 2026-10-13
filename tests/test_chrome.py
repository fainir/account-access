import pytest

from account_access.chrome import handle
from account_access.errors import AccessError


def test_chrome_bridge_discloses_no_credentials_and_rejects_other_site(env):
    _, broker, _ = env
    result = handle(broker, {"method": "accounts"})
    assert "password" not in str(result)
    with pytest.raises(AccessError, match="session_origin_mismatch"):
        handle(broker, {"method": "import", "account": "demo-web", "url": "https://evil.example", "state": {}})
    with pytest.raises(AccessError, match="unsupported_native_message"):
        handle(broker, {"method": "read_passwords"})
