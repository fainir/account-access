import pytest

from account_access.navigation import route_hint, valid_hint


@pytest.mark.parametrize("url,expected", [
    ("https://github.com/sessions/verified-device?code=123456", "origin_0:/sessions/verified-device"),
    ("https://github.com/fainir/token-123456", "origin_0:/?/?"),
    ("https://github.com/%73essions/123456?secret=hidden", "origin_0:/?/?"),
    ("https://private-host.example/sessions/device/123456", "external:/sessions/device/?"),
    ("https://github.com/", "origin_0:/?"),
])
def test_route_hint_only_emits_literal_vocabulary(url, expected):
    hint = route_hint(url, ["https://github.com"])
    assert hint == expected
    assert valid_hint(hint)


@pytest.mark.parametrize("value", [None, "origin_0:/sessions/123456", "https://private.example/",
                                    "origin_0:/sessions?code=123456", "origin_1000:/login",
                                    "external:/" + "/".join(["login"] * 10)])
def test_owner_rejects_arbitrary_diagnostic_text(value):
    assert not valid_hint(value)
