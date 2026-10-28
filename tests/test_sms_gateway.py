import time
from email.utils import formatdate

import pytest

from account_access.errors import AccessError
from account_access.factors import enroll, revoke
from account_access.models import CodeSource


def setup(broker, monkeypatch):
    config = broker.store.config()
    config.code_sources["gateway"] = CodeSource(kind="twilio", sender="+15550000001", recipient="+15550000002",
                                               template="Example sign-in: {code}")
    broker.store.configure(config)
    enroll(broker.store, "gateway", {"sid": "AC" + "0" * 32, "auth_token": "fictional-gateway-secret"})
    response = {"messages": []}
    calls = []

    def get(url, **kwargs):
        calls.append((url, kwargs["params"]))
        return response

    monkeypatch.setattr("account_access.codes.get_json", get)
    return response, calls


def message(ident="1", at=None):
    return {"sid": "SM" + ident * 32, "direction": "inbound", "from": "+15550000001", "to": "+15550000002",
            "date_sent": formatdate(time.time() if at is None else at, usegmt=True), "body": "Example sign-in: 123456"}


def test_gateway_remembers_existing_ids_before_password_can_trigger_delivery(env, monkeypatch):
    _, broker, _ = env
    response, calls = setup(broker, monkeypatch)
    started = time.time() - 2
    response["messages"] = [message(at=time.time() + 2)]
    broker.codes.begin("gateway", "demo-web", started)
    assert broker.codes.resolve("gateway", started, set()) is None
    response["messages"].append(message("2"))
    used = set()
    assert broker.codes.resolve("gateway", started, used) == "123456"
    assert used == {"SM" + "2" * 32}
    assert calls[0][1]["PageSize"] == 20 and "DateSent>" in calls[0][1]


@pytest.mark.parametrize("case,reason", [
    ("page", "sms_gateway_result_limit"), ("too_many", "sms_gateway_result_limit"),
    ("bad_sid", "invalid_sms_gateway_response"), ("duplicate_sid", "invalid_sms_gateway_response"),
    ("bad_list", "invalid_sms_gateway_response"), ("two_codes", "ambiguous_login_code"),
    ("revoked", "login_code_window_missing"),
])
def test_gateway_stops_incomplete_ambiguous_or_revoked_delivery(env, monkeypatch, case, reason):
    _, broker, _ = env
    response, calls = setup(broker, monkeypatch)
    started = time.time() - 2
    broker.codes.begin("gateway", "demo-web", started)
    response["messages"] = [message()]
    if case == "page":
        response["next_page_uri"] = "https://unapproved.example/collect"
    elif case == "too_many":
        response["messages"] *= 21
    elif case == "bad_sid":
        response["messages"][0]["sid"] = "invalid"
    elif case == "duplicate_sid":
        response["messages"] *= 2
    elif case == "bad_list":
        response["messages"] = {"sid": "invalid"}
    elif case == "two_codes":
        response["messages"].append(message("2"))
    elif case == "revoked":
        def revoke_during_read(*args, **kwargs):
            revoke(broker.store, "gateway")
            return response
        monkeypatch.setattr("account_access.codes.get_json", revoke_during_read)
    used = set()
    with pytest.raises(AccessError, match=reason):
        broker.codes.resolve("gateway", started, used)
    assert used == set()
    assert all("unapproved" not in url for url, _ in calls)


@pytest.mark.parametrize("case", ["future", "old", "payment", "wrong_sender", "wrong_recipient", "outgoing", "bad_date", "bad_body"])
def test_gateway_excludes_stale_or_different_purpose_texts(env, monkeypatch, case):
    _, broker, _ = env
    response, _ = setup(broker, monkeypatch)
    started = time.time() - 2
    broker.codes.begin("gateway", "demo-web", started)
    item = message()
    if case == "future":
        item["date_sent"] = formatdate(time.time() + 100, usegmt=True)
    elif case == "old":
        item["date_sent"] = formatdate(started - 1, usegmt=True)
    elif case == "payment":
        item["body"] = "Approve payment: 123456"
    elif case == "wrong_sender":
        item["from"] = "+15550000003"
    elif case == "wrong_recipient":
        item["to"] = "+15550000003"
    elif case == "outgoing":
        item["direction"] = "outbound-api"
    elif case == "bad_date":
        item["date_sent"] = None
    elif case == "bad_body":
        item["body"] = ["Example sign-in: 123456"]
    response["messages"] = [item]
    assert broker.codes.resolve("gateway", started, set()) is None


def test_gateway_preflight_does_not_submit_password_if_source_is_unavailable(env, monkeypatch):
    provider, broker, _ = env
    response, _ = setup(broker, monkeypatch)
    config = broker.store.config()
    config.accounts["demo-mfa"].login.code_source = "gateway"
    broker.store.configure(config)
    broker.grant("test", "demo-mfa", ["summary"])
    response["next_page_uri"] = "/more"
    result = broker.run("test", "demo-mfa", "summary")
    assert result["reason"] == "sms_gateway_result_limit"
    assert provider.login_count == 0 and broker.store.get("code-window:gateway") is None
