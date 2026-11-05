"""A shell command success is not evidence that Android posted the fixture."""
import pytest

from scripts.android_journey import fixture_acknowledged, safe_phone_refusal


def test_only_receiver_acknowledgement_confirms_posting():
    assert fixture_acknowledged('Broadcasting: Intent { extras }\nBroadcast completed: result=1, data="fixture_notification_posted"\n')


@pytest.mark.parametrize("output", [None, "", "Broadcast completed: result=0\n",
    'Broadcast completed: result=1, data="fixture_notification_cancelled"\n',
    'Broadcast completed: result=1, data="unrecognized"\n',
    'Broadcast completed: result=1, data="fixture_notification_posted" unexpected',
    'untrusted extras Broadcast completed: result=1, data="fixture_notification_posted"'])
def test_missing_or_different_receiver_result_is_not_delivery(output):
    assert not fixture_acknowledged(output)


def test_phone_refusal_diagnostic_is_closed_and_secret_free():
    assert safe_phone_refusal("no_current_login_window") == "no_current_login_window"
    assert safe_phone_refusal("arbitrary user data 123456") == "delivery_refused"
    assert safe_phone_refusal(None) == "delivery_refused"
