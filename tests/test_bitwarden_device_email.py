"""An explicit mailbox repair preserves only still-current imported item hints."""
# ruff: noqa: F811 -- pytest consumes the imported shared fixture by name.

import pytest

from account_access import device_email_setup as setup
from account_access.catalog import PYPI_ACCOUNT
from account_access.password_import import SYNC_HINT, sync_suggestion
from test_device_email_setup import connected, review  # noqa: F401

ITEM = "a1111111-b222-4333-8444-c55555555555"


def hint(store):
    return {"provider": "bitwarden", "item": ITEM, "username": "fictional-owner",
            "origin": "https://pypi.org", "fingerprint": store.config().fingerprint(PYPI_ACCOUNT)}


def test_current_import_hint_survives_mailbox_binding_and_removal(connected):
    store = connected.store
    imported = hint(store)
    store.put(SYNC_HINT + PYPI_ACCOUNT, imported)
    assert sync_suggestion(store, PYPI_ACCOUNT) == {"provider": "bitwarden", "item": ITEM}
    setup.apply(store, review(connected)["id"])
    assert store.get(SYNC_HINT + PYPI_ACCOUNT) == {**imported, "fingerprint": store.config().fingerprint(PYPI_ACCOUNT)}
    assert sync_suggestion(store, PYPI_ACCOUNT) == {"provider": "bitwarden", "item": ITEM}
    setup.remove(store, PYPI_ACCOUNT, store.config().fingerprint(PYPI_ACCOUNT))
    assert store.get(SYNC_HINT + PYPI_ACCOUNT) == imported
    assert store.get("password-link:" + PYPI_ACCOUNT) is None


@pytest.mark.parametrize("change", ["username", "origin", "item", "fingerprint"])
def test_invalid_hint_never_revives_when_connector_fingerprint_cycles(connected, change):
    store = connected.store
    imported = hint(store)
    imported[change] = "different" if change != "origin" else "https://other.example.test"
    store.put(SYNC_HINT + PYPI_ACCOUNT, imported)
    assert sync_suggestion(store, PYPI_ACCOUNT) is None
    setup.apply(store, review(connected)["id"])
    setup.remove(store, PYPI_ACCOUNT, store.config().fingerprint(PYPI_ACCOUNT))
    assert sync_suggestion(store, PYPI_ACCOUNT) is None
    assert store.get(SYNC_HINT + PYPI_ACCOUNT)["fingerprint"] != store.config().fingerprint(PYPI_ACCOUNT)
