"""Owner-page revision follows mailbox identity, never returns its secret."""

import json
import re

from account_access.mailboxes import PREFIX, check, connect, update_password, view


def test_owner_mailbox_revision_survives_health_checks_but_invalidates_secret_replacement(
        env, monkeypatch):
    _, broker, _ = env
    monkeypatch.setattr("account_access.mailboxes.probe", lambda *args: {"status": "VERIFIED"})
    saved = connect(broker, {"label": "Fictional Gmail", "host": "imap.gmail.com", "port": 993,
                             "username": "owner@example.test", "password": "fictional-app-password"})
    original = view(broker.store)[0]
    generation = broker.store.get(PREFIX + saved["id"])["generation"]
    assert re.fullmatch(r"[a-f0-9]{64}", original["setup_revision"])
    assert "fictional-app-password" not in json.dumps(original)
    assert generation not in json.dumps(original)
    check(broker, saved["id"])
    assert view(broker.store)[0]["setup_revision"] == original["setup_revision"]
    # Even the same password creates a new enrollment and invalidates an old edit.
    update_password(broker, saved["id"], "fictional-app-password")
    changed = view(broker.store)[0]
    assert changed["setup_revision"] != original["setup_revision"]
    assert "fictional-app-password" not in json.dumps(changed)
    profile = broker.store.get(PREFIX + saved["id"])
    profile["label"] = "Renamed fictional mailbox"
    broker.store.put(PREFIX + saved["id"], profile)
    assert view(broker.store)[0]["setup_revision"] != changed["setup_revision"]
