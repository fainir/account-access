"""Imported IDs are owner-only suggestions, never password-manager authority."""

import json
import threading

import httpx2 as httpx
import pytest

from account_access.demo import DEMO_PASSWORD
from account_access.owner import make_owner_server
from account_access.password_import import SYNC_HINT, apply, parse, preview, sync_suggestion

ITEM = "a1111111-b222-4333-8444-c55555555555"


def export(url, **changes):
    item = {"id": ITEM, "type": 1,
            "login": {"username": "demo@example.test", "password": DEMO_PASSWORD,
                      "uris": [{"uri": url}]}, **changes}
    return json.dumps({"encrypted": False, "items": [item]})


def imported(broker):
    url = broker.store.config().accounts["demo-web"].login_url
    staged = preview(broker.store, export(url))
    assert broker.store.get(SYNC_HINT + "demo-web") is None
    assert broker.store.get("password-link:demo-web") is None
    apply(broker, staged["id"], [{"row": "0:0", "account": "demo-web", "operations": ["summary"]}], ["test"])
    return url


def test_import_preserves_only_exact_selected_item_as_inert_owner_suggestion(env):
    _, broker, _ = env
    imported(broker)
    assert sync_suggestion(broker.store, "demo-web") == {"provider": "bitwarden", "item": ITEM}
    assert broker.store.get("password-link:demo-web") is None
    assert broker.store.get("bitwarden-source:demo-web") is None
    hint = broker.store.get(SYNC_HINT + "demo-web")
    assert DEMO_PASSWORD not in json.dumps(hint)
    assert hint["fingerprint"] == broker.store.config().fingerprint("demo-web")
    assert sync_suggestion(broker.store, "demo-mfa") is None


@pytest.mark.parametrize("changes", [
    {"id": "../other"}, {"id": ITEM.upper()}, {"id": None}, {"id": 1},
    {"reprompt": 1}, {"reprompt": True}, {"archivedDate": "2026-10-01T00:00:00Z"},
])
def test_snapshot_imports_without_supported_source_identity_cannot_suggest_sync(changes):
    rows = parse(export("https://example.test/login", **changes))
    assert len(rows) == 1 and rows[0]["password"] == DEMO_PASSWORD
    assert "sync_item" not in rows[0]


@pytest.mark.parametrize("change", ["credential", "connector", "missing", "item", "origin"])
def test_suggestion_stops_when_imported_account_or_metadata_changes(env, change):
    _, broker, _ = env
    imported(broker)
    if change == "credential":
        broker.store.put("credential:demo-web", {"username": "other@example.test", "password": "fictional"})
    elif change == "connector":
        config = broker.store.config()
        config.accounts["demo-web"].label = "Changed reviewed connector"
        broker.store.configure(config)
    elif change == "missing":
        broker.store.put("credential:demo-web", None)
    else:
        hint = broker.store.get(SYNC_HINT + "demo-web")
        hint[change] = "https://attacker.test" if change == "origin" else "../other"
        broker.store.put(SYNC_HINT + "demo-web", hint)
    assert sync_suggestion(broker.store, "demo-web") is None


def test_selected_csv_replacement_clears_previous_bitwarden_suggestion(env):
    _, broker, _ = env
    url = imported(broker)
    staged = preview(broker.store, f"url,username,password\n{url},demo@example.test,replacement\n")
    apply(broker, staged["id"], [{"row": "0", "account": "demo-web", "operations": ["summary"]}], ["test"])
    assert sync_suggestion(broker.store, "demo-web") is None
    assert broker.store.get(SYNC_HINT + "demo-web") is None


def test_owner_state_exposes_only_safe_hint_and_explicit_edit_removes_it(env):
    _, broker, _ = env
    imported(broker)
    server, token = make_owner_server(broker, guided=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{server.server_port}"
    headers = {"Authorization": "Bearer " + token, "Origin": base}
    try:
        with httpx.Client(base_url=base, trust_env=False) as client:
            response = client.get("/owner/state", headers=headers)
            assert response.status_code == 200
            state = response.json()
            account = next(row for row in state["accounts"] if row["account"] == "demo-web")
            assert account["password_sync_suggestion"] == {"provider": "bitwarden", "item": ITEM}
            assert DEMO_PASSWORD not in response.text
            response = client.post("/owner/credential", headers=headers,
                json={"account": "demo-web", "username": "demo@example.test", "password": "owner-edited-password"})
            assert response.json() == {"status": "SAVED"}
            assert broker.store.get(SYNC_HINT + "demo-web") is None
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
