"""Import -> approved sync -> browser read -> rotation -> restrictive disconnect.

The CLI fixture runs real bounded child processes against fictional source data;
the website is local. This does not constitute personal Bitwarden acceptance.
"""
# ruff: noqa: F811 -- pytest consumes the imported CLI fixture by name.

import json

from account_access import bitwarden_source, password_import, password_sync
from account_access.demo import DEMO_PASSWORD
from test_bitwarden_source import ITEM, cli, link, setup_data  # noqa: F401


def test_imported_item_updates_automatic_browser_login_without_new_owner_prompt(env, cli):
    website, broker, _ = env
    store, source_file = cli
    state = json.loads(source_file.read_text())
    state["item"]["login"]["password"] = DEMO_PASSWORD
    source_file.write_text(json.dumps(state))
    exported = json.dumps({"encrypted": False, "items": [state["item"]]})
    review = password_import.preview(store, exported)
    password_import.apply(broker, review["id"], [
        {"row": "0:0", "account": "demo-web", "operations": ["summary"]}], ["test"])
    assert password_import.sync_suggestion(store, "demo-web") == {"provider": "bitwarden", "item": ITEM}
    connection = bitwarden_source.connect(store, setup_data())
    password_sync.enroll(store, "demo-web", link(connection))
    with store.db() as db:
        grants = [tuple(row) for row in db.execute("SELECT * FROM grants ORDER BY 1,2,3")]
    assert broker.run("test", "demo-web", "summary")["status"] == "COMPLETED"
    assert website.login_count == 1
    assert broker.run("test", "demo-web", "summary")["status"] == "COMPLETED"
    assert website.login_count == 1  # The approved session is reused.

    website.password = state["item"]["login"]["password"] = "rotated-fictional-website-password"
    source_file.write_text(json.dumps(state))
    saved = store.get("password-link:demo-web")
    store.put("password-link:demo-web", {**saved, "next_at": 0})
    store.put("login-attempt:demo-web", 0)
    password_sync.due(store)
    assert store.get("connection:demo-web") is None
    assert broker.run("test", "demo-web", "summary")["status"] == "COMPLETED"
    assert website.login_count == 2 and store.pending("demo-web") == []
    with store.db() as db:
        assert grants == [tuple(row) for row in db.execute("SELECT * FROM grants ORDER BY 1,2,3")]

    bitwarden_source.disconnect(store, connection["id"], connection["generation"])
    assert store.get("credential:demo-web") is None
    assert store.get("connection:demo-web") is None
    assert broker.run("test", "demo-web", "summary")["status"] == "NEEDS_USER"
    assert website.login_count == 2
    for secret in [DEMO_PASSWORD, website.password, setup_data()["client_secret"], setup_data()["master_password"]]:
        assert secret.encode() not in store.path.read_bytes()
