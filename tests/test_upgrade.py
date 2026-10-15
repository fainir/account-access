import json

from account_access.upgrade import retire_development_routes
from account_access.storage import private_file


def test_removed_development_route_cannot_survive_upgrade(env):
    _, broker, _ = env
    before = broker.store.config().model_dump()
    original_password = broker.store.get("credential:demo-web")
    legacy = {**before, "accounts": {**before["accounts"], "retired-connection": {
        "kind": "github_cli", "label": "Retired account", "operations": {"status": {}}}}}
    path = broker.store.root / "config.json"
    private_file(path, json.dumps(legacy).encode(), replace=True)
    with broker.store.db() as db:
        db.execute("INSERT INTO grants VALUES (?,?,?,?,NULL)", ("test", "retired-connection", "status", "retired"))
    broker.store.put("connection:retired-connection", {"provider": "retired"})
    retire_development_routes(broker.store)
    assert broker.store.config().model_dump() == before
    assert broker.store.get("connection:retired-connection") is None
    assert broker.store.get("credential:demo-web") == original_password
    assert broker.run("test", "retired-connection", "status")["status"] == "DENIED"
    assert broker.run("test", "demo-web", "summary")["status"] == "COMPLETED"
    backups = list(broker.store.root.glob("retired-route-*.json"))
    assert len(backups) == 1 and backups[0].stat().st_mode & 0o077 == 0
    assert json.loads(backups[0].read_bytes()) == legacy
    retire_development_routes(broker.store)
    assert len(list(broker.store.root.glob("retired-route-*.json"))) == 1
