"""Narrow, fail-closed cleanup of an abandoned development-only account route."""

import hashlib
import json

from .storage import check_private, private_file
from .models import Configuration


def retire_development_routes(store):
    path = store.root / "config.json"
    if not path.exists():
        return
    with store.lock("configuration"):
        check_private(path)
        original = path.read_bytes()
        raw = json.loads(original)
        retired = {key for key, value in raw.get("accounts", {}).items()
                   if isinstance(value, dict) and value.get("kind") == "github_cli"}
        if not retired:
            return
        raw["accounts"] = {key: value for key, value in raw["accounts"].items() if key not in retired}
        config = Configuration.model_validate(raw)
        # Preserve the previous configuration privately. No provider login is
        # changed or revoked, and other account credentials are untouched.
        backup = store.root / ("retired-route-" + hashlib.sha256(original).hexdigest()[:16] + ".json")
        if not backup.exists():
            private_file(backup, original)
        with store.db() as db:
            for account in retired:
                db.execute("DELETE FROM grants WHERE account=?", (account,))
                store.put("connection:" + account, None, db=db)
            store.put("github-cli-preview", None, db=db)
        private_file(path, config.model_dump_json(indent=2).encode(), replace=True)
