"""Owner-enrolled 1Password Connect links; no vault listing or agent secret API.

Only the password of an exact approved item can change automatically. Account
identity, website, connector, grants and authenticator enrollment cannot change.
"""

import re
import time
from urllib.parse import urlsplit

from .errors import AccessError
from .models import BrowserAccount, origin, validate_url
from .providers import get_json

INTERVAL = 300
IDENTIFIER = re.compile(r"^[a-z0-9]{26}$")


def validate_link(store, account, data):
    spec = store.config().accounts.get(account)
    if not isinstance(spec, BrowserAccount) or not spec.login:
        raise AccessError("DENIED", "password_sync_account_unsupported")
    if not isinstance(data, dict) or set(data) != {"endpoint", "token", "vault", "item"}:
        raise AccessError("DENIED", "invalid_password_sync_link")
    if (any(not isinstance(x, str) for x in data.values())
            or not 1 <= len(data["token"]) <= 8192
            or any(c in data["token"] for c in "\r\n")
            or any(not IDENTIFIER.fullmatch(data[x]) for x in ["vault", "item"])):
        raise AccessError("DENIED", "invalid_password_sync_link")
    endpoint = data["endpoint"].rstrip("/")
    try:
        validate_url(endpoint, store.config().test_mode)
        parts = urlsplit(endpoint)
        if parts.path or parts.query:
            raise ValueError()
    except ValueError:
        raise AccessError("DENIED", "password_sync_requires_https_origin") from None
    return {**data, "endpoint": endpoint}


def fetch(link, expected_origin):
    url = f'{link["endpoint"]}/v1/vaults/{link["vault"]}/items/{link["item"]}'
    try:
        item = get_json(url, headers={"Authorization": "Bearer " + link["token"]})
    except AccessError as exc:
        reason = ("password_source_unavailable" if exc.status == "RETRYABLE"
                  else "password_source_access_removed")
        raise AccessError(exc.status, reason) from None
    if (not isinstance(item, dict) or item.get("id") != link["item"]
            or not isinstance(item.get("vault"), dict)
            or item["vault"].get("id") != link["vault"]
            or item.get("category") != "LOGIN" or item.get("state") != "ACTIVE"):
        raise AccessError("DENIED", "password_source_item_changed")
    try:
        websites = {origin(x["href"]) for x in item.get("urls", [])}
        username = [x["value"] for x in item.get("fields", []) if x.get("purpose") == "USERNAME"]
        password = [x["value"] for x in item.get("fields", []) if x.get("purpose") == "PASSWORD"]
        if (expected_origin not in websites or len(username) != 1 or len(password) != 1
                or any(not isinstance(x, str) or not 0 < len(x) <= 4096
                       for x in [*username, *password])):
            raise ValueError()
    except (AttributeError, KeyError, TypeError, ValueError):
        raise AccessError("DENIED", "password_source_item_changed") from None
    return {"username": username[0], "password": password[0]}


def enroll(store, account, data):
    with store.lock("account:" + account):
        # Serialize the complete enrollment with credential edits, imports and
        # disconnection. A delayed source response cannot restore a link or
        # credential after the owner's newer account action.
        link = validate_link(store, account, data)
        config = store.config()
        credential = fetch(link, origin(config.accounts[account].login_url))
        saved = store.get("credential:" + account) or {}
        if not saved.get("username") or saved["username"] != credential["username"]:
            raise AccessError("DENIED", "password_sync_identity_mismatch")
        # No permissions are created here. Linking follows an approved import.
        if config.fingerprint(account) != store.config().fingerprint(account):
            raise AccessError("DENIED", "password_sync_connector_changed")
        link.update(username=saved["username"], fingerprint=config.fingerprint(account),
                    status="SYNCED", checked=time.time(), next_at=time.time() + INTERVAL)
        with store.db() as db:
            store.put("password-link:" + account, link, db=db)
            if credential != saved:
                store.put("credential:" + account, credential, db=db)
                store.put("connection:" + account, None, db=db)
    store.audit("owner", account, "", "password_sync_connected")
    return {"status": "SYNCED", "account": account}


def refresh(store, account, *, force=False):
    # Caller holds the account lock. Owner unlink/relink uses the same lock.
    link = store.get("password-link:" + account)
    if not link:
        return
    now = time.time()
    if not force and link["next_at"] > now:
        if link["status"] == "BLOCKED":
            raise AccessError("NEEDS_USER", link["reason"])
        return
    try:
        config = store.config()
        if config.fingerprint(account) != link["fingerprint"]:
            raise AccessError("DENIED", "password_sync_connector_changed")
        credential = fetch(link, origin(config.accounts[account].login_url))
        if credential["username"] != link["username"]:
            raise AccessError("DENIED", "password_sync_identity_mismatch")
    except AccessError as exc:
        link.update(status="RETRYABLE" if exc.status == "RETRYABLE" else "BLOCKED",
                    reason=exc.reason, next_at=now + (60 if exc.status == "RETRYABLE" else INTERVAL))
        store.put("password-link:" + account, link)
        raise AccessError("RETRYABLE" if exc.status == "RETRYABLE" else "NEEDS_USER", exc.reason) from None
    changed = credential != store.get("credential:" + account)
    link.update(status="SYNCED", checked=now, next_at=now + INTERVAL)
    link.pop("reason", None)
    with store.db() as db:
        store.put("password-link:" + account, link, db=db)
        db.execute("UPDATE challenges SET resolved=? WHERE account=? AND resolved IS NULL AND kind='login' AND reason IN ('password_source_access_removed','password_source_item_changed','password_sync_identity_mismatch','password_sync_connector_changed')", (now, account))
        if changed:
            store.put("credential:" + account, credential, db=db)
            store.put("connection:" + account, None, db=db)
            # A source password update is not a successful website sign-in.
            # Match owner credential-save semantics: repair only the missing
            # credential/login prerequisite, never an unrelated login gate.
            db.execute("UPDATE challenges SET resolved=? WHERE account=? AND resolved IS NULL AND kind='login' AND reason IN ('password_not_connected','browser_login_required')",
                       (now, account))
    if changed:
        store.audit("service", account, "", "password_synced")


def due(store):
    # Bound both record inspection and network work. Rotate by immutable record
    # ID (put replaces rowids), so busy or not-yet-due links cannot starve later
    # accounts. Exceptions contain only fixed reasons, never item contents.
    cursor = store.get("password-sync-cursor", "")
    if not isinstance(cursor, str) or (cursor and not cursor.startswith("password-link:")):
        cursor = ""
    with store.db() as db:
        query = """SELECT id FROM records WHERE id LIKE 'password-link:%' AND id>?
                   ORDER BY id LIMIT 20"""
        keys = [r[0] for r in db.execute(query, (cursor,))]
        if not keys and cursor:
            keys = [r[0] for r in db.execute(query, ("",))]
    count = 0
    for key in keys:
        store.put("password-sync-cursor", key)
        link = store.get(key)
        if not link or link["next_at"] > time.time():
            continue
        try:
            with store.lock("account:" + key.split(":", 1)[1], timeout=0):
                refresh(store, key.split(":", 1)[1])
        except AccessError:
            pass
        count += 1
        if count == 2:
            break


def view(store):
    result = []
    for account in store.config().accounts:
        link = store.get("password-link:" + account)
        if link:
            result.append({"account": account, "provider": "1Password Connect",
                           "status": link["status"], "checked": link["checked"],
                           "reason": link.get("reason"), "interval": INTERVAL})
    return result


def unlink(store, account):
    if account not in store.config().accounts:
        raise AccessError("DENIED", "unknown_account")
    with store.lock("account:" + account):
        with store.db() as db:
            store.put("password-link:" + account, None, db=db)
            # Disconnect also removes the cached source password and session.
            store.put("credential:" + account, None, db=db)
            store.put("connection:" + account, None, db=db)
    store.audit("owner", account, "", "password_sync_disconnected")
    return {"status": "DISCONNECTED", "account": account}
