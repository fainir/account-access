"""Owner-enrolled exact password-manager items; no agent secret API.

Only the password of an exact approved item can change automatically. Account
identity, website, connector, grants and authenticator enrollment cannot change.
"""

from contextlib import nullcontext
import re
import secrets
import time
from urllib.parse import urlsplit

from .errors import AccessError
from .models import BrowserAccount, origin, validate_url
from .providers import get_json

INTERVAL = 300
IDENTIFIER = re.compile(r"^[a-z0-9]{26}$")
GENERATION = re.compile(r"^[a-f0-9]{32}$")
SERVICE_ACCOUNT = "onepassword-service-account"
BITWARDEN = "bitwarden"
SOURCE_PREREQUISITES = (
    "password_source_access_removed", "password_source_item_changed",
    "password_sync_identity_mismatch", "password_sync_connector_changed",
    "password_source_runtime_unavailable",
    "bitwarden_connection_changed",
)


def _resolve_source_prerequisites(db, account, now):
    # Source validation repairs only this prerequisite. It does not prove a
    # successful website login or satisfy an independent owner/presence gate.
    placeholders = ",".join("?" for _ in SOURCE_PREREQUISITES)
    db.execute(f"""UPDATE challenges SET resolved=? WHERE account=? AND resolved IS NULL
                  AND kind='login' AND reason IN ({placeholders})""",
               (now, account, *SOURCE_PREREQUISITES))


def validate_link(store, account, data):
    spec = store.config().accounts.get(account)
    if not isinstance(spec, BrowserAccount) or not spec.login or spec.login.identity_contact:
        raise AccessError("DENIED", "password_sync_account_unsupported")
    if not isinstance(data, dict):
        raise AccessError("DENIED", "invalid_password_sync_link")
    if data.get("provider") == BITWARDEN:
        from . import bitwarden_source
        if (set(data) != {"provider", "connection", "connection_generation", "item"}
                or any(not isinstance(value, str) for value in data.values())
                or not GENERATION.fullmatch(data["connection"])
                or not GENERATION.fullmatch(data["connection_generation"])
                or not bitwarden_source.UUID.fullmatch(data["item"])):
            raise AccessError("DENIED", "invalid_password_sync_link")
        bitwarden_source.check(store, data)
        return dict(data)
    service_account = data.get("provider") == SERVICE_ACCOUNT
    keys = {"provider", "token", "vault", "item"} if service_account else {
        "endpoint", "token", "vault", "item"}
    if set(data) != keys:
        raise AccessError("DENIED", "invalid_password_sync_link")
    if (any(not isinstance(x, str) for x in data.values())
            or not 1 <= len(data["token"]) <= 8192
            or any(c in data["token"] for c in "\r\n")
            or any(not IDENTIFIER.fullmatch(data[x]) for x in ["vault", "item"])):
        raise AccessError("DENIED", "invalid_password_sync_link")
    if service_account:
        return dict(data)
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
    if link.get("provider") == SERVICE_ACCOUNT:
        from .onepassword_source import fetch as service_fetch
        return service_fetch(link, expected_origin)
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


def _fetch(store, link, expected_origin):
    if link.get("provider") == BITWARDEN:
        from .bitwarden_source import fetch as bitwarden_fetch
        return bitwarden_fetch(store, link, expected_origin)
    return fetch(link, expected_origin)


def _authority(store, link):
    if link.get("provider") == BITWARDEN:
        from .bitwarden_source import authority
        return authority(store, link)
    return nullcontext()


def _bitwarden_failure(store, account, snapshot, error, now):
    """CAS failures too: source revocation deliberately skips account locks."""
    from .bitwarden_source import PREFIX, _database
    with _database(store) as db:
        db.execute("BEGIN IMMEDIATE")
        row = db.execute("SELECT value FROM records WHERE id=?", ("password-link:" + account,)).fetchone()
        current = store.unseal("password-link:" + account, row[0]) if row else None
        authority = ["generation", "provider", "connection", "connection_generation", "item", "username", "fingerprint"]
        if not isinstance(current, dict) or any(current.get(key) != snapshot.get(key) for key in authority):
            return False  # A newer explicit repair/import must remain intact.
        row = db.execute("SELECT value FROM records WHERE id=?", (PREFIX + snapshot["connection"],)).fetchone()
        source = store.unseal(PREFIX + snapshot["connection"], row[0]) if row else None
        if (current != snapshot or not isinstance(source, dict)
                or source.get("generation") != snapshot["connection_generation"]
                or source.get("status") not in {"CONNECTED", "RETRYABLE"}):
            return True  # The source transaction already published its state.
        failed = dict(snapshot)
        failed.update(status="RETRYABLE" if error.status == "RETRYABLE" else "BLOCKED",
                      reason=error.reason, next_at=now + (60 if error.status == "RETRYABLE" else INTERVAL))
        store.put("password-link:" + account, failed, db=db)
        store.put("credential:" + account, None, db=db)
        store.put("connection:" + account, None, db=db)
    return True


def _enroll_locked(store, account, data, *, previous=None):
    link = validate_link(store, account, data)
    config = store.config()
    if previous is not None and (account not in config.accounts
                                 or config.fingerprint(account) != previous["fingerprint"]):
        raise AccessError("DENIED", "password_sync_connector_changed")
    credential = _fetch(store, link, origin(config.accounts[account].login_url))
    saved = store.get("credential:" + account) or {}
    approved_username = saved.get("username")
    repair = None
    if not approved_username and link.get("provider") == BITWARDEN:
        # Explicit owner relinking after source revocation can use the old
        # approved identity, without keeping its revoked password around.
        repair = store.get("password-link:" + account)
        if (isinstance(repair, dict) and repair.get("provider") == BITWARDEN
                and repair.get("fingerprint") == config.fingerprint(account)
                and isinstance(repair.get("username"), str)):
            approved_username = repair["username"]
    if not approved_username or approved_username != credential["username"]:
        raise AccessError("DENIED", "password_sync_identity_mismatch")
    # No permissions are created here. Linking follows an approved import.
    # Bind the last authority check and commit to the configuration lock too;
    # a connector edit must not slip between them after the source read.
    with _authority(store, link), store.lock("configuration"):
        current_config = store.config()
        if (account not in current_config.accounts
                or config.fingerprint(account) != current_config.fingerprint(account)
                or (previous is not None
                    and current_config.fingerprint(account) != previous["fingerprint"])):
            raise AccessError("DENIED", "password_sync_connector_changed")
        if previous is not None:
            # Retain the exact enrollment after the network wait. A delayed
            # token response cannot replace a newer source or approved identity.
            current = store.get("password-link:" + account)
            if not current or current.get("generation") != previous["generation"]:
                raise AccessError("DENIED", "password_sync_connection_changed")
            if saved["username"] != previous["username"]:
                raise AccessError("DENIED", "password_sync_identity_mismatch")
        if repair is not None:
            current = store.get("password-link:" + account)
            if not current or current.get("generation") != repair.get("generation"):
                raise AccessError("DENIED", "password_sync_connection_changed")
        now = time.time()
        link.update(username=approved_username, fingerprint=config.fingerprint(account),
                    generation=secrets.token_hex(16), status="SYNCED", checked=now,
                    next_at=now + INTERVAL)
        with store.db() as db:
            store.put("password-link:" + account, link, db=db)
            _resolve_source_prerequisites(db, account, now)
            if credential != saved:
                store.put("credential:" + account, credential, db=db)
                store.put("connection:" + account, None, db=db)


def enroll(store, account, data):
    with store.lock("account:" + account):
        # Serialize enrollment with credential edits, imports and disconnection.
        _enroll_locked(store, account, data)
    store.audit("owner", account, "", "password_sync_connected")
    return {"status": "SYNCED", "account": account}


def reconnect(store, account, data):
    if (not isinstance(data, dict) or set(data) != {"token", "generation"}
            or not isinstance(data["generation"], str)
            or not GENERATION.fullmatch(data["generation"])):
        raise AccessError("DENIED", "invalid_password_sync_link")
    with store.lock("account:" + account):
        previous = store.get("password-link:" + account)
        if not previous:
            raise AccessError("DENIED", "password_sync_not_connected")
        if previous.get("provider") == BITWARDEN:
            # Re-enroll a fresh explicit source connection; no generic token
            # field may be used to replace a vault unlock session.
            raise AccessError("DENIED", "invalid_password_sync_link")
        if previous.get("generation") != data["generation"]:
            raise AccessError("DENIED", "password_sync_connection_changed")
        config = store.config()
        if (account not in config.accounts
                or config.fingerprint(account) != previous["fingerprint"]):
            raise AccessError("DENIED", "password_sync_connector_changed")
        saved = store.get("credential:" + account) or {}
        if saved.get("username") != previous["username"]:
            raise AccessError("DENIED", "password_sync_identity_mismatch")
        keys = (["provider", "vault", "item"] if previous.get("provider") == SERVICE_ACCOUNT
                else ["endpoint", "vault", "item"])
        connection = {key: previous[key] for key in keys}
        connection["token"] = data["token"]
        _enroll_locked(store, account, connection, previous=previous)
    store.audit("owner", account, "", "password_sync_reconnected")
    return {"status": "SYNCED", "account": account}


def refresh(store, account, *, force=False):
    # Caller holds the account lock. Owner unlink/relink uses the same lock.
    link = store.get("password-link:" + account)
    if not link:
        return
    snapshot = dict(link)
    now = time.time()
    if not force and link["next_at"] > now:
        if link.get("provider") == BITWARDEN:
            from .bitwarden_source import check
            check(store, link)
        if link["status"] == "BLOCKED":
            raise AccessError("NEEDS_USER", link["reason"])
        return
    try:
        config = store.config()
        if config.fingerprint(account) != link["fingerprint"]:
            raise AccessError("DENIED", "password_sync_connector_changed")
        credential = _fetch(store, link, origin(config.accounts[account].login_url))
        if credential["username"] != link["username"]:
            raise AccessError("DENIED", "password_sync_identity_mismatch")
    except AccessError as exc:
        if link.get("provider") == BITWARDEN:
            if not _bitwarden_failure(store, account, snapshot, exc, now):
                raise AccessError("RETRYABLE", "password_source_unavailable") from None
        else:
            link.update(status="RETRYABLE" if exc.status == "RETRYABLE" else "BLOCKED",
                        reason=exc.reason, next_at=now + (60 if exc.status == "RETRYABLE" else INTERVAL))
            store.put("password-link:" + account, link)
        raise AccessError("RETRYABLE" if exc.status == "RETRYABLE" else "NEEDS_USER", exc.reason) from None
    changed = credential != store.get("credential:" + account)
    link.update(status="SYNCED", checked=now, next_at=now + INTERVAL)
    link.pop("reason", None)
    try:
        with _authority(store, link), store.lock("configuration"):
            if store.config().fingerprint(account) != link["fingerprint"]:
                raise AccessError("DENIED", "password_sync_connector_changed")
            with store.db() as db:
                store.put("password-link:" + account, link, db=db)
                _resolve_source_prerequisites(db, account, now)
                if changed:
                    store.put("credential:" + account, credential, db=db)
                    store.put("connection:" + account, None, db=db)
                    # A source password update is not a successful sign-in.
                    db.execute("UPDATE challenges SET resolved=? WHERE account=? AND resolved IS NULL AND kind='login' AND reason IN ('password_not_connected','browser_login_required')",
                               (now, account))
    except AccessError as exc:
        if link.get("provider") == BITWARDEN:
            if not _bitwarden_failure(store, account, snapshot, exc, now):
                raise AccessError("RETRYABLE", "password_source_unavailable") from None
        raise
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
            if not isinstance(link.get("generation"), str) or not GENERATION.fullmatch(link["generation"]):
                # Upgrade existing encrypted links once without changing their
                # token, target, credential, grants or polling state. Never
                # block owner-state reads behind a busy website operation.
                try:
                    with store.lock("account:" + account, timeout=0):
                        link = store.get("password-link:" + account)
                        if not link:
                            continue
                        if (not isinstance(link.get("generation"), str)
                                or not GENERATION.fullmatch(link["generation"])):
                            link["generation"] = secrets.token_hex(16)
                            store.put("password-link:" + account, link)
                except AccessError as exc:
                    if exc.reason != "account_busy":
                        raise
            provider = ("Bitwarden" if link.get("provider") == BITWARDEN else
                        "1Password service account" if link.get("provider") == SERVICE_ACCOUNT
                        else "1Password Connect")
            result.append({"account": account, "provider": provider,
                           "status": link["status"], "checked": link["checked"],
                           "reason": link.get("reason"), "interval": INTERVAL,
                           "generation": link.get("generation")})
            if link.get("provider") == BITWARDEN:
                result[-1].update(connection=link["connection"],
                                  connection_generation=link["connection_generation"], item=link["item"])
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
