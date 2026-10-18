"""Owner-reviewed mailbox binding for the closed PyPI device-confirmation flow.

Only already checked TLS IMAP profiles are selectable.  Connecting a mailbox is
not a grant: this repair carries forward only identical, still active reads that
were present when the owner opened the review.  No mail is read by setup.
"""

import hashlib
import json
import math
import re
import secrets
import sqlite3
import time
from contextlib import ExitStack, contextmanager

from .catalog import pypi
from .errors import AccessError
from .factors import replace_source
from .mailboxes import IDENT as MAILBOX_IDENT
from .mailboxes import PREFIX as MAILBOX_PREFIX
from .models import BrowserAccount, CodeSource, Configuration
from .pypi_device import PURPOSE, SENDER, SUBJECT
from .storage import private_file

PREFIX = "device-email-preview:"
BINDING = "device-email-binding:"
TTL = 600
LIMIT = 8
IDENT = re.compile(r"[a-f0-9]{32}")
HANDLE = re.compile(r"[a-z][a-z0-9_-]{0,63}")
FINGERPRINT = re.compile(r"[a-f0-9]{64}")


def fail(reason, status="DENIED"):
    raise AccessError(status, reason, "email")


def eligible(config, account):
    spec = config.accounts.get(account)
    if not isinstance(spec, BrowserAccount) or not spec.login:
        return False
    core = spec.model_copy(deep=True)
    core.login.device_email_source = None
    return core == pypi()


def _request(account, fingerprint):
    if (not isinstance(account, str) or not HANDLE.fullmatch(account)
            or not isinstance(fingerprint, str) or not FINGERPRINT.fullmatch(fingerprint)):
        fail("invalid_device_email_setup")


def _account(config, account, fingerprint):
    _request(account, fingerprint)
    if not eligible(config, account) or config.fingerprint(account) != fingerprint:
        fail("device_email_setup_changed")
    return config.accounts[account]


def _get(store, db, key):
    row = db.execute("SELECT value FROM records WHERE id=?", (key,)).fetchone()
    return store.unseal(key, row[0]) if row else None


@contextmanager
def _database(store):
    # These are owner RPCs, not the background service's long retry loop.
    # SQLite's busy timeout accumulates sleeps; it is not a wall-clock bound.
    # Use immediate acquisition attempts with our own monotonic deadline.
    deadline = time.monotonic() + 2
    try:
        with store.db() as db:
            db.execute("PRAGMA busy_timeout=0")
            while True:
                if time.monotonic() >= deadline:
                    fail("account_busy", "RETRYABLE")
                try:
                    db.execute("BEGIN IMMEDIATE")
                except sqlite3.OperationalError as error:
                    if getattr(error, "sqlite_errorcode", 0) & 255 not in {sqlite3.SQLITE_BUSY, sqlite3.SQLITE_LOCKED}:
                        raise
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        fail("account_busy", "RETRYABLE")
                    time.sleep(min(0.02, remaining))
                else:
                    if time.monotonic() >= deadline:
                        fail("account_busy", "RETRYABLE")
                    break
            yield db
    except sqlite3.Error as error:
        if getattr(error, "sqlite_errorcode", 0) & 255 in {sqlite3.SQLITE_BUSY, sqlite3.SQLITE_LOCKED}:
            fail("account_busy", "RETRYABLE")
        fail("device_email_setup_incomplete", "NEEDS_USER")


def _profile(store, ident, *, db=None):
    if not isinstance(ident, str) or not MAILBOX_IDENT.fullmatch(ident):
        fail("invalid_device_email_setup")
    profile = _get(store, db, MAILBOX_PREFIX + ident) if db else store.get(MAILBOX_PREFIX + ident)
    if (not isinstance(profile, dict) or not isinstance(profile.get("generation"), str)
            or not IDENT.fullmatch(profile["generation"])
            or not isinstance(profile.get("connection_check"), dict)
            or profile["connection_check"].get("status") != "VERIFIED"
            or not isinstance(profile.get("label"), str) or not 1 <= len(profile["label"]) <= 100
            or not isinstance(profile.get("username"), str)
            or not re.fullmatch(r"[^\s@<>]+@[^\s@<>]+", profile["username"])
            or len(profile["username"]) > 200
            or not isinstance(profile.get("password"), str) or not 1 <= len(profile["password"]) <= 4096
            or not isinstance(profile.get("host"), str)
            or not re.fullmatch(r"[a-zA-Z0-9.-]{1,253}", profile["host"])
            or type(profile.get("port")) is not int or not 1 <= profile["port"] <= 65535):
        fail("device_email_mailbox_unavailable", "NEEDS_USER")
    checked = profile["connection_check"].get("checked")
    if (type(checked) not in {int, float} or not math.isfinite(checked)
            or not 0 < checked <= time.time() + 60):
        fail("device_email_mailbox_unavailable", "NEEDS_USER")
    return profile


def _authority(profile):
    # The digest is encrypted with the review. It is never sent to the owner UI.
    values = {key: profile[key] for key in ["generation", "host", "port", "username", "password"]}
    return hashlib.sha256(json.dumps(values, sort_keys=True).encode()).hexdigest()


def _definition(profile):
    return CodeSource(kind="imap", host=profile["host"], port=profile["port"],
                      recipient=profile["username"], sender=SENDER, subject=SUBJECT,
                      message_purpose=PURPOSE)


def _mailboxes(store):
    with store.db() as db:
        ids = [row[0][len(MAILBOX_PREFIX):] for row in db.execute(
            "SELECT id FROM records WHERE id LIKE 'mailbox-profile:%' ORDER BY id LIMIT 17")]
    candidates = []
    for ident in ids[:16]:
        try:
            profile = _profile(store, ident)
        except AccessError as error:
            if error.reason in {"invalid_device_email_setup", "device_email_mailbox_unavailable"}:
                continue
            raise
        candidates.append({"id": ident, "label": profile["label"],
                           "recipient": profile["username"], "kind": "imap"})
    return candidates


def _connected(store, config, account):
    source_id = config.accounts[account].login.device_email_source
    if not source_id:
        return False
    source = config.code_sources.get(source_id)
    record = store.get("source:" + source_id)
    if (not source or source.message_purpose != PURPOSE or source.kind != "imap"
            or not isinstance(record, dict) or record.get("enabled") is not True):
        return False
    try:
        profile = _profile(store, record.get("mailbox"))
    except AccessError:
        return False
    return source == _definition(profile)


def view(store):
    config = store.config()
    candidates = _mailboxes(store)
    return [{"account": account, "label": spec.label,
             "fingerprint": config.fingerprint(account),
             "configured": bool(spec.login.device_email_source),
             "connected": _connected(store, config, account), "mailboxes": candidates}
            for account, spec in config.accounts.items() if eligible(config, account)]


def _grants(db, config, account, now, *, fingerprint=None):
    fingerprint = fingerprint or config.fingerprint(account)
    return [dict(row) for row in db.execute(
        "SELECT g.* FROM grants g WHERE g.account=? AND g.fingerprint=? "
        "AND (g.expires IS NULL OR g.expires>?) "
        "AND EXISTS (SELECT 1 FROM clients c WHERE c.principal=g.principal AND c.revoked=0)",
        (account, fingerprint, now)) if row["operation"] in config.accounts[account].operations]


def preview(store, account, fingerprint, mailbox):
    _request(account, fingerprint)
    with store.lock("device-email-previews", timeout=2), store.lock("account:" + account, timeout=2), \
            store.lock("catalog", timeout=2), store.lock("mailbox-profiles", timeout=2):
        config = store.config()
        spec = _account(config, account, fingerprint)
        profile = _profile(store, mailbox)
        # Validate the fixed source using the same URL policy as publication.
        proposed = config.model_copy(deep=True)
        source = "pypi-device-" + secrets.token_hex(12)
        proposed.code_sources[source] = _definition(profile)
        proposed.accounts[account].login.device_email_source = source
        Configuration.model_validate(proposed.model_dump())
        now = time.time()
        ident = secrets.token_hex(16)
        with _database(store) as db:
            entries = db.execute("SELECT id,value FROM records WHERE id LIKE 'device-email-preview:%'").fetchall()
            active = 0
            for row in entries:
                item = store.unseal(row["id"], row["value"])
                if isinstance(item, dict) and item.get("expires", 0) > now:
                    active += 1
                else:
                    db.execute("DELETE FROM records WHERE id=?", (row["id"],))
            if active >= LIMIT:
                fail("device_email_setup_limit", "RETRYABLE")
            grants = _grants(db, config, account, now)
            store.put(PREFIX + ident, {"account": account, "fingerprint": fingerprint,
                "mailbox": mailbox, "mailbox_generation": profile["generation"],
                "mailbox_authority": _authority(profile), "source": source,
                "grants": grants, "expires": now + TTL}, db=db)
        operations = sorted({grant["operation"] for grant in grants})
        return {"id": ident, "expires": now + TTL, "account": account, "label": spec.label,
                "recipient": profile["username"], "mailbox_label": profile["label"],
                "operations": [{"name": name, "description": spec.operations[name].description}
                               for name in operations]}


def _take(store, ident):
    if not isinstance(ident, str) or not IDENT.fullmatch(ident):
        fail("invalid_device_email_setup")
    with store.lock("device-email-previews", timeout=2), _database(store) as db:
        value = _get(store, db, PREFIX + ident)
        db.execute("DELETE FROM records WHERE id=?", (PREFIX + ident,))
    if not isinstance(value, dict) or value.get("expires", 0) <= time.time():
        fail("device_email_setup_expired")
    return value


def discard(store, ident):
    _take(store, ident)
    return {"status": "DISCARDED"}


def _write_config(store, config):
    # Caller holds configuration; Store.configure would acquire a second lock.
    private_file(store.root / "config.json", config.model_dump_json(indent=2).encode(), replace=True)


def _link_valid(store, account, saved, db):
    if saved.get("status") != "SYNCED" or not IDENT.fullmatch(str(saved.get("generation", ""))):
        return False
    credential = _get(store, db, "credential:" + account) or {}
    if saved.get("username") != credential.get("username"):
        return False
    from .password_sync import SERVICE_ACCOUNT, validate_link
    keys = (["provider", "token", "vault", "item"] if saved.get("provider") == SERVICE_ACCOUNT
            else ["endpoint", "token", "vault", "item"])
    try:
        validate_link(store, account, {key: saved[key] for key in keys})
    except (AccessError, KeyError, TypeError):
        return False
    return True


def _quarantine(store, config, account, reviewed_grants, token):
    """Durably deny old fingerprints before a cross-file configuration change.

    A crash followed by removal can return a connector to an earlier fingerprint.
    No stale grant, saved browser session or password-source binding may become
    valid again merely because that value cycles. Revocation can delete rows
    between these transactions; final publication never inserts them again.
    """
    authorities = {}
    with _database(store) as db:
        approved = [row for row in _grants(db, config, account, time.time()) if row in reviewed_grants]
        db.execute("DELETE FROM grants WHERE account=?", (account,))
        for row in approved:
            db.execute("INSERT INTO grants VALUES (?,?,?,?,?)",
                       (row["principal"], account, row["operation"], token, row["expires"]))
        for prefix in ["connection:", "password-link:"]:
            saved = _get(store, db, prefix + account)
            if not isinstance(saved, dict) or not isinstance(saved.get("fingerprint"), str):
                continue
            valid = (saved["fingerprint"] == config.fingerprint(account)
                     and not saved.get("revoked") and not saved.get("invalid")
                     and (isinstance(saved.get("state"), dict) if prefix == "connection:"
                          else _link_valid(store, account, saved, db)))
            value = {**saved, "fingerprint": token}
            store.put(prefix + account, value, db=db)
            authorities[prefix] = {"previous": saved, "quarantined": value, "valid": valid}
    return authorities


def _restore(store, previous, account, token, authorities):
    if store.config() != previous:
        return
    with _database(store) as db:
        for grant in _grants(db, previous, account, time.time(), fingerprint=token):
            db.execute("UPDATE grants SET fingerprint=? WHERE principal=? AND account=? AND operation=? "
                       "AND fingerprint=? AND expires IS ?",
                       (previous.fingerprint(account), grant["principal"], account, grant["operation"],
                        token, grant["expires"]))
        for prefix, saved in authorities.items():
            if saved["valid"] and _get(store, db, prefix + account) == saved["quarantined"]:
                store.put(prefix + account, saved["previous"], db=db)


def _publish(store, previous, updated, account, reviewed_grants, *, source=None, mailbox=None,
             old_source=None):
    """Quarantine, then config first: lost publication cannot restore authority.

    A normal failure restores only our exact published configuration while still
    holding its lock. A crash leaves quarantined authority requiring a fresh
    permission/session review. No independent challenge is resolved.
    """
    new_fingerprint = updated.fingerprint(account)
    token = "device-email-quarantine:" + secrets.token_hex(16)
    authorities = {}
    try:
        authorities = _quarantine(store, previous, account, reviewed_grants, token)
        with _database(store) as db:
            _write_config(store, updated)
            if source:
                replace_source(store, source, {"mailbox": mailbox, "enabled": True}, db=db)
                store.put(BINDING + account, {"source": source}, db=db)
            else:
                store.put(BINDING + account, None, db=db)
            if old_source:
                replace_source(store, old_source, {"enabled": False}, db=db)
            for grant in _grants(db, previous, account, time.time(), fingerprint=token):
                db.execute("UPDATE grants SET fingerprint=? WHERE principal=? AND account=? AND operation=? "
                           "AND fingerprint=? AND expires IS ?",
                           (new_fingerprint, grant["principal"], account, grant["operation"],
                            token, grant["expires"]))
            for prefix, saved in authorities.items():
                if saved["valid"] and _get(store, db, prefix + account) == saved["quarantined"]:
                    store.put(prefix + account, {**saved["previous"], "fingerprint": new_fingerprint}, db=db)
            db.execute("INSERT INTO audit(at,principal,account,operation,event,reason) VALUES (?,?,?,?,?,?)",
                       (time.time(), "owner", account, "", "device_email_enrolled" if source else "device_email_removed", ""))
    except Exception:
        try:
            if store.config() == updated:
                _write_config(store, previous)
            _restore(store, previous, account, token, authorities)
        except Exception:
            pass  # A partial publication remains conservative, never auto-approved.
        fail("device_email_setup_incomplete", "NEEDS_USER")


def _retired(store, config, account):
    current = config.accounts[account].login.device_email_source
    owned = store.get(BINDING + account) or {}
    if (not current or owned.get("source") != current
            or any(name != account and isinstance(spec, BrowserAccount) and spec.login
                   and current in spec.login.sources() for name, spec in config.accounts.items())):
        return None
    return current


def apply(store, ident):
    review = _take(store, ident)
    account, source = review["account"], review["source"]
    with ExitStack() as held:
        for key in ["account:" + account, "catalog", "mailbox-profiles"]:
            held.enter_context(store.lock(key, timeout=2))
        current = store.config()
        _account(current, account, review["fingerprint"])
        retired = _retired(store, current, account)
        for item in sorted({source, retired} - {None}):
            held.enter_context(store.lock("source:" + item, timeout=2))
            held.enter_context(store.lock("code-window:" + item, timeout=2))
        held.enter_context(store.lock("configuration", timeout=2))
        current = store.config()
        _account(current, account, review["fingerprint"])
        profile = _profile(store, review["mailbox"])
        if (profile["generation"] != review["mailbox_generation"]
                or _authority(profile) != review["mailbox_authority"]):
            fail("device_email_mailbox_changed")
        if review["expires"] <= time.time():
            fail("device_email_setup_expired")
        if source in current.code_sources or store.get("source:" + source) is not None:
            fail("device_email_setup_changed")
        updated = current.model_copy(deep=True)
        updated.code_sources[source] = _definition(profile)
        updated.accounts[account].login.device_email_source = source
        if retired:
            updated.code_sources.pop(retired, None)
        updated = Configuration.model_validate(updated.model_dump())
        _publish(store, current, updated, account, review["grants"], source=source,
                 mailbox=review["mailbox"], old_source=retired)
    return {"status": "ENROLLED", "account": account, "source": source}


def remove(store, account, fingerprint):
    _request(account, fingerprint)
    with ExitStack() as held:
        for key in ["account:" + account, "catalog", "mailbox-profiles"]:
            held.enter_context(store.lock(key, timeout=2))
        current = store.config()
        spec = _account(current, account, fingerprint)
        source = spec.login.device_email_source
        if not source:
            fail("device_email_setup_changed")
        retired = _retired(store, current, account)
        if retired:
            held.enter_context(store.lock("source:" + retired, timeout=2))
            held.enter_context(store.lock("code-window:" + retired, timeout=2))
        held.enter_context(store.lock("configuration", timeout=2))
        current = store.config()
        _account(current, account, fingerprint)
        updated = current.model_copy(deep=True)
        updated.accounts[account].login.device_email_source = None
        if retired:
            updated.code_sources.pop(retired, None)
        updated = Configuration.model_validate(updated.model_dump())
        with store.db() as db:
            grants = _grants(db, current, account, time.time())
        _publish(store, current, updated, account, grants, old_source=retired)
    return {"status": "REMOVED", "account": account, "source": source}
