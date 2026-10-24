"""Owner-selected checked Gmail identity for an existing login-code filter.

Binding never changes a connector, message filter or operation grant. A review
is scoped to the current source, referencing accounts, source enrollment and
Google authorization; renewable access-token bytes are deliberately excluded.
"""

import hashlib
import json
import re
import secrets
import sqlite3

from .errors import AccessError
from .factors import replace_source, source_mutation
from .models import BrowserAccount
from . import mailbox_oauth

FINGERPRINT = re.compile(r"[a-f0-9]{64}")


def fail(reason, status="DENIED"):
    raise AccessError(status, reason, "email")


def _digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _record(store, key, db=None):
    if db is None:
        return store.get(key)
    row = db.execute("SELECT value FROM records WHERE id=?", (key,)).fetchone()
    return store.unseal(key, row[0]) if row else None


def _source(config, source_id):
    if not isinstance(source_id, str):
        return None
    source = config.code_sources.get(source_id)
    if (source is None or source.kind != "gmail" or source.message_purpose is not None
            or not mailbox_oauth.supported(config, source.account)):
        return None
    return source


def _context(config, source_id):
    source = _source(config, source_id)
    if source is None:
        return None
    accounts = {key: config.fingerprint(key) for key, spec in config.accounts.items()
                if isinstance(spec, BrowserAccount) and spec.login
                and source_id in spec.login.sources()}
    return _digest({"source_id": source_id, "source": source.model_dump(),
                    "accounts": accounts, "mailbox_account": config.fingerprint(source.account)})


def metadata(store, source_id, *, config=None, db=None):
    """Nonsecret picker context; this performs no provider or message request."""
    config = config or store.config()
    source = _source(config, source_id)
    if source is None:
        return {}
    if db is None:
        # One consistent read transaction covers the enrollment, generation,
        # checked profile and Google authorization. Reopening the database for
        # each field both costs I/O and risks combining different revisions.
        with store.db() as snapshot:
            snapshot.execute("BEGIN")
            result = metadata(store, source_id, config=config, db=snapshot)
        return result if _context(store.config(), source_id) == result["setup_context"] else {}
    context = _context(config, source_id)
    credential = _record(store, "source:" + source_id, db)
    connection = _record(store, "connection:" + source.account, db)
    malformed_connection = connection is not None and not isinstance(connection, dict)
    connection = connection if isinstance(connection, dict) else {}
    authorization = {"fingerprint": connection.get("fingerprint"),
                     "authorization": connection.get("authorization_id") or connection.get("generation"),
                     "connected": bool(connection), "malformed": malformed_connection,
                     "issue": mailbox_oauth.connection_issue(connection)}
    ident = mailbox_oauth.profile_id(source.account)
    try:
        saved = mailbox_oauth.profile(store, ident, config=config, db=db)
    except AccessError:
        # Match reusable(): unusable or revoked checked identities are never
        # picker candidates. Linking still returns the precise profile error.
        saved = None
    matches = saved is not None and saved["username"].lower() == source.recipient.lower()
    options = [{"id": ident, "label": saved["label"], "recipient": saved["username"], "kind": "gmail"}] if matches else []
    profile_revision = ({key: saved[key] for key in ["generation", "authorization_id", "fingerprint", "username"]}
                        if saved is not None else None)
    revision = _digest({"context": context, "credential": credential,
                        "generation": _record(store, "source-generation:" + source_id, db),
                        "authorization": authorization, "profile": profile_revision})
    return {"setup_context": context, "setup_revision": revision, "mailbox_options": options,
            "linked_mailbox": credential.get("gmail_mailbox") if isinstance(credential, dict) else None}


def link(store, source_id, data):
    if (type(data) is not dict or set(data) != {"mailbox", "setup_context", "setup_revision"}
            or not isinstance(data["mailbox"], str)
            or not mailbox_oauth.PROFILE_IDENT.fullmatch(data["mailbox"])
            or any(not isinstance(data[key], str) or not FINGERPRINT.fullmatch(data[key])
                   for key in ["setup_context", "setup_revision"])):
        fail("invalid_mailbox_binding")
    source = _source(store.config(), source_id)
    if source is None:
        fail("mailbox_binding_unsupported")
    # Match the code-window publication order: source -> window -> OAuth
    # account. Google consent/check also owns mailbox-profiles before account.
    with store.lock("mailbox-profiles", timeout=2), source_mutation(store, source_id), \
            store.lock("account:" + source.account, timeout=2), store.lock("configuration", timeout=2):
        config = store.config()
        current = _source(config, source_id)
        if current is None or current.account != source.account:
            fail("mailbox_binding_changed")
        try:
            with store.db() as db:
                db.execute("PRAGMA busy_timeout=2000")
                db.execute("BEGIN IMMEDIATE")
                review = metadata(store, source_id, config=config, db=db)
                if any(not secrets.compare_digest(data[key], review[key])
                       for key in ["setup_context", "setup_revision"]):
                    fail("mailbox_binding_changed")
                saved = mailbox_oauth.profile(store, data["mailbox"], config=config, db=db)
                if (saved["account"] != current.account
                        or saved["username"].lower() != current.recipient.lower()):
                    fail("mailbox_source_mismatch")
                replace_source(store, source_id, {"enabled": True, "gmail_mailbox": data["mailbox"],
                    "gmail_generation": saved["generation"], "gmail_authorization": saved["authorization_id"]}, db=db)
        except sqlite3.OperationalError as error:
            if getattr(error, "sqlite_errorcode", 0) & 255 in {sqlite3.SQLITE_BUSY, sqlite3.SQLITE_LOCKED}:
                fail("account_busy", "RETRYABLE")
            raise
    store.audit("owner", "", "", "factor_enrolled", "gmail")
    return {"status": "ENROLLED", "source": source_id, "kind": "gmail"}
