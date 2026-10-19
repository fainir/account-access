"""Owner-managed reusable TLS IMAP connections; never exposed by the agent API."""

import hashlib
import imaplib
import json
import re
import secrets
import time

from .errors import AccessError
from .factors import replace_source, source_mutation
from .models import CodeSource, validate_url

PREFIX = "mailbox-profile:"
IDENT = re.compile(r"mailbox-[a-f0-9]{24}")


def get(store, ident):
    if not isinstance(ident, str) or not IDENT.fullmatch(ident):
        raise AccessError("DENIED", "unknown_mailbox", "email")
    profile = store.get(PREFIX + ident)
    if not profile:
        raise AccessError("NEEDS_USER", "mailbox_not_connected", "email")
    return profile


def view(store):
    with store.db() as db:
        ids = [row[0][len(PREFIX):] for row in db.execute("SELECT id FROM records WHERE id LIKE 'mailbox-profile:%'")]
    result = []
    for ident in ids:
        profile = store.get(PREFIX + ident)
        if profile:
            # Owner-page draft identity, not a credential or an authorization.
            # A check must not erase an edit, but credential replacement must.
            context = {key: profile.get(key) for key in
                       ["label", "host", "port", "username", "generation"]}
            revision = hashlib.sha256(json.dumps(
                {"id": ident, **context}, sort_keys=True, separators=(",", ":"),
            ).encode()).hexdigest()
            result.append({"id": ident, "label": profile["label"], "host": profile["host"],
                           "port": profile["port"], "username": profile["username"],
                           "setup_revision": revision,
                           "connection_check": profile.get("connection_check", {"status": "UNTESTED"})})
    return result


def enrollment(store, source_id):
    """Resolve a narrow source link, checking its exact mailbox identity/server.

    Returning effective credentials also binds active code windows and health
    checks to password changes and mailbox revocation. Gmail OAuth consent
    does not authorize a configured login-code filter until the owner enables
    that source. Legacy inline IMAP enrollment is unchanged.
    """
    credential = store.get("source:" + source_id) or {}
    if credential.get("enabled") is False:
        return credential
    source = store.config().code_sources[source_id]
    if source.kind == "gmail" and credential.get("enabled") is not True:
        raise AccessError("NEEDS_USER", "mailbox_not_connected", "email")
    if credential.get("gmail_mailbox"):
        from .mailbox_oauth import profile
        saved = profile(store, credential["gmail_mailbox"], allow_refresh=True)
        if (source.kind != "gmail" or source.account != saved["account"]
                or source.recipient.lower() != saved["username"].lower()):
            raise AccessError("NEEDS_USER", "mailbox_source_mismatch", "email")
        if (credential.get("gmail_generation") != saved["generation"]
                or credential.get("gmail_authorization") != saved["authorization_id"]):
            raise AccessError("NEEDS_USER", "mailbox_identity_check_required", "email")
        return {"enabled": True, "gmail_mailbox": credential["gmail_mailbox"],
                "username": saved["username"], "mailbox_generation": saved["generation"],
                "mailbox_authorization": saved["authorization_id"]}
    if not credential.get("mailbox"):
        return credential
    profile = get(store, credential["mailbox"])
    if (source.kind != "imap" or source.account or source.host.lower() != profile["host"]
            or source.port != profile["port"] or source.recipient.lower() != profile["username"].lower()):
        raise AccessError("NEEDS_USER", "mailbox_source_mismatch", "email")
    effective = {"enabled": True, "mailbox": credential["mailbox"], "username": profile["username"],
                 "password": profile["password"]}
    if "generation" in profile:
        effective["mailbox_generation"] = profile["generation"]
    return effective


def probe(broker, profile):
    """Check only authentication, read-only selection and UID tracking."""
    from .codes import imap_number, mailbox_error
    source = CodeSource(kind="imap", host=profile["host"], port=profile["port"],
                        sender="login@example.invalid", recipient=profile["username"],
                        subject="Connection check", template="Login: {code}")
    try:
        with broker.codes.mailbox(source, profile, broker.store.config()) as mailbox:
            for name in ["UIDVALIDITY", "UIDNEXT"]:
                imap_number(mailbox.response(name)[1])
    except (imaplib.IMAP4.error, OSError) as exc:
        error = mailbox_error(exc)
        return {"status": error.status, "reason": error.reason, "checked": time.time()}
    except AccessError as exc:
        return {"status": exc.status, "reason": exc.reason, "checked": time.time()}
    return {"status": "VERIFIED", "checked": time.time()}


def connect(broker, data):
    if (not isinstance(data, dict) or set(data) != {"label", "host", "port", "username", "password"}
            or any(not isinstance(data[name], str) or not data[name].strip()
                   for name in ["label", "host", "username", "password"])
            or len(data["label"]) > 100 or len(data["username"]) > 200 or len(data["password"]) > 4096
            or not re.fullmatch(r"[a-zA-Z0-9.-]{1,253}", data["host"])
            or not re.fullmatch(r"[^\s@<>]+@[^\s@<>]+", data["username"])
            or type(data["port"]) is not int or not 1 <= data["port"] <= 65535):
        raise AccessError("DENIED", "invalid_mailbox_setup", "email")
    try:
        if not (broker.store.config().test_mode and data["host"] == "127.0.0.1"):
            validate_url("https://" + data["host"])
    except ValueError:
        raise AccessError("DENIED", "invalid_mailbox_setup", "email") from None
    profile = {**data, "host": data["host"].lower(), "username": data["username"].strip(),
               "label": data["label"].strip()}
    store = broker.store
    with store.lock("mailbox-profiles"):
        existing = view(store)
        if len(existing) >= 16:
            raise AccessError("DENIED", "mailbox_connection_limit", "email")
        if any(item["host"] == profile["host"] and item["port"] == profile["port"]
               and item["username"].lower() == profile["username"].lower() for item in existing):
            raise AccessError("DENIED", "mailbox_already_connected", "email")
        ident = "mailbox-" + secrets.token_hex(12)
        profile["generation"] = secrets.token_hex(16)
        profile["connection_check"] = probe(broker, profile)
        store.put(PREFIX + ident, profile)
        store.audit("owner", "", "", "mailbox_saved")
    return {"status": "SAVED", "id": ident, "connection_check": profile["connection_check"],
            "login_delivery_verified": False}


def check(broker, ident):
    with broker.store.lock("mailbox-profiles"):
        profile = get(broker.store, ident)
        profile["connection_check"] = probe(broker, profile)
        broker.store.put(PREFIX + ident, profile)
    return {"status": profile["connection_check"]["status"],
            "connection_check": profile["connection_check"], "login_delivery_verified": False}


def update_password(broker, ident, password):
    if not isinstance(password, str) or not password.strip() or len(password) > 4096:
        raise AccessError("DENIED", "invalid_mailbox_setup", "email")
    with broker.store.lock("mailbox-profiles"):
        profile = get(broker.store, ident)
        profile["password"] = password
        profile["generation"] = secrets.token_hex(16)
        profile["connection_check"] = probe(broker, profile)
        broker.store.put(PREFIX + ident, profile)
    return {"status": "SAVED", "connection_check": profile["connection_check"], "login_delivery_verified": False}


def link(store, source_id, ident):
    # No website connector, recipient/filter or standing operation grant can
    # be created or widened by connecting a mailbox.
    with store.lock("mailbox-profiles"), source_mutation(store, source_id):
        source = store.config().code_sources.get(source_id)
        profile = get(store, ident)
        if (not source or source.kind != "imap" or source.account or source.host.lower() != profile["host"]
                or source.port != profile["port"] or source.recipient.lower() != profile["username"].lower()):
            raise AccessError("DENIED", "mailbox_source_mismatch", "email")
        with store.db() as db:
            replace_source(store, source_id, {"mailbox": ident, "enabled": True}, db=db)
    return {"status": "ENROLLED", "source": source_id, "kind": "imap"}


def remove(store, ident):
    with store.lock("mailbox-profiles"):
        get(store, ident)
        store.put(PREFIX + ident, None)
    # Existing source references remain visible for repair. Every new or
    # pending code read rechecks that the mailbox still exists.
    store.audit("owner", "", "", "mailbox_disconnected")
    return {"status": "DISCONNECTED"}
