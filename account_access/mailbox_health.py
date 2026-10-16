"""Owner-only mailbox checks without fetching messages or starting a website login."""

import hashlib
import imaplib
import json
import time

from .codes import imap_number
from .errors import AccessError
from .providers import get_json

GMAIL_PROFILE = "https://gmail.googleapis.com/gmail/v1/users/me/profile"


def binding(store, source_id):
    source = store.config().code_sources.get(source_id)
    if source is None or source.kind not in {"imap", "gmail"}:
        raise AccessError("DENIED", "mailbox_check_unsupported", "email")
    credential = store.get("source:" + source_id) or {}
    value = {"source": source.model_dump(), "credential": credential}
    digest = hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest()
    return source, credential, digest


def view(store, source_id):
    source = store.config().code_sources[source_id]
    if source.kind not in {"imap", "gmail"}:
        return None
    _, credential, digest = binding(store, source_id)
    saved = store.get("mailbox-health:" + source_id) or {}
    if credential.get("enabled") is False or saved.get("binding") != digest:
        return {"status": "UNTESTED"}
    return {key: saved[key] for key in ["status", "checked", "reason"] if key in saved}


def check(broker, source_id):
    if not isinstance(source_id, str) or source_id not in broker.store.config().code_sources:
        raise AccessError("DENIED", "unknown_code_source", "email")
    store = broker.store
    with store.lock("source:" + source_id):
        source, credential, digest = binding(store, source_id)
        try:
            if not credential or credential.get("enabled") is False:
                raise AccessError("NEEDS_USER", "mailbox_not_connected", "email")
            if source.kind == "imap":
                with broker.codes.mailbox(source, credential, store.config()) as mailbox:
                    for name in ["UIDVALIDITY", "UIDNEXT"]:
                        imap_number(mailbox.response(name)[1])
            else:
                with store.lock("account:" + source.account):
                    headers = broker.codes.gmail_headers(source, store.config())
                    try:
                        profile = get_json(GMAIL_PROFILE, headers=headers)
                    except AccessError as exc:
                        if exc.reason != "provider_rejected_access":
                            raise
                        headers = broker.codes.gmail_headers(source, store.config(), force=True)
                        profile = get_json(GMAIL_PROFILE, headers=headers)
                if (not isinstance(profile, dict) or not isinstance(profile.get("emailAddress"), str)):
                    raise AccessError("RETRYABLE", "invalid_mailbox_response", "email")
                if profile["emailAddress"].lower() != source.recipient.lower():
                    raise AccessError("NEEDS_USER", "mailbox_identity_mismatch", "email")
            if binding(store, source_id)[2] != digest:
                raise AccessError("DENIED", "verification_source_enrollment_changed", "email")
        except (imaplib.IMAP4.error, OSError):
            error = AccessError("NEEDS_USER", "mailbox_connection_failed", "email")
        except AccessError as exc:
            error = AccessError(exc.status, exc.reason, "email")
        else:
            store.put("mailbox-health:" + source_id, {"binding": digest, "status": "VERIFIED", "checked": time.time()})
            store.audit("owner", "", "", "mailbox_connection_checked", source.kind)
            return {"status": "VERIFIED", "source": source_id, "login_delivery_verified": False}
        store.put("mailbox-health:" + source_id, {"binding": digest, "status": error.status,
                                                "checked": time.time(), "reason": error.reason})
        raise error
