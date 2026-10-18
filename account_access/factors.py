"""Enrollment belongs to the owner, never to the agent client."""

import re
import secrets
from contextlib import contextmanager
from urllib.parse import parse_qs, urlsplit

import pyotp

from .errors import AccessError


@contextmanager
def source_mutation(store, source_id):
    """Owner changes take the source lock before its delivery/window lock.

    Browser-account/catalog/mailbox-profile locks, when needed, precede these locks.
    Delivery takes only the window lock and never acquires a source lock, so
    revocation waits for a current delivery before invalidating its window.
    Keep network access outside this short mutation boundary.
    """
    with store.lock("source:" + source_id), store.lock("code-window:" + source_id):
        yield


def replace_source(store, source_id, value, *, db):
    """Write one authority revision while holding source_mutation and a DB transaction.

    A new generation is required even when credentials are unchanged: an old
    login must not survive disable/re-enable or a new phone pairing.
    """
    store.put("source:" + source_id, value, db=db)
    store.put("source-generation:" + source_id, secrets.token_hex(16), db=db)
    store.put("code-window:" + source_id, None, db=db)
    store.put("mailbox-health:" + source_id, None, db=db)


def totp_seed(value):
    if not isinstance(value, str) or not 1 <= len(value) <= 2048:
        raise AccessError("DENIED", "invalid_authenticator_seed")
    if value.startswith("otpauth://"):
        url = urlsplit(value)
        params = parse_qs(url.query)
        if (url.netloc != "totp" or params.get("digits", ["6"]) != ["6"]
                or params.get("period", ["30"]) != ["30"]
                or params.get("algorithm", ["SHA1"]) != ["SHA1"]
                or len(params.get("secret", [])) != 1):
            raise AccessError("DENIED", "unsupported_authenticator_settings")
        value = params["secret"][0]
    seed = value.replace(" ", "").upper().rstrip("=")
    if not re.fullmatch(r"[A-Z2-7]{16,256}", seed):
        raise AccessError("DENIED", "invalid_authenticator_seed")
    try:
        pyotp.TOTP(seed).now()
    except Exception:
        raise AccessError("DENIED", "invalid_authenticator_seed") from None
    return seed


def enroll(store, source_id, data):
    config = store.config()
    if not isinstance(source_id, str) or source_id not in config.code_sources:
        raise AccessError("DENIED", "unknown_code_source")
    kind = config.code_sources[source_id].kind
    if kind == "imap" and isinstance(data, dict) and set(data) == {"mailbox"}:
        from .mailboxes import link
        return link(store, source_id, data["mailbox"])
    if kind == "google_messages":
        raise AccessError("NEEDS_USER", "google_messages_extension_setup_required", "sms")
    required = {"totp": {"seed"}, "imap": ({"username"} if config.code_sources[source_id].account else {"username", "password"}),
                "twilio": {"sid", "auth_token"}, "mac_messages": {"enabled"},
                "gmail": set(), "phone_relay": set()}[kind]
    if not isinstance(data, dict) or set(data) != required:
        raise AccessError("DENIED", "invalid_code_source_enrollment")
    if kind == "totp":
        value = {"seed": totp_seed(data["seed"])}
    elif kind in {"gmail", "phone_relay"}:
        value = {"enabled": True}
    elif kind == "mac_messages":
        if data["enabled"] is not True:
            raise AccessError("DENIED", "message_permission_required")
        value = {"enabled": True}
    else:
        if any(not isinstance(v, str) or not 0 < len(v) <= 4096 for v in data.values()):
            raise AccessError("DENIED", "invalid_code_source_enrollment")
        value = data
    with source_mutation(store, source_id):
        current = store.config().code_sources.get(source_id)
        if current is None or current.model_dump() != config.code_sources[source_id].model_dump():
            raise AccessError("DENIED", "login_code_source_changed")
        with store.db() as db:
            replace_source(store, source_id, value, db=db)
    store.audit("owner", "", "", "factor_enrolled", kind)
    return {"status": "ENROLLED", "source": source_id, "kind": kind}


def revoke(store, source_id):
    if not isinstance(source_id, str) or source_id not in store.config().code_sources:
        raise AccessError("DENIED", "unknown_code_source")
    with source_mutation(store, source_id):
        with store.db() as db:
            replace_source(store, source_id, {"enabled": False}, db=db)
            store.put("phone-pair:" + source_id, None, db=db)
    return {"status": "REVOKED", "source": source_id}
