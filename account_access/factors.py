"""Enrollment belongs to the owner, never to the agent client."""

import re
from urllib.parse import parse_qs, urlsplit

import pyotp

from .errors import AccessError


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
    with store.lock("source:" + source_id):
        store.put("source:" + source_id, value)
    store.audit("owner", "", "", "factor_enrolled", kind)
    return {"status": "ENROLLED", "source": source_id, "kind": kind}


def revoke(store, source_id):
    if source_id not in store.config().code_sources:
        raise AccessError("DENIED", "unknown_code_source")
    with store.lock("source:" + source_id):
        store.put("source:" + source_id, {"enabled": False})
        store.put("phone-pair:" + source_id, None)
        store.put("code-window:" + source_id, None)
    return {"status": "REVOKED", "source": source_id}
