"""Owner-authorized Google Messages bridge; codes never enter the agent API."""

import re
import secrets
import time

from .codes import Codes
from .errors import AccessError
from .models import CodeSource, LoginFactor
from .sms_setup import eligible, prepare, save

TEMPLATE = "{code} is your GitHub authentication code."


def accounts(store):
    config = store.config()
    result = []
    for account, spec in config.accounts.items():
        factor = getattr(spec, "login", None) and spec.login.factor("sms")
        connected = bool(factor and config.code_sources[factor.code_source].kind == "google_messages")
        if eligible(config, account) or connected:
            result.append({"account": account, "label": spec.label, "fingerprint": config.fingerprint(account),
                           "connected": connected})
    return result


def connect(store, account, fingerprint):
    """Called only by the installed extension's explicit owner connect action."""
    if not isinstance(account, str) or not isinstance(fingerprint, str):
        raise AccessError("DENIED", "google_messages_setup_changed")
    with store.lock("account:" + account, timeout=5), store.lock("catalog"):
        config = store.config()
        spec = config.accounts.get(account)
        factor = getattr(spec, "login", None) and spec.login.factor("sms")
        if factor and config.code_sources[factor.code_source].kind == "google_messages":
            if config.fingerprint(account) != fingerprint:
                raise AccessError("DENIED", "google_messages_setup_changed")
            store.put("source:" + factor.code_source, {"enabled": True})
            return {"status": "CONNECTED", "account": account}
    fingerprint = prepare(store, account, fingerprint)
    source_id = "github-google-sms-" + secrets.token_hex(8)
    with store.lock("account:" + account, timeout=5), store.lock("catalog"):
        config = store.config()
        if not eligible(config, account) or config.fingerprint(account) != fingerprint:
            raise AccessError("DENIED", "google_messages_setup_changed")
        spec = config.accounts[account]
        config.code_sources[source_id] = CodeSource(
            kind="google_messages", sender="github-login-rotating-senders",
            recipient="paired-google-messages", template=TEMPLATE)
        spec.login.factors["sms"] = LoginFactor(code_source=source_id, code_selector="#sms_totp",
                                                code_submit_selector=spec.login.factor("totp").code_submit_selector)
        spec.challenge_selectors["sms"] = "#sms_totp"
        save(store, config, account, fingerprint, source=source_id)
        store.audit("owner", account, "", "factor_enrolled", "google_messages")
    return {"status": "CONNECTED", "account": account}


def window(store, source_id, ident):
    saved = store.get("code-window:" + source_id) or {}
    source, current, _ = Codes(store, None).check_window(source_id, saved.get("started", 0))
    if source.kind != "google_messages" or not secrets.compare_digest(current.get("google_window", ""), ident):
        raise AccessError("DENIED", "google_messages_window_missing")
    return current


def handle(store, message):
    if not isinstance(message, dict):
        raise AccessError("DENIED", "invalid_google_messages_message")
    method = message.get("method")
    if method == "accounts" and set(message) == {"method"}:
        return {"accounts": accounts(store)}
    if method == "connect" and set(message) == {"method", "account", "fingerprint"}:
        return connect(store, message["account"], message["fingerprint"])
    if method == "pending" and set(message) == {"method"}:
        pending = []
        source_enabled = False
        for source_id, source in store.config().code_sources.items():
            if source.kind != "google_messages":
                continue
            source_enabled |= (store.get("source:" + source_id) or {}).get("enabled") is True
            current = store.get("code-window:" + source_id) or {}
            try:
                current = window(store, source_id, current.get("google_window", ""))
            except AccessError:
                continue
            if current.get("consumed") or current.get("lost"):
                continue
            pending.append({"source": source_id, "window": current["google_window"],
                            "phase": "watch" if current.get("armed") else "baseline",
                            "template": source.template, "expires": current["expires"]})
        return {"pending": pending, "source_enabled": source_enabled}
    if method not in {"armed", "lost", "deliver"}:
        raise AccessError("DENIED", "unsupported_google_messages_method")
    expected = {"method", "source", "window"} | ({"messages"} if method == "deliver" else set())
    if (set(message) != expected or not isinstance(message.get("source"), str)
            or not re.fullmatch(r"[a-z][a-z0-9_-]{0,63}", message["source"])
            or not isinstance(message.get("window"), str) or not re.fullmatch(r"[0-9a-f]{32}", message["window"])):
        raise AccessError("DENIED", "invalid_google_messages_message")
    source_id = message["source"]
    with store.lock("code-window:" + source_id):
        current = window(store, source_id, message["window"])
        if current.get("consumed") or current.get("lost"):
            raise AccessError("DENIED", "google_messages_window_finished")
        if method == "armed":
            current["armed"] = True
        elif method == "lost":
            current["lost"] = True
        else:
            batch = message["messages"]
            if (not current.get("armed") or not isinstance(batch, list) or not 1 <= len(batch) <= 8
                    or any(not isinstance(item, dict) or set(item) != {"id", "code", "observed_at"}
                           or not isinstance(item["id"], str) or not re.fullmatch(r"[0-9a-f]{64}", item["id"])
                           or not isinstance(item["code"], str) or not re.fullmatch(r"[0-9]{6}", item["code"])
                           or type(item["observed_at"]) not in {int, float}
                           or not current["started"] <= item["observed_at"] <= time.time() + 5 for item in batch)):
                raise AccessError("DENIED", "invalid_google_messages_delivery")
            seen = current.setdefault("seen", [])
            for item in batch:
                if item["id"] in seen:
                    continue
                if len(seen) >= 8:
                    raise AccessError("DENIED", "google_messages_delivery_limit")
                seen.append(item["id"])
                current["incoming"].append({"code": item["code"]})
        store.put("code-window:" + source_id, current)
    return {"status": "RECEIVED"}
