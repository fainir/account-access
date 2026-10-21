"""Owner-requested Chrome session transfer, verified before replacing saved access.

The first provider is the reviewed GitHub profile read. This is session reuse,
not proof of fresh password/SMS verification or a Chrome password-vault API.
"""

import json
import math
import re
import secrets
import time
from urllib.parse import urlsplit

from .errors import AccessError
from .models import BrowserAccount, origin

USERNAME = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9]|-(?=[A-Za-z0-9])){0,38}")
MAX_STATE = 48_000


def eligible(config, account):
    spec = config.accounts.get(account)
    return (isinstance(spec, BrowserAccount) and bool(spec.operations)
            and ((origin(spec.login_url) == "https://github.com"
                  and urlsplit(spec.login_url).path == "/login"
                  and all(op.url == "https://github.com/settings/profile" for op in spec.operations.values()))
                 or (config.test_mode and origin(spec.login_url).startswith("http://127.0.0.1:"))))


def candidates(broker):
    config = broker.store.config()
    result = []
    for account, spec in config.accounts.items():
        if not eligible(config, account):
            continue
        for operation in spec.operations:
            try:
                broker.permit("generic", account, operation)
            except AccessError:
                continue
            hint = (broker.store.get("credential:" + account) or {}).get("username", "")
            result.append({"account": account, "label": spec.label,
                           "fingerprint": config.fingerprint(account),
                           "operation": operation,
                           "username_hint": hint if isinstance(hint, str) and USERNAME.fullmatch(hint) else ""})
            break
    return result


def begin(broker, account, fingerprint, username):
    if (not isinstance(account, str) or not isinstance(fingerprint, str)
            or not isinstance(username, str) or not USERNAME.fullmatch(username)):
        raise AccessError("DENIED", "browser_session_username_required")
    store = broker.store
    with store.lock("account:" + account):
        config = store.config()
        choices = {item["account"]: item for item in candidates(broker)}
        if account not in choices or config.fingerprint(account) != fingerprint:
            raise AccessError("DENIED", "browser_session_configuration_changed")
        operation = choices[account]["operation"]
        request = {"id": secrets.token_hex(16), "fingerprint": fingerprint,
                   "account": account, "operation": operation, "username": username,
                   "expires": time.time() + 300, "status": "AWAITING_BROWSER"}
        with store.lock("browser-session:" + account):
            store.put("browser-session-request:" + account, request)
    return {"status": "AWAITING_BROWSER", "id": request["id"], "expires": request["expires"]}


def requests(broker, *, owner=False):
    store, config = broker.store, broker.store.config()
    result = []
    for account, spec in config.accounts.items():
        saved = store.get("browser-session-request:" + account)
        if not saved or saved["expires"] < time.time():
            continue
        try:
            broker.permit("generic", account, saved["operation"])
        except AccessError:
            continue
        if config.fingerprint(account) != saved["fingerprint"] or not eligible(config, account):
            continue
        item = {"account": account, "label": spec.label, "origin": origin(spec.login_url),
                "id": saved["id"], "fingerprint": saved["fingerprint"],
                "expires": saved["expires"], "status": saved["status"]}
        if owner:
            item["reason"] = saved.get("reason")
        elif saved["status"] != "AWAITING_BROWSER":
            continue
        else:
            item["username"] = saved["username"]
        result.append(item)
    return result


def cancel(store, account, ident):
    if not isinstance(account, str) or not isinstance(ident, str):
        raise AccessError("DENIED", "invalid_browser_session_request")
    with store.lock("browser-session:" + account):
        current = store.get("browser-session-request:" + account)
        if not current or current["id"] != ident or current["status"] not in {"AWAITING_BROWSER", "VERIFYING"}:
            raise AccessError("DENIED", "browser_session_request_expired_or_changed")
        current["status"] = "CANCELLED"
        store.put("browser-session-request:" + account, current)
    return {"status": "CANCELLED"}


def validate_state(state, expected_origin):
    """Accept only bounded Playwright cookie/localStorage values for one site."""
    try:
        size = len(json.dumps(state, allow_nan=False).encode())
    except (TypeError, ValueError, OverflowError):
        raise AccessError("DENIED", "invalid_browser_session_state") from None
    if (not isinstance(state, dict) or set(state) != {"cookies", "origins"}
            or not isinstance(state["cookies"], list) or not 1 <= len(state["cookies"]) <= 128
            or not isinstance(state["origins"], list) or len(state["origins"]) > 1
            or size > MAX_STATE):
        raise AccessError("DENIED", "invalid_browser_session_state")
    host = urlsplit(expected_origin).hostname
    seen = set()
    for cookie in state["cookies"]:
        if (not isinstance(cookie, dict) or set(cookie) != {
                "name", "value", "domain", "path", "expires", "httpOnly", "secure", "sameSite"}
                or any(not isinstance(cookie[key], str) or not 0 < len(cookie[key]) <= cap
                       for key, cap in [("name", 256), ("domain", 253), ("path", 2048)])
                or not isinstance(cookie["value"], str) or len(cookie["value"]) > 16_384
                or cookie["domain"] not in {host, "." + host}
                or not cookie["path"].startswith("/")
                or type(cookie["httpOnly"]) is not bool or type(cookie["secure"]) is not bool
                or not isinstance(cookie["sameSite"], str) or cookie["sameSite"] not in {"Strict", "Lax", "None"}
                or type(cookie["expires"]) not in {int, float}
                or not math.isfinite(cookie["expires"]) or cookie["expires"] < -1
                or cookie["expires"] > 2**53):
            raise AccessError("DENIED", "invalid_browser_session_state")
        key = cookie["name"], cookie["domain"], cookie["path"]
        if key in seen:
            raise AccessError("DENIED", "invalid_browser_session_state")
        seen.add(key)
    for item in state["origins"]:
        if (not isinstance(item, dict) or set(item) != {"origin", "localStorage"}
                or item["origin"] != expected_origin or not isinstance(item["localStorage"], list)
                or len(item["localStorage"]) > 128):
            raise AccessError("DENIED", "invalid_browser_session_state")
        names = set()
        for value in item["localStorage"]:
            if (not isinstance(value, dict) or set(value) != {"name", "value"}
                    or not isinstance(value["name"], str) or not 0 < len(value["name"]) <= 1024
                    or not isinstance(value["value"], str) or len(value["value"]) > 65_536
                    or value["name"] in names):
                raise AccessError("DENIED", "invalid_browser_session_state")
            names.add(value["name"])
    return state


def accept(broker, message):
    if (not isinstance(message, dict) or set(message) != {
            "method", "account", "request", "fingerprint", "origin", "state"}
            or message["method"] != "session-import"
            or any(not isinstance(message[key], str) for key in ["account", "request", "fingerprint", "origin"])):
        raise AccessError("DENIED", "invalid_browser_session_request")
    store, account = broker.store, message["account"]
    with store.lock("account:" + account, timeout=5):
        config = store.config()
        saved = store.get("browser-session-request:" + account)
        if (not saved or saved["status"] != "AWAITING_BROWSER" or saved["expires"] < time.time()
                or message["request"] != saved["id"] or message["fingerprint"] != saved["fingerprint"]
                or account not in config.accounts or config.fingerprint(account) != saved["fingerprint"]
                or not eligible(config, account) or message["origin"] != origin(config.accounts[account].login_url)):
            raise AccessError("DENIED", "browser_session_request_expired_or_changed")
        broker.permit("generic", account, saved["operation"])
        try:
            state = validate_state(message["state"], message["origin"])
        except (TypeError, ValueError, OverflowError):
            raise AccessError("DENIED", "invalid_browser_session_state") from None
        with store.lock("browser-session:" + account):
            current = store.get("browser-session-request:" + account)
            if current != saved:
                raise AccessError("DENIED", "browser_session_request_expired_or_changed")
            saved["status"] = "VERIFYING"
            store.put("browser-session-request:" + account, saved)
        try:
            state = broker.browser.verify_imported_state(account, state, saved["username"], saved["operation"])
            broker.permit("generic", account, saved["operation"])
            if store.config().fingerprint(account) != saved["fingerprint"] or saved["expires"] < time.time():
                raise AccessError("DENIED", "browser_session_request_expired_or_changed")
            with store.lock("browser-session:" + account):
                current = store.get("browser-session-request:" + account)
                if (not current or current["id"] != saved["id"] or current["status"] != "VERIFYING"
                        or current["expires"] < time.time()):
                    raise AccessError("DENIED", "browser_session_cancelled")
                saved["status"] = "CONNECTED"
                with store.db() as db:
                    broker.browser.save(account, state, db=db)
                    store.resolve_login(account, db=db)
                    store.put("browser-session-request:" + account, saved, db=db)
            store.audit("owner", account, "", "browser_session_verified")
        except AccessError as exc:
            saved.update(status=exc.status, reason=exc.reason)
            raise
        except Exception:
            saved.update(status="NEEDS_USER", reason="browser_session_verification_failed")
            raise AccessError("NEEDS_USER", "browser_session_verification_failed") from None
        finally:
            # Replays never trigger another website request, even after a lost
            # native reply. Failed checks leave the old connection untouched.
            with store.lock("browser-session:" + account):
                current = store.get("browser-session-request:" + account)
                if current and current["id"] == saved["id"] and current["status"] not in {"CONNECTED", "CANCELLED"}:
                    store.put("browser-session-request:" + account, saved)
    return {"status": "SESSION_CONNECTED", "account": account}
