"""Closed structural diagnostics for an owner's already-stopped browser attempt.

These records explain a pending challenge. They never identify a new login
method, authorize a destination, resolve a challenge or trigger another attempt.
"""

import copy
import math
import time

from .models import BrowserAccount, origin
from .navigation import route_hint, valid_hint

PREFIX = "browser-diagnostics:"
MAX_AGE = 24 * 60 * 60
FIELDS = {
    "password": 'input[type="password"]',
    "one_time_code": 'input[autocomplete="one-time-code"]',
    "numeric_input": 'input[inputmode="numeric"], input[type="number"], input[type="tel"]',
    "email_input": 'input[type="email"], input[autocomplete="email"]',
}
MARKERS = frozenset({"login", "sms", "email", "totp", "device", "passkey", "captcha",
                     "admin", "action", "recovery", "unknown", "method"})
PROGRESS = frozenset({"password_submit_attempted", "identity_submit_attempted", "sms_requested", "email_requested",
                      "sms_code_filled", "email_code_filled", "totp_code_filled",
                      "sms_submit_attempted", "email_submit_attempted", "totp_submit_attempted"})


def require(value):
    if not value:
        raise ValueError("invalid_browser_diagnostics")


def validate(value):
    """Refuse arbitrary website strings, extra keys and coercible primitives."""
    require(type(value) is dict and set(value) == {
        "schema", "page", "forms", "fields", "field_counts", "visible_field_counts", "markers", "progress"})
    require(type(value["schema"]) is int and value["schema"] == 1 and valid_hint(value["page"]))
    require(type(value["forms"]) is list and len(value["forms"]) <= 8)
    for form in value["forms"]:
        require(type(form) is dict and set(form) == {"method", "visible", "reviewed_action", "controls"})
        require(type(form["method"]) is str and form["method"] in {"GET", "POST", "other"}
                and type(form["visible"]) is bool and type(form["reviewed_action"]) is bool
                and type(form["controls"]) is int and 0 <= form["controls"] <= 32)
    for key in ("fields", "field_counts", "visible_field_counts"):
        require(type(value[key]) is dict and set(value[key]) == set(FIELDS))
    for name in FIELDS:
        count, visible = value["field_counts"][name], value["visible_field_counts"][name]
        require(type(count) is int and type(visible) is int and 0 <= visible <= count <= 8
                and type(value["fields"][name]) is bool and value["fields"][name] == (visible > 0))
    require(type(value["markers"]) is dict and set(value["markers"]) == MARKERS
            and all(type(flag) is bool for flag in value["markers"].values()))
    progress = value["progress"]
    require(type(progress) is dict and set(progress) <= PROGRESS | {"method"})
    for name, flag in progress.items():
        require(type(flag) is str and flag in {"email", "sms", "totp"}
                if name == "method" else type(flag) is bool)
    return value


def capture(page, config):
    """Read fixed structural properties only; never read a control's value/text.

    Form actions are compared inside the page against configured public URLs.
    Only the comparison boolean leaves the page, never the action itself.
    """
    forms = page.locator("form").evaluate_all("""(forms, reviewed) => forms.slice(0, 8).map(form => {
        const native = key => Object.getOwnPropertyDescriptor(HTMLFormElement.prototype, key).get.call(form);
        const method = native('method');
        return {
            method: ['get', 'post'].includes(method) ? method.toUpperCase() : 'other',
            visible: Element.prototype.getClientRects.call(form).length > 0,
            reviewed_action: reviewed.includes(native('action')),
            controls: Math.min(native('elements').length, 32)
        };
    })""", list(config.login_post_urls))
    counts, visible = {}, {}
    for name, selector in FIELDS.items():
        fields = page.locator(selector)
        counts[name] = min(fields.count(), 8)
        visible[name] = sum(fields.nth(index).is_visible() for index in range(counts[name]))
    markers = {}
    for kind in sorted(MARKERS):
        selector = config.challenge_selectors.get(kind)
        markers[kind] = bool(selector and page.locator(selector).first.is_visible())
    current = getattr(page.context, "_login_progress", {})
    progress = {key: current[key] for key in PROGRESS if type(current.get(key)) is bool}
    if current.get("method") in {"email", "sms", "totp"}:
        progress["method"] = current["method"]
    return validate({"schema": 1, "page": route_hint(page.url, [origin(config.login_url)]),
                     "forms": forms, "fields": {name: visible[name] > 0 for name in FIELDS},
                     "field_counts": counts, "visible_field_counts": visible,
                     "markers": markers, "progress": progress})


def remember(store, account, operation, fingerprint, challenge, attention):
    """Best-effort, encrypted first-failure record after the challenge exists.

    Failure to collect/store diagnostics must never change the original result.
    The normal pending challenge continues to prevent another website attempt.
    """
    try:
        require(type(attention) is dict and set(attention) == {"status", "kind", "reason", "diagnostics"})
        require(attention["status"] == "NEEDS_USER" and challenge["account"] == account
                and attention["kind"] == challenge["kind"] and attention["reason"] == challenge["reason"])
        diagnostics = validate(attention["diagnostics"])
        with store.lock("account:" + account, timeout=0):
            config = store.config()
            spec = config.accounts.get(account)
            require(isinstance(spec, BrowserAccount) and operation in spec.operations
                    and config.fingerprint(account) == fingerprint)
            with store.db() as db:
                pending = db.execute("SELECT * FROM challenges WHERE id=? AND account=? AND resolved IS NULL",
                                     (challenge["id"], account)).fetchone()
                require(pending is not None and pending["kind"] == challenge["kind"]
                        and pending["reason"] == challenge["reason"] and pending["created"] == challenge["created"])
                row = db.execute("SELECT value FROM records WHERE id=?", (PREFIX + account,)).fetchone()
                previous = store.unseal(PREFIX + account, row[0]) if row else None
                if type(previous) is dict and previous.get("challenge_id") == challenge["id"]:
                    return False
                store.put(PREFIX + account, {"schema": 1, "account": account, "operation": operation,
                    "fingerprint": fingerprint, "challenge_id": challenge["id"],
                    "challenge_created": challenge["created"], "kind": challenge["kind"], "reason": challenge["reason"],
                    "recorded_at": time.time(), "diagnostics": copy.deepcopy(diagnostics)}, db=db)
        return True
    except Exception:
        return False


def owner_view(config, account, pending, record, *, now=None):
    """Project only a matching, recent pending record into an owner response.

    Accept an existing owner-state database snapshot; this helper performs no
    reads, repairs or authority changes and is never used by agent responses.
    """
    try:
        require(type(record) is dict and set(record) == {"schema", "account", "operation", "fingerprint",
                "challenge_id", "challenge_created", "kind", "reason", "recorded_at", "diagnostics"})
        spec = config.accounts.get(account)
        require(type(record["schema"]) is int and record["schema"] == 1
                and isinstance(spec, BrowserAccount) and record["operation"] in spec.operations
                and record["account"] == account and record["fingerprint"] == config.fingerprint(account))
        at = record["recorded_at"]
        require(type(at) in {int, float} and math.isfinite(at)
                and 0 <= (time.time() if now is None else now) - at <= MAX_AGE)
        require(any(item["id"] == record["challenge_id"] and item["account"] == account
                    and item["created"] == record["challenge_created"] and item["kind"] == record["kind"]
                    and item["reason"] == record["reason"] and item.get("resolved") is None for item in pending))
        return {"challenge_id": record["challenge_id"], "diagnostics": copy.deepcopy(validate(record["diagnostics"]))}
    except Exception:
        return None
