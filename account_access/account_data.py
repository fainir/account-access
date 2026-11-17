"""Owner-only export and removal for locally saved website logins."""

import csv
import io
import re
import time

from .errors import AccessError
from .models import BrowserAccount

ACCOUNT_ID = re.compile(r"[a-z][a-z0-9_-]{0,63}")


def _valid_id(account):
    if not isinstance(account, str) or ACCOUNT_ID.fullmatch(account) is None:
        raise AccessError("DENIED", "unknown_account")
    return account


def _account(store, account):
    if not isinstance(account, str) or account not in store.config().accounts:
        raise AccessError("DENIED", "unknown_account")
    spec = store.config().accounts[account]
    if not isinstance(spec, BrowserAccount) or spec.login is None:
        raise AccessError("DENIED", "saved_login_unavailable")
    return spec


def export_login(store, account):
    """Return a single explicit CSV snapshot; this value must never enter agent output."""
    account = _valid_id(account)
    with store.lock("account:" + account):
        spec = _account(store, account)
        if spec.login.identity_contact:
            raise AccessError("DENIED", "saved_login_export_unsupported")
        credential = store.get("credential:" + account)
        if not spec.login.credential_ready(credential):
            raise AccessError("NEEDS_USER", "saved_login_unavailable")
        output = io.StringIO(newline="")
        writer = csv.writer(output, lineterminator="\r\n")
        writer.writerow(("url", "username", "password"))
        writer.writerow((spec.login_url, credential["username"], credential["password"]))
        value = output.getvalue()
    store.audit("owner", account, "", "saved_login_exported", "plaintext_csv")
    return {"status": "EXPORTED", "csv": value}


def forget_login(store, account):
    """Remove local password, website/browser state and sync binding atomically."""
    account = _valid_id(account)
    with store.lock("account:" + account):
        _account(store, account)
        now = time.time()
        keys = (
            "credential:" + account,
            "connection:" + account,
            "password-link:" + account,
            "password-sync-hint:" + account,
            "browser-session-request:" + account,
        )
        with store.db() as db:
            db.execute("PRAGMA secure_delete=ON")
            db.executemany("DELETE FROM records WHERE id=?", ((key,) for key in keys))
            # A deliberate forget also ends stale sign-in challenges for this
            # account. Shared verification-source enrollment is untouched.
            db.execute("UPDATE challenges SET resolved=? WHERE account=? AND resolved IS NULL",
                       (now, account))
    store.audit("owner", account, "", "saved_login_forgotten")
    return {"status": "FORGOTTEN", "account": account}
