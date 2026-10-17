"""Resume only proven mailbox prerequisites; website authentication still runs."""

import time

from .errors import AccessError
from .models import BrowserAccount

REASONS = {"mailbox_not_connected", "mailbox_connection_failed", "account_not_connected",
           "mailbox_scope_missing", "provider_rejected_access", "provider_grant_revoked_or_expired",
           "refresh_outcome_uncertain", "renewal_unavailable"}
PREFIX = "source-recovery:"


def email_source(config, account):
    spec = config.accounts.get(account)
    if not isinstance(spec, BrowserAccount) or not spec.login:
        return None
    factor = spec.login.factor("email")
    source = config.code_sources.get(factor.code_source) if factor else None
    return factor.code_source if source and source.kind in {"imap", "gmail"} else None


def remember(store, challenge, source_id, reason):
    # A historical challenge with no proven source context stays pending.
    # Never replace the meaning of an older ambiguous/delivery/presence gate.
    if (not source_id or challenge["kind"] != "email" or challenge["reason"] != reason or reason not in REASONS):
        return
    config = store.config()
    if email_source(config, challenge["account"]) != source_id:
        return
    key = PREFIX + challenge["id"]
    with store.lock(key):
        if store.get(key) is None:
            parent = config.code_sources[source_id].account
            store.put(key, {"account": challenge["account"], "source": source_id,
                            "fingerprint": config.fingerprint(challenge["account"]),
                            "mailbox_fingerprint": config.fingerprint(parent) if parent else None,
                            "reason": challenge["reason"]})


def checked_after(store, source_id, created):
    from .mailbox_health import view
    health = view(store, source_id) or {}
    if health.get("status") == "VERIFIED" and health.get("checked", 0) >= created:
        return True
    credential = store.get("source:" + source_id) or {}
    if credential.get("enabled") is False or not credential.get("mailbox"):
        return False
    from .mailboxes import enrollment, get
    enrollment(store, source_id)  # Recheck exact identity, server and current connection.
    profile = get(store, credential["mailbox"])
    health = profile.get("connection_check", {})
    return health.get("status") == "VERIFIED" and health.get("checked", 0) >= created


def recover(store):
    # Rotate a bounded scan so stale/locked prerequisites cannot starve later
    # accounts. Nothing in this reconciliation makes a provider request.
    cursor = store.get("source-recovery-cursor", 0)
    if type(cursor) is not int or cursor < 0:
        cursor = 0
    with store.db() as db:
        query = """SELECT c.*,c.rowid AS scan_id FROM challenges c
                   JOIN records r ON r.id=('source-recovery:' || c.id)
                   WHERE c.resolved IS NULL AND c.kind='email' AND c.rowid>?
                   ORDER BY c.rowid LIMIT 20"""
        rows = db.execute(query, (cursor,)).fetchall()
        if not rows and cursor:
            rows = db.execute(query, (0,)).fetchall()
    repaired = 0
    for challenge in rows:
        store.put("source-recovery-cursor", challenge["scan_id"])
        try:
            with store.lock("account:" + challenge["account"], timeout=0):
                config = store.config()
                context = store.get(PREFIX + challenge["id"]) or {}
                source_id = context.get("source")
                if (not isinstance(source_id, str) or challenge["reason"] not in REASONS
                        or context.get("reason") != challenge["reason"]
                        or context.get("account") != challenge["account"]
                        or email_source(config, challenge["account"]) != source_id
                        or context.get("fingerprint") != config.fingerprint(challenge["account"])):
                    continue
                parent = config.code_sources[source_id].account
                if context.get("mailbox_fingerprint") != (config.fingerprint(parent) if parent else None):
                    continue
                if not checked_after(store, source_id, challenge["created"]):
                    continue
                with store.db() as db:
                    grant = db.execute("""SELECT 1 FROM grants g JOIN clients c ON c.principal=g.principal
                        WHERE g.account=? AND g.fingerprint=? AND c.revoked=0
                        AND (g.expires IS NULL OR g.expires>?) LIMIT 1""",
                        (challenge["account"], context["fingerprint"], time.time())).fetchone()
                    if not grant:
                        continue
                    changed = db.execute("""UPDATE challenges SET resolved=? WHERE id=? AND resolved IS NULL
                        AND kind='email' AND reason=?""", (time.time(), challenge["id"], context["reason"])).rowcount
                    if changed:
                        store.put(PREFIX + challenge["id"], None, db=db)
                if changed:
                    store.audit("service", challenge["account"], "", "mailbox_prerequisite_repaired")
                    repaired += 1
        except AccessError:
            continue
    return repaired
