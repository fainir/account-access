"""The authority boundary: identity comes from the service, never from tool arguments."""

import secrets
import time

from . import __version__
from .browser import Browser
from .codes import Codes
from .errors import AccessError
from .models import BrowserAccount, OAuthAccount, TaskRequest
from .providers import OAuth, credential_values, redact

MESSAGES = {
    "login": "Complete sign-in for this account in the local owner setup flow.",
    "email": "Complete the email login challenge or reconnect its approved mailbox source.",
    "sms": "Complete the SMS login challenge or reconnect its approved SMS source.",
    "totp": "Complete the authenticator login challenge or enroll its approved code source.",
    "method": "Connect one of this website's approved email, SMS or authenticator methods locally.",
    "device": "Approve the provider's sign-in request on your genuine device.",
    "passkey": "Complete the provider's passkey or biometric verification on your device.",
    "admin": "An administrator must approve the required access through the provider.",
    "action": "This is an action authorization challenge. Review it directly with the provider.",
    "unknown": "The page needs review because its authentication state was not recognized.",
    "vault": "Unlock or repair the credential store locally.",
}


class Broker:
    def __init__(self, store):
        self.store = store
        self.oauth = OAuth(store)
        self.codes = Codes(store, self.oauth)
        self.browser = Browser(store, self.codes)

    def permit(self, principal, account, operation):
        config = self.store.config()
        if not self.store.principal_active(principal):
            raise AccessError("DENIED", "client_revoked")
        if account not in config.accounts or operation not in config.accounts[account].operations:
            raise AccessError("DENIED", "unknown_account_or_operation")
        with self.store.db() as db:
            grant = db.execute("SELECT * FROM grants WHERE principal=? AND account=? AND operation=?",
                               (principal, account, operation)).fetchone()
        if not grant:
            raise AccessError("DENIED", "standing_permission_missing")
        if grant["expires"] and grant["expires"] <= time.time():
            raise AccessError("DENIED", "standing_permission_expired")
        if grant["fingerprint"] != config.fingerprint(account):
            raise AccessError("DENIED", "owner_configuration_changed")
        return config

    def grant(self, principal, account, operations, expires=None):
        config = self.store.config()
        if not operations or not set(operations) <= config.accounts[account].operations.keys():
            raise AccessError("DENIED", "unknown_operation")
        with self.store.lock("account:" + account):
            with self.store.db() as db:
                db.execute("DELETE FROM grants WHERE principal=? AND account=?", (principal, account))
                for operation in operations:
                    db.execute("INSERT OR REPLACE INTO grants VALUES (?,?,?,?,?)",
                               (principal, account, operation, config.fingerprint(account), expires))
            self.store.audit("owner", account, "", "permission_granted")

    def revoke(self, account=None, principal=None):
        if account:
            with self.store.lock("account:" + account):
                connection = self.store.get("connection:" + account)
                if connection:
                    connection["revoked"] = True
                    # Stop locally first. Best-effort remote revocation is a separate owner action.
                    self.store.put("connection:" + account, connection)
                with self.store.db() as db:
                    db.execute("DELETE FROM grants WHERE account=?", (account,))
                self.store.audit("owner", account, "", "account_revoked")
        if principal:
            with self.store.db() as db:
                db.execute("UPDATE clients SET revoked=1 WHERE principal=?", (principal,))
                db.execute("DELETE FROM grants WHERE principal=?", (principal,))
            self.store.audit("owner", "", "", "client_revoked")

    def challenge_view(self, challenge):
        return {"id": challenge["id"], "account": challenge["account"], "kind": challenge["kind"],
                "reason": challenge["reason"], "required_action": MESSAGES.get(challenge["kind"], MESSAGES["unknown"]),
                "created": challenge["created"]}

    def error(self, exc, account, *, challenge=True):
        result = {"status": exc.status, "reason": exc.reason, "account": account}
        if exc.status == "NEEDS_USER" and challenge:
            result["challenge"] = self.challenge_view(self.store.challenge(account, exc.kind, exc.reason))
        return result

    def accounts(self, principal):
        result = []
        config = self.store.config()
        for account, spec in config.accounts.items():
            operations = []
            for name, op in spec.operations.items():
                try:
                    self.permit(principal, account, name)
                    operations.append({"name": name, "description": op.description})
                except AccessError:
                    pass
            if operations:
                result.append({"account": account, "label": spec.label, "route": spec.kind,
                               **self.connection_view(account, config),
                               "operations": operations})
        return {"status": "OK", "accounts": result, "service_version": __version__,
                "environment": "controlled-demo" if config.test_mode else "live"}

    def connection_view(self, account, config):
        """Saved credentials alone are not evidence of a successful sign-in."""
        spec = config.accounts[account]
        saved = self.store.get("connection:" + account) or {}
        credential = self.store.get("credential:" + account) or {}
        ready = bool(isinstance(spec, BrowserAccount) and spec.login
                     and credential.get("username") and credential.get("password"))
        if saved.get("revoked"):
            state = "revoked"
        elif saved and saved.get("fingerprint") != config.fingerprint(account):
            state = "needs_review"
        elif self.store.pending(account):
            state = "needs_attention"
        elif saved:
            state = "saved_access"
        else:
            state = "login_recovery_ready" if ready else "needs_setup"
        return {"connected": state == "saved_access", "verified_now": False,
                "connection_state": state,
                "automatic_recovery_available": ready and state in {"saved_access", "login_recovery_ready"}}

    def status(self, principal, account, operation):
        try:
            self.permit(principal, account, operation)
            pending = self.store.pending(account)
            if pending:
                return {"status": "NEEDS_USER", "account": account,
                        "challenge": self.challenge_view(pending[0])}
            view = self.connection_view(account, self.store.config())
            return {"status": "AVAILABLE" if view["connected"] else "RECOVERABLE" if view["automatic_recovery_available"] else "UNCONNECTED", "account": account,
                    "verified_now": False}
        except AccessError as exc:
            return self.error(exc, account, challenge=False)

    def run(self, principal, account, operation):
        try:
            with self.store.lock("account:" + account):
                config = self.permit(principal, account, operation)
                spec = config.accounts[account]
                if isinstance(spec, BrowserAccount):
                    from .password_sync import refresh
                    refresh(self.store, account)
                pending = self.store.pending(account)
                if pending:
                    return {"status": "NEEDS_USER", "account": account,
                            "challenge": self.challenge_view(pending[0])}
                op = spec.operations[operation]
                secrets_seen = credential_values(self.store.get("credential:" + account, {}))
                if isinstance(spec, BrowserAccount) and spec.login:
                    for source_id in spec.login.sources():
                        secrets_seen |= credential_values(self.store.get("source:" + source_id, {}))
                        source_account = config.code_sources[source_id].account
                        if source_account:
                            secrets_seen |= credential_values(self.store.get("connection:" + source_account, {}))
                if isinstance(spec, OAuthAccount):
                    data = self.oauth.read(account, op, config)
                elif isinstance(spec, BrowserAccount):
                    data = self.browser.read(account, op, spec, secret_values=secrets_seen)
                else:
                    raise AccessError("DENIED", "unsupported_connector")
                # Catch permission revocation that occurred concurrently during an in-flight request.
                self.permit(principal, account, operation)
                secrets_seen |= credential_values(self.store.get("connection:" + account, {}))
                self.store.audit(principal, account, operation, "operation_completed")
                return {"status": "COMPLETED", "account": account, "operation": operation,
                        "environment": "controlled-demo" if config.test_mode else "live",
                        "data": redact(data, secrets_seen), "untrusted_data": True}
        except AccessError as exc:
            self.store.audit(principal, account, operation, "operation_blocked", exc.reason)
            return self.error(exc, account, challenge=exc.status != "DENIED")
        except Exception:
            self.store.audit(principal, account, operation, "operation_failed", "internal_error")
            return {"status": "RETRYABLE", "reason": "internal_error", "account": account}

    def submit(self, principal, request: TaskRequest):
        for step in request.steps:
            self.permit(principal, step.account, step.operation)
        with self.store.lock("submit:" + principal):
            with self.store.db() as db:
                existing = db.execute("SELECT id FROM jobs WHERE principal=? AND request_key=?",
                                      (principal, request.key)).fetchone()
                if existing:
                    job = self.store.get("job:" + existing[0])
                    if job["steps"] != [s.model_dump() for s in request.steps]:
                        raise AccessError("DENIED", "idempotency_key_conflict")
                    return self.task(principal, existing[0])
                count = db.execute("SELECT COUNT(*) FROM jobs WHERE principal=? AND status!='COMPLETED'",
                                   (principal,)).fetchone()[0]
                if count >= 1000:
                    raise AccessError("DENIED", "task_queue_limit")
                job_id = secrets.token_hex(16)
                job = {"id": job_id, "principal": principal, "steps": [s.model_dump() for s in request.steps],
                       "completed": [], "status": "QUEUED", "created": time.time(), "attempts": 0}
                self.store.put("job:" + job_id, job, db=db)
                db.execute("INSERT INTO jobs(id,principal,request_key,status) VALUES (?,?,?,?)",
                           (job_id, principal, request.key, "QUEUED"))
        return self.task(principal, job_id)

    def task(self, principal, job_id):
        job = self.store.get("job:" + job_id)
        if not job or job["principal"] != principal:
            raise AccessError("DENIED", "unknown_task")
        for step in job["steps"]:
            self.permit(principal, step["account"], step["operation"])
        return {"status": job["status"], "task_id": job_id, "progress": len(job["completed"]),
                "total": len(job["steps"]), "results": job["completed"],
                "blocked": job.get("blocked"), "untrusted_data": True}

    def save_job(self, job, next_at=0):
        with self.store.db() as db:
            self.store.put("job:" + job["id"], job, db=db)
            db.execute("UPDATE jobs SET status=?,next_at=? WHERE id=?", (job["status"], next_at, job["id"]))

    def advance(self, job_id):
        with self.store.lock("job:" + job_id, timeout=0):
            job = self.store.get("job:" + job_id)
            if not job or job["status"] in {"COMPLETED", "DENIED", "FAILED"}:
                return
            job["status"] = "RUNNING"
            self.save_job(job)
            while len(job["completed"]) < len(job["steps"]):
                step = job["steps"][len(job["completed"])]
                result = self.run(job["principal"], step["account"], step["operation"])
                if result["status"] != "COMPLETED":
                    job["status"] = result["status"]
                    job["blocked"] = result
                    job["attempts"] += 1
                    delay = min(300, 2 ** min(job["attempts"], 8)) if result["status"] == "RETRYABLE" else 1
                    self.save_job(job, time.time() + delay)
                    return
                job["completed"].append(result)
                job.pop("blocked", None)
                job["attempts"] = 0
                self.save_job(job)
            job["status"] = "COMPLETED"
            self.save_job(job)

    def tick(self):
        from .password_sync import due
        due(self.store)
        self.tick_schedules()
        with self.store.db() as db:
            ids = [r[0] for r in db.execute("SELECT id FROM jobs WHERE status IN ('QUEUED','RUNNING','NEEDS_USER','RETRYABLE') AND next_at<=? ORDER BY rowid LIMIT 20", (time.time(),))]
        for job_id in ids:
            try:
                job = self.store.get("job:" + job_id)
                if job.get("blocked", {}).get("status") == "NEEDS_USER":
                    # Do not keep hitting a provider while the same challenge is pending.
                    if self.store.pending(job["blocked"]["account"]):
                        continue
                self.advance(job_id)
            except AccessError:
                continue

    def tick_schedules(self):
        with self.store.lock("schedules", timeout=0):
            with self.store.db() as db:
                due = [dict(r) for r in db.execute("SELECT * FROM schedules WHERE enabled=1 AND next_at<=?", (time.time(),))]
            for schedule in due:
                details = self.store.get("schedule:" + schedule["id"])
                try:
                    self.submit(schedule["principal"], TaskRequest.model_validate({
                        "key": "schedule:" + schedule["id"] + ":" + str(int(schedule["next_at"])),
                        "steps": details["steps"],
                    }))
                    next_at = time.time() + schedule["interval"]
                    with self.store.db() as db:
                        db.execute("UPDATE schedules SET next_at=? WHERE id=?", (next_at, schedule["id"]))
                except AccessError:
                    with self.store.db() as db:
                        db.execute("UPDATE schedules SET enabled=0 WHERE id=?", (schedule["id"],))

    def audit(self, principal, limit=100):
        with self.store.db() as db:
            return {"status": "OK", "events": [dict(r) for r in db.execute(
                "SELECT * FROM audit WHERE principal=? ORDER BY id DESC LIMIT ?", (principal, min(limit, 100)))]}

    def metrics(self):
        with self.store.db() as db:
            challenges = db.execute("SELECT account,COUNT(*) count FROM challenges GROUP BY account").fetchall()
            counts = {r[0]: r[1] for r in db.execute("SELECT event,COUNT(*) FROM audit GROUP BY event")}
            jobs = {r[0]: r[1] for r in db.execute("SELECT status,COUNT(*) FROM jobs GROUP BY status")}
        return {"unique_challenges_per_account": {r[0]: r[1] for r in challenges},
                "events": counts, "tasks": jobs}
