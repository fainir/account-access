"""Native-only, one-time Harel email enrollment; private values stay local.

An owner-approved request sends one login email. The owner enters its first
code locally, reviews the exact redacted sender/subject/pattern, then approves
only session status. Later attempts use the existing purpose-bound resolver.
"""

from contextlib import ExitStack
import imaplib
import json
import re
import secrets
import threading
import time

from .codes import imap_number, mailbox_error
from .device_email_setup import _authority, _profile, _write_config
from .email_codes import MAX_MESSAGE_BYTES
from .errors import AccessError
from .factors import replace_source
from .harel_email_review import preview
from .harel_login import ACCOUNT, SOURCES, configuration, read as login_read
from .harel_protocol import HarelLogin
from .mailboxes import view as mailbox_view
from .models import CodeSource, Configuration

IDENT = re.compile(r"[a-f0-9]{32}")
ACTIVE = {"STARTING", "WAITING_CODE", "READING_EMAIL", "REVIEW", "VERIFYING", "TESTING"}
ATTEMPT_MAX_AGE_SECONDS = 600
ATTEMPT_FUTURE_SKEW_SECONDS = 5
ATTEMPT_LIMIT = 8
OPERATION_PREFIX = "harel-setup-operation:"
OPERATIONS_LOCK = "harel-setup-operations"
LIMIT_STATE = "harel-setup-admission-limit"
TERMINAL_REVISION = 2**53 - 1


def _created(ident):
    if not isinstance(ident, str) or not IDENT.fullmatch(ident):
        fail("invalid_harel_setup")
    # Native IDs keep their opaque 32-hex wire shape: UTC seconds followed by
    # 96 random bits. Expired IDs cannot become new after state is pruned.
    return int(ident[:8], 16)


def _age_valid(ident):
    created = _created(ident)
    now = time.time()
    return now - ATTEMPT_MAX_AGE_SECONDS < created <= now + ATTEMPT_FUTURE_SKEW_SECONDS


class _EnrollmentStore:
    """Unpublished setup authority, using the real code resolver and mailbox.

    Credentials/source/connection remain in memory until the automatic login
    succeeds. Code windows use the existing encrypted store and its locks.
    No temporary credential file, client identity or agent grant is created.
    """

    def __init__(self, store, config, records, active):
        self.store, self.configuration, self.records, self.active = store, config, records, active

    def __getattr__(self, name):
        return getattr(self.store, name)

    def config(self):
        self.active()
        return self.configuration

    def get(self, key, default=None):
        if key in self.records:
            self.active()
            return self.records[key]
        return self.store.get(key, default)

    def put(self, key, value, db=None):
        if key == "connection:" + ACCOUNT:
            self.active()
            self.records[key] = value
        else:
            self.store.put(key, value, db=db)

    def resolve_login(self, account, db=None):
        pass  # Unpublished setup cannot resolve an existing owner challenge.


def fail(reason="harel_setup_changed"):
    raise AccessError("NEEDS_USER", reason, "email")


def available(store):
    # Gmail through a checked TLS IMAP profile is supported here. A registered
    # Gmail OAuth client is a separate existing setup, not silently invented.
    result = []
    for item in mailbox_view(store):
        try:
            profile = _profile(store, item["id"])
        except AccessError:
            continue
        if profile.get("kind") != "gmail":
            result.append({"id": item["id"], "label": item["label"], "recipient": item["username"]})
    return result


def _vacant(store, config):
    source = SOURCES["email"]
    present = ACCOUNT in config.accounts
    if present != (source in config.code_sources):
        return False
    if present and config.accounts[ACCOUNT] != configuration("email"):
        return False
    if any(key != ACCOUNT and getattr(spec, "login", None) and source in spec.login.sources()
           for key, spec in config.accounts.items()):
        return False
    if any(store.get(prefix + key) is not None for prefix, key in (
            ("credential:", ACCOUNT), ("connection:", ACCOUNT), ("password-link:", ACCOUNT), ("source:", source))):
        return False
    with store.db() as db:
        return db.execute("SELECT 1 FROM grants WHERE account=? LIMIT 1", (ACCOUNT,)).fetchone() is None


def _source(profile, pattern=None):
    return CodeSource(kind="imap", host=profile["host"], port=profile["port"],
                      **(pattern or {"sender": "unconfigured@example.invalid", "recipient": profile["username"],
                                     "subject": "Unconfigured Harel review", "template": "Unconfigured: {code}"}))


def _mailbox(broker, profile):
    return broker.codes.mailbox(_source(profile), {"username": profile["username"], "password": profile["password"]},
                                broker.store.config())


def _baseline(broker, profile, active):
    try:
        active()
        with _mailbox(broker, profile) as mailbox:
            active()
            result = {}
            for name in ("UIDVALIDITY", "UIDNEXT"):
                active()
                response = mailbox.response(name)
                active()
                result[name] = imap_number(response[1])
        active()
        return result
    except (imaplib.IMAP4.error, OSError) as error:
        raise mailbox_error(error) from None


def _pattern(broker, profile, baseline, code, started, active):
    """Only new messages to the selected recipient and only the entered code."""
    recipient = profile["username"]
    quoted = '"' + recipient.replace('\\', '\\\\').replace('"', '\\"') + '"'
    try:
        active()
        with _mailbox(broker, profile) as mailbox:
            active()
            validity = mailbox.response("UIDVALIDITY")
            active()
            if imap_number(validity[1]) != baseline["UIDVALIDITY"]:
                fail("mailbox_uid_validity_changed")
            status, data = mailbox.uid("SEARCH", None, "UID", str(baseline["UIDNEXT"]) + ":*", "TO", quoted)
            active()
            if (status != "OK" or not isinstance(data, list) or len(data) != 1
                    or not isinstance(data[0], bytes) or len(data[0]) > 4096):
                fail("invalid_mailbox_response")
            ids = []
            for value in data[0].split():
                number = imap_number([value])
                if number >= baseline["UIDNEXT"] and value not in ids:
                    ids.append(value)
            if len(ids) > 20:
                fail("mailbox_result_limit")
            candidates = []
            for ident in ids:
                active()
                if time.time() > started + 120:
                    fail("login_code_window_expired")
                status, data = mailbox.uid("FETCH", ident, "(UID INTERNALDATE BODY.PEEK[]<0.256001>)")
                active()
                if status != "OK" or not isinstance(data, list):
                    fail("invalid_mailbox_response")
                bodies = [item for item in data if isinstance(item, tuple)]
                if len(bodies) != 1 or len(bodies[0]) != 2:
                    fail("invalid_mailbox_response")
                metadata, raw = bodies[0]
                if (not isinstance(metadata, bytes) or not isinstance(raw, bytes)
                        or re.findall(rb"(?:^|[ (])UID ([0-9]+)(?=[ )])", metadata) != [ident]):
                    fail("invalid_mailbox_response")
                received = imaplib.Internaldate2tuple(metadata)
                received_at = time.mktime(received) if received else None
                if (received_at is None or not int(started) <= received_at <= time.time() + 5
                        or len(raw) > MAX_MESSAGE_BYTES):
                    continue
                selected = preview(raw, recipient=recipient, code=code)
                if selected:
                    candidates.append(selected)
            if len(candidates) > 1:
                fail("ambiguous_login_code")
            return candidates[0] if candidates else None
    except (imaplib.IMAP4.error, OSError) as error:
        raise mailbox_error(error) from None
    except (TypeError, ValueError, OverflowError):
        fail("invalid_mailbox_response")


class HarelSetup:
    def __init__(self, broker):
        self.broker = broker
        self.guard = threading.RLock()
        self.jobs = {}
        self.key = secrets.token_bytes(32)

    def _operations(self, db):
        """Prune expired product operations while holding OPERATIONS_LOCK."""
        rows = db.execute("SELECT id,value FROM records WHERE id LIKE ?", (OPERATION_PREFIX + "%",)).fetchall()
        now = time.time()
        for row in rows:
            ident = row["id"][len(OPERATION_PREFIX):]
            if _created(ident) + ATTEMPT_MAX_AGE_SECONDS <= now:
                db.execute("DELETE FROM records WHERE id=?", (row["id"],))
        return db.execute("SELECT COUNT(*) FROM records WHERE id LIKE ?", (OPERATION_PREFIX + "%",)).fetchone()[0]

    def _record(self, db, ident):
        key = OPERATION_PREFIX + ident
        row = db.execute("SELECT value FROM records WHERE id=?", (key,)).fetchone()
        return self.broker.store.unseal(key, row[0]) if row else None

    def _reserve(self, db, ident, status):
        count = self._operations(db)
        row = db.execute("SELECT value FROM records WHERE id=?", (LIMIT_STATE,)).fetchone()
        denied_until = self.broker.store.unseal(LIMIT_STATE, row[0]) if row else 0
        if count >= ATTEMPT_LIMIT or denied_until > time.time():
            # No room for a cancellation tombstone: deny all unknown IDs until
            # every ID rejected now is too old to start, even if a slot frees.
            self.broker.store.put(LIMIT_STATE, max(denied_until, time.time()
                + ATTEMPT_MAX_AGE_SECONDS + ATTEMPT_FUTURE_SKEW_SECONDS), db=db)
            return None
        state = {"status": status, "revision": 0, "issued": False}
        self.broker.store.put(OPERATION_PREFIX + ident, state, db=db)
        return state

    @staticmethod
    def _terminal(ident, reason, status="NEEDS_USER"):
        return {"id": ident, "status": status, "reason": reason, "revision": TERMINAL_REVISION}

    @staticmethod
    def _adopt(job, state):
        if state["status"] != "ACTIVE":
            job.update(status=state["status"])
            if state.get("reason"):
                job["reason"] = state["reason"]
            if state["status"] != "COMPLETED" and "stop" in job:
                if state["status"] == "CANCELLED":
                    job["cancelled"] = True
                job["stop"].set()
                job["event"].set()

    def _job(self, ident):
        _created(ident)
        for old_id, job in list(self.jobs.items()):
            if not _age_valid(old_id):
                if "stop" in job:
                    job["cancelled"] = True
                    job["stop"].set()
                    job["event"].set()
                del self.jobs[old_id]
        if ident in self.jobs:
            return self.jobs[ident]
        # The manager cannot resume a private live cookie context after a
        # restart. Consume an old operation safely instead of sending again.
        store = self.broker.store
        with store.lock(OPERATIONS_LOCK, timeout=2), store.db() as db:
            if not _age_valid(ident):
                return self._terminal(ident, "harel_setup_expired")
            state = self._record(db, ident)
            if state is None:
                state = self._reserve(db, ident, "NEEDS_USER")
                if state is None:
                    return self._terminal(ident, "harel_setup_limit")
            if state["status"] in {"ACTIVE", "NEEDS_USER"} and not state.get("reason"):
                state.update(status="NEEDS_USER", reason="harel_setup_interrupted")
                store.put(OPERATION_PREFIX + ident, state, db=db)
            job = {"id": ident, "status": state["status"], "created": _created(ident)}
            self._adopt(job, state)
            self.jobs[ident] = job
            return job

    def _view(self, job):
        store = self.broker.store
        if job.get("revision") == TERMINAL_REVISION:
            return dict(job)
        with store.lock(OPERATIONS_LOCK, timeout=2), store.db() as db:
            if not _age_valid(job["id"]):
                return self._terminal(job["id"], "harel_setup_expired")
            state = self._record(db, job["id"])
            if state is None:
                return self._terminal(job["id"], "harel_setup_interrupted")
            if state["status"] == "ACTIVE" and time.monotonic() >= job.get("deadline", float("inf")):
                state.update(status="NEEDS_USER", reason="login_code_window_expired")
            self._adopt(job, state)
            state["revision"] = min(state["revision"] + 1, TERMINAL_REVISION - 1)
            store.put(OPERATION_PREFIX + job["id"], state, db=db)
        result = {"id": job["id"], "status": job["status"], "revision": state["revision"]}
        if job.get("reason"):
            result["reason"] = job["reason"]
        if job["status"] == "REVIEW":
            result.update(candidate=job["candidate"], review=dict(job["pattern"]))
        if job["status"] == "COMPLETED":
            result["authenticated"] = True
        return result

    def check(self, ident):
        with self.guard:
            return self._view(self._job(ident))

    def start(self, data):
        if (not isinstance(data, dict) or set(data) != {"id", "mailbox", "identity", "phone", "consent"}
                or not isinstance(data["id"], str) or not IDENT.fullmatch(data["id"])
                or data["consent"] is not True
                or not isinstance(data["identity"], str) or not re.fullmatch(r"[0-9]{5,9}", data["identity"])
                or not isinstance(data["phone"], str) or not re.fullmatch(r"05[0-9]{8}", data["phone"])):
            fail("invalid_harel_setup")
        import hmac
        digest = hmac.digest(self.key, json.dumps(data, sort_keys=True).encode(), "sha256")
        with self.guard:
            if data["id"] in self.jobs:
                job = self.jobs[data["id"]]
                if "request" in job and not secrets.compare_digest(digest, job["request"]):
                    fail()
                return self._view(job)
            store = self.broker.store
            with store.lock(OPERATIONS_LOCK, timeout=2), store.db() as db:
                if not _age_valid(data["id"]):
                    fail("harel_setup_expired")
                existing = self._record(db, data["id"])
            if existing is not None:
                return self._view(self._job(data["id"]))
            if any(job["status"] in ACTIVE or job["status"] == "CANCELLING" for job in self.jobs.values()):
                fail("harel_setup_busy")
            self.jobs = {key: job for key, job in self.jobs.items() if _age_valid(key)}
            config = store.config()
            if not _vacant(store, config):
                fail("harel_already_connected")
            profile = _profile(store, data["mailbox"])
            if profile.get("kind") == "gmail":
                fail("harel_tls_mailbox_required")
            with store.lock(OPERATIONS_LOCK, timeout=2), store.db() as db:
                # Cancellation or another manager can win during profile checks.
                existing = self._record(db, data["id"])
                if existing is None:
                    reserved = self._reserve(db, data["id"], "ACTIVE")
                else:
                    reserved = None
            if existing is not None:
                return self._view(self._job(data["id"]))
            if reserved is None:
                fail("harel_setup_limit")
            job = {"id": data["id"], "status": "STARTING", "created": time.time(), "request": digest,
                   "mailbox": data["mailbox"], "profile": _authority(profile), "event": threading.Event(),
                   "cancelled": False, "tries": 0, "stop": threading.Event()}
            self.jobs[data["id"]] = job
            threading.Thread(target=self._run, args=(job, profile, data["identity"], data["phone"]), daemon=True).start()
            return self._view(job)

    def code(self, ident, code):
        if not isinstance(code, str) or re.fullmatch(r"[0-9]{6}", code) is None:
            fail("invalid_login_code")
        with self.guard:
            job = self._job(ident)
            if job["status"] != "WAITING_CODE":
                fail()
            job.update(status="READING_EMAIL", code=code)
            job["event"].set()
            return self._view(job)

    def approve(self, ident, candidate):
        with self.guard:
            job = self._job(ident)
            if (job["status"] != "REVIEW" or not isinstance(candidate, str)
                    or not secrets.compare_digest(candidate, job["candidate"])):
                fail()
            job["status"] = "VERIFYING"
            job["event"].set()
            return self._view(job)

    def cancel(self, ident):
        with self.guard:
            _created(ident)
            if not _age_valid(ident):
                return self._terminal(ident, "harel_setup_expired")
            store = self.broker.store
            with store.lock(OPERATIONS_LOCK, timeout=2), store.db() as db:
                state = self._record(db, ident)
                if state is None:
                    state = self._reserve(db, ident, "CANCELLED")
                    if state is None:
                        return self._terminal(ident, "harel_setup_cancelled", "CANCELLED")
                if state["status"] in {"ACTIVE", "CANCELLED"}:
                    state.update(status="CANCELLED", reason="harel_setup_cancelled")
                    store.put(OPERATION_PREFIX + ident, state, db=db)
            job = self.jobs.get(ident) or {"id": ident, "created": _created(ident)}
            self._adopt(job, state)
            return self._view(job)

    def close(self):
        with self.guard:
            for job in self.jobs.values():
                if job["status"] in ACTIVE or job["status"] == "CANCELLING":
                    job["cancelled"] = True
                    job["stop"].set()
                    job["event"].set()
                    self.cancel(job["id"])

    def _active(self, job):
        state = self.broker.store.get(OPERATION_PREFIX + job["id"])
        if state is None:
            fail("harel_setup_interrupted")
        self._adopt(job, state)
        if job["cancelled"]:
            fail("harel_setup_cancelled")
        if state["status"] != "ACTIVE":
            fail(state.get("reason", "harel_setup_interrupted"))
        if not _age_valid(job["id"]):
            fail("harel_setup_expired")
        if time.monotonic() >= job["deadline"]:
            fail("login_code_window_expired")
        if not _vacant(self.broker.store, self.broker.store.config()):
            fail("harel_setup_changed")
        current = _profile(self.broker.store, job["mailbox"])
        if not secrets.compare_digest(_authority(current), job["profile"]):
            fail("harel_mailbox_changed")

    def _wait(self, job):
        while True:
            self._active(job)
            if job["event"].wait(min(1, max(0, job["deadline"] - time.monotonic()))):
                job["event"].clear()
                self._active(job)
                return

    def _claim_first_send(self, job):
        store = self.broker.store
        with store.lock(OPERATIONS_LOCK, timeout=2), store.db() as db:
            self._active(job)
            state = self._record(db, job["id"])
            if state["issued"]:
                fail("harel_setup_interrupted")
            # This durable handoff precedes any possible send. A restart or
            # uncertain response can never replay this native attempt ID.
            state["issued"] = True
            store.put(OPERATION_PREFIX + job["id"], state, db=db)

    def _finish(self, job):
        store = self.broker.store
        with store.lock(OPERATIONS_LOCK, timeout=2), store.db() as db:
            state = self._record(db, job["id"])
            if state is None:
                return
            if state["status"] == "ACTIVE":
                state.update(status=job["status"], reason=job["reason"])
                store.put(OPERATION_PREFIX + job["id"], state, db=db)
            else:
                self._adopt(job, state)

    def _publish(self, job, profile, identity, phone, state):
        store = self.broker.store
        with self.guard, ExitStack() as held:
            # _run owns the account for this attempt, before delivery/source locks.
            for name in ["catalog", "mailbox-profiles",
                         "source:" + SOURCES["email"], "code-window:" + SOURCES["email"], "configuration",
                         OPERATIONS_LOCK]:
                held.enter_context(store.lock(name, timeout=2))
            self._active(job)
            old = store.config()
            source = SOURCES["email"]
            if not _vacant(store, old):
                fail("harel_already_connected")
            updated = old.model_copy(deep=True)
            updated.accounts[ACCOUNT] = configuration("email")
            updated.code_sources[source] = _source(profile, job["pattern"])
            updated = Configuration.model_validate(updated.model_dump())
            # New-account publication adds no authority to any existing row.
            # Configuration is protected by the same lock as other owner writes.
            # If this transaction fails normally, restore the prior config.
            try:
                with store.db() as db:
                    _write_config(store, updated)
                    store.put("credential:" + ACCOUNT, {"identity": identity, "phone": phone}, db=db)
                    replace_source(store, source, {"enabled": True, "mailbox": job["mailbox"]}, db=db)
                    store.put("connection:" + ACCOUNT, {"state": state, "fingerprint": updated.fingerprint(ACCOUNT),
                                                        "generation": secrets.token_hex(16)}, db=db)
                    db.execute("INSERT INTO grants VALUES (?,?,?,?,?)",
                               ("generic", ACCOUNT, "status", updated.fingerprint(ACCOUNT), None))
                    db.execute("UPDATE challenges SET resolved=? WHERE account=? AND kind='login' AND resolved IS NULL AND reason IN ('identity_contact_not_connected','browser_login_required')",
                               (time.time(), ACCOUNT))
                    operation = self._record(db, job["id"])
                    operation.update(status="COMPLETED")
                    operation.pop("reason", None)
                    store.put(OPERATION_PREFIX + job["id"], operation, db=db)
            except Exception:
                _write_config(store, old)
                raise
            job["status"] = "COMPLETED"
            try:
                store.audit("owner", ACCOUNT, "status", "harel_email_setup_completed")
            except Exception:
                pass  # A saved, verified connection must not invite a duplicate request.

    def _run(self, job, profile, identity, phone):
        try:
            with self.broker.store.lock("account:" + ACCOUNT, timeout=0):
                with self.broker.store.lock("code-delivery:email", timeout=0), HarelLogin("email") as login:
                    job["deadline"] = time.monotonic() + 120
                    self._active(job)

                    def active():
                        self._active(job)

                    baseline = _baseline(self.broker, profile, active)
                    self._active(job)
                    login.open()
                    self._active(job)
                    if login.session_status()["authenticated"]:
                        fail("harel_setup_changed")
                    self._active(job)
                    login.select_channel()
                    self._active(job)
                    if time.time() - self.broker.store.get("login-attempt:" + ACCOUNT, 0) < 60:
                        fail("login_retry_cooldown")
                    started = time.time()
                    self.broker.store.put("login-attempt:" + ACCOUNT, started)
                    self._claim_first_send(job)
                    login.request_code(identity=identity, phone=phone)
                    self._active(job)
                    with self.guard:
                        job["status"] = "WAITING_CODE"
                    while True:
                        self._wait(job)
                        code = job.pop("code", None)
                        if not isinstance(code, str):
                            fail()
                        pattern = _pattern(self.broker, profile, baseline, code, started, active)
                        self._active(job)
                        with self.guard:
                            if not pattern:
                                job["tries"] += 1
                                if job["tries"] >= 3:
                                    fail("harel_email_not_found")
                                job.update(status="WAITING_CODE", reason="harel_email_not_found")
                                continue
                            job.update(status="REVIEW", pattern=pattern, candidate=secrets.token_hex(16))
                            job.pop("reason", None)
                        self._wait(job)
                        if job["status"] != "VERIFYING":
                            fail()
                        login.submit_code(code)
                        self._active(job)
                        break
                # Approval explicitly permits one additional email to verify
                # unattended delivery. Reuse Codes with unpublished in-memory
                # authority, not the first owner-entered code or a saved session.
                with self.guard:
                    job.update(status="TESTING", deadline=time.monotonic() + 120)
                while True:
                    self._active(job)
                    remaining = 60 - (time.time() - self.broker.store.get("login-attempt:" + ACCOUNT, 0))
                    if remaining <= 0:
                        break
                    job["stop"].wait(min(remaining, 1))
                stage = self.broker.store.config().model_copy(deep=True)
                stage.accounts[ACCOUNT] = configuration("email")
                source = SOURCES["email"]
                stage.code_sources[source] = _source(profile, job["pattern"])
                stage = Configuration.model_validate(stage.model_dump())
                records = {"credential:" + ACCOUNT: {"identity": identity, "phone": phone},
                           "source:" + source: {"enabled": True, "mailbox": job["mailbox"]},
                           "source-generation:" + source: secrets.token_hex(16)}
                local = _EnrollmentStore(self.broker.store, stage, records, lambda: self._active(job))
                from .browser import Browser
                from .codes import Codes
                browser = Browser(local, Codes(local, self.broker.oauth))
                spec = stage.accounts[ACCOUNT]
                login_read(browser, ACCOUNT, spec.operations["status"], spec, state=None, review_stop=job["stop"])
                self._active(job)
                state = local.get("connection:" + ACCOUNT)["state"]
                self._publish(job, profile, identity, phone, state)
        except AccessError as error:
            with self.guard:
                job.update(status="CANCELLED" if job["cancelled"] else "NEEDS_USER", reason=error.reason)
        except Exception:
            with self.guard:
                job.update(status="NEEDS_USER", reason="harel_setup_failed")
        finally:
            with self.guard:
                if job["status"] != "COMPLETED":
                    try:
                        self._finish(job)
                    except Exception:
                        job.update(status="NEEDS_USER", reason="harel_setup_failed")
                for field in ("code", "pattern", "candidate"):
                    job.pop(field, None)
