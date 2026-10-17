"""Native-owner enrollment of one portable client; never writes an owner's home.

The separately managed worker accepts only a client capability generated locally
by the owner setup flow. It stores its digest, returns no capability, and cannot
silently replace or revive an existing connection. Native setup authorization is
enforced before this module by the pinned owner gateway.
"""

import hashlib
import re

from .errors import AccessError


RECORD = "native-portable-client-v1"
HOSTS = {"codex", "claude"}


def identity(token):
    if type(token) is not str or re.fullmatch(r"[A-Za-z0-9_-]{43}", token) is None:
        raise AccessError("DENIED", "invalid_client_enrollment")
    return hashlib.sha256(token.encode()).hexdigest()


def enroll(store, token):
    digest = identity(token)
    with store.lock(RECORD):
        with store.db() as db:
            db.execute("BEGIN IMMEDIATE")
            record = db.execute("SELECT value FROM records WHERE id=?", (RECORD,)).fetchone()
            existing = store.unseal(RECORD, record[0]) if record else None
            row = db.execute(
                "SELECT principal,revoked FROM clients WHERE digest=?", (digest,)
            ).fetchone()
            if existing is not None:
                if (
                    type(existing) is not dict
                    or type(existing.get("schema")) is not int
                    or existing.get("schema") != 1
                    or existing.get("client_id") != digest
                    or not row
                    or row["principal"] != "generic"
                ):
                    raise AccessError("NEEDS_USER", "client_connection_conflict")
                if row["revoked"] != 0:
                    raise AccessError("NEEDS_USER", "portable_client_revoked")
                return {"status": "ENROLLED", "client_id": digest, "principal": "generic"}
            if (
                row
                or db.execute("SELECT 1 FROM clients WHERE principal='generic' LIMIT 1").fetchone()
            ):
                raise AccessError("NEEDS_USER", "client_connection_conflict")
            if any(
                db.execute(
                    "SELECT 1 FROM " + table + " WHERE principal='generic' LIMIT 1"
                ).fetchone()
                for table in ["grants", "jobs", "schedules"]
            ):
                raise AccessError("NEEDS_USER", "client_connection_conflict")
            db.execute("INSERT INTO clients VALUES (?,'generic',0)", (digest,))
            store.put(RECORD, {"schema": 1, "client_id": digest, "installed": False}, db=db)
    return {"status": "ENROLLED", "client_id": digest, "principal": "generic"}


def installed(store, client_id, hosts):
    if (
        type(client_id) is not str
        or re.fullmatch(r"[a-f0-9]{64}", client_id) is None
        or type(hosts) is not list
        or len(hosts) > 2
        or any(type(host) is not str or host not in HOSTS for host in hosts)
        or len(hosts) != len(set(hosts))
    ):
        raise AccessError("DENIED", "invalid_client_enrollment")
    with store.lock(RECORD):
        with store.db() as db:
            db.execute("BEGIN IMMEDIATE")
            record = db.execute("SELECT value FROM records WHERE id=?", (RECORD,)).fetchone()
            existing = store.unseal(RECORD, record[0]) if record else None
            active = db.execute(
                "SELECT 1 FROM clients WHERE digest=? AND principal='generic' AND revoked=0",
                (client_id,),
            ).fetchone()
            if (
                type(existing) is not dict
                or type(existing.get("schema")) is not int
                or existing.get("schema") != 1
                or existing.get("client_id") != client_id
                or not active
            ):
                raise AccessError("NEEDS_USER", "client_connection_conflict")
            store.put(RECORD, {"schema": 1, "client_id": client_id, "installed": True}, db=db)
            store.put("agent-integrations", sorted(hosts), db=db)
            store.put(
                "session-integrations", {host: {"enabled": True} for host in sorted(hosts)}, db=db
            )
    return {"status": "INSTALLED", "client_id": client_id, "principal": "generic"}


def view(store):
    record = store.get(RECORD)
    if not record:
        return {"status": "NOT_CONNECTED"}
    if (
        type(record) is not dict
        or type(record.get("schema")) is not int
        or record.get("schema") != 1
        or type(record.get("client_id")) is not str
        or re.fullmatch(r"[a-f0-9]{64}", record["client_id"]) is None
    ):
        return {"status": "NEEDS_REPAIR"}
    with store.db() as db:
        row = db.execute(
            "SELECT revoked FROM clients WHERE digest=? AND principal='generic'",
            (record["client_id"],),
        ).fetchone()
    if not row or row["revoked"] != 0:
        return {"status": "REVOKED"}
    return {
        "status": "INSTALLED" if record.get("installed") is True else "ENROLLED",
        "client_id": record["client_id"],
        "principal": "generic",
    }
