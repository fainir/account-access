"""Private staged-store initializer for a trusted native supervisor.

No elevation, owner authorization, key enrollment or publication happens here.
The native parent must authorize setup, own the runtime/policy, select a private
empty stage and permanently drop this child's identity before handing it keys.
"""
import argparse
import hashlib
import hmac
import json
import os
from pathlib import Path
import resource
import socket
import stat
import struct
import uuid

from .models import Configuration
from .storage import Store, check_private
from .worker_bootstrap import BootstrapError, read_bootstrap, read_policy, require_worker_identity


RECORD = "system-vault-enrollment-v1"
DOMAIN = b"account-access-vault-enrollment-v1\0"


def canonical_uuid(value):
    try:
        if type(value) is not str or str(uuid.UUID(value)) != value:
            raise ValueError()
        return value
    except (ValueError, AttributeError):
        raise BootstrapError("invalid_worker_enrollment_identity") from None


def receipt_message(vault_id, enrollment_id, root):
    return DOMAIN + canonical_uuid(vault_id).encode() + b"\0" + canonical_uuid(enrollment_id).encode() + b"\0" + str(root).encode()


def verify_store_key(store):
    """Authenticate actual ciphertext before a private worker reports ready.

    New stores have a dedicated marker. Older enrolled stores must have at
    least one authentic encrypted record; no verification marker is silently
    created with an uncertain key. No decrypted record leaves this process.
    """
    with store.db() as database:
        row = database.execute("SELECT id,value FROM records ORDER BY (id=?) DESC,id LIMIT 1", (RECORD,)).fetchone()
    if row is None:
        raise BootstrapError("worker_vault_key_verification_required")
    value = store.unseal(row[0], row[1])
    if row[0] == RECORD:
        if not isinstance(value, dict) or set(value) != {"schema", "vault_id", "enrollment_id"} or type(value["schema"]) is not int or value["schema"] != 1:
            raise BootstrapError("invalid_worker_enrollment_identity")
        canonical_uuid(value["vault_id"])
        canonical_uuid(value["enrollment_id"])


def initialize(root, key, vault_id, enrollment_id, *, controlled_fixture=False):
    """Initialize only a caller-validated, empty, private staging directory."""
    canonical_uuid(vault_id)
    canonical_uuid(enrollment_id)
    if type(key) is not bytes or len(key) != 32 or type(controlled_fixture) is not bool:
        raise BootstrapError("invalid_worker_bootstrap")
    root = Path(root)
    check_private(root)
    if not root.is_absolute() or root.is_symlink() or not root.is_dir() or any(root.iterdir()):
        raise BootstrapError("worker_enrollment_state_not_empty")
    # Claim atomically before SQLite/configuration creation. Two initializers
    # that both observed emptiness cannot overwrite each other's staged work.
    claim = os.open(root / ".enrollment-claim", os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    os.close(claim)
    store = Store(root, key)
    store.configure(Configuration(accounts={}, test_mode=controlled_fixture))
    store.put(RECORD, {"schema": 1, "vault_id": vault_id, "enrollment_id": enrollment_id})
    verify_store_key(store)
    directory = os.open(root, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0))
    try:
        os.fsync(directory)
    finally:
        os.close(directory)
    return store


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--policy", required=True)
    parser.add_argument("--vault-id", required=True)
    parser.add_argument("--enrollment-id", required=True)
    parser.add_argument("--bootstrap-fd", type=int, required=True)
    parser.add_argument("--receipt-fd", type=int, required=True)
    parser.add_argument("--controlled-fixture", action="store_true")
    args = parser.parse_args(argv)
    os.umask(0o077)
    receipt = None
    try:
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        if args.bootstrap_fd < 3 or args.receipt_fd < 3 or args.bootstrap_fd == args.receipt_fd:
            raise BootstrapError("invalid_worker_descriptors")
        policy = read_policy(args.policy)
        root = require_worker_identity(policy, worker_module=__file__, fresh=True)
        canonical_uuid(args.vault_id)
        canonical_uuid(args.enrollment_id)
        info = os.fstat(args.receipt_fd)
        if not stat.S_ISSOCK(info.st_mode) or info.st_uid != 0:
            raise BootstrapError("invalid_worker_descriptors")
        receipt = socket.socket(fileno=args.receipt_fd)
        if receipt.family != socket.AF_UNIX or receipt.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE) != socket.SOCK_STREAM:
            raise BootstrapError("invalid_worker_descriptors")
        receipt.set_inheritable(False)
        receipt.settimeout(15)
        material = read_bootstrap(args.bootstrap_fd)
        initialize(root, material.vault_key, args.vault_id, args.enrollment_id, controlled_fixture=args.controlled_fixture)
        proof = hmac.digest(material.owner_proof_key, receipt_message(args.vault_id, args.enrollment_id, root), hashlib.sha256)
        report = {"status": "INITIALIZED", "vault_id": args.vault_id, "enrollment_id": args.enrollment_id,
                  "uid": os.getuid(), "gid": os.getgid(), "pid": os.getpid(), "proof": proof.hex()}
        data = json.dumps(report).encode()
        receipt.sendall(struct.pack("!I", len(data)) + data)
        if receipt.recv(1) != b"1":
            raise BootstrapError("worker_enrollment_receipt_unconfirmed")
        return 0
    except Exception:
        # No exception text, configuration, keys or receipt proof on stdout.
        print('{"status":"NEEDS_USER","reason":"worker_enrollment_failed"}')
        return 78
    finally:
        if receipt is not None:
            receipt.close()


if __name__ == "__main__":
    raise SystemExit(main())
