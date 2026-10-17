"""Disposable-CI receiver; never installed as a consumer command.

Use the production isolated-worker bootstrap reader after the native launcher's
permanent UID drop. All receipts remain on inherited private FD 5, not stdout.
"""

import argparse
import errno
import hashlib
import hmac
import json
import os
import re
import runpy
from pathlib import Path
import socket
import struct

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from account_access.worker_bootstrap import read_bootstrap, read_policy, require_worker_identity
from account_access.storage import Store, check_private
from account_access.worker_enroll import initialize


def seed_native_host_fixture(store, settings):
    """CI-only source/client preparation; store already holds a verified key."""
    from urllib.parse import urlsplit
    from account_access.broker import Broker
    from account_access.demo import DEMO_PASSWORD
    from account_access.models import CodeSource

    base = settings["provider_url"]
    parts = urlsplit(base)
    digest = settings["client_digest"]
    config = store.config()
    if (
        config.test_mode is not True
        or config.accounts
        or parts.scheme != "http"
        or parts.hostname != "127.0.0.1"
        or not parts.port
        or parts.path
        or parts.username
        or parts.password
        or parts.query
        or parts.fragment
        or type(digest) is not str
        or re.fullmatch(r"[a-f0-9]{64}", digest) is None
    ):
        raise ValueError("invalid_native_host_fixture")
    module = Path(__file__).with_name("native-sms-fixture.py")
    from account_access.worker_bootstrap import root_managed_path

    root_managed_path(module)
    account = runpy.run_path(str(module))["native_account"](base, identity=True)
    with store.db() as db:
        if (
            db.execute("SELECT 1 FROM clients LIMIT 1").fetchone()
            or db.execute("SELECT 1 FROM grants LIMIT 1").fetchone()
        ):
            raise ValueError("invalid_native_host_fixture")
        db.execute("INSERT INTO clients VALUES (?, 'fixture-agent', 0)", (digest,))
    config.accounts["native-sms"] = account
    config.code_sources["native-sms"] = CodeSource(
        kind="mac_messages", sender="Example", recipient="owner", template="Example login: {code}"
    )
    store.configure(config)
    store.put("credential:native-sms", {"username": "demo@example.test", "password": DEMO_PASSWORD})
    store.put("source:native-sms", {"enabled": True})
    Broker(store).grant("fixture-agent", "native-sms", ["summary"])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--policy", required=True)
    parser.add_argument("--store-mode", choices=["create", "reopen", "native-host"], required=True)
    args = parser.parse_args()
    report = {"status": "FAILED", "reason": "key_handoff_probe_failed"}
    with socket.socket(fileno=5) as receipt:
        receipt.settimeout(15)
        try:
            policy = read_policy(args.policy)
            require_worker_identity(policy, worker_module=__file__, fresh=args.store_mode == "native-host")
            material = read_bootstrap(3)  # Exactly 64 bytes and EOF, production parser.
            sealed = os.read(4, 257)
            os.close(4)
            assert 28 < len(sealed) <= 256
            marker = AESGCM(material.vault_key).decrypt(sealed[:12], sealed[12:], None)
            assert marker == b"account-access-system-key-canary-v1"
            state = (
                Path(policy["root"])
                if args.store_mode == "native-host"
                else Path(args.policy).parent / "key-handoff-state"
            )
            check_private(state)
            if args.store_mode == "native-host":
                settings = json.loads(
                    Path(args.policy).with_name("native-host-fixture.json").read_bytes()
                )
                store = initialize(
                    state,
                    material.vault_key,
                    settings["vault_id"],
                    "33333333-3333-4333-8333-333333333333",
                    controlled_fixture=True,
                )
                seed_native_host_fixture(store, settings)
            elif args.store_mode == "create":
                assert not list(state.iterdir())
                store = initialize(
                    state,
                    material.vault_key,
                    "11111111-1111-4111-8111-111111111111",
                    "22222222-2222-4222-8222-222222222222",
                    controlled_fixture=True,
                )
                store.put("handoff-canary", {"marker": marker.decode()})
            else:
                for name in ["state.db", "config.json"]:
                    check_private(state / name)
                    assert (state / name).is_file() and (state / name).stat().st_nlink == 1
                store = Store(state, material.vault_key)
                assert store.config().test_mode is True
                assert store.get("handoff-canary") == {"marker": marker.decode()}
            try:
                os.fstat(128)
            except OSError as exc:
                if exc.errno != errno.EBADF:
                    raise
                closed = True
            else:
                closed = False
            assert closed
            proof = hmac.digest(
                material.owner_proof_key,
                b"account-access-key-handoff-ci-v1" + args.store_mode.encode() + sealed,
                hashlib.sha256,
            )
            report = {
                "status": "PASSED",
                "uid": os.getuid(),
                "gid": os.getgid(),
                "pid": os.getpid(),
                "proof": proof.hex(),
                "fd128_closed": closed,
                "storage_checked": True,
                "store_mode": args.store_mode,
            }
        except Exception:
            pass  # Never return traceback, bytes, configuration or key material.
        data = json.dumps(report).encode()
        receipt.sendall(struct.pack("!I", len(data)) + data)
        if report["status"] != "PASSED" or receipt.recv(1) != b"1":
            return 78
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
