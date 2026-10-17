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
import socket
import struct

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from account_access.worker_bootstrap import read_bootstrap, read_policy, require_worker_identity


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--policy", required=True)
    args = parser.parse_args()
    report = {"status": "FAILED", "reason": "key_handoff_probe_failed"}
    with socket.socket(fileno=5) as receipt:
        receipt.settimeout(15)
        try:
            policy = read_policy(args.policy)
            require_worker_identity(policy, worker_module=__file__)
            material = read_bootstrap(3)  # Exactly 64 bytes and EOF, production parser.
            sealed = os.read(4, 257)
            os.close(4)
            assert 28 < len(sealed) <= 256
            marker = AESGCM(material.vault_key).decrypt(sealed[:12], sealed[12:], None)
            assert marker == b"account-access-system-key-canary-v1"
            try:
                os.fstat(128)
            except OSError as exc:
                if exc.errno != errno.EBADF:
                    raise
                closed = True
            else:
                closed = False
            assert closed
            proof = hmac.digest(material.owner_proof_key, b"account-access-key-handoff-ci-v1" + sealed, hashlib.sha256)
            report = {"status": "PASSED", "uid": os.getuid(), "gid": os.getgid(), "pid": os.getpid(),
                      "proof": proof.hex(), "fd128_closed": closed}
        except Exception:
            pass  # Never return traceback, bytes, configuration or key material.
        data = json.dumps(report).encode()
        receipt.sendall(struct.pack("!I", len(data)) + data)
        if report["status"] != "PASSED" or receipt.recv(1) != b"1":
            return 78
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
