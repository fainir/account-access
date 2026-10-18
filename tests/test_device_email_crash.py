"""Real process death at publication boundaries, using only fictional local state."""

import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path

import pytest

from account_access import device_email_setup
from account_access.broker import Broker
from account_access.catalog import PYPI_ACCOUNT, PYPI_SOURCE, pypi
from account_access.errors import AccessError
from account_access.mailboxes import enrollment
from account_access.models import CodeSource, Configuration
from account_access.storage import Store

KEY = b"k" * 32  # Public, synthetic fixture key; never an owner/vault key.
MAILBOX = "mailbox-" + "a" * 24
PHASES = ("quarantine_committed", "config_published", "publication_committed")

# This child never starts a service or obtains credentials from the host. The
# public code receives a synthetic key/profile and normal process privileges.
# Killing the process rather than raising an exception bypasses all rollback
# handlers and lets a new parent Store exercise SQLite's real crash recovery.
CHILD = r"""
import os
import signal
import sys
from contextlib import contextmanager
from pathlib import Path

sys.path.insert(0, sys.argv[1])
from account_access import device_email_setup as setup
from account_access.storage import Store

root, phase, operation, review, marker = sys.argv[2:]
assert phase in {"quarantine_committed", "config_published", "publication_committed"}
assert operation in {"apply", "remove"}

def no_network(event, arguments):
    if event in {"socket.bind", "socket.connect", "socket.getaddrinfo", "socket.sendto"}:
        raise RuntimeError("crash_test_network_forbidden")

sys.addaudithook(no_network)
store = Store(Path(root), b"k" * 32)

def die():
    fd = os.open(marker, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as stream:
        stream.write(phase)
        stream.flush()
        os.fsync(stream.fileno())
    os.kill(os.getpid(), signal.SIGKILL)
    raise AssertionError("SIGKILL did not terminate the test child")

original_quarantine = setup._quarantine
original_write = setup._write_config
original_db = store.db
published = False

def quarantine(*args, **kwargs):
    value = original_quarantine(*args, **kwargs)
    if phase == "quarantine_committed":
        die()
    return value

def write(*args, **kwargs):
    global published
    original_write(*args, **kwargs)
    published = True
    if phase == "config_published":
        die()

@contextmanager
def database():
    with original_db() as db:
        yield db
    # No inner Store.db is opened between _write_config and this publication
    # transaction's exit. Exiting original_db commits before this kill point.
    if published and phase == "publication_committed":
        die()

setup._quarantine = quarantine
setup._write_config = write
store.db = database
if operation == "apply":
    setup.apply(store, review)
else:
    setup.remove(store, "personal-pypi", review)
raise AssertionError("requested crash boundary was not reached")
"""


@pytest.fixture
def crash_store(tmp_path):
    store = Store(tmp_path / "fictional-store", KEY)
    config = Configuration(accounts={PYPI_ACCOUNT: pypi()},
                           code_sources={PYPI_SOURCE: CodeSource(kind="totp")})
    store.configure(config)
    store.new_client("crash-approved")
    store.new_client("crash-stale")
    broker = Broker(store)
    broker.grant("crash-approved", PYPI_ACCOUNT, ["status"])
    with store.db() as db:
        db.execute("INSERT INTO grants VALUES (?,?,?,?,?)",
                   ("crash-stale", PYPI_ACCOUNT, "status", "f" * 64, None))
    fingerprint = config.fingerprint(PYPI_ACCOUNT)
    store.put("credential:" + PYPI_ACCOUNT,
              {"username": "fictional-pypi-user", "password": "synthetic-website-password"})
    store.put("mailbox-profile:" + MAILBOX,
              {"label": "Fictional mailbox", "generation": "b" * 32,
               "connection_check": {"status": "VERIFIED", "checked": time.time()},
               "username": "crash-qa@example.test", "password": "synthetic-mail-password",
               "host": "imap.example.test", "port": 993})
    store.put("connection:" + PYPI_ACCOUNT,
              {"fingerprint": fingerprint, "generation": "synthetic-session-generation",
               "state": {"cookies": [], "origins": []}})
    store.put("password-link:" + PYPI_ACCOUNT,
              {"fingerprint": fingerprint, "generation": "c" * 32,
               "status": "SYNCED", "username": "fictional-pypi-user",
               "provider": "onepassword-service-account", "token": "synthetic-source-token",
               "vault": "a" * 26, "item": "b" * 26, "next_at": time.time() + 300})
    gate = store.challenge(PYPI_ACCOUNT, "passkey", "browser_passkey_required")
    return store, fingerprint, gate["id"]


def review(store):
    return device_email_setup.preview(store, PYPI_ACCOUNT,
                                      store.config().fingerprint(PYPI_ACCOUNT), MAILBOX)


def kill_at(store, phase, operation, reviewed, tmp_path):
    marker = tmp_path / "reached-crash-boundary"
    result = subprocess.run(
        [sys.executable, "-I", "-c", CHILD, str(Path(__file__).resolve().parents[1]),
         str(store.root), phase, operation, reviewed, str(marker)],
        capture_output=True, text=True, timeout=20,
        env={"PATH": os.defpath, "LC_ALL": "C", "TZ": "UTC"})
    assert result.returncode == -signal.SIGKILL, result.stderr
    assert marker.read_text() == phase
    assert result.stdout == result.stderr == ""
    return Store(store.root, KEY)


def authority(store, *, permitted):
    broker = Broker(store)
    if permitted:
        broker.permit("crash-approved", PYPI_ACCOUNT, "status")
    else:
        with pytest.raises(AccessError) as error:
            broker.permit("crash-approved", PYPI_ACCOUNT, "status")
        assert error.value.reason in {"owner_configuration_changed", "standing_permission_missing"}
    with pytest.raises(AccessError):
        broker.permit("crash-stale", PYPI_ACCOUNT, "status")
    fingerprint = store.config().fingerprint(PYPI_ACCOUNT)
    for prefix in ["connection:", "password-link:"]:
        record = store.get(prefix + PYPI_ACCOUNT)
        assert (record["fingerprint"] == fingerprint) is permitted
        if not permitted:
            assert record["fingerprint"].startswith("device-email-quarantine:")
    link = store.get("password-link:" + PYPI_ACCOUNT)
    assert link["status"] == "SYNCED"
    assert link["token"] == "synthetic-source-token"
    assert link["generation"] == "c" * 32


def cycle(store, original, *, permitted):
    """Return to the historical fingerprint, then reapply without a new grant."""
    if store.config().accounts[PYPI_ACCOUNT].login.device_email_source:
        device_email_setup.remove(store, PYPI_ACCOUNT, store.config().fingerprint(PYPI_ACCOUNT))
    assert store.config().fingerprint(PYPI_ACCOUNT) == original
    authority(store, permitted=permitted)
    pending = review(store)
    assert [item["name"] for item in pending["operations"]] == (["status"] if permitted else [])
    device_email_setup.apply(store, pending["id"])
    authority(store, permitted=permitted)
    device_email_setup.remove(store, PYPI_ACCOUNT, store.config().fingerprint(PYPI_ACCOUNT))
    assert store.config().fingerprint(PYPI_ACCOUNT) == original
    authority(store, permitted=permitted)


@pytest.mark.skipif(not hasattr(signal, "SIGKILL") or os.name != "posix", reason="requires POSIX SIGKILL")
@pytest.mark.parametrize("phase", PHASES)
@pytest.mark.parametrize("operation", ["apply", "remove"])
def test_real_sigkill_never_revives_uncommitted_authority(crash_store, tmp_path, phase, operation):
    store, original, gate = crash_store
    if operation == "remove":
        device_email_setup.apply(store, review(store)["id"])
        inspected = store.config().fingerprint(PYPI_ACCOUNT)
    else:
        inspected = review(store)["id"]
    reopened = kill_at(store, phase, operation, inspected, tmp_path)
    committed = phase == "publication_committed"
    authority(reopened, permitted=committed)
    source = reopened.config().accounts[PYPI_ACCOUNT].login.device_email_source
    if source:
        connected = device_email_setup.view(reopened)[0]["connected"]
        assert connected is (committed if operation == "apply" else True)
        if connected:
            assert enrollment(reopened, source)["password"] == "synthetic-mail-password"
        else:
            assert reopened.get("source:" + source) is None
    else:
        assert operation == "remove" or phase == "quarantine_committed"
    # Neither connecting mail nor a complete SQLite publication approves an
    # independent device/presence challenge.
    assert [item["id"] for item in reopened.pending(PYPI_ACCOUNT)] == [gate]
    cycle(reopened, original, permitted=committed)
    assert [item["id"] for item in reopened.pending(PYPI_ACCOUNT)] == [gate]
    # The child's fixture data stays in the encrypted record store, including
    # after SQLite WAL recovery. No plaintext staging export is involved.
    for path in reopened.root.glob("state.db*"):
        payload = path.read_bytes()
        for secret in [b"synthetic-mail-password", b"synthetic-source-token", b"synthetic-website-password"]:
            assert secret not in payload
    assert json.dumps(device_email_setup.view(reopened)).find("synthetic-") == -1
