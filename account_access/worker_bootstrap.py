"""Private bootstrap primitives for a separately managed broker worker.

The trusted supervisor must own the runtime, create both listeners and drop the
worker's identity before exec. These checks do not turn a same-user process into
an isolation boundary, and this module does not install or elevate a service.
"""

import base64
from dataclasses import dataclass
import hashlib
import hmac
import json
import os
from pathlib import Path
import selectors
import socket
import stat
import sys
import time


class BootstrapError(Exception):
    def __init__(self, reason):
        self.reason = reason
        super().__init__(reason)


@dataclass(repr=False)
class BootstrapSecrets:
    vault_key: bytes
    owner_token: str
    owner_proof_key: bytes

    def __repr__(self):
        return "<BootstrapSecrets redacted>"


def read_bootstrap(fd, *, issuer_uid=0, timeout=3):
    """Consume exactly 64 bytes and EOF from the supervisor's private pipe.

    No secret is accepted from argv, an environment variable, a regular file or
    a fallback keyring. The inherited descriptor is closed on every outcome.
    On Darwin, pipe stat ownership describes the caller, not the creator;
    root provenance is the trusted native launcher's responsibility. Its
    protected policy/runtime and separate worker identity are checked first.
    """
    if type(fd) is not int or fd < 3 or not 0 < timeout <= 10:
        raise BootstrapError("invalid_worker_bootstrap")
    data = bytearray()
    try:
        info = os.fstat(fd)
        # XNU pipe_stat synthesizes uid/gid from the current caller and leaves
        # dev/nlink zero. Do not mistake that uid for root-creator attestation.
        # A vnode-backed filesystem FIFO is never a Darwin bootstrap channel.
        if sys.platform == "darwin":
            trusted_pipe = (info.st_uid == os.getuid() and issuer_uid in (0, os.getuid())
                            and info.st_dev == 0 and info.st_nlink == 0)
        else:
            trusted_pipe = info.st_uid == issuer_uid
        if not stat.S_ISFIFO(info.st_mode) or not trusted_pipe:
            raise BootstrapError("invalid_worker_bootstrap")
        os.set_inheritable(fd, False)
        os.set_blocking(fd, False)
        deadline = time.monotonic() + timeout
        with selectors.DefaultSelector() as ready:
            ready.register(fd, selectors.EVENT_READ)
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0 or not ready.select(remaining):
                    raise BootstrapError("worker_bootstrap_timed_out")
                try:
                    chunk = os.read(fd, 65 - len(data))
                except BlockingIOError:
                    continue
                if not chunk:
                    break
                data.extend(chunk)
                if len(data) > 64:
                    raise BootstrapError("invalid_worker_bootstrap")
        if len(data) != 64:
            raise BootstrapError("invalid_worker_bootstrap")
        owner = bytes(data[32:])
        return BootstrapSecrets(bytes(data[:32]), base64.urlsafe_b64encode(owner).decode().rstrip("="),
                                hmac.digest(owner, b"account-access-owner-channel-v1", hashlib.sha256))
    except BootstrapError:
        raise
    except (OSError, ValueError):
        raise BootstrapError("invalid_worker_bootstrap") from None
    finally:
        data[:] = b"\0" * len(data)
        try:
            os.close(fd)
        except OSError:
            pass


def take_listener(fd, *, issuer_uid=0):
    """Take ownership of an inherited, already-listening Unix stream socket."""
    if type(fd) is not int or fd < 3:
        raise BootstrapError("invalid_worker_listener")
    listener = None
    try:
        info = os.fstat(fd)
        if not stat.S_ISSOCK(info.st_mode) or info.st_uid != issuer_uid:
            raise BootstrapError("invalid_worker_listener")
        listener = socket.socket(fileno=fd)
        listener.set_inheritable(False)
        name = listener.getsockname()
        if (listener.family != socket.AF_UNIX
                or listener.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE) != socket.SOCK_STREAM
                or not isinstance(name, str) or not name.startswith("/") or "\0" in name):
            raise BootstrapError("invalid_worker_listener")
        listener.listen(128)
        return listener
    except (OSError, ValueError, BootstrapError):
        if listener is not None:
            listener.close()
        else:
            try:
                os.close(fd)
            except OSError:
                pass
        raise BootstrapError("invalid_worker_listener") from None


def root_managed_path(path):
    """Reject code reached through agent-writable files or parent directories."""
    try:
        original = Path(path).absolute()
        resolved = original.resolve(strict=True)
        pending, checked = [original, resolved], set()
        while pending:
            endpoint = pending.pop()
            if endpoint in checked:
                continue
            checked.add(endpoint)
            if len(checked) > 64:
                raise BootstrapError("untrusted_worker_runtime")
            for item in [endpoint, *endpoint.parents]:
                info = item.lstat()
                if info.st_uid != 0 or (not stat.S_ISLNK(info.st_mode) and info.st_mode & 0o022):
                    raise BootstrapError("untrusted_worker_runtime")
                if stat.S_ISLNK(info.st_mode):
                    target = Path(os.readlink(item))
                    pending.append(target if target.is_absolute() else item.parent / target)
        return resolved
    except (OSError, RuntimeError):
        raise BootstrapError("untrusted_worker_runtime") from None


def read_policy(path):
    """Read non-secret identity/path bindings from the supervisor's root-owned policy."""
    try:
        path = root_managed_path(path)
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > 4096:
            raise ValueError()
        value = json.loads(path.read_bytes())
        if (not isinstance(value, dict) or set(value) != {"managed_by", "schema", "broker_uid",
                "agent_uid", "root", "agent_socket", "owner_socket", "owner_port"}
                or value["managed_by"] != "account-access-worker-v1"
                or type(value["schema"]) is not int or value["schema"] != 1
                or any(type(value[name]) is not int or value[name] <= 0
                       for name in ["broker_uid", "agent_uid", "owner_port"])
                or value["broker_uid"] == value["agent_uid"] or value["owner_port"] > 65535):
            raise ValueError()
        for name in ["root", "agent_socket", "owner_socket"]:
            raw = value[name]
            if (not isinstance(raw, str) or not raw.startswith("/") or "\0" in raw
                    or ".." in Path(raw).parts or str(Path(raw)) != raw):
                raise ValueError()
        if value["agent_socket"] == value["owner_socket"]:
            raise ValueError()
        for name in ["agent_socket", "owner_socket"]:
            directory = root_managed_path(Path(value[name]).parent)
            if not directory.is_dir():
                raise ValueError()
            if name == "owner_socket" and directory.stat().st_mode & 0o077:
                raise ValueError()
        return value
    except (OSError, ValueError, TypeError, KeyError, BootstrapError):
        raise BootstrapError("invalid_worker_policy") from None


def require_worker_identity(policy, *, worker_module, fresh=False):
    """Validate the supervisor's identity/runtime contract before reading keys."""
    try:
        worker_uid = os.getuid()
        if (worker_uid != policy["broker_uid"] or worker_uid in {0, policy["agent_uid"]}
                or os.geteuid() != worker_uid or os.getgid() == 0 or os.getegid() != os.getgid()
                or 0 in os.getgroups()
                or (hasattr(os, "getresuid") and len(set(os.getresuid())) != 1)):
            raise BootstrapError("invalid_worker_identity")
        if not sys.flags.isolated:
            raise BootstrapError("worker_requires_isolated_python")
        for path in [sys.executable, sys.prefix, __file__, worker_module]:
            root_managed_path(path)
        if sys.platform == "linux":
            status = {}
            for line in Path("/proc/self/status").read_text().splitlines():
                name, _, value = line.partition(":")
                status[name] = value.strip()
            if (status.get("NoNewPrivs") != "1" or any(
                    int(status.get(name, "1"), 16) != 0
                    for name in ["CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"])):
                raise BootstrapError("unsafe_worker_privileges")
        root = Path(policy["root"])
        info = root.lstat()
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != worker_uid or info.st_mode & 0o077
                or not root.is_absolute()):
            raise BootstrapError("unsafe_worker_state")
        root_managed_path(root.parent)
        if type(fresh) is not bool:
            raise BootstrapError("unsafe_worker_state")
        if fresh:
            # Only the separate initializer requests this path, after native
            # owner authorization and private staging preparation. Never infer
            # initialization from a missing database in the ordinary worker.
            if any(root.iterdir()):
                raise BootstrapError("worker_enrollment_state_not_empty")
            return root.resolve()
        # Ordinary workers open an existing enrolled store only.
        for name in ["state.db", "config.json"]:
            item = (root / name).lstat()
            if (not stat.S_ISREG(item.st_mode) or item.st_uid != worker_uid
                    or item.st_nlink != 1 or item.st_mode & 0o077):
                raise BootstrapError("unsafe_worker_state")
        return root.resolve()
    except BootstrapError:
        raise
    except (OSError, ValueError):
        raise BootstrapError("unsafe_worker_state") from None
