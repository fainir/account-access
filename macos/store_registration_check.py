# ruff: noqa: E402 -- reject unsafe interpreter flags before source imports.
"""Read-only registration diagnosis; no credential, key, database or service API.

The installed entrypoint has no arguments or path overrides. Only root-owned
program policies and the publication registration are read. The two private
store directories are statted, never opened or enumerated. No file is written.
"""

import sys

if __name__ == "__main__" and (
    not sys.flags.isolated or not sys.flags.no_site or not sys.dont_write_bytecode
):
    print('{"schema":1,"status":"REFUSED","reason":"installer_context_required"}')
    raise SystemExit(1)

import ctypes
import errno
import fcntl
import hashlib
import json
import os
import stat
import uuid

BASE = "/Library/Application Support/Account Access"
PYTHON = BASE + "/runtime/bin/python3.12"
PINS = {
    "bin/AccountAccess-broker": "22472ef4d1fdcf2e18eefd46213c55c94db8d761f4d47970f9e1816189e7c97f",
    "package-identity.json": "75692fee2d246fa51f8455287e5491162eaa584554ee9d9c1c08571bd7e5682c",
    "owner.app/Contents/Info.plist": "8eb499ed801d6f44fd3dbb2f13ef8eb7bce3fa028df5a2ea9560ad656995a31f",
}
DIRECTORY = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
REGULAR = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK
REASONS = frozenset(
    {
        "installer_context_required",
        "public_image_changed",
        "metadata_unavailable",
        "metadata_changed",
        "unsafe_metadata",
        "invalid_registration",
        "registration_busy",
        "registration_not_published",
        "registration_matches",
        "device_number_changed",
        "directory_identity_mismatch",
        "registration_paused",
        "registration_not_authorized",
    }
)


class Refused(Exception):
    pass


def require(condition, reason="invalid_registration"):
    if not condition:
        raise Refused(reason)


def no_acl(fd):
    library = ctypes.CDLL(None, use_errno=True)
    library.acl_get_fd.argtypes = [ctypes.c_int]
    library.acl_get_fd.restype = ctypes.c_void_p
    library.acl_get_entry.argtypes = [
        ctypes.c_void_p,
        ctypes.c_int,
        ctypes.POINTER(ctypes.c_void_p),
    ]
    library.acl_get_entry.restype = ctypes.c_int
    library.acl_free.argtypes = [ctypes.c_void_p]
    ctypes.set_errno(0)
    acl = library.acl_get_fd(fd)
    if not acl:
        require(ctypes.get_errno() == errno.ENOENT, "unsafe_metadata")
        return
    try:
        entry = ctypes.c_void_p()
        ctypes.set_errno(0)
        require(
            library.acl_get_entry(acl, 0, ctypes.byref(entry)) == -1
            and ctypes.get_errno() == errno.EINVAL,
            "unsafe_metadata",
        )
    finally:
        library.acl_free(acl)


def stamp(info):
    return (
        info.st_dev,
        info.st_ino,
        info.st_mode,
        info.st_uid,
        info.st_gid,
        info.st_nlink,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
    )


def check(fd, *, directory=False, mode=None, owner=0):
    info = os.fstat(fd)
    require(
        (stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode))
        and info.st_uid == owner
        and not info.st_mode & 0o7022
        and (directory or info.st_nlink == 1),
        "unsafe_metadata",
    )
    if mode is not None:
        require(stat.S_IMODE(info.st_mode) == mode, "unsafe_metadata")
    no_acl(fd)
    return info


def child(parent, name, *, mode=None):
    require(
        type(name) is str and name not in {"", ".", ".."} and "/" not in name and "\0" not in name
    )
    before = os.stat(name, dir_fd=parent, follow_symlinks=False)
    fd = os.open(name, DIRECTORY, dir_fd=parent)
    try:
        opened = check(fd, directory=True, mode=mode)
        require(
            stamp(before)
            == stamp(opened)
            == stamp(os.stat(name, dir_fd=parent, follow_symlinks=False)),
            "metadata_changed",
        )
        return fd
    except BaseException:
        os.close(fd)
        raise


def read(parent, name, *, mode=0o600, limit=4096):
    require(
        name
        in {
            "enrollment.json",
            "worker.json",
            "worker-launch.json",
            "plan.json",
            "ready",
            "authorized",
            "paused",
        }
        or name in {path.rsplit("/", 1)[-1] for path in PINS}
    )
    before = os.stat(name, dir_fd=parent, follow_symlinks=False)
    fd = os.open(name, REGULAR, dir_fd=parent)
    try:
        opened = check(fd, mode=mode)
        require(stamp(before) == stamp(opened) and 0 <= opened.st_size <= limit, "unsafe_metadata")
        data = bytearray()
        while len(data) <= limit:
            block = os.read(fd, min(65536, limit + 1 - len(data)))
            if not block:
                break
            data.extend(block)
        require(
            len(data) == opened.st_size
            and stamp(opened)
            == stamp(check(fd, mode=mode))
            == stamp(os.stat(name, dir_fd=parent, follow_symlinks=False)),
            "metadata_changed",
        )
        return bytes(data)
    finally:
        os.close(fd)


def object(raw):
    def pairs(values):
        result = {}
        for key, value in values:
            require(key not in result)
            result[key] = value
        return result

    require(type(raw) is bytes and 0 < len(raw) <= 4096)
    value = json.loads(
        raw,
        object_pairs_hook=pairs,
        parse_constant=lambda _: (_ for _ in ()).throw(Refused("invalid_registration")),
    )
    require(type(value) is dict)
    return value


def integer(value, low=1, high=2**63 - 1):
    require(type(value) is int and low <= value <= high)
    return value


def identifier(value):
    require(type(value) is str and str(uuid.UUID(value)) == value and uuid.UUID(value).int != 0)
    return value


def policy(enrollment, worker, launcher):
    require(
        set(enrollment)
        == {"managed_by", "schema", "worker_launcher", "stage_policy", "vault_id", "enrollment_id"}
        and enrollment["managed_by"] == "account-access-worker-enrollment-v1"
        and integer(enrollment["schema"]) == 1
        and enrollment["worker_launcher"] == BASE + "/broker/worker-launch.json"
        and enrollment["stage_policy"] == BASE + "/broker/stage.json"
    )
    vault = identifier(enrollment["vault_id"])
    enrollment_id = identifier(enrollment["enrollment_id"])
    require(
        set(worker)
        == {
            "managed_by",
            "schema",
            "broker_uid",
            "agent_uid",
            "root",
            "agent_socket",
            "owner_socket",
            "owner_port",
        }
        and worker["managed_by"] == "account-access-worker-v1"
        and integer(worker["schema"]) == 1
        and worker["root"] == BASE + "/vault/data"
        and worker["agent_socket"] == BASE + "/run/agent.sock"
        and worker["owner_socket"] == BASE + "/control/owner.sock"
        and integer(worker["owner_port"]) == 8765
    )
    broker = integer(worker["broker_uid"], 450, 499)
    owner = integer(worker["agent_uid"], 1, 2**32 - 1)
    require(owner != broker)
    require(
        launcher
        == {
            "managed_by": "account-access-mac-worker-v1",
            "schema": 1,
            "python": BASE + "/runtime/bin/python",
            "runtime": BASE + "/runtime",
            "worker_policy": BASE + "/broker/worker.json",
            "broker_gid": broker,
            "broker_home": BASE + "/home",
            "browsers": BASE + "/browsers",
            "fixture": False,
            "fixture_ca": None,
        }
    )
    require(
        type(launcher["schema"]) is int
        and type(launcher["broker_gid"]) is int
        and launcher["fixture"] is False
    )
    return vault, enrollment_id, broker, owner


def registration(record, *, vault, enrollment_id, broker):
    require(
        set(record)
        == {
            "schema",
            "vault",
            "enrollment",
            "stage",
            "destination",
            "uid",
            "gid",
            "stagedIdentity",
            "emptyIdentity",
        }
        and integer(record["schema"]) == 1
        and record["vault"] == vault
        and record["enrollment"] == enrollment_id
        and record["stage"] == ".enrollment-" + enrollment_id
        and record["destination"] == "data"
        and integer(record["uid"]) == broker
        and integer(record["gid"]) == broker
    )
    identities = []
    for name in ["stagedIdentity", "emptyIdentity"]:
        value = record[name]
        require(type(value) is dict and set(value) == {"device", "inode"})
        identities.append((integer(value["device"], 0, 2**31 - 1), integer(value["inode"])))
    require(identities[0][0] == identities[1][0] and identities[0][1] != identities[1][1])
    return identities


def classify(original, observed, *, ready):
    require(type(ready) is bool)
    if observed == original:
        return "registration_not_published"
    if observed == list(reversed(original)):
        require(ready)
        return "registration_matches"
    old_devices = {value[0] for value in original}
    new_devices = {value[0] for value in observed}
    old_inodes = [value[1] for value in original]
    new_inodes = [value[1] for value in observed]
    if (
        len(old_devices) == len(new_devices) == 1
        and old_devices != new_devices
        and new_inodes in [old_inodes, old_inodes[::-1]]
    ):
        return "device_number_changed"
    return "directory_identity_mismatch"


def inspect(support):
    """Caller supplies the already checked fixed installation directory."""
    handles = []
    try:
        broker_fd = child(support, "broker", mode=0o700)
        handles.append(broker_fd)
        raw = {
            name: read(broker_fd, name, mode=0o644)
            for name in ["enrollment.json", "worker.json", "worker-launch.json"]
        }
        vault_id, enrollment_id, broker_uid, owner_uid = policy(
            *(object(raw[name]) for name in raw)
        )
        vault_parent = child(support, "vault", mode=0o755)
        handles.append(vault_parent)
        lock = os.open(".account-access-enrollment.lock", REGULAR, dir_fd=vault_parent)
        handles.append(lock)
        require(check(lock, mode=0o600).st_size == 0, "unsafe_metadata")
        try:
            fcntl.flock(lock, fcntl.LOCK_SH | fcntl.LOCK_NB)
        except BlockingIOError:
            raise Refused("registration_busy") from None
        journal = child(vault_parent, ".enrollment-" + enrollment_id + ".publication", mode=0o700)
        handles.append(journal)
        raw_record = read(journal, "plan.json")
        original = registration(
            object(raw_record), vault=vault_id, enrollment_id=enrollment_id, broker=broker_uid
        )
        authorized = object(read(journal, "authorized"))
        require(
            authorized == {"schema": 1, "owner_uid": owner_uid}
            and type(authorized["schema"]) is int
            and type(authorized["owner_uid"]) is int,
            "registration_not_authorized",
        )
        try:
            require(read(journal, "paused") == b"paused\n")
            return "registration_paused"
        except FileNotFoundError:
            pass
        try:
            require(read(journal, "ready") == b"account-access-publication-ready-v1\n")
            ready = True
        except FileNotFoundError:
            ready = False
        names = [".enrollment-" + enrollment_id, "data"]
        observed = []
        for name in names:
            info = os.stat(name, dir_fd=vault_parent, follow_symlinks=False)
            require(
                stat.S_ISDIR(info.st_mode)
                and info.st_uid == info.st_gid == broker_uid
                and stat.S_IMODE(info.st_mode) == 0o700,
                "unsafe_metadata",
            )
            observed.append(info)
        require(
            observed[0].st_dev == observed[1].st_dev == os.fstat(vault_parent).st_dev,
            "unsafe_metadata",
        )
        result = classify(original, [(item.st_dev, item.st_ino) for item in observed], ready=ready)
        require(read(journal, "plan.json") == raw_record, "metadata_changed")
        for name, prior in zip(names, observed):
            require(
                stamp(os.stat(name, dir_fd=vault_parent, follow_symlinks=False)) == stamp(prior),
                "metadata_changed",
            )
        for name, prior in raw.items():
            require(read(broker_fd, name, mode=0o644) == prior, "metadata_changed")
        return result
    finally:
        for fd in reversed(handles):
            os.close(fd)


def open_support():
    fd = os.open("/", DIRECTORY)
    try:
        check(fd, directory=True)
        for name in ["Library", "Application Support", "Account Access"]:
            following = child(fd, name)
            os.close(fd)
            fd = following
        return fd
    except BaseException:
        os.close(fd)
        raise


def validate_public_image(support):
    require(len(PINS) == 3, "public_image_changed")
    for path, digest in PINS.items():
        fd = os.dup(support)
        try:
            parts = path.split("/")
            for name in parts[:-1]:
                following = child(fd, name)
                os.close(fd)
                fd = following
            mode = 0o755 if path.startswith("bin/") else 0o644
            require(
                hashlib.sha256(read(fd, parts[-1], mode=mode, limit=16 * 1024 * 1024)).hexdigest()
                == digest,
                "public_image_changed",
            )
        finally:
            os.close(fd)


def main():
    if (
        sys.platform != "darwin"
        or os.getuid() != 0
        or os.geteuid() != 0
        or len(sys.argv) != 1
        or sys.executable != PYTHON
        or not sys.flags.isolated
        or not sys.flags.no_site
        or not sys.dont_write_bytecode
    ):
        print('{"schema":1,"status":"REFUSED","reason":"installer_context_required"}')
        return 1
    support = None
    try:
        support = open_support()
        validate_public_image(support)
        reason = inspect(support)
        require(reason in REASONS)
        print(
            json.dumps(
                {
                    "schema": 1,
                    "status": "CHECK_COMPLETED",
                    "reason": reason,
                    "credential_contents_read": False,
                    "keychain_accessed": False,
                    "files_modified": False,
                    "service_actions": False,
                }
            )
        )
        return 0
    except Exception as error:
        reason = error.args[0] if isinstance(error, Refused) and len(error.args) == 1 else None
        print(
            json.dumps(
                {
                    "schema": 1,
                    "status": "REFUSED",
                    "reason": reason
                    if type(reason) is str and reason in REASONS
                    else "metadata_unavailable",
                }
            )
        )
        return 1
    finally:
        if support is not None:
            os.close(support)


if __name__ == "__main__":
    raise SystemExit(main())
