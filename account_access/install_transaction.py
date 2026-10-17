"""Trusted package coordinator, entered only after native source verification.

No path override, elevation, download, credentials or owner-approval bypass.
The native launcher supplies two verified public descriptors, closes unrelated
handles and replaces its image with this exact isolated, preassembled runtime.
"""

import fcntl
import json
import os
from pathlib import Path
import pwd
import re
import subprocess
import sys

from . import system_provision as provision
from .install_image import (
    APPLICATION,
    DIRECTORY,
    REGULAR,
    ROOTS,
    SUPPORT,
    ImageConflict,
    ImageManifest,
    ImageRecovery,
    _check,
    _same_record,
    _stamp,
)
from .package_manifest import MAX_MANIFEST_BYTES
from .worker_bootstrap import root_managed_path

JOURNAL = "Account Access Installer"


def _read(fd, maximum, uid):
    before = _check(fd, uid, False)
    if not 0 < before.st_size <= maximum:
        raise ImageConflict("invalid_install_descriptor")
    os.lseek(fd, 0, os.SEEK_SET)
    result = bytearray()
    while len(result) <= maximum:
        block = os.read(fd, min(64 * 1024, maximum + 1 - len(result)))
        if not block:
            break
        result.extend(block)
    if len(result) != before.st_size or _stamp(before) != _stamp(_check(fd, uid, False)):
        raise ImageConflict("install_source_changed")
    return bytes(result)


def _descend(root, path, uid):
    fd = os.dup(root)
    try:
        for name in path.lstrip("/").split("/"):
            if name in {"", ".", ".."}:
                raise ImageConflict("invalid_install_descriptor")
            child = os.open(name, DIRECTORY, dir_fd=fd)
            try:
                _check(child, uid, True)
            except BaseException:
                os.close(child)
                raise
            os.close(fd)
            fd = child
        return fd
    except BaseException:
        os.close(fd)
        raise


def _peer_identity(source, uid):
    fd = os.open("package-identity.json", REGULAR, dir_fd=source)
    try:
        value = json.loads(_read(fd, 8192, uid))
    finally:
        os.close(fd)
    if (
        type(value) is not dict
        or set(value) != {"schema", "managed_by", "signatures"}
        or type(value["schema"]) is not int
        or value["schema"] != 1
        or value["managed_by"] != "account-access-package-identity-v1"
        or type(value["signatures"]) is not dict
        or set(value["signatures"]) != {"owner", "broker", "bootstrap"}
    ):
        raise ImageConflict("invalid_package_identity")
    identifiers = {
        "owner": "com.fainir.accountaccess",
        "broker": "com.fainir.accountaccess.broker",
        "bootstrap": "com.fainir.accountaccess.bootstrap",
    }
    teams = set()
    for key, item in value["signatures"].items():
        if (
            type(item) is not dict
            or set(item) != {"team", "identifier", "hashes"}
            or item["identifier"] != identifiers[key]
            or type(item["team"]) is not str
            or item["team"] != "fixture"
            and re.fullmatch(r"[A-Z0-9]{10}", item["team"]) is None
            or type(item["hashes"]) is not list
            or not 1 <= len(item["hashes"]) <= 2
            or any(
                type(digest) is not str or re.fullmatch(r"[a-f0-9]{40}", digest) is None
                for digest in item["hashes"]
            )
            or item["hashes"] != sorted(set(item["hashes"]))
        ):
            raise ImageConflict("invalid_package_identity")
        teams.add(item["team"])
    if len(teams) != 1:
        raise ImageConflict("invalid_package_identity")
    return value["signatures"]


def _native_verification(source_fd, manifest_fd, lease, expected):
    # F_GETPATH asks the kernel for the already pinned public source directory.
    # No caller-selected executable or inherited PATH/environment is used.
    encoded = fcntl.fcntl(source_fd, getattr(fcntl, "F_GETPATH", 50), bytes(1024))
    path = encoded.split(b"\0", 1)[0].decode("utf-8", errors="strict")
    if not path.startswith("/") or "\0" in path:
        raise ImageConflict("invalid_install_descriptor")
    verifier = path + SUPPORT + "/bin/AccountAccess-installerverify"
    result = subprocess.run(
        [verifier, "--verify-image-manifest-fd", str(manifest_fd)],
        capture_output=True,
        timeout=180,
        pass_fds=(manifest_fd, lease),
        stdin=subprocess.DEVNULL,
        env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LANG": "C"},
    )
    if result.returncode != 0 or len(result.stdout) > 4096 or len(result.stderr) > 4096:
        raise ImageConflict("installed_image_not_verified")
    if not _same_record(json.loads(result.stdout), expected):
        raise ImageConflict("installed_image_not_verified")


def _fresh_identity():
    if os.path.lexists("/Library/LaunchDaemons/" + provision.LABEL + ".plist"):
        raise ImageConflict("existing_installation_requires_repair")
    for prefix in ["/Users/", "/Groups/"]:
        if provision.directory_value(prefix + provision.IDENTITY, "RecordName") is not None:
            raise ImageConflict("existing_installation_requires_repair")


def run(source_fd, manifest_fd, digest):
    """Fixed production layout. Called only after main's root-context check."""
    if sys.platform != "darwin" or os.getuid() != 0 or os.geteuid() != 0:
        raise ImageConflict("invalid_install_context")
    if source_fd < 3 or manifest_fd < 3 or source_fd == manifest_fd:
        raise ImageConflict("invalid_install_descriptor")
    for fd in [source_fd, manifest_fd]:
        os.set_inheritable(fd, False)
    _check(source_fd, 0, True)
    manifest = ImageManifest(_read(manifest_fd, MAX_MANIFEST_BYTES, 0), digest)
    owner = os.stat("/dev/console").st_uid
    person = pwd.getpwuid(owner)
    if owner <= 0 or person.pw_name in {"loginwindow", "_mbsetupuser"}:
        raise ImageConflict("interactive_owner_required")
    root_managed_path(Path("/Library/Application Support"))
    sources, handles = {}, []
    try:
        for root in ROOTS:
            fd = _descend(source_fd, root, 0)
            sources[root] = fd
            handles.append(fd)
        peers = _peer_identity(sources[SUPPORT], 0)
        library = os.open("/Library/Application Support", DIRECTORY)
        handles.append(library)
        _check(library, 0, True)
        applications = os.open("/Applications", DIRECTORY)
        handles.append(applications)
        _check(applications, 0, True, shared=True)
        try:
            os.mkdir(JOURNAL, 0o700, dir_fd=library)
            os.fsync(library)
        except FileExistsError:
            pass
        journal = os.open(JOURNAL, DIRECTORY, dir_fd=library)
        handles.append(journal)
        _check(journal, 0, True, 0o700)
        targets = {
            SUPPORT: (library, "Account Access"),
            APPLICATION: (applications, "Account Access.app"),
        }
        with ImageRecovery(sources, journal, targets, manifest, owner, object_uid=0) as recovery:
            if recovery._read_record("intent.json") is None:
                _fresh_identity()
            proof = recovery.materialize()
            _native_verification(source_fd, manifest_fd, recovery.lease, proof)
            recovery.publish_verification(proof)
            if os.stat("/dev/console").st_uid != owner:
                raise ImageConflict("interactive_owner_changed")
            if not recovery.was_complete:
                with provision.command_lease(recovery.lease):
                    provision.activate(
                        provision.Layout.installed(), owner, expected_signatures=peers
                    )
                recovery.mark_complete()
    finally:
        for fd in handles:
            os.close(fd)
    # The ordinary owner app must never inherit the privileged installer lease
    # or public source handles. command uses close_fds with no pass_fds here.
    provision.command(
        [
            "/bin/launchctl",
            "asuser",
            str(owner),
            "/usr/bin/sudo",
            "-n",
            "-H",
            "-u",
            "#" + str(owner),
            "--",
            "/usr/bin/open",
            "-a",
            "/Applications/Account Access.app",
        ]
    )
    return {"status": "REGISTERED"}


def main():
    try:
        if (
            sys.platform != "darwin"
            or os.getuid() != 0
            or os.geteuid() != 0
            or len(sys.argv) != 7
            or sys.argv[1] != "--source-fd"
            or sys.argv[3] != "--manifest-fd"
            or sys.argv[5] != "--manifest-sha256"
            or any(re.fullmatch(r"[0-9]{1,8}", sys.argv[index]) is None for index in [2, 4])
            or re.fullmatch(r"[a-f0-9]{64}", sys.argv[6]) is None
        ):
            raise ImageConflict("invalid_install_context")
        result = run(int(sys.argv[2]), int(sys.argv[4]), sys.argv[6])
        print(json.dumps(result))
        return 0
    except Exception:
        print('{"status":"FAILED","reason":"system_install_not_completed"}')
        return 78


if __name__ == "__main__":
    raise SystemExit(main())
