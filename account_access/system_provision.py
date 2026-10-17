"""Fresh-install provisioning after a trusted Mac package has installed its payload.

No elevation, downloads, vault key access, account credential import or native
owner approval occurs here. Production accepts no paths, identity or commands.
The package and protected payload must be trusted before this entrypoint runs.
"""

import ctypes
import grp
import hashlib
import json
import os
from pathlib import Path
import plistlib
import pwd
import re
import stat
import subprocess
import sys
import tempfile
import time
import uuid
from dataclasses import dataclass

from filelock import FileLock

from .worker_bootstrap import root_managed_path


class ProvisionError(Exception):
    pass


BASE = Path("/Library/Application Support/Account Access")
MARKER = "account-access-system-install-v1"
IDENTITY = "_accountaccess"
LABEL = "com.fainir.accountaccess.broker"
SERVICE = LABEL + ".owner"


@dataclass(frozen=True)
class Layout:
    base: Path
    runtime: Path
    browsers: Path
    owner_app: Path
    broker: Path
    bootstrap: Path
    broker_name: str
    label: str
    fixture: bool = False

    @classmethod
    def installed(cls):
        return cls(
            BASE,
            BASE / "runtime",
            BASE / "browsers",
            Path("/Applications/Account Access.app"),
            BASE / "bin/AccountAccess-broker",
            BASE / "bin/AccountAccess-bootstrap",
            IDENTITY,
            LABEL,
        )

    @classmethod
    def ci_fixture(cls, prefix, *, name):
        prefix = Path(prefix)
        if (
            sys.platform != "darwin"
            or os.getuid() != 0
            or os.environ.get("GITHUB_ACTIONS") != "true"
            or not str(prefix).startswith(
                "/Library/PrivilegedHelperTools/account-access-worker-qa-"
            )
            or re.fullmatch(r"_aaq[a-f0-9]{12}", name) is None
        ):
            raise ProvisionError("disposable_provisioning_required")
        root_managed_path(prefix)
        return cls(
            prefix / "provisioned",
            prefix / "runtime",
            prefix / "browsers",
            prefix / "root-owner-client",
            prefix / "system-broker",
            prefix / "mac-worker-bootstrap",
            name,
            LABEL + ".qa.provision",
            True,
        )


def command(arguments):
    result = subprocess.run(
        arguments,
        capture_output=True,
        timeout=20,
        env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LANG": "C"},
    )
    if result.returncode != 0 or len(result.stdout) + len(result.stderr) > 65536:
        raise ProvisionError("provisioning_command_failed")
    return result


def signature(path, identifier, *, fixture=False):
    path = Path(path)
    command(["/usr/bin/codesign", "--verify", "--strict", "--all-architectures", str(path)])
    binary = path / "Contents/MacOS/AccountAccess" if path.suffix == ".app" else path
    result = command(["/usr/bin/lipo", "-archs", str(binary)])
    architectures = result.stdout.decode().strip().split()
    if not architectures or not set(architectures) <= {"arm64", "x86_64"}:
        raise ProvisionError("unsupported_payload_architecture")
    hashes, teams = [], set()
    for architecture in architectures:
        result = command(
            ["/usr/bin/codesign", "-d", "--verbose=4", "--arch", architecture, str(path)]
        )
        text = result.stderr.decode("utf-8", errors="strict")
        found = re.findall(r"^CDHash=([a-f0-9]{40})$", text, re.MULTILINE)
        actual = re.findall(r"^Identifier=(.+)$", text, re.MULTILINE)
        team = re.findall(r"^TeamIdentifier=(.+)$", text, re.MULTILINE)
        if len(found) != 1 or len(actual) != 1 or len(team) != 1:
            raise ProvisionError("invalid_payload_signature")
        if not fixture and actual != [identifier]:
            raise ProvisionError("invalid_payload_signature")
        hashes.extend(found)
        teams.update(team)
    if fixture:
        if teams != {"not set"}:
            raise ProvisionError("invalid_fixture_signature")
        return {"team": "fixture", "identifier": identifier, "hashes": sorted(set(hashes))}
    if len(teams) != 1 or re.fullmatch(r"[A-Z0-9]{10}", next(iter(teams))) is None:
        raise ProvisionError("invalid_payload_publisher")
    team = next(iter(teams))
    requirement = (
        'anchor apple generic and identifier "'
        + identifier
        + '" and certificate leaf[subject.OU] = "'
        + team
        + '" and !(entitlement["com.apple.security.get-task-allow"] exists)'
    )
    command(
        [
            "/usr/bin/codesign",
            "--verify",
            "--strict",
            "--all-architectures",
            "-R",
            requirement,
            str(path),
        ]
    )
    return {"team": team, "identifier": identifier, "hashes": sorted(set(hashes))}


def payload(layout):
    for path in [
        layout.runtime,
        layout.runtime / "bin/python",
        layout.browsers,
        layout.broker,
        layout.bootstrap,
    ]:
        root_managed_path(path)
    # The native worker validator additionally checks entire runtime, Python and
    # browser trees before execution. The package build must preserve those trees.
    owner = signature(layout.owner_app, "com.fainir.accountaccess", fixture=layout.fixture)
    broker = signature(layout.broker, LABEL, fixture=layout.fixture)
    bootstrap = signature(
        layout.bootstrap, "com.fainir.accountaccess.bootstrap", fixture=layout.fixture
    )
    if len({item["team"] for item in [owner, broker, bootstrap]}) != 1:
        raise ProvisionError("payload_publishers_disagree")
    return {"owner": owner, "broker": broker, "bootstrap": bootstrap}


def root_directory(path, mode=0o755):
    path = Path(path)
    root_managed_path(path.parent)
    try:
        path.mkdir(mode=mode)
        descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fchmod(
                descriptor, mode
            )  # Do not let an inherited private umask hide public policy paths.
        finally:
            os.close(descriptor)
    except FileExistsError:
        pass
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or stat.S_IMODE(info.st_mode) != mode:
        raise ProvisionError("unsafe_install_directory")
    return path


def root_json(path):
    root_managed_path(path)
    info = path.lstat()
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_nlink != 1
        or info.st_size > 4096
        or stat.S_IMODE(info.st_mode) != 0o600
    ):
        raise ProvisionError("unsafe_install_record")
    value = json.loads(path.read_bytes())
    if type(value) is not dict:
        raise ProvisionError("unsafe_install_record")
    return value


def choose_identity():
    for candidate in range(450, 500):
        try:
            pwd.getpwuid(candidate)
            continue
        except KeyError:
            pass
        try:
            grp.getgrgid(candidate)
            continue
        except KeyError:
            return candidate
    raise ProvisionError("service_identity_unavailable")


def directory_value(record, field):
    result = subprocess.run(
        ["/usr/bin/dscl", ".", "-read", record, field],
        capture_output=True,
        timeout=20,
        env={"PATH": "/usr/bin:/bin"},
    )
    if result.returncode:
        if b"(eDSRecordNotFound)" in result.stdout + result.stderr:
            return None
        raise ProvisionError("directory_services_unavailable")
    text = result.stdout.decode("utf-8", errors="strict").strip()
    if text == "No such key: " + field:
        return None
    prefix = field + ": "
    if not text.startswith(prefix) or "\n" in text:
        raise ProvisionError("service_identity_conflict")
    return text[len(prefix) :]


def identity_record(layout, uid):
    group, user = "/Groups/" + layout.broker_name, "/Users/" + layout.broker_name
    home = layout.base / "home"
    for lookup in [pwd.getpwuid, grp.getgrgid]:
        try:
            registered = lookup(uid)
        except KeyError:
            continue
        name = registered.pw_name if hasattr(registered, "pw_name") else registered.gr_name
        if name != layout.broker_name:
            raise ProvisionError("service_identity_conflict")
    fields = {
        "UniqueID": str(uid),
        "PrimaryGroupID": str(uid),
        "NFSHomeDirectory": str(home),
        "UserShell": "/usr/bin/false",
        "IsHidden": "1",
        "Password": "*",
    }
    # A committed root transaction reserves the name and UID. Only missing
    # fields may be completed; conflicting records are never rewritten.
    for record, expected in [(group, {"PrimaryGroupID": str(uid)}), (user, fields)]:
        for field, value in expected.items():
            present = directory_value(record, field)
            if present is not None and present != value:
                raise ProvisionError("service_identity_conflict")
    for record, expected in [(group, {"PrimaryGroupID": str(uid)}), (user, fields)]:
        command(["/usr/bin/dscl", ".", "-create", record])
        for field, value in expected.items():
            if directory_value(record, field) is None:
                command(["/usr/bin/dscl", ".", "-create", record, field, value])
    command(["/usr/bin/dscacheutil", "-flushcache"])
    check = pwd.getpwnam(layout.broker_name)
    group_check = grp.getgrnam(layout.broker_name)
    if (
        check.pw_uid != uid
        or check.pw_gid != uid
        or check.pw_dir != str(home)
        or check.pw_shell != "/usr/bin/false"
        or group_check.gr_gid != uid
        or group_check.gr_mem
        or any(layout.broker_name in group.gr_mem for group in grp.getgrall())
    ):
        raise ProvisionError("service_identity_conflict")
    return check


def private_directory(path, uid):
    root_managed_path(path.parent)
    try:
        path.mkdir(mode=0o700)
        os.chown(path, uid, uid)
    except FileExistsError:
        pass
    info = path.lstat()
    if (
        not stat.S_ISDIR(info.st_mode)
        or info.st_uid != uid
        or info.st_gid != uid
        or stat.S_IMODE(info.st_mode) != 0o700
    ):
        raise ProvisionError("unsafe_private_directory")


def publish(path, data, *, mode=0o644):
    root_managed_path(path.parent)
    if path.exists() or path.is_symlink():
        root_managed_path(path)
        info = path.lstat()
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_nlink != 1
            or stat.S_IMODE(info.st_mode) != mode
            or path.read_bytes() != data
        ):
            raise ProvisionError("existing_installation_requires_repair")
        return
    fd, name = tempfile.mkstemp(prefix=".provision-", dir=path.parent)
    temporary = Path(name)
    try:
        with os.fdopen(fd, "wb") as output:
            os.fchmod(output.fileno(), mode)
            output.write(data)
            output.flush()
            os.fsync(output.fileno())
        if sys.platform == "darwin":
            libc = ctypes.CDLL(None, use_errno=True)
            libc.renamex_np.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_uint]
            libc.renamex_np.restype = ctypes.c_int
            # Darwin RENAME_EXCL publishes one inode without replacing a name
            # or leaving a second hard link across an interrupted installation.
            if libc.renamex_np(os.fsencode(temporary), os.fsencode(path), 4) != 0:
                raise OSError(ctypes.get_errno(), "metadata_publication_failed")
        else:
            os.link(temporary, path, follow_symlinks=False)

    finally:
        temporary.unlink(missing_ok=True)
    descriptor = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def discard_unpublished(directory):
    for path in directory.glob(".provision-*"):
        info = path.lstat()
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != 0
            or info.st_nlink != 1
            or stat.S_IMODE(info.st_mode) not in {0o600, 0o644}
            or info.st_size > 4096
        ):
            raise ProvisionError("unsafe_install_record")
        path.unlink()


def plans(layout, transaction, signatures, owner_group):
    uid, owner = transaction["broker_uid"], transaction["owner_uid"]
    base = layout.base
    worker = {
        "managed_by": "account-access-worker-v1",
        "schema": 1,
        "broker_uid": uid,
        "agent_uid": owner,
        "root": str(base / "vault/data"),
        "agent_socket": str(base / "run/agent.sock"),
        "owner_socket": str(base / "control/owner.sock"),
        "owner_port": 8765,
    }
    staged = dict(
        worker, root=str(base / "vault" / (".enrollment-" + transaction["enrollment_id"]))
    )
    launcher = {
        "managed_by": "account-access-mac-worker-v1",
        "schema": 1,
        "python": str(layout.runtime / "bin/python"),
        "runtime": str(layout.runtime),
        "worker_policy": str(base / "broker/worker.json"),
        "broker_gid": uid,
        "broker_home": str(base / "home"),
        "browsers": str(layout.browsers),
        "fixture": layout.fixture,
        "fixture_ca": None,
    }
    staged_launcher = dict(launcher, worker_policy=str(base / "broker/stage.json"))
    enrollment = {
        "managed_by": "account-access-worker-enrollment-v1",
        "schema": 1,
        "worker_launcher": str(base / "broker/worker-launch.json"),
        "stage_policy": str(base / "broker/stage.json"),
        "vault_id": transaction["vault_id"],
        "enrollment_id": transaction["enrollment_id"],
    }
    owner_signature, broker_signature, bootstrap_signature = (
        signatures[key] for key in ["owner", "broker", "bootstrap"]
    )
    host = {
        "managed_by": "account-access-system-host-v1",
        "schema": 1,
        "worker_launcher": str(base / "broker/worker-launch.json"),
        "enrollment_policy": str(base / "broker/enrollment.json"),
        "bootstrap": str(layout.bootstrap),
        "vault_id": transaction["vault_id"],
        "owner_uid": owner,
        "publisher_team": broker_signature["team"],
        "owner_identifier": owner_signature["identifier"],
        "owner_hashes": owner_signature["hashes"],
        "bootstrap_identifier": bootstrap_signature["identifier"],
        "bootstrap_hashes": bootstrap_signature["hashes"],
    }
    profile = {
        "managed_by": "account-access-desktop-owner-v1",
        "schema": 1,
        "owner_uid": owner,
        "publisher_team": broker_signature["team"],
        "server_identifier": LABEL,
        "server_hashes": broker_signature["hashes"],
    }
    arguments = [str(layout.broker)] + (
        ["--fixture-policy", str(base / "broker/host.json")] if layout.fixture else []
    )
    job = {
        "Label": layout.label,
        "ProgramArguments": arguments,
        "UserName": "root",
        "GroupName": "wheel",
        "RunAtLoad": True,
        "KeepAlive": False,
        "AbandonProcessGroup": False,
        "ExitTimeOut": 20,
        "Umask": 0o077,
        "ProcessType": "Background",
        "StandardOutPath": "/dev/null",
        "StandardErrorPath": "/dev/null",
        "MachServices": {SERVICE: True},
        "Sockets": {
            "AccountAccessAgent": {
                "SockPathName": worker["agent_socket"],
                "SockPathOwner": 0,
                "SockPathGroup": owner_group,
                "SockPathMode": 0o660,
            },
            "AccountAccessOwner": {
                "SockPathName": worker["owner_socket"],
                "SockPathOwner": 0,
                "SockPathGroup": 0,
                "SockPathMode": 0o600,
            },
        },
    }
    values = {
        "worker.json": worker,
        "stage.json": staged,
        "worker-launch.json": launcher,
        "stage-launch.json": staged_launcher,
        "enrollment.json": enrollment,
        "host.json": host,
    }
    return values, profile, job


def prepare(layout, owner_uid):
    if sys.platform != "darwin" or os.getuid() != 0 or os.geteuid() != 0:
        raise ProvisionError("system_install_requires_root")
    if type(owner_uid) is not int or owner_uid <= 0:
        raise ProvisionError("interactive_owner_required")
    owner = pwd.getpwuid(owner_uid)
    if owner_uid == 0 or owner.pw_name in {"loginwindow", "_mbsetupuser"}:
        raise ProvisionError("interactive_owner_required")
    signatures = payload(layout)
    root_directory(layout.base)
    root_directory(layout.base / "broker", 0o755)
    lock_path = layout.base / "broker/install.lock"
    if lock_path.is_symlink():
        raise ProvisionError("unsafe_install_record")
    with FileLock(lock_path, mode=0o600):
        root_managed_path(lock_path)
        discard_unpublished(layout.base / "broker")
        discard_unpublished(layout.base)
        record = layout.base / "broker/install.json"
        fingerprint = hashlib.sha256(
            json.dumps(
                {
                    "signatures": signatures,
                    "layout": {
                        key: str(getattr(layout, key))
                        for key in [
                            "runtime",
                            "browsers",
                            "owner_app",
                            "broker",
                            "bootstrap",
                            "broker_name",
                            "label",
                        ]
                    },
                },
                sort_keys=True,
            ).encode()
        ).hexdigest()
        if record.exists() or record.is_symlink():
            transaction = root_json(record)
            if (
                type(transaction.get("broker_uid")) is not int
                or not 450 <= transaction["broker_uid"] < 500
                or type(transaction.get("owner_uid")) is not int
                or any(
                    type(transaction.get(key)) is not str
                    or str(uuid.UUID(transaction[key])) != transaction[key]
                    for key in ["vault_id", "enrollment_id"]
                )
            ):
                raise ProvisionError("unsafe_install_record")
            if (
                set(transaction)
                != {
                    "managed_by",
                    "schema",
                    "owner_uid",
                    "broker_uid",
                    "broker_name",
                    "vault_id",
                    "enrollment_id",
                    "payload_fingerprint",
                }
                or transaction["managed_by"] != MARKER
                or type(transaction["schema"]) is not int
                or transaction["schema"] != 1
                or transaction["owner_uid"] != owner_uid
                or transaction["broker_name"] != layout.broker_name
                or transaction["payload_fingerprint"] != fingerprint
            ):
                raise ProvisionError("existing_installation_requires_repair")
        else:
            if any(
                (layout.base / name).exists() or (layout.base / name).is_symlink()
                for name in ["home", "vault", "run", "control", "owner.json"]
            ):
                raise ProvisionError("existing_installation_requires_repair")
            if set(path.name for path in (layout.base / "broker").iterdir()) != {"install.lock"}:
                raise ProvisionError("existing_installation_requires_repair")
            if any(
                directory_value(kind + layout.broker_name, "RecordName") is not None
                for kind in ["/Users/", "/Groups/"]
            ):
                raise ProvisionError("service_identity_conflict")
            try:
                pwd.getpwnam(layout.broker_name)
            except KeyError:
                pass
            else:
                raise ProvisionError("service_identity_conflict")
            try:
                grp.getgrnam(layout.broker_name)
            except KeyError:
                pass
            else:
                raise ProvisionError("service_identity_conflict")
            transaction = {
                "managed_by": MARKER,
                "schema": 1,
                "owner_uid": owner_uid,
                "broker_uid": choose_identity(),
                "broker_name": layout.broker_name,
                "vault_id": str(uuid.uuid4()),
                "enrollment_id": str(uuid.uuid4()),
                "payload_fingerprint": fingerprint,
            }
            publish(record, json.dumps(transaction, sort_keys=True).encode(), mode=0o600)
        identity = identity_record(layout, transaction["broker_uid"])
        domain = "user/" + str(identity.pw_uid)
        observed = subprocess.run(
            ["/bin/launchctl", "print", domain],
            capture_output=True,
            timeout=20,
            env={"PATH": "/usr/bin:/bin"},
        )
        if observed.returncode != 0:
            command(["/bin/launchctl", "bootstrap", domain])
        command(["/bin/launchctl", "print", domain])
        for name, mode in [("vault", 0o755), ("run", 0o755), ("control", 0o700)]:
            root_directory(layout.base / name, mode)
        for path in [
            layout.base / "home",
            layout.base / "vault/data",
            layout.base / "vault" / (".enrollment-" + transaction["enrollment_id"]),
        ]:
            private_directory(path, identity.pw_uid)
        values, profile, job = plans(layout, transaction, signatures, owner.pw_gid)
        for name, value in values.items():
            publish(layout.base / "broker" / name, json.dumps(value, sort_keys=True).encode())
        # Native read-only registration is public. Never publish capabilities.
        publish(layout.base / "owner.json", json.dumps(profile, sort_keys=True).encode())
        publish(layout.base / "broker/service.plist", plistlib.dumps(job, sort_keys=True))
    return {
        "status": "PREPARED",
        "owner_uid": owner_uid,
        "broker_uid": identity.pw_uid,
        "vault_id": transaction["vault_id"],
    }


def main():
    try:
        if len(sys.argv) != 1:
            raise ProvisionError("invalid_install_arguments")
        layout = Layout.installed()
        owner = os.stat("/dev/console").st_uid
        result = prepare(layout, owner)
        print(json.dumps({"status": result["status"]}))
        return 0
    except Exception:
        print('{"status":"FAILED","reason":"system_install_not_completed"}')
        return 78


if __name__ == "__main__":
    raise SystemExit(main())


def remove_ci_identity(layout):
    """Remove only this disposable fixture's recorded, stopped service identity."""
    if (
        not layout.fixture
        or sys.platform != "darwin"
        or os.getuid() != 0
        or os.environ.get("GITHUB_ACTIONS") != "true"
        or not str(layout.base).startswith(
            "/Library/PrivilegedHelperTools/account-access-worker-qa-"
        )
        or re.fullmatch(r"_aaq[a-f0-9]{12}", layout.broker_name) is None
    ):
        raise ProvisionError("disposable_provisioning_required")
    record = root_json(layout.base / "broker/install.json")
    registered = pwd.getpwnam(layout.broker_name)
    if (
        record["broker_uid"] != registered.pw_uid
        or registered.pw_dir != str(layout.base / "home")
        or registered.pw_shell != "/usr/bin/false"
        or registered.pw_uid == record["owner_uid"]
    ):
        raise ProvisionError("service_identity_conflict")
    # The caller stops its system job first. Drop this fixture's user domain,
    # then require all processes for its reserved identity to have exited.
    command(["/bin/launchctl", "bootout", "user/" + str(registered.pw_uid)])
    deadline = time.monotonic() + 15
    while True:
        processes = command(["/bin/ps", "-axo", "uid="]).stdout.decode().split()
        if str(registered.pw_uid) not in processes:
            break
        if time.monotonic() >= deadline:
            raise ProvisionError("service_identity_still_running")
        time.sleep(0.1)
    command(["/usr/bin/dscl", ".", "-delete", "/Users/" + layout.broker_name])
    command(["/usr/bin/dscl", ".", "-delete", "/Groups/" + layout.broker_name])
    command(["/usr/bin/dscacheutil", "-flushcache"])
    try:
        pwd.getpwnam(layout.broker_name)
    except KeyError:
        return
    raise ProvisionError("service_identity_conflict")
