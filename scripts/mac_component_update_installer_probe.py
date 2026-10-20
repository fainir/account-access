"""Actual signed-native component candidate acceptance in a fresh hosted Mac VM.

This is not an owner-Mac command. It installs the retained public build76 image,
normally quits its fresh GUI, applies the exact reviewed candidate through native
Installer, and checks public files/policies and same-package reapplication. It
does not enroll a store, connect accounts, inspect a vault or inject a crash.
The VM is discarded after the job; only its created job is stopped here.
"""

import argparse
import ctypes
import errno
import hashlib
import json
import os
from pathlib import Path
import platform
import plistlib
import pwd
import grp
import re
import stat
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET

BASE_SOURCE = "fbd2a733b60acde68e82fe796cb7abd971d5d625"
BASE_PACKAGE_SHA256 = "e525233e74ee942a53c389babac57eee6cad25b79ea178ff9a6384b0a5c5567c"
BASE_MANIFEST_SHA256 = "5618053e6f8ed0a8720a9d2f7dde317425cecda6a970abd90c499fbfe27b43a8"
BASE = Path("/Library/Application Support/Account Access")
COMPONENTS = Path("/Library/Application Support/Account Access Components")
JOURNAL = Path("/Library/Application Support/Account Access Installer")
APP = Path("/Applications/Account Access.app")
JOB = Path("/Library/LaunchDaemons/com.fainir.accountaccess.broker.plist")
LABEL = "com.fainir.accountaccess.broker"
TEAM = "WBULD6N4NQ"
ENV = {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LANG": "C", "LC_ALL": "C"}
GIT_ENV = {**ENV, "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_SYSTEM": "/dev/null",
           "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_ATTR_NOSYSTEM": "1", "GIT_TERMINAL_PROMPT": "0"}
MAX_SOURCE = 2 * 1024 * 1024
PRIVATE = {"broker", "home", "vault", "run", "control", "owner.json", "install-verification.json"}
UNCHANGED_POLICIES = ("worker.json", "stage.json", "worker-launch.json", "stage-launch.json", "enrollment.json", "service.plist")
CHECKS = frozenset({"fresh_hosted_vm", "reviewed_public_inputs", "candidate_expansion_matches_review",
                    "genuine_signed_helper", "actual_base_installer", "base_public_image", "fresh_gui_quit",
                    "actual_candidate_installer", "target_public_image", "only_three_policy_values_changed",
                    "unchanged_worker_plans_and_original_journal", "verified_head", "same_package_reapplication",
                    "reapplication_preserved_bytes_and_ids", "created_job_stopped"})


def require(value):
    if not value:
        raise ValueError("component_installer_acceptance_failed")


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def hex_value(value, size):
    return isinstance(value, str) and re.fullmatch(r"[a-f0-9]{" + str(size) + "}", value) is not None


def guard():
    require(sys.platform == "darwin" and platform.machine() == "arm64" and os.getuid() == os.geteuid() == 0
            and os.environ.get("GITHUB_ACTIONS") == "true" and os.environ.get("CI") == "true"
            and os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted" and os.environ.get("RUNNER_OS") == "macOS"
            and os.environ.get("RUNNER_ARCH") == "ARM64" and os.environ.get("GITHUB_REPOSITORY") == "fainir/account-access"
            and re.fullmatch(r"[1-9][0-9]{0,19}", os.environ.get("GITHUB_RUN_ID", "")) is not None
            and re.fullmatch(r"[1-9][0-9]{0,9}", os.environ.get("GITHUB_RUN_ATTEMPT", "")) is not None
            and hex_value(os.environ.get("GITHUB_SHA"), 40))


def report_path(run_id):
    require(isinstance(run_id, str) and re.fullmatch(r"[1-9][0-9]{0,19}", run_id) is not None)
    return Path("/Library/Logs/AccountAccessComponentInstallerQA-" + run_id + "/report.json")


def protected_metadata(info, *, mode=None, directory=True):
    require((stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode))
            and info.st_uid == 0 and not info.st_mode & 0o7022
            and (directory or info.st_nlink == 1)
            and (mode is None or stat.S_IMODE(info.st_mode) == mode))


def deny_only_acl(descriptor):
    """A deny ACL cannot add write access omitted by the protected mode."""
    library = ctypes.CDLL(None, use_errno=True)
    library.acl_get_fd.argtypes, library.acl_get_fd.restype = [ctypes.c_int], ctypes.c_void_p
    library.acl_get_entry.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.POINTER(ctypes.c_void_p)]
    library.acl_get_entry.restype = ctypes.c_int
    library.acl_get_tag_type.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_int)]
    library.acl_get_tag_type.restype = ctypes.c_int
    library.acl_free.argtypes = [ctypes.c_void_p]
    ctypes.set_errno(0)
    acl = library.acl_get_fd(descriptor)
    if not acl:
        require(ctypes.get_errno() == errno.ENOENT)
        return
    try:
        for position in [0] + [1] * 169:
            entry, tag = ctypes.c_void_p(), ctypes.c_int()
            ctypes.set_errno(0)
            result = library.acl_get_entry(acl, position, ctypes.byref(entry))
            if result == -1:
                require(ctypes.get_errno() == errno.EINVAL)
                return
            require(result == 0 and entry.value and library.acl_get_tag_type(entry, ctypes.byref(tag)) == 0
                    and tag.value == 2)  # ACL_EXTENDED_DENY only.
        require(False)
    finally:
        library.acl_free(acl)


class RootOutput:
    """Exclusive descriptor-anchored evidence publication below fixed root Logs."""

    def __init__(self, path, run_id):
        require(path == report_path(run_id))
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
        parent = os.open("/", flags)
        self.parent = self.descriptor = None
        try:
            protected_metadata(os.fstat(parent))
            deny_only_acl(parent)
            for name in ("Library", "Logs"):
                child = os.open(name, flags, dir_fd=parent)
                try:
                    protected_metadata(os.fstat(child))
                    deny_only_acl(child)
                    require(stamp(os.fstat(child)) == stamp(os.stat(name, dir_fd=parent, follow_symlinks=False)))
                except Exception:
                    os.close(child)
                    raise
                os.close(parent)
                parent = child
            self.name = path.parent.name
            os.mkdir(self.name, mode=0o700, dir_fd=parent)  # Never adopt an existing directory.
            self.descriptor = os.open(self.name, flags, dir_fd=parent)
            protected_metadata(os.fstat(self.descriptor), mode=0o700)
            deny_only_acl(self.descriptor)
            require(stamp(os.fstat(self.descriptor)) == stamp(os.stat(self.name, dir_fd=parent, follow_symlinks=False)))
            os.fsync(parent)
            self.parent = parent
            parent = None
        except Exception:
            self.close()
            raise
        finally:
            if parent is not None:
                os.close(parent)

    def write(self, name, raw):
        require(name == "report.json" or re.fullmatch(r"[a-z][a-z0-9-]{0,70}\.log", name) is not None)
        require(isinstance(raw, bytes) and len(raw) <= 256 * 1024)
        protected_metadata(os.fstat(self.descriptor), mode=0o700)
        descriptor = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                             0o600, dir_fd=self.descriptor)
        try:
            protected_metadata(os.fstat(descriptor), mode=0o600, directory=False)
            with os.fdopen(os.dup(descriptor), "wb") as stream:
                stream.write(raw)
                stream.flush()
                os.fsync(stream.fileno())
            os.fchmod(descriptor, 0o644)
            os.fsync(descriptor)
            require(stamp(os.fstat(descriptor)) == stamp(os.stat(name, dir_fd=self.descriptor, follow_symlinks=False)))
            os.fsync(self.descriptor)
        finally:
            os.close(descriptor)

    def publish(self):
        current = os.stat(self.name, dir_fd=self.parent, follow_symlinks=False)
        require(stamp(current) == stamp(os.fstat(self.descriptor)))
        protected_metadata(current, mode=0o700)
        os.fchmod(self.descriptor, 0o755)
        os.fsync(self.descriptor)
        os.fsync(self.parent)

    def close(self):
        for name in ("descriptor", "parent"):
            descriptor = getattr(self, name, None)
            if descriptor is not None:
                os.close(descriptor)
                setattr(self, name, None)


def stamp(value):
    return (value.st_dev, value.st_ino, value.st_mode, value.st_uid, value.st_gid,
            value.st_nlink, value.st_size, value.st_mtime_ns, value.st_ctime_ns)


def read_file(path, *, maximum=16 * 1024 * 1024, owner=0):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(descriptor)
        require(stat.S_ISREG(before.st_mode) and before.st_uid == owner and before.st_nlink == 1
                and not before.st_mode & 0o7022 and 0 <= before.st_size <= maximum)
        with os.fdopen(os.dup(descriptor), "rb") as stream:
            raw = stream.read(maximum + 1)
        require(len(raw) == before.st_size and stamp(before) == stamp(os.fstat(descriptor))
                and stamp(before) == stamp(path.lstat()))
        return raw
    finally:
        os.close(descriptor)


def stage_file(source, destination, expected, maximum):
    require(re.fullmatch(r"[a-f0-9]{64}", expected) is not None)
    incoming = os.open(source, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(incoming)
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and 0 < before.st_size <= maximum)
        outgoing = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        digest = hashlib.sha256()
        with os.fdopen(outgoing, "wb") as output, os.fdopen(os.dup(incoming), "rb") as stream:
            for block in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(block)
                output.write(block)
            output.flush()
            os.fsync(output.fileno())
        require(stamp(before) == stamp(os.fstat(incoming)) and digest.hexdigest() == expected)
    finally:
        os.close(incoming)


def validate_review(value, source, candidate_hash):
    require(hex_value(source, 40) and hex_value(candidate_hash, 64))
    require(isinstance(value, dict) and set(value) == {"schema", "managed_by", "component_source_commit", "base_source_commit",
            "package_sha256", "package_bytes", "plan_sha256", "scripts", "source_files"}
            and type(value["schema"]) is int and value["schema"] == 1
            and value["managed_by"] == "account-access-component-public-review-v1"
            and value["component_source_commit"] == source and value["base_source_commit"] == BASE_SOURCE
            and value["package_sha256"] == candidate_hash and type(value["package_bytes"]) is int
            and 0 < value["package_bytes"] <= 32 * 1024 * 1024
            and hex_value(value["plan_sha256"], 64)
            and isinstance(value["scripts"], dict) and len(value["scripts"]) == 15
            and isinstance(value["source_files"], dict) and 8 <= len(value["source_files"]) <= 100)
    required = {"macos/ComponentUpdate.swift", "macos/ComponentUpdatePolicies.swift", "macos/ComponentUpdateIdentity.swift",
                "macos/InstallerPayload.swift", "macos/build-component-update.py"}
    require(required <= set(value["source_files"]))
    for name, digest in value["source_files"].items():
        require(isinstance(name, str) and len(name) <= 512
                and re.fullmatch(r"(?:macos|scripts|account_access|\.github/workflows)/[A-Za-z0-9_./-]+", name) is not None
                and all(part not in {"", ".", ".."} for part in name.split("/"))
                and hex_value(digest, 64))
    for name, item in value["scripts"].items():
        require(isinstance(name, str) and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.-]{0,90}", name) is not None
                and isinstance(item, dict) and set(item) == {"sha256", "mode", "bytes"}
                and type(item["mode"]) is int and item["mode"] in {0o644, 0o755}
                and type(item["bytes"]) is int and 0 < item["bytes"] <= 16 * 1024 * 1024
                and hex_value(item["sha256"], 64))
    return value


def git_bytes(repository, arguments, *, maximum):
    # No inherited environment/config, replacement objects, hooks, fsmonitor,
    # pager, external diff or text conversion participates in source evidence.
    result = subprocess.run(["/usr/bin/git", "--no-pager", "--no-replace-objects", "--no-optional-locks",
        "-c", "core.fsmonitor=false", "-c", "core.hooksPath=/dev/null", "-c", "safe.directory=" + str(repository),
        "-C", str(repository), *arguments], stdin=subprocess.DEVNULL, capture_output=True,
        timeout=10, env=GIT_ENV, check=False)
    require(result.returncode == 0 and len(result.stdout) <= maximum and len(result.stderr) <= 4096)
    return result.stdout


def bind_sources(review, repository, source):
    require(repository.is_absolute() and all(part not in {".", ".."} for part in repository.parts)
            and "\0" not in str(repository) and hex_value(source, 40))
    require(git_bytes(repository, ["rev-parse", "--show-object-format"], maximum=16) == b"sha1\n")
    require(git_bytes(repository, ["cat-file", "-t", source], maximum=16) == b"commit\n")
    for name, expected in review["source_files"].items():
        row = git_bytes(repository, ["ls-tree", "--full-tree", "-z", source, "--", name], maximum=1024)
        pattern = rb"100(?:644|755) blob ([a-f0-9]{40})\t" + re.escape(name.encode()) + rb"\x00"
        match = re.fullmatch(pattern, row)
        require(match is not None)
        size = git_bytes(repository, ["cat-file", "-s", match[1].decode()], maximum=16)
        require(re.fullmatch(rb"[0-9]{1,8}\n", size) is not None and 0 < int(size) <= MAX_SOURCE)
        raw = git_bytes(repository, ["show", "--no-ext-diff", "--no-textconv", source + ":" + name], maximum=MAX_SOURCE)
        require(len(raw) == int(size) and sha(raw) == expected)


def command(arguments, *, report, output, log, timeout=30, check=True):
    result = subprocess.run(arguments, stdin=subprocess.DEVNULL, capture_output=True, timeout=timeout, env=ENV, check=False)
    require(len(result.stdout) + len(result.stderr) <= 128 * 1024)
    raw = json.dumps({"returncode": result.returncode, "stdout": result.stdout.decode("utf-8", errors="replace"),
                      "stderr": result.stderr.decode("utf-8", errors="replace")}, sort_keys=True).encode() + b"\n"
    output.write(log, raw)
    report["logs"][log] = sha(raw)
    if check:
        require(result.returncode == 0)
    return result


def candidate_scripts(expanded, review):
    require(set(path.name for path in expanded.iterdir()) <= {"PackageInfo", "Scripts", "Bom"})
    info = ET.fromstring(read_file(expanded / "PackageInfo"))
    require(info.get("identifier") == "com.fainir.accountaccess.componentupdate76v2" and info.get("version") == "0.1.0")
    payload = info.find("payload")
    require(payload is None or all(int(payload.get(key, "0")) == 0 for key in ("numberOfFiles", "installKBytes")))
    phases = info.find("scripts")
    require(phases is not None and len(phases) == 1 and phases[0].tag == "postinstall"
            and phases[0].get("file") in {"./postinstall", "postinstall"})
    scripts = expanded / "Scripts"
    actual = {}
    for path in scripts.iterdir():
        raw = read_file(path)
        actual[path.name] = {"sha256": sha(raw), "mode": stat.S_IMODE(path.lstat().st_mode), "bytes": len(raw)}
    require(actual == review["scripts"])
    plan_raw = read_file(scripts / "ComponentPlan.json")
    require(sha(plan_raw) == review["plan_sha256"])
    plan = json.loads(plan_raw)
    require(plan["component_source_commit"] == review["component_source_commit"]
            and plan["base_manifest_sha256"] == BASE_MANIFEST_SHA256
            and sha(read_file(scripts / "BaseManifest.json")) == BASE_MANIFEST_SHA256
            and sha(read_file(scripts / "TargetManifest.json")) == plan["target_manifest_sha256"])
    return scripts, plan


def verify_image(manifest):
    require(set(manifest["roots"]) == {str(BASE), str(APP)})
    tree = manifest["roots"][str(BASE)]
    children = {}
    for name in tree:
        if name:
            parent, _, child = name.rpartition("/")
            children.setdefault(parent, set()).add(child)
    for relative, expected in tree.items():
        path = BASE / relative
        before = path.lstat()
        require(before.st_uid == 0)
        kind = expected["kind"]
        if kind == "directory":
            require(stat.S_ISDIR(before.st_mode) and stat.S_IMODE(before.st_mode) == expected["mode"])
            actual = {entry.name for entry in path.iterdir()}
            require(actual - (PRIVATE if not relative else set()) == children.get(relative, set()))
        elif kind == "symlink":
            require(stat.S_ISLNK(before.st_mode) and before.st_nlink == 1 and os.readlink(path) == expected["target"])
        else:
            require(kind == "file" and stat.S_ISREG(before.st_mode) and before.st_nlink == 1
                    and stat.S_IMODE(before.st_mode) == expected["mode"] and before.st_size == expected["size"])
            descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            try:
                require(stamp(os.fstat(descriptor)) == stamp(before))
                digest = hashlib.sha256()
                with os.fdopen(os.dup(descriptor), "rb") as stream:
                    for block in iter(lambda: stream.read(1024 * 1024), b""):
                        digest.update(block)
                require(digest.hexdigest() == expected["sha256"] and stamp(os.fstat(descriptor)) == stamp(before))
            finally:
                os.close(descriptor)
        require(stamp(path.lstat()) == stamp(before))
    alias = manifest["roots"][str(APP)]
    require(set(alias) == {""} and APP.is_symlink() and APP.lstat().st_uid == 0
            and os.readlink(APP) == alias[""]["target"])


def policies():
    return {name: json.loads(read_file(path, maximum=4096)) for name, path in (
        ("install", BASE / "broker/install.json"), ("host", BASE / "broker/host.json"), ("owner", BASE / "owner.json"))}


def fixed_records():
    names = [BASE / "broker" / name for name in UNCHANGED_POLICIES]
    names += [JOURNAL / name for name in ("intent.json", "ready.json", "published.json", "complete.json")]
    names += [BASE / "install-verification.json", JOB]
    return {str(path): (sha(read_file(path)), stamp(path.lstat())) for path in names}


def acceptance_passed(report):
    return (isinstance(report.get("checks"), dict) and set(report["checks"]) == CHECKS
            and all(value is True for value in report["checks"].values())
            and "failure_reason" not in report and "cleanup_unverified" not in report)


def run(args):
    guard()  # Before any filesystem, Installer, directory-account or job lookup.
    require(hex_value(args.source, 40) and hex_value(args.candidate_sha256, 64) and hex_value(args.review_sha256, 64))
    output = RootOutput(args.report, os.environ["GITHUB_RUN_ID"])
    report = {"schema": 1, "status": "FAILED", "environment": "fresh-hosted-mac-actual-installer",
              "source_revision": args.source, "controller_revision": os.environ["GITHUB_SHA"],
              "candidate_sha256": args.candidate_sha256, "base_package_sha256": BASE_PACKAGE_SHA256,
              "run_id": os.environ["GITHUB_RUN_ID"], "run_attempt": os.environ["GITHUB_RUN_ATTEMPT"],
              "review_sha256": args.review_sha256, "checks": dict.fromkeys(CHECKS, False), "logs": {},
              "personal_accounts_used": 0, "enrollment_attempted": False, "private_vault_read": False,
              "crash_injection_tested": False, "physical_delivery_verified": False, "production_ready": False,
              "filesystem_cleanup": "hosted VM teardown; created service stopped explicitly"}
    touched = False
    try:
        for path in (BASE, COMPONENTS, JOURNAL, APP, JOB):
            require(not os.path.lexists(path))
        for lookup in (pwd.getpwnam, grp.getgrnam):
            try:
                lookup("_accountaccess")
                raise ValueError("existing_service_identity")
            except KeyError:
                pass
        console = os.stat("/dev/console").st_uid
        person = pwd.getpwuid(console)
        require(console > 0 and person.pw_name == "runner" and person.pw_dir == "/Users/runner")
        report["checks"]["fresh_hosted_vm"] = True
        with tempfile.TemporaryDirectory(prefix="account-access-component-installer-") as temporary:
            stage = Path(temporary)
            stage_file(args.base, stage / "base.pkg", BASE_PACKAGE_SHA256, 300 * 1024 * 1024)
            stage_file(args.base_manifest, stage / "base-manifest.json", BASE_MANIFEST_SHA256, 16 * 1024 * 1024)
            stage_file(args.candidate, stage / "candidate.pkg", args.candidate_sha256, 32 * 1024 * 1024)
            stage_file(args.review, stage / "review.json", args.review_sha256, 1024 * 1024)
            review = validate_review(json.loads(read_file(stage / "review.json")), args.source, args.candidate_sha256)
            require((stage / "candidate.pkg").stat().st_size == review["package_bytes"])
            bind_sources(review, args.repository, args.source)
            report["source_files"] = review["source_files"]
            report["checks"]["reviewed_public_inputs"] = True
            command(["/usr/sbin/pkgutil", "--expand-full", str(stage / "candidate.pkg"), str(stage / "expanded")],
                    report=report, output=output, log="expand.log", timeout=60)
            scripts, plan = candidate_scripts(stage / "expanded", review)
            report["checks"]["candidate_expansion_matches_review"] = True
            requirement = ('anchor apple generic and identifier "com.fainir.accountaccess.componentupdate" '
                'and certificate 1[field.1.2.840.113635.100.6.2.6] exists '
                'and certificate leaf[field.1.2.840.113635.100.6.1.13] exists '
                'and certificate leaf[subject.OU] = "WBULD6N4NQ" '
                'and !(entitlement["com.apple.security.get-task-allow"] exists)')
            command(["/usr/bin/codesign", "--verify", "--strict", "--all-architectures", "-R=" + requirement,
                     str(scripts / "AccountAccess-componentupdate")], report=report, output=output, log="signature.log")
            report["checks"]["genuine_signed_helper"] = True
            touched = True
            command(["/usr/sbin/installer", "-pkg", str(stage / "base.pkg"), "-target", "/"],
                    report=report, output=output, log="base-installer.log", timeout=360)
            report["checks"]["actual_base_installer"] = True
            verify_image(json.loads(read_file(stage / "base-manifest.json")))
            report["checks"]["base_public_image"] = True
            # This fresh CI GUI has no owner input or unsaved account setup.
            command(["/bin/launchctl", "asuser", str(console), "/usr/bin/sudo", "-n", "-H", "-u", "#" + str(console), "--",
                     "/usr/bin/osascript", "-e", 'tell application id "com.fainir.accountaccess" to quit'],
                    report=report, output=output, log="fresh-gui-quit.log", timeout=30)
            report["checks"]["fresh_gui_quit"] = True
            before, retained = policies(), fixed_records()
            command(["/usr/sbin/installer", "-pkg", str(stage / "candidate.pkg"), "-target", "/"],
                    report=report, output=output, log="candidate-installer.log", timeout=180)
            report["checks"]["actual_candidate_installer"] = True
            target = json.loads(read_file(scripts / "TargetManifest.json"))
            verify_image(target)
            report["checks"]["target_public_image"] = True
            expected = json.loads(json.dumps(before))
            expected["install"]["payload_fingerprint"] = plan["new_fingerprint"]
            expected["host"]["bootstrap_hashes"] = plan["new_signatures"]["bootstrap"]["hashes"]
            expected["owner"]["server_hashes"] = plan["new_signatures"]["broker"]["hashes"]
            require(policies() == expected)
            report["checks"]["only_three_policy_values_changed"] = True
            require(fixed_records() == retained)
            report["checks"]["unchanged_worker_plans_and_original_journal"] = True
            head = json.loads(read_file(COMPONENTS / "head.json", maximum=4096))
            require(head == {"schema": 1, "managed_by": "account-access-component-head-v1", "plan_sha256": review["plan_sha256"],
                "base_manifest_sha256": BASE_MANIFEST_SHA256, "manifest_sha256": plan["target_manifest_sha256"],
                "state": "public_image_verified_gui_unverified", "automatic_reboot_recovery": False})
            report["checks"]["verified_head"] = True
            command(["/usr/sbin/installer", "-pkg", str(stage / "candidate.pkg"), "-target", "/"],
                    report=report, output=output, log="same-package-installer.log", timeout=180)
            report["checks"]["same_package_reapplication"] = True
            verify_image(target)
            require(policies() == expected and fixed_records() == retained
                    and json.loads(read_file(COMPONENTS / "head.json", maximum=4096)) == head)
            report["checks"]["reapplication_preserved_bytes_and_ids"] = True
    except Exception:
        report["failure_reason"] = "actual_component_installer_acceptance_failed"
    finally:
        if touched:
            try:
                value = plistlib.loads(read_file(JOB, maximum=8192))
                require(value.get("Label") == LABEL and value.get("ProgramArguments") == [str(BASE / "bin/AccountAccess-broker")])
                command(["/bin/launchctl", "bootout", "system/" + LABEL], report=report,
                        output=output, log="cleanup-bootout.log", check=False)
                absent = command(["/bin/launchctl", "print", "system/" + LABEL], report=report,
                                 output=output, log="cleanup-lookup.log", check=False)
                require(absent.returncode == 113 and absent.stdout + absent.stderr == (
                    'Bad request.\nCould not find service "' + LABEL + '" in domain for system\n').encode())
                report["checks"]["created_job_stopped"] = True
            except Exception:
                report["cleanup_unverified"] = True
        if acceptance_passed(report):
            report["status"] = "PASSED"
        try:
            output.write("report.json", json.dumps(report, indent=2, sort_keys=True).encode() + b"\n")
            output.publish()
        finally:
            output.close()
    return 0 if report["status"] == "PASSED" else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("base", "base-manifest", "candidate", "review", "report", "repository"):
        parser.add_argument("--" + name, type=Path, required=True)
    for name in ("review-sha256", "source", "candidate-sha256"):
        parser.add_argument("--" + name, required=True)
    return run(parser.parse_args())


if __name__ == "__main__":
    raise SystemExit(main())
