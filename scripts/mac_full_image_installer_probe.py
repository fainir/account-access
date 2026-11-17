"""PROPOSAL: actual Installer acceptance in a newly allocated hosted ARM64 VM.

Never run on an owner's Mac. Root guard precedes filesystem access. The optional
interruption scenarios stop only this probe's direct child, using the exact
package helper. Resume/reapply use actual Installer and unchanged package bytes.
This does not claim interruption of Apple's Installer daemon or a power failure.
"""
import argparse
import ctypes
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import runpy
import signal
import stat
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace
import xml.etree.ElementTree as ET

REPOSITORY = "fainir/account-access"
OLD_PROBE_SHA = "1b790d06ae7d20bc04d9f356b364145cc24afdba9a42cd63e5c9089911d3b92b"
COMPONENT_SOURCE = "213509c6bd9ff40131bd71dcb1a2967e96cd76a3"
COMPONENT_SHA = "674c5df7866477e48811d002128370aaec6385aeb0565137036880de4c626bef"
COMPONENT_PLAN = "be4e1429466cc0fbe8d2e85fe9f0d54f9c93b1a1edd6dfa32b77b9c72cc4d1b7"
BEFORE_MANIFEST = "9f0d1274928702dd4d5064b4d3bc8ac7df3bf81c3f70be2f9ccad410785d810c"
TARGET_SOURCE = "d5741bc9912aaf907fe5c52486af18818654dda5"
# Genuine static DR derivation + exact native data proof are independently
# verified; package/release assets remain pending. The fixture-DR plan is refused.
PLAN_SHA = "7c80a671d8b87815db127c6e7d7e8dd9db8c023d70e891185258391b2b3f14a3"
TARGET_SHA = "d1f74db86890b306f989b65a8c521ce3b0879f261ded122dd409be2ca2fbe317"
LEGACY_PINS = (TARGET_SOURCE, PLAN_SHA, TARGET_SHA)
CONFIGURATION_PINS = ("d30fda732c589b9ac4dc339a7237ad8ba00d0016",
    "9dbd37cf8282fe605de7d73a828b6e4d6379e021177cc089a0b21f522f8edd85",
    "05553235819dd43d76d8f1d506f3da16a57617e63c5f8c49bf58c298e11b55da")
FULL = Path("/Library/Application Support/Account Access Full Images")
SCENARIOS = {"install-reapply", "interrupt-remove", "interrupt-create"}
RESOURCE_NAMES = {"FullImagePlan.json", "BaseManifest.json", "TargetManifest.json", "BaseIdentity.json",
                  "TargetIdentity.json", "ProviderManifest.json", "RuntimeCAReceipt.json", "TargetImage",
                  "Predecessor", "AccountAccess-fullimageupdate", "postinstall"}
ASSET_FILES = frozenset({"base.pkg", "base-manifest.json", "base-source.tar.gz", "component.pkg",
    "component-review.json", "component-source.tar.gz", "full.pkg", "full-review.json",
    "full-scripts-inventory.json", "full-source.tar.gz"})
ENV = {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LANG": "C", "LC_ALL": "C"}
DIRECTORY = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
REGULAR = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
CHECKS = {"fresh_hosted_vm", "pinned_public_assets_and_controller", "closed_full_package_resources",
          "genuine_signed_helper", "actual_build76_installer", "base_public_image", "fresh_gui_closed",
          "actual_213_installer", "predecessor_public_image", "actual_full_installer", "target_public_image",
          "only_reviewed_policy_values_changed", "original_and_predecessor_evidence_unchanged", "head_last_history",
          "live_canonical_job", "same_package_reapplication", "reapply_preserves_bytes_and_inodes", "created_job_stopped"}


def require(value):
    if not value:
        raise ValueError("full_image_installer_acceptance_failed")


def install_package(package, *, scenario, report, output, log, cohort=81):
    """Fixed QA budgets, preserving Installer failure and daemon diagnostics.

    The normal first upgrade has measured 398 seconds on a passing hosted Mac;
    another run exceeded the former 420-second budget. Only that phase receives
    840 seconds. Package code, recovery, reapplication and validation are unchanged.
    """
    cohort_contract(cohort)
    require(scenario in SCENARIOS and (package.name, log) in {
        ("base.pkg", "base-installer"), ("component.pkg", "component-installer"),
        ("full.pkg", "full-installer"), ("full.pkg", "full-reapply-installer")})
    budget = 840 if scenario == "install-reapply" and log == "full-installer" else 420
    if cohort == 85 and package.name == "full.pkg":
        budget = 2100  # Includes the qualified 1800-second native script deadline.
    attempts = report.setdefault("installer_attempts", {})
    require(log not in attempts)
    attempt = {"budget_seconds": budget, "completed_successfully": False}
    attempts[log] = attempt
    checkpoint = h.InstallerLogDelta()
    started = time.monotonic()
    try:
        result = h.command(
            ["/usr/sbin/installer", "-dumplog", "-verboseR", "-pkg", str(package), "-target", "/"],
            report=report, output=output, log=log + ".log", timeout=budget)
        attempt["completed_successfully"] = True
        return result
    finally:
        attempt["elapsed_seconds"] = round(time.monotonic() - started, 3)
        checkpoint.capture(report=report, output=output, log=log + "-daemon.log")


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def unique(pairs):
    value = {}
    for key, item in pairs:
        require(key not in value)
        value[key] = item
    return value


def decode(raw):
    return json.loads(raw, object_pairs_hook=unique)


def asset_name(value):
    return isinstance(value, str) and value in ASSET_FILES


def validate_deadline_repack(review, package_info, repacker_source):
    """One frozen container derivative; compiled app, helper and script tree are unchanged."""
    require(digest(package_info) == "d5a5ac883c690ad25648b395cf01458ea913d2676f8326304432ac14a6bfdbf9"
            and digest(repacker_source) == "63a21ee22d2af3176831e19b32f8125012e3e8d0d7c19a6b0bb7a7a749b598c0"
            and review["package_sha256"] == "a01657042819ff5f7ff5166f11b221291bde44f331c643a60ba3ebe120f1489b"
            and review["package_bytes"] == 295994278
            and review["scripts_inventory_sha256"] == "bb035f32e14b14406a601748eb09043aed7a8ae29e79edfe7aca669db35da4c7")
    parent = review["original_build_review_json"]
    require(type(parent) is str and len(parent.encode()) <= 128 * 1024
            and digest(parent.encode()) == "837e416d835a240b602d4f2e468179891443c7adbde10336fddfed3ad2787ab4")
    proof = review["deadline_repack"]
    require(proof["status"] == "REPACKED_REQUIRES_INDEPENDENT_REVIEW_AND_INSTALLER_QA"
            and proof["parent_package_sha256"] == "de6769837c00f41e307b5342ab86021c6e2aac27ba7fd99914f670ab2bd99d95"
            and proof["package_sha256"] == review["package_sha256"] and proof["package_bytes"] == review["package_bytes"]
            and proof["repacker_sha256"] == digest(repacker_source)
            and proof["old_timeout_seconds"] == 600 and proof["new_timeout_seconds"] == 1800
            and proof["compressed_scripts_unchanged"] is True and proof["only_timeout_attribute_changed"] is True
            and proof["script_archive_sha256"] == "99d6b7c1b649bdd3a5139eccb0a362dcabf44ee8e9987d8c181f2f2b4265a008"
            and proof["script_archive_bytes"] == 295993047
            and proof["installed_or_helper_executed"] is False and proof["owner_data_read"] is False
            and proof["actual_installer_qualified"] is False and proof["production_ready"] is False)


def canonical_stage_name(value):
    return isinstance(value, Path) and value.parent == Path("/private/tmp") and re.fullmatch(
        "account-access-full-image-acceptance-[A-Za-z0-9_-]+", value.name) is not None


def verify_owned_stage(stage):
    require(canonical_stage_name(stage))
    fd = os.open("/", DIRECTORY)
    try:
        for name in ("private", "tmp", stage.name):
            parent = fd
            linked = os.stat(name, dir_fd=parent, follow_symlinks=False)
            child = os.open(name, DIRECTORY, dir_fd=parent)
            try:
                observed = os.fstat(child)
                require(stat.S_ISDIR(observed.st_mode) and observed.st_uid == observed.st_gid == 0
                        and h.stamp(observed) == h.stamp(linked)
                        == h.stamp(os.stat(name, dir_fd=parent, follow_symlinks=False)))
                expected_mode = 0o1777 if name == "tmp" else 0o700 if name == stage.name else 0o755
                require(stat.S_IMODE(observed.st_mode) == expected_mode)
                empty_acl(child)
            except Exception:
                os.close(child)
                raise
            os.close(parent)
            fd = child
        require(h.stamp(os.fstat(fd)) == h.stamp(stage.lstat()))
    finally:
        os.close(fd)


def normalize_owned_resource_ancestors(stage):
    # These exact directories were created by this invocation's exclusive
    # full-stage/pkgutil expansion, after the complete inventory comparison.
    # Never normalize an installed path or a caller-selected arbitrary tree.
    verify_owned_stage(stage)
    fd = os.open(stage, DIRECTORY)
    try:
        for name in ("full-stage", "expanded", "Scripts"):
            parent = fd
            child = os.open(name, DIRECTORY, dir_fd=parent)
            try:
                observed = os.fstat(child)
                require(stat.S_ISDIR(observed.st_mode) and not observed.st_mode & 0o7022
                        and h.stamp(observed) == h.stamp(os.stat(name, dir_fd=parent, follow_symlinks=False)))
                empty_acl(child)
                if (observed.st_uid, observed.st_gid) != (0, 0):
                    os.fchown(child, 0, 0)
                    os.fsync(child)
                observed = os.fstat(child)
                require(observed.st_uid == observed.st_gid == 0
                        and h.stamp(observed) == h.stamp(os.stat(name, dir_fd=parent, follow_symlinks=False)))
            except Exception:
                os.close(child)
                raise
            os.close(parent)
            fd = child
    finally:
        os.close(fd)
    verify_owned_stage(stage)


def guard():
    # Deliberately before importing the reusable source or consulting any path.
    require(sys.platform == "darwin" and platform.machine() == "arm64"
            and os.getuid() == os.geteuid() == 0 and os.environ.get("GITHUB_ACTIONS") == "true"
            and os.environ.get("CI") == "true" and os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted"
            and os.environ.get("RUNNER_OS") == "macOS" and os.environ.get("RUNNER_ARCH") == "ARM64"
            and os.environ.get("GITHUB_REPOSITORY") == REPOSITORY
            and re.fullmatch("[1-9][0-9]{0,19}", os.environ.get("GITHUB_RUN_ID", "")) is not None
            and re.fullmatch("[1-9][0-9]{0,9}", os.environ.get("GITHUB_RUN_ATTEMPT", "")) is not None
            and re.fullmatch("[a-f0-9]{40}", os.environ.get("GITHUB_SHA", "")) is not None)


def predecessor_directory_metadata():
    """Fixed completed-installation directory metadata on the guarded VM only."""
    guard()
    result = {}
    for name, path in (("original", h.JOURNAL), ("components", h.COMPONENTS),
                       ("transition", h.COMPONENTS / ("transition-" + COMPONENT_PLAN))):
        info = path.lstat()  # Never follow a symlink or inspect directory contents.
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and stat.S_IMODE(info.st_mode) == 0o700)
        result[name] = {"uid": info.st_uid, "gid": info.st_gid, "mode": stat.S_IMODE(info.st_mode),
                        "device": info.st_dev, "inode": info.st_ino}
    return result


def hash_file(path, maximum):
    fd = os.open(path, REGULAR)
    try:
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and 0 < before.st_size <= maximum)
        value = hashlib.sha256()
        with os.fdopen(os.dup(fd), "rb") as stream:
            for block in iter(lambda: stream.read(1024**2), b""):
                value.update(block)
        require(h.stamp(before) == h.stamp(os.fstat(fd)) == h.stamp(path.lstat()))
        return value.hexdigest(), before.st_size
    finally:
        os.close(fd)


def empty_acl(fd):
    library = ctypes.CDLL(None, use_errno=True)
    library.acl_get_fd.argtypes, library.acl_get_fd.restype = [ctypes.c_int], ctypes.c_void_p
    library.acl_get_entry.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.POINTER(ctypes.c_void_p)]
    library.acl_free.argtypes = [ctypes.c_void_p]
    ctypes.set_errno(0)
    acl = library.acl_get_fd(fd)
    if not acl:
        import errno
        require(ctypes.get_errno() == errno.ENOENT)
        return
    try:
        import errno
        entry = ctypes.c_void_p()
        ctypes.set_errno(0)
        require(library.acl_get_entry(acl, 0, ctypes.byref(entry)) == -1 and ctypes.get_errno() == errno.EINVAL)
    finally:
        library.acl_free(acl)


def inventory(directory, *, normalize=False):
    """Closed public package tree only; never called on an installed root.

    normalize changes ownership only inside this invocation's exclusive expansion,
    for the direct-child interruption seam. Installer performs its own resource
    extraction in the ordinary happy/reapply scenario.
    """
    rows = {}
    def walk(fd, prefix):
        before = os.fstat(fd)
        require(stat.S_ISDIR(before.st_mode) and not before.st_mode & 0o7022)
        empty_acl(fd)
        if normalize and (before.st_uid, before.st_gid) != (0, 0):
            os.fchown(fd, 0, 0)
            before = os.fstat(fd)
        members = sorted(os.listdir(fd))
        require(len(members) < 20000 and len(rows) < 100000)
        rows[prefix] = {"kind": "directory", "mode": stat.S_IMODE(before.st_mode), "acl": "empty"}
        for name in members:
            require(name not in {"", ".", ".."} and "/" not in name and "\x00" not in name)
            relative = prefix + "/" + name if prefix else name
            info = os.stat(name, dir_fd=fd, follow_symlinks=False)
            if stat.S_ISLNK(info.st_mode):
                child = os.open(name, os.O_RDONLY | os.O_NONBLOCK | os.O_CLOEXEC | 0x200000, dir_fd=fd)
            else:
                child = os.open(name, DIRECTORY if stat.S_ISDIR(info.st_mode) else REGULAR, dir_fd=fd)
            try:
                require(h.stamp(info) == h.stamp(os.fstat(child)))
                empty_acl(child)
                if normalize and (info.st_uid, info.st_gid) != (0, 0):
                    os.chown(name, 0, 0, dir_fd=fd, follow_symlinks=False)
                    info = os.fstat(child)
                if stat.S_ISDIR(info.st_mode):
                    walk(child, relative)
                elif stat.S_ISLNK(info.st_mode):
                    require(info.st_nlink == 1)
                    rows[relative] = {"kind": "symlink", "mode": stat.S_IMODE(info.st_mode),
                                      "target": os.readlink(name, dir_fd=fd), "acl": "empty"}
                else:
                    require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_size <= 1024**3)
                    value, count = hashlib.sha256(), 0
                    while block := os.read(child, 1024**2):
                        count += len(block)
                        require(count <= 1024**3)
                        value.update(block)
                    require(count == info.st_size)
                    rows[relative] = {"kind": "file", "mode": stat.S_IMODE(info.st_mode), "bytes": count,
                                      "sha256": value.hexdigest(), "acl": "empty"}
                require(h.stamp(info) == h.stamp(os.fstat(child))
                        == h.stamp(os.stat(name, dir_fd=fd, follow_symlinks=False)))
            finally:
                os.close(child)
        require(members == sorted(os.listdir(fd)) and h.stamp(before) == h.stamp(os.fstat(fd)))
    fd = os.open(directory, DIRECTORY)
    try:
        walk(fd, "")
    finally:
        os.close(fd)
    return rows


def public_evidence():
    # Original fixed public setup records, plus old component journal evidence.
    # Never descend broker/home/vault/control/run/account state.
    evidence = h.fixed_records()
    queue = [h.COMPONENTS]
    for directory in queue:
        require(len(queue) < 1000)
        metadata = directory.lstat()
        require(stat.S_ISDIR(metadata.st_mode) and metadata.st_uid == 0 and not metadata.st_mode & 0o7022)
        for path in sorted(directory.iterdir()):
            info = path.lstat()
            if stat.S_ISDIR(info.st_mode):
                queue.append(path)
            else:
                require(stat.S_ISREG(info.st_mode) and len(evidence) < 20000)
                evidence[str(path)] = (digest(h.read_file(path)), h.stamp(info))
    return evidence


def expected_policies(before, peers):
    value = decode(json.dumps(before).encode())
    base = str(h.BASE)
    layout = {"runtime": base + "/runtime", "browsers": base + "/browsers", "owner_app": base + "/owner.app",
              "broker": base + "/bin/AccountAccess-broker", "bootstrap": base + "/bin/AccountAccess-bootstrap",
              "broker_name": "_accountaccess", "label": h.LABEL}
    value["install"]["payload_fingerprint"] = digest(json.dumps({"signatures": peers, "layout": layout}, sort_keys=True).encode())
    value["host"]["bootstrap_hashes"] = peers["bootstrap"]["hashes"]
    value["host"]["owner_hashes"] = peers["owner"]["hashes"]
    value["owner"]["server_hashes"] = peers["broker"]["hashes"]
    return value


def history(pins=LEGACY_PINS):
    TARGET_SOURCE, PLAN_SHA, TARGET_SHA = pins
    directory = FULL / ("transition-" + PLAN_SHA) / "global"
    intent_raw = h.read_file(directory / "intent.json", maximum=256 * 1024)
    intent = decode(intent_raw)
    require(intent["schema"] == 2 and intent["planSHA256"] == PLAN_SHA
            and intent["beforeManifestSHA256"] == BEFORE_MANIFEST and intent["afterManifestSHA256"] == TARGET_SHA
            and intent["targetSourceCommit"] == TARGET_SOURCE and intent["automaticRebootRecovery"] is False
            and len(intent["operations"]) == 29 and intent["operations"][-1]["file"]["unit"] == "head")
    names = sorted(path.name for path in directory.iterdir() if re.fullmatch("record-[0-9]{4}.json", path.name))
    require(len(names) <= 10000)
    previous, records = digest(intent_raw), []
    for index, name in enumerate(names):
        require(name == f"record-{index:04d}.json")
        raw = h.read_file(directory / name, maximum=8192)
        row = decode(raw)
        require(row["schema"] == 1 and row["managedBy"] == "account-access-full-image-journal-v1"
                and row["sequence"] == index and row["planSHA256"] == PLAN_SHA
                and row["intentSHA256"] == digest(intent_raw) and row["previousSHA256"] == previous)
        previous = digest(raw)
        records.append(row)
    return intent, records


def completed_history(pins=LEGACY_PINS):
    TARGET_SOURCE, PLAN_SHA, TARGET_SHA = pins
    intent, records = history(pins)
    applied = [row["operation"] for row in records if row.get("transition") == "applied"]
    require(applied == list(range(29)) and any(row.get("transition") == "new_image_verified_gui_unverified" for row in records))
    require(any(row.get("service") == "disabled_quiescence_confirmed" for row in records)
            and any(row.get("service") == "canonical_job_bootstrapped_gui_unverified" for row in records))
    head = decode(h.read_file(FULL / "head.json", maximum=4096))
    require(head == {"schema": 1, "managed_by": "account-access-full-image-head-v1", "plan_sha256": PLAN_SHA,
        "before_manifest_sha256": BEFORE_MANIFEST, "manifest_sha256": TARGET_SHA, "source_commit": TARGET_SOURCE,
        "predecessor_evidence_sha256": intent["predecessorEvidenceSHA256"],
        "state": "public_image_verified_gui_unverified", "automatic_reboot_recovery": False})
    return digest(h.read_file(FULL / "head.json", maximum=4096)), h.stamp((FULL / "head.json").lstat())


def public_directory_metadata(info):
    """Bounded numeric evidence only; validation does not adopt these values."""
    value = {"uid": info.st_uid, "gid": info.st_gid, "mode": stat.S_IMODE(info.st_mode),
             "device": info.st_dev, "inode": info.st_ino, "kind": stat.S_IFMT(info.st_mode)}
    require(all(type(item) is int for item in value.values())
            and 0 <= value["uid"] < 2**32 and 0 <= value["gid"] < 2**32
            and -(2**31) <= value["device"] < 2**31 and 0 < value["inode"] < 2**64)
    return value


def support_root_metadata():
    """The fixed public root supplies legacy group authority before launch."""
    guard()
    descriptor = os.open(h.BASE, DIRECTORY)
    try:
        info = os.fstat(descriptor)
        h.protected_metadata(info, mode=0o755)
        h.deny_only_acl(descriptor)
        require(h.stamp(info) == h.stamp(os.fstat(descriptor)) == h.stamp(h.BASE.lstat()))
        return public_directory_metadata(info)
    finally:
        os.close(descriptor)


def selected_tree_pin_metadata(pin):
    require(isinstance(pin, dict) and all(type(pin.get(name)) is int
            for name in ("owner", "group", "mode", "device", "inode")))
    require(all(0 <= pin[name] < 2**32 for name in ("owner", "group"))
            and 0 <= pin["mode"] <= 0o7777 and -(2**31) <= pin["device"] < 2**31
            and 0 < pin["inode"] < 2**64)
    return {name: pin[name] for name in ("owner", "group", "mode", "device", "inode")}


def stopped_tree_metadata(scenario, support_before, support_after, pin, observed):
    """Compare a stopped optional tree to pre-launch authority, never to a chosen GID."""
    require(scenario in {"interrupt-remove", "interrupt-create"}
            and support_before == support_after and support_before["uid"] == 0
            and support_before["mode"] == 0o755 and support_before["kind"] == stat.S_IFDIR)
    expected_group = support_before["gid"] if scenario == "interrupt-remove" else 0
    pin = selected_tree_pin_metadata(pin)
    require(pin["owner"] == 0 and pin["group"] == expected_group and pin["mode"] == 0o755
            and pin["device"] == support_before["device"] and 0 < pin["inode"] < 2**64)
    require(observed == {"uid": 0, "gid": expected_group, "mode": 0o755,
            "device": pin["device"], "inode": pin["inode"], "kind": stat.S_IFDIR})
    return pin


def interrupt(scripts, scenario, report, output, *, pins=LEGACY_PINS):
    """Stop only a Popen child created here, never a discovered/adopted PID."""
    index = 6 if scenario == "interrupt-remove" else 7
    _, PLAN_SHA, _ = pins
    unit = "pythonOldPipInfo" if index == 6 else "pythonPipInfo"
    helper = scripts / "AccountAccess-fullimageupdate"
    stdout_path, stderr_path = scripts.parent / "owned-helper.stdout", scripts.parent / "owned-helper.stderr"
    report["failure_stage"] = "owned_helper_launch"
    try:
        with stdout_path.open("xb") as stdout, stderr_path.open("xb") as stderr:
            report["failure_stage"] = "owned_helper_support_before"
            support_before = support_root_metadata()
            report["interruption_support_before"] = support_before
            report["failure_stage"] = "owned_helper_launch"
            child = subprocess.Popen([str(helper)], stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr,
                                     env=ENV, start_new_session=True)
            report["failure_stage"] = "owned_helper_checkpoint_wait"
            stopped = False
            try:
                until = time.monotonic() + 900
                while time.monotonic() < until and child.poll() is None:
                    require(stdout_path.stat().st_size + stderr_path.stat().st_size < 128 * 1024)
                    try:
                        intent, records = history(pins)
                    except FileNotFoundError:
                        time.sleep(0.005)
                        continue
                    operation = intent["operations"][index]["tree"]
                    require(operation["unit"] == unit)
                    if any(row.get("transition") == "applied" and row.get("operation") == index for row in records):
                        report["failure_stage"] = "owned_helper_stop_confirmation"
                        os.killpg(child.pid, signal.SIGSTOP)
                        until_stopped = time.monotonic() + 5
                        while time.monotonic() < until_stopped:
                            pid, status = os.waitpid(child.pid, os.WNOHANG | os.WUNTRACED)
                            if pid:
                                require(os.WIFSTOPPED(status))
                                stopped = True
                                break
                            time.sleep(0.005)
                        require(stopped)
                        report["failure_stage"] = "owned_helper_stopped_head_absent"
                        require(not os.path.lexists(FULL / "head.json"))
                        report["failure_stage"] = "owned_helper_stopped_history"
                        intent, records = history(pins)
                        operation = intent["operations"][index]["tree"]
                        require(operation["unit"] == unit)
                        report["failure_stage"] = "owned_helper_stopped_applied_history"
                        require(any(row.get("transition") == "applied" and row.get("operation") == index for row in records)
                                and not any(row.get("operation") == 28 and row.get("transition") == "applied" for row in records))
                        report["failure_stage"] = "owned_helper_stopped_service_history"
                        require(any(row.get("service") == "disabled_quiescence_confirmed" for row in records)
                                and not any(row.get("service") == "coherent_image_enable_intent" for row in records))
                        target = h.BASE / "python/lib/python3.12/site-packages" / (
                            "pip-26.2.1.dist-info" if index == 6 else "pip-26.2.2.dist-info")
                        retained = FULL / ("transition-" + PLAN_SHA) / "trees" / unit / "retained" / ("slot-" + unit)
                        report["failure_stage"] = "owned_helper_stopped_optional_absence"
                        if index == 6:
                            require(not os.path.lexists(target))
                            pin, observed_path = operation["before"], retained
                        else:
                            require(not os.path.lexists(retained))
                            pin, observed_path = operation["after"], target
                        report["failure_stage"] = "owned_helper_stopped_support_metadata"
                        support_after = support_root_metadata()
                        report["interruption_support_after"] = support_after
                        report["failure_stage"] = "owned_helper_stopped_tree_metadata"
                        observed = public_directory_metadata(observed_path.lstat())
                        report["interruption_observed_tree"] = observed
                        # Publish only bounded integers even if the immutable pin is invalid.
                        report["interruption_selected_pin"] = selected_tree_pin_metadata(pin)
                        stopped_tree_metadata(scenario, support_before, support_after, pin, observed)
                        report["failure_stage"] = "owned_helper_stopped_broker_quiescence"
                        broker = h.policies()["install"]["broker_uid"]
                        observed = h.ProcessDiagnosticReader().observed(4, broker, expected_uid=broker)
                        require(observed.get("status") == "measured" and observed.get("count") == 0)
                        report["interruption"] = {"status": "EXACT_OWNED_HELPER_STOPPED_BEFORE_HEAD", "optional_unit": unit,
                            "operation": index, "durable_records": len(records), "head_absent": True,
                            "broker_uid_processes": 0, "production_fault_flags": False,
                            "installer_daemon_interrupted": False, "power_failure_tested": False}
                        break
                    time.sleep(0.005)
                require(stopped)  # A missed checkpoint fails; never retry for green.
            finally:
                try:
                    os.killpg(child.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                child.wait(timeout=10)
    finally:
        # Closed public outputs from this invocation's direct child. Preserve
        # them even when launch, native refusal or checkpoint observation fails.
        captured = True
        for name, path in [("owned-helper-stdout.log", stdout_path), ("owned-helper-stderr.log", stderr_path)]:
            try:
                raw = h.read_file(path, maximum=128 * 1024)
                output.write(name, raw)
                report["logs"][name] = digest(raw)
            except Exception:
                captured = False
        report["owned_helper_logs_captured"] = captured
        require(captured)


def run(args):
    guard()
    require(args.scenario in SCENARIOS)
    contract_path, package_identifier = cohort_contract(getattr(args, "cohort", 81))
    pins = cohort_pins(getattr(args, "cohort", 81))
    TARGET_SOURCE, PLAN_SHA, TARGET_SHA = pins
    revision = os.environ["GITHUB_SHA"]
    old_path = args.repository / "scripts/mac_component_update_installer_probe.py"
    old_raw = old_path.read_bytes()
    require(digest(old_raw) == OLD_PROBE_SHA)
    # The reused module contains imports/definitions only; its guarded main is not run.
    global h
    h = SimpleNamespace(**runpy.run_path(str(old_path)))
    h.guard()
    for name in ("scripts/mac_full_image_installer_probe.py", "scripts/mac_component_update_installer_probe.py"):
        require(h.git_bytes(args.repository, ["show", revision + ":" + name], maximum=2 * 1024**2)
                == (args.repository / name).read_bytes())
    output = h.RootOutput(h.report_path(os.environ["GITHUB_RUN_ID"]), os.environ["GITHUB_RUN_ID"])
    report = {"schema": 1, "status": "FAILED", "environment": "fresh-hosted-mac-full-image-installer",
        "scenario": args.scenario, "controller_revision": revision, "checks": dict.fromkeys(CHECKS, False), "logs": {},
        "failure_stage": "fresh_vm_preflight", "personal_accounts_used": 0, "enrollment_attempted": False,
        "private_vault_read": False, "owner_GUI_qualified": False, "production_ready": False,
        "interruption": {"status": "NOT_REQUESTED", "installer_daemon_interrupted": False, "power_failure_tested": False}}
    touched = False
    try:
        for path in (h.BASE, h.COMPONENTS, h.JOURNAL, h.APP, h.JOB, h.REVALIDATION_NAMESPACE, FULL):
            require(not os.path.lexists(path))
        import pwd
        import grp
        for lookup in (pwd.getpwnam, grp.getgrnam):
            try:
                lookup("_accountaccess")
            except KeyError:
                continue
            require(False)
        console = os.stat("/dev/console").st_uid
        person = pwd.getpwuid(console)
        require(console > 0 and person.pw_name == "runner" and person.pw_dir == "/Users/runner")
        report["checks"]["fresh_hosted_vm"] = True
        controller = decode((args.bundle / "controller.json").read_bytes())
        contract_raw = (args.bundle / "asset-contract.json").read_bytes()
        contract = decode(contract_raw)
        require(controller["controller_revision"] == revision and controller["contract_sha256"] == digest(contract_raw)
                and contract["status"] == "FROZEN_REVIEWED_ASSETS" and contract["repository"] == REPOSITORY
                and contract_raw == h.git_bytes(args.repository,
                    ["show", revision + ":" + contract_path], maximum=64 * 1024))
        require(set(contract["assets"]) == ASSET_FILES
                and contract.get("plan_sha256") == PLAN_SHA and contract.get("target_source") == TARGET_SOURCE)
        for name, row in contract["assets"].items():
            require(asset_name(name))
            require(hash_file(args.bundle / name, 1024**3) == (row["sha256"], row["bytes"]))
        report["checks"]["pinned_public_assets_and_controller"] = True
        report["package_sha256"] = contract["assets"]["full.pkg"]["sha256"]
        with tempfile.TemporaryDirectory(prefix="account-access-full-image-acceptance-", dir="/private/tmp") as temporary:
            stage = Path(temporary)
            verify_owned_stage(stage)
            for name in ("base.pkg", "base-manifest.json", "component.pkg", "component-review.json",
                         "full.pkg", "full-review.json", "full-scripts-inventory.json"):
                h.stage_file(args.bundle / name, stage / name, contract["assets"][name]["sha256"], 1024**3)
            def command(arguments, log, timeout=120, check=True):
                return h.command(arguments, report=report, output=output, log=log, timeout=timeout, check=check)
            def install(name, log):
                return install_package(stage / name, scenario=args.scenario,
                    report=report, output=output, log=log, cohort=getattr(args, "cohort", 81))
            report["failure_stage"] = "candidate_expansion"
            component_review = h.validate_review(decode(h.read_file(stage / "component-review.json")), COMPONENT_SOURCE, COMPONENT_SHA)
            h.bind_sources(component_review, args.repository, COMPONENT_SOURCE)
            require(component_review["plan_sha256"] == COMPONENT_PLAN)
            command(["/usr/sbin/pkgutil", "--expand-full", str(stage / "component.pkg"), str(stage / "expanded")], "component-expand.log")
            _, component_plan, predecessor_manifest = h.candidate_scripts(stage / "expanded", component_review,
                staging_anchor=stage, diagnostics=report)
            require(component_plan["target_manifest_sha256"] == BEFORE_MANIFEST)
            # Use a separate exclusive stage so the original ArchiveExpansion contract remains exact.
            full_stage = stage / "full-stage"
            full_stage.mkdir(mode=0o700)
            command(["/usr/sbin/pkgutil", "--expand-full", str(stage / "full.pkg"), str(full_stage / "expanded")], "full-expand.log", 300)
            expanded = full_stage / "expanded"
            require({path.name for path in expanded.iterdir()} == {"PackageInfo", "Scripts"})
            info_raw = h.read_file(expanded / "PackageInfo", owner=expanded.joinpath("PackageInfo").lstat().st_uid)
            info = ET.fromstring(info_raw)
            payload, phases = info.find("payload"), info.find("scripts")
            require(info.get("identifier") == package_identifier and info.get("version") == "0.1.0"
                    and info.get("auth") == "root" and (payload is None or
                    all(int(payload.get(key, "0")) == 0 for key in ("numberOfFiles", "installKBytes")))
                    and phases is not None and len(phases) == 1 and phases[0].tag == "postinstall"
                    and phases[0].get("file") in {"postinstall", "./postinstall"})
            scripts = expanded / "Scripts"
            expected_inventory = decode(h.read_file(stage / "full-scripts-inventory.json", maximum=64 * 1024**2))
            require(inventory(scripts) == expected_inventory and {path.name for path in scripts.iterdir()} == RESOURCE_NAMES)
            full_review = decode(h.read_file(stage / "full-review.json", maximum=2 * 1024**2))
            require(full_review["status"] == "BUILT_NOT_INSTALLED_NOT_INSTALL_QUALIFIED"
                    and full_review["package_sha256"] == report["package_sha256"]
                    and full_review["package_bytes"] == (stage / "full.pkg").stat().st_size
                    and full_review["plan_sha256"] == PLAN_SHA and full_review["target_manifest_sha256"] == TARGET_SHA
                    and full_review["target_gui_source_commit"] == TARGET_SOURCE
                    and full_review["scripts_inventory_sha256"] == contract["assets"]["full-scripts-inventory.json"]["sha256"]
                    and full_review["production_ready"] is False and full_review["actual_Installer_qualified"] is False)
            if getattr(args, "cohort", 81) == 85:
                repacker = h.git_bytes(args.repository,
                    ["show", revision + ":scripts/repack_full_image84_timeout.py"], maximum=65536)
                validate_deadline_repack(full_review, info_raw, repacker)
                report["script_timeout_seconds"] = 1800
            def resource(name):
                return h.read_file(scripts / name, owner=(scripts / name).lstat().st_uid)
            require(digest(resource("FullImagePlan.json")) == PLAN_SHA and digest(resource("TargetManifest.json")) == TARGET_SHA
                    and digest(resource("BaseManifest.json")) == BEFORE_MANIFEST)
            plan, target = decode(resource("FullImagePlan.json")), decode(resource("TargetManifest.json"))
            require(len(plan["units"]) == 25)
            for name, row in component_review["scripts"].items():
                path = scripts / "Predecessor" / name
                require(digest(h.read_file(path, owner=path.lstat().st_uid)) == row["sha256"])
            report["checks"]["closed_full_package_resources"] = True
            requirement = ('anchor apple generic and identifier "com.fainir.accountaccess.componentupdate" '
                'and certificate 1[field.1.2.840.113635.100.6.2.6] exists '
                'and certificate leaf[field.1.2.840.113635.100.6.1.13] exists '
                'and certificate leaf[subject.OU] = "WBULD6N4NQ" '
                'and !(entitlement["com.apple.security.get-task-allow"] exists)')
            command(["/usr/bin/codesign", "--verify", "--strict", "--all-architectures", "-R=" + requirement,
                     str(scripts / "AccountAccess-fullimageupdate")], "helper-signature.log")
            report["checks"]["genuine_signed_helper"] = True
            report["failure_stage"] = "actual_build76_installer"
            touched = True
            install("base.pkg", "base-installer")
            report["checks"]["actual_build76_installer"] = True
            h.verify_image(decode(h.read_file(stage / "base-manifest.json")))
            report["checks"]["base_public_image"] = True
            h.close_fresh_gui(console, report=report, output=output)
            report["checks"]["fresh_gui_closed"] = True
            report["failure_stage"] = "actual_213_installer"
            install("component.pkg", "component-installer")
            report["checks"]["actual_213_installer"] = True
            h.verify_image(predecessor_manifest)
            report["checks"]["predecessor_public_image"] = True
            report["failure_stage"] = "predecessor_directory_metadata"
            report["predecessor_directory_metadata"] = predecessor_directory_metadata()
            report["failure_stage"] = "predecessor_evidence_snapshot"
            before, retained = h.policies(), public_evidence()
            roots = {str(path): (path.lstat().st_dev, path.lstat().st_ino) for path in (h.BASE, h.APP)}
            expected = expected_policies(before, plan["new_peers"])
            if args.scenario != "install-reapply":
                report["failure_stage"] = "owned_helper_stage_before_normalization"
                verify_owned_stage(stage)
                report["failure_stage"] = "owned_helper_ancestor_normalization"
                normalize_owned_resource_ancestors(stage)
                report["failure_stage"] = "owned_helper_normalized_inventory"
                require(inventory(scripts, normalize=True) == expected_inventory)
                report["failure_stage"] = "owned_helper_stage_after_normalization"
                verify_owned_stage(stage)
                interrupt(scripts, args.scenario, report, output, pins=pins)
                require(public_evidence() == retained)
            report["failure_stage"] = "actual_full_installer"
            install("full.pkg", "full-installer")
            report["checks"]["actual_full_installer"] = True
            h.verify_image(target)
            report["checks"]["target_public_image"] = True
            require(h.policies() == expected)
            report["checks"]["only_reviewed_policy_values_changed"] = True
            require(public_evidence() == retained and all(
                (Path(path).lstat().st_dev, Path(path).lstat().st_ino) == identity for path, identity in roots.items()))
            report["checks"]["original_and_predecessor_evidence_unchanged"] = True
            head = completed_history(pins)
            report["checks"]["head_last_history"] = True
            command(["/bin/launchctl", "print", "system/" + h.LABEL], "live-job.log")
            report["checks"]["live_canonical_job"] = True
            report["failure_stage"] = "same_package_reapply"
            install("full.pkg", "full-reapply-installer")
            report["checks"]["same_package_reapplication"] = True
            h.verify_image(target)
            require(h.policies() == expected and public_evidence() == retained and completed_history(pins) == head)
            require(hash_file(stage / "full.pkg", 1024**3)[0] == report["package_sha256"])
            report["checks"]["reapply_preserves_bytes_and_inodes"] = True
    except Exception:
        report["failure_reason"] = "actual_full_image_installer_acceptance_failed"
    finally:
        report["measurement_failure_stage"] = report["failure_stage"] if "failure_reason" in report else None
        if touched:
            try:
                h.command(["/bin/launchctl", "bootout", "system/" + h.LABEL], report=report,
                    output=output, log="cleanup-bootout.log", check=False)
                absent = h.command(["/bin/launchctl", "print", "system/" + h.LABEL], report=report,
                    output=output, log="cleanup-lookup.log", check=False)
                require(absent.returncode == 113 and absent.stdout + absent.stderr == (
                    'Bad request.\nCould not find service "' + h.LABEL + '" in domain for system\n').encode())
                report["checks"]["created_job_stopped"] = True
            except Exception:
                report["cleanup_unverified"] = True
        if all(report["checks"].values()) and "failure_reason" not in report and "cleanup_unverified" not in report:
            report["status"], report["failure_stage"] = "PASSED", None
        try:
            output.write("report.json", (json.dumps(report, indent=2, sort_keys=True) + "\n").encode())
            output.publish()
        finally:
            output.close()
    return 0 if report["status"] == "PASSED" else 1


def cohort_contract(cohort):
    contracts = {81: "artifacts/full-image-installer81-recovery-inputs.json",
                 82: "artifacts/full-image-installer82-inputs.json",
                 83: "artifacts/full-image-installer83-inputs.json",
                 84: "artifacts/full-image-installer84-inputs.json",
                 85: "artifacts/full-image-installer85-inputs.json"}
    require(type(cohort) is int and cohort in contracts)
    return contracts[cohort], f"com.fainir.accountaccess.fullimageupdate{84 if cohort == 85 else cohort}"


def cohort_pins(cohort):
    cohort_contract(cohort)
    return CONFIGURATION_PINS if cohort in {84, 85} else LEGACY_PINS


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", type=Path, required=True)
    parser.add_argument("--bundle", type=Path, required=True)
    parser.add_argument("--scenario", choices=sorted(SCENARIOS), required=True)
    parser.add_argument("--cohort", type=int, choices=[81, 82, 83, 84, 85], default=81)
    return run(parser.parse_args())


if __name__ == "__main__":
    raise SystemExit(main())
