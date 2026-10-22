"""Actual fresh install/reapply QA, exclusively in a new hosted ARM64 Mac VM.

No base/component installer, owner accounts, negative smoke, fault injection or
development payload is used. This controller has no dispatch capability.
"""

import argparse
import ast
import hashlib
import json
import os
from pathlib import Path
import platform
import plistlib
import re
import runpy
import stat
import sys
import tempfile
import time
from types import SimpleNamespace
import xml.etree.ElementTree as ET

REPOSITORY = "fainir/account-access"
HELPER = "scripts/mac_component_update_installer_probe.py"
HELPER_SHA = "a4507756990cf6ff96e666653dab7aa7d636f1c37a01027dce9fae0e465311da"
INPUTS = "scripts/download_fresh_image_installer_inputs.py"
CONTRACT = "artifacts/fresh-image80-installer-inputs.json"
MANIFEST_SHA = "d1f74db86890b306f989b65a8c521ce3b0879f261ded122dd409be2ca2fbe317"
APP_SOURCE = "d5741bc9912aaf907fe5c52486af18818654dda5"
VERIFIER_SHA = "cce66e7499a755a4bd5dba098059012860d5e0fcf54ae8e461708b4ac4ef8534"
RESOURCES = {"preinstall", "postinstall", "RecoveryManifest.json", "AccountAccess-installerverify", "PublicImage"}
PEERS = {"owner.app": "com.fainir.accountaccess", "bin/AccountAccess-broker": "com.fainir.accountaccess.broker",
         "bin/AccountAccess-bootstrap": "com.fainir.accountaccess.bootstrap",
         "bin/AccountAccess-installerverify": "com.fainir.accountaccess.installerverify"}
COUNTS = {"files": 25165, "directories": 2297, "aliases": 21}
CHECKS = frozenset({"fresh_hosted_vm", "fixed_public_assets_and_sources", "closed_product_envelope",
    "genuine_production_signatures", "actual_fresh_installer", "exact_public_image", "fresh_gui_closed",
    "original_image_receipts", "live_service", "identical_package_reapply", "reapply_preserves_bytes_and_inodes",
    "reapplied_gui_closed", "created_job_stopped"})
DIRECTORY = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
REGULAR = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC


def require(value):
    if not value:
        raise ValueError("fresh_image_installer_acceptance_failed")


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def guard():
    require(sys.platform == "darwin" and platform.machine() == "arm64" and os.getuid() == os.geteuid() == 0
        and os.environ.get("GITHUB_ACTIONS") == "true" and os.environ.get("CI") == "true"
        and os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted" and os.environ.get("RUNNER_OS") == "macOS"
        and os.environ.get("RUNNER_ARCH") == "ARM64" and os.environ.get("GITHUB_REPOSITORY") == REPOSITORY
        and re.fullmatch(r"[1-9][0-9]{0,19}", os.environ.get("GITHUB_RUN_ID", "")) is not None
        and re.fullmatch(r"[1-9][0-9]{0,9}", os.environ.get("GITHUB_RUN_ATTEMPT", "")) is not None
        and re.fullmatch(r"[a-f0-9]{40}", os.environ.get("GITHUB_SHA", "")) is not None)


def unique(pairs):
    value = {}
    for key, item in pairs:
        require(key not in value)
        value[key] = item
    return value


def decode(raw):
    return json.loads(raw, object_pairs_hook=unique)


def hash_file(path, maximum):
    descriptor = os.open(path, REGULAR)
    try:
        before = os.fstat(descriptor)
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and 0 < before.st_size <= maximum)
        checksum, size = hashlib.sha256(), 0
        with os.fdopen(os.dup(descriptor), "rb") as stream:
            for block in iter(lambda: stream.read(1024**2), b""):
                size += len(block)
                require(size <= maximum)
                checksum.update(block)
        require(size == before.st_size and h.stamp(before) == h.stamp(os.fstat(descriptor)) == h.stamp(path.lstat()))
        return checksum.hexdigest(), size
    finally:
        os.close(descriptor)


def owned_stage(stage):
    require(stage.parent == Path("/private/tmp")
        and re.fullmatch(r"account-access-fresh-image-acceptance-[A-Za-z0-9_-]+", stage.name) is not None)
    descriptor = os.open(stage, DIRECTORY)
    try:
        h.protected_metadata(os.fstat(descriptor), mode=0o700)
        h.deny_only_acl(descriptor)
        require(h.stamp(os.fstat(descriptor)) == h.stamp(stage.lstat()))
    finally:
        os.close(descriptor)


def inventory(directory):
    """The exclusive public package expansion only; no installed/private walk."""
    rows = {}

    def walk(descriptor, prefix):
        before = os.fstat(descriptor)
        require(stat.S_ISDIR(before.st_mode) and not before.st_mode & 0o7022)
        h.deny_only_acl(descriptor)
        members = sorted(os.listdir(descriptor))
        require(len(members) < 20000 and len(rows) < 100000)
        rows[prefix] = {"kind": "directory", "mode": stat.S_IMODE(before.st_mode)}
        for name in members:
            require(name not in {"", ".", ".."} and "/" not in name and "\x00" not in name)
            relative = prefix + "/" + name if prefix else name
            linked = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
            flags = os.O_RDONLY | os.O_NONBLOCK | os.O_CLOEXEC | 0x200000 if stat.S_ISLNK(linked.st_mode) else (
                DIRECTORY if stat.S_ISDIR(linked.st_mode) else REGULAR)
            child = os.open(name, flags, dir_fd=descriptor)
            try:
                require(h.stamp(linked) == h.stamp(os.fstat(child)))
                h.deny_only_acl(child)
                if stat.S_ISDIR(linked.st_mode):
                    walk(child, relative)
                elif stat.S_ISLNK(linked.st_mode):
                    require(linked.st_nlink == 1)
                    rows[relative] = {"kind": "symlink", "mode": stat.S_IMODE(linked.st_mode),
                                      "target": os.readlink(name, dir_fd=descriptor)}
                else:
                    require(stat.S_ISREG(linked.st_mode) and linked.st_nlink == 1 and linked.st_size <= 1024**3)
                    checksum, size = hashlib.sha256(), 0
                    while block := os.read(child, 1024**2):
                        size += len(block)
                        require(size <= linked.st_size)
                        checksum.update(block)
                    require(size == linked.st_size)
                    rows[relative] = {"kind": "file", "mode": stat.S_IMODE(linked.st_mode),
                                      "bytes": size, "sha256": checksum.hexdigest()}
                require(h.stamp(linked) == h.stamp(os.fstat(child))
                    == h.stamp(os.stat(name, dir_fd=descriptor, follow_symlinks=False)))
            finally:
                os.close(child)
        require(members == sorted(os.listdir(descriptor)) and h.stamp(before) == h.stamp(os.fstat(descriptor)))

    descriptor = os.open(directory, DIRECTORY)
    try:
        walk(descriptor, "")
    finally:
        os.close(descriptor)
    return rows


def validate_review(review, contract):
    require(type(review) is dict and set(review) == {"schema", "status", "package_sha256", "package_bytes",
        "target_manifest_sha256", "target_source", "packaging_source", "installer_verifier_sha256",
        "expanded_inventory_sha256", "actual_Installer_qualified", "production_ready"}
        and type(review["schema"]) is int and review["schema"] == 1
        and review["status"] == "BUILT_NOT_INSTALLED_NOT_INSTALL_QUALIFIED"
        and review["package_sha256"] == contract["assets"]["fresh.pkg"]["sha256"]
        and type(review["package_bytes"]) is int and review["package_bytes"] == contract["assets"]["fresh.pkg"]["bytes"]
        and review["target_manifest_sha256"] == MANIFEST_SHA and review["target_source"] == APP_SOURCE
        and review["packaging_source"] == contract["packaging_source"]
        and review["installer_verifier_sha256"] == VERIFIER_SHA
        and review["expanded_inventory_sha256"] == contract["assets"]["fresh-expanded-inventory.json"]["sha256"]
        and review["actual_Installer_qualified"] is False and review["production_ready"] is False)
    return review


def validate_package_info(raw):
    info = ET.fromstring(raw)
    require(info.tag == "pkg-info" and info.get("identifier") == "com.fainir.accountaccess.system"
        and info.get("version") == "0.8.0" and info.get("auth") == "root")
    payload, phases = info.find("payload"), info.find("scripts")
    require(payload is None or all(int(payload.get(key, "0")) == 0 for key in ("numberOfFiles", "installKBytes")))
    require(phases is not None and len(phases) == 2
        and {phase.tag for phase in phases} == {"preinstall", "postinstall"}
        and all(phase.get("file") in {phase.tag, "./" + phase.tag} for phase in phases))


def install_script_bodies(raw):
    """Read the two literal scripts from Git source without importing/executing it."""
    result = {}
    for node in ast.parse(raw).body:
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id in {"PREINSTALL", "POSTINSTALL"}:
                    require(target.id.lower() not in result and isinstance(node.value, ast.Constant)
                        and type(node.value.value) is str)
                    body = node.value.value.encode()
                    require(0 < len(body) < 16384 and b"\0" not in body)
                    result[target.id.lower()] = body
    require(set(result) == {"preinstall", "postinstall"})
    return result


def validate_expansion(expanded, expected, scripts_expected):
    require(type(expected) is dict and 0 < len(expected) < 100000 and inventory(expanded) == expected)
    # Exact entire membership comes from the reviewed frozen inventory; no guessed
    # optional Resources/Bom members are accepted by a separate loose allowlist.
    scripts = expanded / "payload.pkg/Scripts"
    require({path.name for path in scripts.iterdir()} == RESOURCES)
    for name, raw in scripts_expected.items():
        require(h.read_file(scripts / name, owner=(scripts / name).lstat().st_uid, maximum=16384) == raw)
    validate_package_info(h.read_file(expanded / "payload.pkg/PackageInfo",
        owner=(expanded / "payload.pkg/PackageInfo").lstat().st_uid, maximum=64 * 1024))
    validate_distribution(h.read_file(expanded / "Distribution",
        owner=(expanded / "Distribution").lstat().st_uid, maximum=64 * 1024))
    require(hash_file(scripts / "RecoveryManifest.json", 16 * 1024**2)[0] == MANIFEST_SHA
        and hash_file(scripts / "AccountAccess-installerverify", 32 * 1024**2)[0] == VERIFIER_SHA)
    return scripts


def validate_distribution(raw):
    distribution = ET.fromstring(raw)
    options, domains = distribution.find("options"), distribution.find("domains")
    references = distribution.findall("pkg-ref")
    payloads = [item for item in references if (item.text or "").strip()]
    # productbuild embeds the component with a fragment reference and adds a
    # separate bundle-version metadata reference. Do not accept URLs, another
    # component, or another nonempty reference when checking that envelope.
    require(distribution.tag == "installer-gui-script" and options is not None
        and options.get("hostArchitectures") == "arm64"
        and domains is not None and domains.attrib == {"enable_anywhere": "false",
            "enable_currentUserHome": "false", "enable_localSystem": "true"}
        and len(payloads) == 1 and payloads[0].text == "#payload.pkg"
        and all(item.get("id") == "com.fainir.accountaccess.system"
                for item in distribution.iter("pkg-ref")))


def validate_packaged_image(manifest, rows):
    roots = {"/Library/Application Support/Account Access", "/Applications/Account Access.app"}
    require(type(manifest) is dict and set(manifest["roots"]) == roots)
    prefix = "payload.pkg/Scripts/PublicImage"
    names = {prefix, prefix + "/Library", prefix + "/Library/Application Support", prefix + "/Applications"}
    for root, tree in manifest["roots"].items():
        for relative, node in tree.items():
            name = prefix + root + ("/" + relative if relative else "")
            names.add(name)
            actual = rows[name]
            require(actual["kind"] == node["kind"])
            if node["kind"] == "file":
                require(actual == {"kind": "file", "mode": node["mode"],
                    "bytes": node["size"], "sha256": node["sha256"]})
            elif node["kind"] == "directory":
                require(actual == {"kind": "directory", "mode": node["mode"]})
            else:
                require(node["kind"] == "symlink" and actual["target"] == node["target"])
    require({name for name in rows if name == prefix or name.startswith(prefix + "/")} == names)


def signature_check(command, payload, suffix):
    for index, (relative, identifier) in enumerate(PEERS.items()):
        requirement = ('anchor apple generic and identifier "' + identifier + '" '
            'and certificate 1[field.1.2.840.113635.100.6.2.6] exists '
            'and certificate leaf[field.1.2.840.113635.100.6.1.13] exists '
            'and certificate leaf[subject.OU] = "WBULD6N4NQ" '
            'and !(entitlement["com.apple.security.get-task-allow"] exists)')
        command(["/usr/bin/codesign", "--verify", "--strict", "--all-architectures", "-R=" + requirement,
                 str(payload / relative)], f"signatures-{suffix}-{index}.log")


def public_snapshot(manifest):
    h.verify_image(manifest)  # File bytes, modes, types, links and closed public membership.
    result = {}
    for root, tree in manifest["roots"].items():
        for relative in tree:
            path = Path(root) / relative
            before = path.lstat()
            require(before.st_uid == 0)
            result[str(path)] = {"device": before.st_dev, "inode": before.st_ino,
                "uid": before.st_uid, "gid": before.st_gid, "mode": stat.S_IMODE(before.st_mode),
                "kind": stat.S_IFMT(before.st_mode)}
            if stat.S_ISLNK(before.st_mode):
                result[str(path)]["target"] = os.readlink(path)
            require(h.stamp(before) == h.stamp(path.lstat()))
    return result


def original_receipts(owner):
    intent = decode(h.read_file(h.JOURNAL / "intent.json", maximum=8192))
    require(intent == {"managed_by": "account-access-public-image-install-v1", "schema": 1,
        "manifest_sha256": MANIFEST_SHA, "owner_uid": owner})
    require(decode(h.read_file(h.JOURNAL / "complete.json", maximum=8192)) == {
        "manifest_sha256": MANIFEST_SHA, "owner_uid": owner, "status": "REGISTERED"})
    records = h.fixed_records()
    require(not any(path.name.startswith(".pending-") for path in h.JOURNAL.iterdir()))
    return records


def live_service(command, suffix):
    value = plistlib.loads(h.read_file(h.JOB, maximum=8192))
    require(value.get("Label") == h.LABEL
        and value.get("ProgramArguments") == [str(h.BASE / "bin/AccountAccess-broker")])
    command(["/bin/launchctl", "print", "system/" + h.LABEL], "live-job-" + suffix + ".log")
    import pwd
    uid = h.policies()["install"]["broker_uid"]
    require(type(uid) is int and 0 < uid < 2**31 and pwd.getpwnam("_accountaccess").pw_uid == uid)
    reader, until = h.ProcessDiagnosticReader(), time.monotonic() + 15
    while time.monotonic() < until:
        value = reader.observed(4, uid, expected_uid=uid)
        require(value.get("status") == "measured" and type(value.get("count")) is int)
        if value["count"] > 0:
            return
        time.sleep(0.25)
    require(False)


def close_gui(console, phase, report, output):
    require(phase in {"fresh", "reapplied"})
    prefix = "gui-" + phase + "-"
    detail = {"logs": {}}
    try:
        h.close_fresh_gui(console, report=detail,
            output=SimpleNamespace(write=lambda name, raw: output.write(prefix + name, raw)))
    finally:
        detail["logs"] = {prefix + name: checksum for name, checksum in detail["logs"].items()}
        report["logs"].update(detail["logs"])
        report.setdefault("gui", {})[phase] = detail


def run(args):
    guard()  # First action: no paths, helper import, process or network before this.
    revision = os.environ["GITHUB_SHA"]
    helper_raw = (args.repository / HELPER).read_bytes()
    require(digest(helper_raw) == HELPER_SHA)
    global h
    h = SimpleNamespace(**runpy.run_path(str(args.repository / HELPER)))
    h.guard()
    inputs_raw = (args.repository / INPUTS).read_bytes()
    require(h.git_bytes(args.repository, ["show", revision + ":" + INPUTS], maximum=2 * 1024**2) == inputs_raw)
    inputs = SimpleNamespace(**runpy.run_path(str(args.repository / INPUTS)))
    source_pins = {}
    for name in inputs.PROBES:
        raw = (args.repository / name).read_bytes()
        require(h.git_bytes(args.repository, ["show", revision + ":" + name], maximum=2 * 1024**2) == raw)
        source_pins[name] = digest(raw)
    output = h.RootOutput(h.report_path(os.environ["GITHUB_RUN_ID"]), os.environ["GITHUB_RUN_ID"])
    report = {"schema": 1, "status": "FAILED", "environment": "fresh-hosted-mac-direct-installer",
        "controller_revision": revision, "checks": dict.fromkeys(CHECKS, False), "logs": {},
        "failure_stage": "fresh_vm_preflight", "personal_accounts_used": 0, "private_vault_read": False,
        "owner_GUI_qualified": False, "production_ready": False}
    touched = False
    try:
        for path in (h.BASE, h.APP, h.JOB, h.JOURNAL, h.COMPONENTS, h.REVALIDATION_NAMESPACE,
                     Path("/Library/Application Support/Account Access Full Images")):
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
        report["failure_stage"] = "fixed_input_contract"
        contract_raw = (args.bundle / "asset-contract.json").read_bytes()
        require(len(contract_raw) < 64 * 1024 and contract_raw == h.git_bytes(args.repository,
            ["show", revision + ":" + CONTRACT], maximum=64 * 1024))
        contract = inputs.validate(decode(contract_raw))
        controller = decode((args.bundle / "controller.json").read_bytes())
        require(controller == {"schema": 1, "controller_revision": revision,
            "contract_sha256": digest(contract_raw), "probe_sources": source_pins,
            "files": {name: row["sha256"] for name, row in contract["assets"].items()}})
        for name, row in contract["assets"].items():
            require(hash_file(args.bundle / name, 1024**3) == (row["sha256"], row["bytes"]))
        report["checks"]["fixed_public_assets_and_sources"] = True
        report["package_sha256"] = contract["assets"]["fresh.pkg"]["sha256"]
        with tempfile.TemporaryDirectory(prefix="account-access-fresh-image-acceptance-", dir="/private/tmp") as temporary:
            stage = Path(temporary)
            owned_stage(stage)
            for name in ("fresh.pkg", "fresh-review.json", "fresh-expanded-inventory.json", "fresh-manifest.json"):
                h.stage_file(args.bundle / name, stage / name, contract["assets"][name]["sha256"], 1024**3)

            def command(arguments, log, timeout=120, check=True):
                return h.command(arguments, report=report, output=output, log=log, timeout=timeout, check=check)

            def install(log):
                return h.candidate_install(stage / "fresh.pkg", report=report, output=output,
                    log=log + ".log", daemon_log=log + "-daemon.log")

            report["failure_stage"] = "closed_product_expansion"
            validate_review(decode(h.read_file(stage / "fresh-review.json", maximum=2 * 1024**2)), contract)
            scripts_expected = install_script_bodies(h.git_bytes(args.repository,
                ["show", contract["packaging_source"] + ":macos/system_package.py"], maximum=2 * 1024**2))
            expanded = stage / "expanded"
            command(["/usr/sbin/pkgutil", "--expand-full", str(stage / "fresh.pkg"), str(expanded)], "expand.log", 300)
            expected_inventory = decode(h.read_file(stage / "fresh-expanded-inventory.json", maximum=64 * 1024**2))
            scripts = validate_expansion(expanded, expected_inventory, scripts_expected)
            manifest_raw = h.read_file(stage / "fresh-manifest.json", maximum=16 * 1024**2)
            require(digest(manifest_raw) == MANIFEST_SHA)
            manifest = decode(manifest_raw)
            validate_packaged_image(manifest, expected_inventory)
            require({kind: sum(node["kind"] == word for tree in manifest["roots"].values() for node in tree.values())
                for kind, word in [("files", "file"), ("directories", "directory"), ("aliases", "symlink")]} == COUNTS)
            report["checks"]["closed_product_envelope"] = True
            signature_check(command, scripts / "PublicImage/Library/Application Support/Account Access", "package")
            report["checks"]["genuine_production_signatures"] = True
            report["failure_stage"] = "actual_fresh_installer"
            touched = True
            install("fresh-installer")
            report["checks"]["actual_fresh_installer"] = True
            report["failure_stage"] = "installed_public_image"
            before = public_snapshot(manifest)
            signature_check(command, h.BASE, "installed")
            report["checks"]["exact_public_image"] = True
            report["failure_stage"] = "fresh_gui_normal_quit"
            close_gui(console, "fresh", report, output)
            report["checks"]["fresh_gui_closed"] = True
            receipts, policies = original_receipts(console), h.policies()
            report["checks"]["original_image_receipts"] = True
            live_service(command, "fresh")
            report["checks"]["live_service"] = True
            report["failure_stage"] = "identical_package_reapply"
            install("reapply-installer")
            report["checks"]["identical_package_reapply"] = True
            require(public_snapshot(manifest) == before and original_receipts(console) == receipts and h.policies() == policies)
            require(hash_file(stage / "fresh.pkg", 1024**3)[0] == report["package_sha256"])
            report["public_node_count"] = len(before)
            report["public_identity_snapshot_sha256"] = digest(json.dumps(before, sort_keys=True).encode())
            report["checks"]["reapply_preserves_bytes_and_inodes"] = True
            signature_check(command, h.BASE, "reapplied")
            live_service(command, "reapplied")
            report["failure_stage"] = "reapplied_gui_normal_quit"
            close_gui(console, "reapplied", report, output)
            report["checks"]["reapplied_gui_closed"] = True
    except Exception:
        report["failure_reason"] = "actual_fresh_image_installer_acceptance_failed"
    finally:
        report["measurement_failure_stage"] = report["failure_stage"] if "failure_reason" in report else None
        if touched:
            try:
                if os.path.lexists(h.JOB):
                    value = plistlib.loads(h.read_file(h.JOB, maximum=8192))
                    require(value.get("Label") == h.LABEL
                        and value.get("ProgramArguments") == [str(h.BASE / "bin/AccountAccess-broker")])
                    h.command(["/bin/launchctl", "bootout", "system/" + h.LABEL], report=report,
                        output=output, log="cleanup-bootout.log", check=False)
                absent = h.command(["/bin/launchctl", "print", "system/" + h.LABEL], report=report,
                    output=output, log="cleanup-lookup.log", check=False)
                require(absent.returncode == 113 and absent.stdout + absent.stderr == (
                    'Bad request.\nCould not find service "' + h.LABEL + '" in domain for system\n').encode())
                report["checks"]["created_job_stopped"] = True
            except Exception:
                report["cleanup_unverified"] = True
        if all(value is True for value in report["checks"].values()) and "failure_reason" not in report:
            report["status"], report["failure_stage"] = "PASSED", None
        try:
            output.write("report.json", (json.dumps(report, indent=2, sort_keys=True) + "\n").encode())
            output.publish()
        finally:
            output.close()
    return 0 if report["status"] == "PASSED" else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", type=Path, required=True)
    parser.add_argument("--bundle", type=Path, required=True)
    return run(parser.parse_args())


if __name__ == "__main__":
    raise SystemExit(main())
