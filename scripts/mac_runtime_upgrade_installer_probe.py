"""Qualify the runtime successor inside the already accepted hosted package91 fixture.

This module has no owner-machine entrypoint. Its caller first verifies the
disposable hosted root context and completes the exact predecessor Installer QA.
"""
import os
import json
import pwd
import re
from pathlib import Path
import runpy
import signal
import stat
import subprocess
import time
import xml.etree.ElementTree as ET

CONTROLLER = "cbf06067e7dc5a53dc6f2d1e87f0284503474e6d"
TARGET = "7051ef225ff2f35d67576d0ddbbc3e0b107e00bf"
PLAN = "671c32eb5daacb79a1ec5f63d97cc29d2b6f34b5c75a773a1b477aca981ce6df"
BEFORE = "5a732de4623ba50aefa6d31c54e7b1eae660b2921341f95042c5675d922d808b"
AFTER = "03fb35eb2787ebd67079dd1cbe4dda125f430964540bdd2f2e9c81eda602fd7a"
NAMESPACE = Path("/Library/Application Support/Account Access Runtime Updates")
SCENARIOS = {"install-reapply", "interrupt-owner", "interrupt-runtime", "quiescence-recovery", "alias-recovery"}
RECOVERY_CHECKS = {"old_package_refused", "new_package_unknown_process_refused", "previous_image_unchanged",
                   "owned_disabled_intent_retained", "apple_witness_survived", "witness_removed"}
ALIAS_CHECKS = {"old_package_installed", "ordinary_users_refused_old_aliases", "closed_alias_set_repaired",
                "link_targets_preserved", "ordinary_users_accept_repaired_aliases", "reapply_preserves_aliases"}
CHECKS = {"fixed_inputs", "predecessor_fixture_accepted", "signature_verified", "scenario_exercised",
          "actual_installer", "exact_public_image", "policy_rotation", "roots_and_history_preserved",
          "live_service", "exact_reapply", "unchanged_reapply", "foreign_audit_refused", "service_after_refusal",
          "ordinary_public_runtime", "ordinary_public_runtime_reapply", "restart_declared"}
CACHE_REPAIR_FILES = (
    "runtime/lib/python3.12/encodings/__pycache__/__init__.cpython-312.pyc",
    "runtime/lib/python3.12/encodings/__pycache__/aliases.cpython-312.pyc",
    "runtime/lib/python3.12/encodings/__pycache__/utf_8.cpython-312.pyc",
)
PUBLISHED_TREES = (
    "owner.app", "runtime/lib/python3.12/site-packages/account_access",
    "runtime/lib/python3.12/site-packages/account_access-0.8.0.dist-info",
    "python/libexec/bitwarden", "runtime/libexec/bitwarden",
    "python/lib/python3.12/site-packages/pip", "python/lib/python3.12/site-packages/pip-26.2.2.dist-info",
    "python/lib/python3.12/ensurepip", "runtime/lib/python3.12/site-packages/pip",
    "runtime/lib/python3.12/site-packages/pip-26.2.2.dist-info", "runtime/lib/python3.12/ensurepip",
)
PUBLISHED_FILES = frozenset(CACHE_REPAIR_FILES) | {
    "wheels/account_access-0.8.0-py3-none-any.whl", "python/bin/pip", "python/bin/pip3",
    "runtime/bin/pip", "runtime/bin/pip3",
}

# Executed only by the guarded disposable-Mac controller, under both the real
# console UID and the dedicated worker UID. It checks public code paths before
# any policy, key, account, listener or worker bootstrap is opened.
PUBLIC_ALIAS_CHECK = r'''
import json, os, stat, sys
from pathlib import Path
try:
    assert os.getuid() == os.geteuid() != 0 and os.getgid() != 0
    assert sys.flags.isolated and sys.dont_write_bytecode
    assert os.environ.get("GITHUB_ACTIONS") == "true"
    assert os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted"
    assert os.environ.get("GITHUB_REPOSITORY") == "fainir/account-access"
    from account_access.worker_bootstrap import root_managed_path
    base = Path("/Library/Application Support/Account Access")
    targets = {
        "bin/2to3": "2to3-3.12", "bin/idle3": "idle3.12", "bin/pydoc3": "pydoc3.12",
        "bin/python": "python3.12", "bin/python3": "python3.12", "bin/python3-config": "python3.12-config",
        "lib/pkgconfig/python3-embed.pc": "python-3.12-embed.pc", "lib/pkgconfig/python3.pc": "python-3.12.pc",
        "share/man/man1/python.1": "python3.12.1", "share/man/man1/python3.1": "python3.12.1",
    }
    count = 0
    for prefix in ("python", "runtime"):
        for suffix, target in targets.items():
            path = base / prefix / suffix
            before = path.lstat()
            assert stat.S_ISLNK(before.st_mode) and stat.S_IMODE(before.st_mode) == 0o755
            assert before.st_uid == before.st_gid == 0 and before.st_nlink == 1
            assert os.readlink(path) == target
            assert root_managed_path(path) == root_managed_path(path.parent / target)
            after = path.lstat()
            assert (before.st_dev, before.st_ino, before.st_mode, before.st_ctime_ns) == (
                after.st_dev, after.st_ino, after.st_mode, after.st_ctime_ns)
            count += 1
    assert count == 20
    print(json.dumps({"schema": 1, "status": "PASSED", "aliases": count,
        "ordinary_identity": True, "worker_path_validator": True, "private_data_read": False}))
except Exception:
    print(json.dumps({"schema": 1, "status": "REFUSED", "reason": "public_runtime_alias_not_usable"}))
    raise SystemExit(78)
'''


def ordinary_runtime_aliases(controller, command, suffix, *, expected_success=True):
    controller.guard()  # Never impersonate an identity on an owner host.
    h, require = controller.h, controller.require
    require(suffix in {"after-upgrade", "after-reapply", "before-alias-repair", "after-alias-repair"})
    policy = h.policies()["install"]
    owner, broker = policy["owner_uid"], policy["broker_uid"]
    require(type(owner) is int and owner > 0 and type(broker) is int and 450 <= broker < 500 and owner != broker)
    person = pwd.getpwuid(owner)
    require(os.stat("/dev/console").st_uid == owner and person.pw_name == "runner" and person.pw_dir == "/Users/runner")
    rows = {}
    for role, uid in (("console", owner), ("worker", broker)):
        gid = pwd.getpwuid(uid).pw_gid
        require(gid > 0)
        result = command(["/usr/bin/sudo", "-n", "-u", "#" + str(uid), "-g", "#" + str(gid), "--",
            "/usr/bin/env", "-i", "PATH=/usr/bin:/bin:/usr/sbin:/sbin", "HOME=/var/empty",
            "GITHUB_ACTIONS=true", "RUNNER_ENVIRONMENT=github-hosted", "GITHUB_REPOSITORY=fainir/account-access",
            str(h.BASE / "runtime/bin/python3.12"), "-I", "-B", "-c", PUBLIC_ALIAS_CHECK],
            "public-alias-" + suffix + "-" + role + ".log", check=False)
        require(result.returncode == (0 if expected_success else 78)
                and result.stderr == b"" and len(result.stdout) <= 2048)
        value = json.loads(result.stdout)
        expected = ({"schema": 1, "status": "PASSED", "aliases": 20, "ordinary_identity": True,
            "worker_path_validator": True, "private_data_read": False} if expected_success else
            {"schema": 1, "status": "REFUSED", "reason": "public_runtime_alias_not_usable"})
        require(type(value) is dict and json.dumps(value, sort_keys=True) == json.dumps(expected, sort_keys=True))
        rows[role] = value
    return rows


def acceptance_passed(value):
    return (type(value) is dict and value.get("scenario") in SCENARIOS
            and set(value.get("checks", {})) == CHECKS and all(v is True for v in value["checks"].values())
            and value.get("production_ready") is False and value.get("real_account_login_tested") is False
            and value.get("installed_owner_machine") is False and value.get("failure_stage") is None
            and (value["scenario"] != "quiescence-recovery" or (
                set(value.get("quiescence_recovery", {})) == RECOVERY_CHECKS
                and all(v is True for v in value["quiescence_recovery"].values())))
            and (value["scenario"] != "alias-recovery" or (
                set(value.get("alias_recovery", {})) == ALIAS_CHECKS
                and all(v is True for v in value["alias_recovery"].values()))))


def runtime_alias_snapshot(controller, manifest):
    controller.guard()
    h, require = controller.h, controller.require
    require(h.BASE == Path("/Library/Application Support/Account Access"))
    nodes = manifest["roots"][str(h.BASE)]
    aliases = {path: row for path, row in nodes.items() if row["kind"] == "symlink"
               and path.split("/", 1)[0] in {"python", "runtime"}}
    require(len(aliases) == 20)
    result = {}
    for path, row in sorted(aliases.items()):
        leaf = h.BASE / path
        before = leaf.lstat()
        require(stat.S_ISLNK(before.st_mode) and before.st_uid == before.st_gid == 0 and before.st_nlink == 1)
        target = os.readlink(leaf)
        require(target == row["target"] and h.stamp(before) == h.stamp(leaf.lstat()))
        result[path] = {"device": before.st_dev, "inode": before.st_ino, "mode": stat.S_IMODE(before.st_mode),
                        "target": target, "size": before.st_size, "mtime_ns": before.st_mtime_ns}
    return result


def preceding_group(relative, legacy):
    # Independent readable projection of the frozen native predecessor mapping.
    if relative in PUBLISHED_FILES or any(relative == p or relative.startswith(p + "/") for p in PUBLISHED_TREES):
        return 0
    return legacy


def public_tree_groups(controller, nodes):
    controller.guard()
    root = controller.h.BASE
    controller.require(root == Path("/Library/Application Support/Account Access"))
    legacy = root.lstat().st_gid
    checked, issues = 0, []
    for relative in nodes:
        if relative.split("/", 1)[0] not in {"owner.app", "python", "runtime", "browsers", "wheels"}:
            continue
        info = (root / relative).lstat()
        expected = preceding_group(relative, legacy)
        checked += 1
        if info.st_gid != expected:
            controller.require(len(issues) < 100)
            issues.append({"public_path": relative, "gid": info.st_gid, "expected_gid": expected})
    return {"nodes_checked": checked, "legacy_group": legacy, "issues": issues}


def normalize_expansion(controller, stage):
    """Normalize only this fresh VM's independently verified package expansion."""
    controller.guard()
    f, h, require = controller.f, controller.h, controller.require
    f.verify_owned_stage(stage)
    fd = os.open(stage, f.DIRECTORY)
    try:
        # Both names are fixed here; no installed path or caller-selected
        # descendant can be normalized through this fixture seam.
        for name in ("runtime-upgrade-expanded", "Scripts"):
            child = os.open(name, f.DIRECTORY, dir_fd=fd)
            try:
                before = os.fstat(child)
                require(stat.S_ISDIR(before.st_mode) and not before.st_mode & 0o7022
                        and h.stamp(before) == h.stamp(os.stat(name, dir_fd=fd, follow_symlinks=False)))
                f.empty_acl(child)
                if (before.st_uid, before.st_gid) != (0, 0):
                    os.fchown(child, 0, 0)
                    os.fsync(child)
                after = os.fstat(child)
                require(after.st_uid == after.st_gid == 0
                        and h.stamp(after) == h.stamp(os.stat(name, dir_fd=fd, follow_symlinks=False)))
            except Exception:
                os.close(child)
                raise
            os.close(fd)
            fd = child
    finally:
        os.close(fd)
    f.verify_owned_stage(stage)


def reproduce_historical_cache_repair(controller, scripts, result):
    """Reproduce the owner's earlier three-file repair only in the fresh VM.

    The production successor deliberately requires this exact predecessor
    metadata. A clean base package does not include that earlier repair. This
    fixture cannot normalize any other installed file or run on an owner host.
    """
    controller.guard()
    c, h, f = controller, controller.h, controller.f
    c.require(h.BASE == Path("/Library/Application Support/Account Access"))
    raw = h.read_file(scripts / "BaseManifest.json", maximum=16 * 1024**2)
    c.require(c.digest(raw) == BEFORE)
    manifest = f.decode(raw)
    h.verify_image(manifest)
    nodes = manifest["roots"][str(h.BASE)]
    held = []
    detail = {"scope": "three fixed public cache files in disposable VM", "before": [], "after": [],
              "bytes_and_inodes_preserved": False, "owner_machine": False}
    result["historical_cache_repair_fixture"] = detail
    detail["before_tree_groups"] = public_tree_groups(c, nodes)
    c.require(all(row["public_path"] in CACHE_REPAIR_FILES for row in detail["before_tree_groups"]["issues"]))
    try:
        # Hold and qualify every path before the first metadata change.
        for relative in CACHE_REPAIR_FILES:
            parent = os.open("/", f.DIRECTORY)
            try:
                for part in (h.BASE / relative).parts[1:-1]:
                    child = os.open(part, f.DIRECTORY, dir_fd=parent)
                    try:
                        info = os.fstat(child)
                        c.require(info.st_uid == 0 and not info.st_mode & 0o7022)
                        f.empty_acl(child)
                    except Exception:
                        os.close(child)
                        raise
                    os.close(parent)
                    parent = child
                name = Path(relative).name
                leaf = os.open(name, f.REGULAR, dir_fd=parent)
                held.append((parent, leaf, name, relative, os.fstat(leaf)))
                parent = None
            finally:
                if parent is not None:
                    os.close(parent)
        legacy_group = h.BASE.lstat().st_gid
        for parent, leaf, name, relative, before in held:
            node = nodes[relative]
            c.require(node["kind"] == "file" and node["mode"] == 0o644
                      and stat.S_ISREG(before.st_mode) and stat.S_IMODE(before.st_mode) == 0o644
                      and before.st_uid == 0 and before.st_gid in {0, legacy_group} and before.st_nlink == 1
                      and before.st_size == node["size"] and before.st_size <= 65536
                      and h.stamp(before) == h.stamp(os.stat(name, dir_fd=parent, follow_symlinks=False))
                      and c.digest(os.pread(leaf, before.st_size + 1, 0)) == node["sha256"])
            f.empty_acl(leaf)
            detail["before"].append({"public_path": relative, "gid": before.st_gid})
        c.require(len({row[4].st_gid for row in held}) == 1)
        for parent, leaf, name, relative, before in held:
            c.require(h.stamp(before) == h.stamp(os.fstat(leaf))
                      == h.stamp(os.stat(name, dir_fd=parent, follow_symlinks=False)))
            if before.st_gid != 0:
                os.fchown(leaf, 0, 0)
                os.fsync(leaf)
            after = os.fstat(leaf)
            c.require(after.st_gid == 0 and h.stamp(after) == h.stamp(os.stat(name, dir_fd=parent, follow_symlinks=False))
                      and (after.st_dev, after.st_ino, after.st_uid, after.st_mode, after.st_nlink, after.st_size, after.st_mtime_ns)
                      == (before.st_dev, before.st_ino, before.st_uid, before.st_mode, before.st_nlink, before.st_size, before.st_mtime_ns)
                      and c.digest(os.pread(leaf, after.st_size + 1, 0)) == nodes[relative]["sha256"])
            detail["after"].append({"public_path": relative, "gid": after.st_gid})
        h.verify_image(manifest)
        detail["after_tree_groups"] = public_tree_groups(c, nodes)
        c.require(not detail["after_tree_groups"]["issues"])
        detail["bytes_and_inodes_preserved"] = True
    finally:
        for parent, leaf, *_ in held:
            os.close(leaf)
            os.close(parent)


def run(*, controller, args, stage, report, output, command, publication=None):
    controller.guard()  # Before any path, process, file or callback is consulted.
    c, h, f = controller, controller.h, controller.f
    require = c.require
    require(callable(publication))
    require(args.cohort == 91 and args.scenario == "install-reapply" and args.runtime_scenario in SCENARIOS
            and report["checks"]["reapplication_preserved_bytes_and_ids"] is True and not os.path.lexists(NAMESPACE))
    revision = report["controller_revision"]
    def source(name):
        path = args.repository / name
        require(path.read_bytes() == h.git_bytes(args.repository, ["show", revision + ":" + name], maximum=2 * 1024**2))
        return path
    source("scripts/mac_runtime_upgrade_installer_probe.py")
    download = runpy.run_path(str(source("scripts/download_runtime_upgrade_inputs.py")))
    raw = (args.runtime_upgrade / "asset-contract.json").read_bytes()
    require(raw == h.git_bytes(args.repository, ["show", revision + ":" + download["CONTRACT"]], maximum=65536))
    contract = download["validate"](f.decode(raw))
    c.verify_assets(args.runtime_upgrade, contract, download["FILES"], f.hash_file)
    result = {"scenario": args.runtime_scenario, "checks": dict.fromkeys(CHECKS, False),
        "controller_source": CONTROLLER, "application_source": TARGET, "production_ready": False,
        "real_account_login_tested": False, "installed_owner_machine": False, "failure_stage": "inputs"}
    report["runtime_upgrade"] = result
    result["checks"]["predecessor_fixture_accepted"] = True
    for name in download["FILES"]:
        h.stage_file(args.runtime_upgrade / name, stage / name, contract["assets"][name]["sha256"], 1024**3)
    review = f.decode(h.read_file(stage / "upgrade-review.json", maximum=65536))
    require(review["status"] == "BUILT_PENDING_INSTALLER_QA" and review["controller_source"] == CONTROLLER
            and review["application_source"] == TARGET and review["plan_sha256"] == PLAN
            and review["before_manifest_sha256"] == BEFORE and review["after_manifest_sha256"] == AFTER
            and review["package_sha256"] == contract["assets"]["runtime-upgrade.pkg"]["sha256"]
            and review["scripts_inventory_sha256"] == contract["assets"]["upgrade-scripts-inventory.json"]["sha256"]
            and review["installed"] is False and review["production_ready"] is False
            and review["postinstall_action"] == "restart")
    for name, digest in review["source_sha256"].items():
        require(name.startswith("macos/") and ".." not in name
                and c.digest(h.git_bytes(args.repository, ["show", CONTROLLER + ":" + name], maximum=2 * 1024**2)) == digest)
    expanded = stage / "runtime-upgrade-expanded"
    command(["/usr/sbin/pkgutil", "--expand-full", str(stage / "runtime-upgrade.pkg"), str(expanded)], "upgrade-expand.log", 300)
    require({p.name for p in expanded.iterdir()} == {"PackageInfo", "Scripts"})
    info = ET.fromstring(h.read_file(expanded / "PackageInfo", maximum=65536))
    require(info.get("identifier") == "com.fainir.accountaccess.runtimeupgrade95"
            and info.get("version") == "0.1.0" and info.get("auth") == "root"
            and info.get("postinstall-action") == "restart"
            and info.find("scripts/postinstall").attrib == {"file": "./postinstall", "timeout": "1800"})
    restart = command(["/usr/sbin/installer", "-query", "RestartAction", "-pkg", str(stage / "runtime-upgrade.pkg")],
                      "upgrade-restart-policy.log")
    require(restart.stdout == b"RequireRestart\n" and restart.stderr == b"")
    result["checks"]["restart_declared"] = True
    scripts = expanded / "Scripts"
    expected_inventory = f.decode(h.read_file(stage / "upgrade-scripts-inventory.json", maximum=32 * 1024**2))
    require(f.inventory(scripts) == expected_inventory)
    # pkgutil preserves archive ownership. Qualify all bytes first, then apply
    # the existing root-only fixture normalization inside our exclusive scratch
    # tree. Actual Installer performs a separate extraction for installation.
    normalize_expansion(c, stage)
    require(f.inventory(scripts, normalize=True) == expected_inventory)
    require(c.digest(h.read_file(scripts / "RuntimeUpgradePlan.json", maximum=34 * 1024**2)) == PLAN
            and c.digest(h.read_file(scripts / "TargetManifest.json", maximum=16 * 1024**2)) == AFTER)
    result["checks"]["fixed_inputs"] = True
    command(["/usr/bin/codesign", "--verify", "--strict", "-R=anchor apple generic and identifier "
        '\"com.fainir.accountaccess.componentupdate\" and certificate leaf[subject.OU] = \"WBULD6N4NQ\" '
        'and !(entitlement[\"com.apple.security.get-task-allow\"] exists)', str(scripts / "AccountAccess-runtimeupgrade")],
        "upgrade-signature.log")
    require(c.digest(h.read_file(scripts / "AccountAccess-runtimeupgrade", maximum=16 * 1024**2)) == review["helper_sha256"])
    result["checks"]["signature_verified"] = True
    result["failure_stage"] = "historical_cache_fixture"
    reproduce_historical_cache_repair(c, scripts, result)
    def history():
        # Fixed public repair history only. Never inspect the account store.
        values = {str(p): c.snapshot(p, maximum=16 * 1024**2)
                  for p in c.NAMESPACE.rglob("*") if p.is_file()}
        return {"original": f.public_evidence(), "repair": values, "fictional_publication": publication(),
                "full_head": f.completed_history(f.CONFIGURATION_PINS),
                "roots": [(p.lstat().st_dev, p.lstat().st_ino) for p in (h.BASE, h.APP)]}
    preserved = history()
    old_policy = h.policies()
    def install(label, *, expected=0, package="runtime-upgrade.pkg"):
        result["failure_stage"] = label
        delta = h.InstallerLogDelta()
        try:
            response = command(["/usr/sbin/installer", "-dumplog", "-verboseR", "-pkg", str(stage / package), "-target", "/"],
                               label + ".log", 2100, check=False)
            require(response.returncode == 0 if expected == 0 else response.returncode != 0)
        finally:
            delta.capture(report=report, output=output, log=label + "-daemon.log")
    fresh = runpy.run_path(str(source("scripts/mac_fresh_image_installer_probe.py")))
    fresh["live_service"].__globals__["h"] = h
    witness = None
    old_aliases = None
    try:
        if args.runtime_scenario == "alias-recovery":
            result["alias_recovery"] = dict.fromkeys(ALIAS_CHECKS, False)
            old_download = runpy.run_path(str(source("scripts/download_runtime_upgrade94_inputs.py")))
            old_raw = (args.alias_predecessor / "asset-contract.json").read_bytes()
            require(old_raw == h.git_bytes(args.repository, ["show", revision + ":" + old_download["CONTRACT"]], maximum=65536))
            old_contract = old_download["validate"](f.decode(old_raw))
            c.verify_assets(args.alias_predecessor, old_contract, old_download["FILES"], f.hash_file)
            h.stage_file(args.alias_predecessor / "runtime-upgrade.pkg", stage / "runtime-upgrade94.pkg",
                         old_contract["assets"]["runtime-upgrade.pkg"]["sha256"], 1024**3)
            install("old-runtime94-before-alias-repair", package="runtime-upgrade94.pkg")
            result["alias_recovery"]["old_package_installed"] = True
            target_manifest = f.decode(h.read_file(scripts / "TargetManifest.json", maximum=16 * 1024**2))
            h.verify_image(target_manifest)
            old_aliases = runtime_alias_snapshot(c, target_manifest)
            require(all(row["mode"] == 0o700 for row in old_aliases.values()))
            result["ordinary_before_repair"] = ordinary_runtime_aliases(c, command, "before-alias-repair", expected_success=False)
            result["alias_recovery"]["ordinary_users_refused_old_aliases"] = True
        if args.runtime_scenario == "quiescence-recovery":
            result["failure_stage"] = "quiescence_recovery_fixture"
            fixture = runpy.run_path(str(source("scripts/mac_runtime_quiescence_fixture.py")))
            require(fixture["RECOVERY_CHECKS"] == RECOVERY_CHECKS)
            witness = fixture["Witness"](c, stage, command, old_policy["install"]["broker_uid"])
            witness.start()
            base_manifest = f.decode(h.read_file(scripts / "BaseManifest.json", maximum=16 * 1024**2))
            base_snapshot = fresh["public_snapshot"](base_manifest)
            refused_attempts = 0
            def unchanged():
                nonlocal refused_attempts
                refused_attempts += 1
                require(fresh["public_snapshot"](base_manifest) == base_snapshot
                        and history() == preserved and h.policies() == old_policy
                        and not os.path.lexists(NAMESPACE / "head.json"))
                global_dir = NAMESPACE / ("transition-" + PLAN) / "global"
                intent = f.decode(h.read_file(global_dir / "intent.json", maximum=256 * 1024))
                events = [f.decode(h.read_file(p)) for p in sorted(global_dir.glob("record-*.json"))]
                require(intent["planSHA256"] == PLAN and events
                        and all(e.get("planSHA256") == PLAN and e.get("kind") != "transition" for e in events)
                        and any(e.get("service") == "disable_intent_prior_enabled" for e in events)
                        and events[-1].get("service") == "user_domain_bootout_intent")
                disabled = command(["/bin/launchctl", "print-disabled", "system"], f"refused-disabled-{refused_attempts}.log")
                require(re.findall(rb'(?m)^\s*"com\.fainir\.accountaccess\.broker"\s+=>\s+(\w+)\s*$', disabled.stdout) == [b"disabled"])
                absent = command(["/bin/launchctl", "print", "system/" + h.LABEL], f"refused-absent-{refused_attempts}.log", check=False)
                require(absent.returncode == 113)
                log = "runtime-old-quiescence-daemon.log" if refused_attempts == 1 else "runtime-new-unknown-daemon.log"
                evidence = report["installer_daemon_logs"][log]
                require(evidence["status"] == "captured")
                fd = os.open(log, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=output.descriptor)
                try:
                    raw_log = os.read(fd, 256 * 1024 + 1)
                finally:
                    os.close(fd)
                require(len(raw_log) <= 256 * 1024 and c.digest(raw_log) == report["logs"][log]
                        and b'"reason":"component_service_quiescence_not_confirmed","checkpoint":"transition"' in raw_log)
                witness.verify("refusal-" + str(refused_attempts))
            fixture["prepare"](controller=c, args=args, stage=stage, source=source, install=install,
                               result=result, unchanged=unchanged)
        if args.runtime_scenario in {"interrupt-owner", "interrupt-runtime"}:
            result["failure_stage"] = "owned_helper_interruption"
            selected = "owner.app" if args.runtime_scenario == "interrupt-owner" else "runtime"
            target = h.BASE / selected
            old_inode = target.lstat().st_ino
            out_path, err_path = stage / "runtime-owned.stdout", stage / "runtime-owned.stderr"
            child, stopped = None, False
            try:
                with out_path.open("xb") as out, err_path.open("xb") as err:
                    child = subprocess.Popen([str(scripts / "AccountAccess-runtimeupgrade")], stdin=subprocess.DEVNULL,
                        stdout=out, stderr=err, env=c.ENV, start_new_session=True)
                    deadline = time.monotonic() + 1800
                    while time.monotonic() < deadline and child.poll() is None:
                        require(out_path.stat().st_size + err_path.stat().st_size < 65536)
                        if target.lstat().st_ino != old_inode:
                            os.kill(child.pid, signal.SIGSTOP)
                            until = time.monotonic() + 5
                            while time.monotonic() < until:
                                pid, state = os.waitpid(child.pid, os.WNOHANG | os.WUNTRACED)
                                if pid:
                                    require(os.WIFSTOPPED(state))
                                    stopped = True
                                    break
                                time.sleep(0.01)
                            require(stopped and not os.path.lexists(NAMESPACE / "head.json"))
                            global_dir = NAMESPACE / ("transition-" + PLAN) / "global"
                            intent = f.decode(h.read_file(global_dir / "intent.json", maximum=256 * 1024))
                            require(intent["planSHA256"] == PLAN)
                            selected_unit = "runtimeOwner" if selected == "owner.app" else "runtimeRoot"
                            tree = [r["tree"] for r in intent["operations"]
                                    if isinstance(r.get("tree"), dict) and r["tree"].get("unit") == selected_unit]
                            require(len(tree) == 1 and tree[0]["after"]["inode"] == target.lstat().st_ino)
                            events = [f.decode(h.read_file(p)) for p in sorted(global_dir.glob("record-*.json"))]
                            require(all(e.get("planSHA256") == PLAN for e in events)
                                    and any(e.get("service") == "disabled_quiescence_confirmed" for e in events)
                                    and not any(e.get("service") == "coherent_image_enable_intent" for e in events))
                            break
                        time.sleep(0.02)
                    require(stopped)
            finally:
                if child is not None and child.returncode is None:
                    try:
                        os.kill(child.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    child.wait(timeout=10)
                for name, path in (("stdout", out_path), ("stderr", err_path)):
                    if path.exists():
                        data = h.read_file(path, maximum=65536)
                        label = "runtime-owned-" + name + ".log"
                        output.write(label, data)
                        report["logs"][label] = c.digest(data)
            result["interruption"] = {"owned_child_only": True, "tree": selected, "head_not_published": True,
                                      "installer_daemon_interrupted": False, "power_failure_tested": False}
        result["checks"]["scenario_exercised"] = True
        install("runtime-upgrade-install")
        result["checks"]["actual_installer"] = True
        manifest = f.decode(h.read_file(scripts / "TargetManifest.json", maximum=16 * 1024**2))
        h.verify_image(manifest)
        aliases = runtime_alias_snapshot(c, manifest)
        require(all(row["mode"] == 0o755 for row in aliases.values()))
        if old_aliases is not None:
            result["alias_recovery"]["closed_alias_set_repaired"] = True
            def unchanged(rows):
                return {path: {key: value for key, value in row.items() if key != "mode"}
                        for path, row in rows.items()}
            require(unchanged(aliases) == unchanged(old_aliases))
            result["alias_recovery"]["link_targets_preserved"] = True
            result["alias_metadata"] = {"before": old_aliases, "after": aliases}
        head = f.decode(h.read_file(NAMESPACE / "head.json"))
        require(head["plan_sha256"] == PLAN and head["manifest_sha256"] == AFTER and head["source_commit"] == TARGET)
        result["checks"]["exact_public_image"] = True
        peers = f.decode(h.read_file(scripts / "TargetIdentity.json"))["signatures"]
        require(h.policies() == f.expected_policies(old_policy, peers))
        result["checks"]["policy_rotation"] = True
        require(history() == preserved)
        result["checks"]["roots_and_history_preserved"] = True
        fresh["live_service"](command, "runtime-upgrade")
        result["checks"]["live_service"] = True
        result["ordinary_after_upgrade"] = ordinary_runtime_aliases(c, command, "after-upgrade")
        result["checks"]["ordinary_public_runtime"] = True
        if old_aliases is not None:
            result["alias_recovery"]["ordinary_users_accept_repaired_aliases"] = True
        image_snapshot = fresh["public_snapshot"](manifest)
        policy_snapshot = h.policies()
        upgrade_head = c.snapshot(NAMESPACE / "head.json")
        install("runtime-upgrade-reapply")
        result["checks"]["exact_reapply"] = True
        require(fresh["public_snapshot"](manifest) == image_snapshot and h.policies() == policy_snapshot
                and c.snapshot(NAMESPACE / "head.json") == upgrade_head and history() == preserved)
        result["checks"]["unchanged_reapply"] = True
        require(runtime_alias_snapshot(c, manifest) == aliases)
        result["ordinary_after_reapply"] = ordinary_runtime_aliases(c, command, "after-reapply")
        result["checks"]["ordinary_public_runtime_reapply"] = True
        if old_aliases is not None:
            result["alias_recovery"]["reapply_preserves_aliases"] = True
        foreign = NAMESPACE / ("transition-" + PLAN) / "global/foreign-audit-fixture.json"
        c.create_file(foreign, b'{"schema":1,"foreign":true}')
        try:
            install("runtime-upgrade-foreign-audit", expected=1)
            require(fresh["public_snapshot"](manifest) == image_snapshot and h.policies() == policy_snapshot
                    and c.snapshot(NAMESPACE / "head.json") == upgrade_head and history() == preserved)
            result["checks"]["foreign_audit_refused"] = True
            fresh["live_service"](command, "after-runtime-refusal")
            result["checks"]["service_after_refusal"] = True
        finally:
            require(h.read_file(foreign) == b'{"schema":1,"foreign":true}')
            foreign.unlink()
        if witness is not None:
            witness.verify("after-recovery")
            result["quiescence_recovery"]["apple_witness_survived"] = True
    finally:
        if witness is not None:
            witness.close()
            if "quiescence_recovery" in result:
                result["quiescence_recovery"]["witness_removed"] = True
    result["failure_stage"] = None
    require(acceptance_passed(result))
