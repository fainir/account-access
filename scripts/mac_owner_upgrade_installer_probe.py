"""Qualify the fixed owner successor only inside the hosted runtime95 fixture.

No owner-machine entrypoint, account access, arbitrary target, or privileged
fallback is provided. Actual Installer receives the exact reviewed package.
"""

import os
import hashlib
from pathlib import Path
import runpy
import signal
import stat
import subprocess
import time
import xml.etree.ElementTree as ET

TARGET = "6736a20f8ed20d9188380b83b808ec9e380df501"
PACKAGING = "9b867da0de9f91ffbca4a8c838c4bc692f1b5e47"
PLAN = "1b5812e7e6618ce92a242f6acc5683daccd4485c7e2e57859597c029960ee42c"
BEFORE = "03fb35eb2787ebd67079dd1cbe4dda125f430964540bdd2f2e9c81eda602fd7a"
AFTER = "c80f0430c7529acb8479661554aadd7e6b1cfb98303df1e2bda1e5024a75356c"
NAMESPACE = Path("/Library/Application Support/Account Access Owner Updates")
INTERRUPT_SCENARIOS = {"interrupt-owner", "interrupt-identity", "interrupt-host", "interrupt-published-preparation"}
SCENARIOS = {"install-reapply", "after-alias-repair", "after-quiescence-recovery"} | INTERRUPT_SCENARIOS
PREDECESSOR_SCENARIOS = {name: "alias-recovery" if name == "after-alias-repair" else
    "quiescence-recovery" if name == "after-quiescence-recovery" else "install-reapply" for name in SCENARIOS}
CHECKS = {
    "fixed_inputs", "runtime_predecessor_accepted", "signature_verified", "compact_payload_verified",
    "no_restart_declared", "foreign_predecessor_refused", "scenario_exercised", "actual_installer",
    "exact_public_image", "policy_rotation", "roots_and_history_preserved", "live_service",
    "ordinary_public_runtime", "ordinary_public_runtime_reapply", "exact_reapply", "unchanged_reapply", "foreign_audit_refused",
    "service_after_refusal", "old_package_resource_root_refused",
}


def owner_runtime_aliases(controller, runtime, command, phase):
    controller.guard()
    require = controller.require
    require(phase in {"after-upgrade", "after-reapply"})
    expected = {"public-alias-" + phase + "-" + role + ".log" for role in ("console", "worker")}

    def named_command(arguments, log, *, check):
        require(log in expected and check is False)
        return command(arguments, "owner-" + log, check=False)

    return runtime["ordinary_runtime_aliases"](controller, named_command, phase)


def refusal_record(raw, checkpoint):
    reason = {"source": "owner_upgrade_source_not_verified",
              "predecessor": "owner_upgrade_transition_conflict", "journal": "owner_upgrade_transition_conflict"}.get(checkpoint)
    return (type(raw) is bytes and reason is not None
            and (b'{"schema":1,"status":"REFUSED","reason":"' + reason.encode("ascii") + b'","checkpoint":"'
                 + checkpoint.encode("ascii") + b'"}') in raw)


def require_native_refusal(controller, report, output, label, checkpoint):
    controller.guard()
    require = controller.require
    require({"owner-old-resource-root": "source", "owner-foreign-predecessor": "predecessor",
             "owner-upgrade-foreign-audit": "journal"}.get(label) == checkpoint)
    name = label + "-daemon.log"
    require(report["installer_daemon_logs"][name]["status"] == "captured")
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=output.descriptor)
    try:
        raw = os.read(fd, 256 * 1024 + 1)
    finally:
        os.close(fd)
    require(len(raw) <= 256 * 1024 and controller.digest(raw) == report["logs"][name]
            and refusal_record(raw, checkpoint))


def namespace_snapshot(controller, namespace):
    """Stream only public update evidence on the guarded disposable Mac.

    Retained public images include zero-length Python files, large binaries and
    aliases. Never follow their links or load a whole binary into memory.
    """
    controller.guard()
    h, require = controller.h, controller.require
    require(namespace in {NAMESPACE, Path("/Library/Application Support/Account Access Runtime Updates"),
                          Path("/Library/Application Support/Account Access Broker Repair")})
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK
    rows = {}

    def walk(fd, relative):
        before = os.fstat(fd)
        require(stat.S_ISDIR(before.st_mode) and before.st_uid == 0 and not before.st_mode & 0o7022)
        rows[relative] = {"kind": "directory", "identity": h.stamp(before)[:6]}
        names = sorted(os.listdir(fd))
        require(len(names) <= 100000)
        for name in names:
            path = relative + "/" + name if relative else name
            info = os.stat(name, dir_fd=fd, follow_symlinks=False)
            require(info.st_uid == 0)
            if stat.S_ISLNK(info.st_mode):
                require(info.st_nlink == 1)
                rows[path] = {"kind": "symlink", "identity": h.stamp(info), "target": os.readlink(name, dir_fd=fd)}
            elif stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode):
                child = os.open(name, flags | (os.O_DIRECTORY if stat.S_ISDIR(info.st_mode) else 0), dir_fd=fd)
                try:
                    require(h.stamp(info) == h.stamp(os.fstat(child)))
                    if stat.S_ISDIR(info.st_mode):
                        walk(child, path)
                    else:
                        require(info.st_nlink == 1 and not info.st_mode & 0o7022 and 0 <= info.st_size <= 1024**3)
                        checksum, size = hashlib.sha256(), 0
                        while block := os.read(child, 1024**2):
                            size += len(block)
                            require(size <= info.st_size)
                            checksum.update(block)
                        require(size == info.st_size)
                        rows[path] = {"kind": "file", "identity": h.stamp(info), "sha256": checksum.hexdigest()}
                    require(h.stamp(info) == h.stamp(os.fstat(child)))
                finally:
                    os.close(child)
            else:
                require(False)
            require(h.stamp(info) == h.stamp(os.stat(name, dir_fd=fd, follow_symlinks=False)))
        require(names == sorted(os.listdir(fd)) and h.stamp(before) == h.stamp(os.fstat(fd)))

    fd = os.open(namespace, flags | os.O_DIRECTORY)
    try:
        walk(fd, "")
    finally:
        os.close(fd)
    return rows


def acceptance_passed(value):
    interruption = value.get("interruption", {}) if type(value) is dict else {}
    expected = {"owned_child_only": True, "head_not_published": True,
                "installer_daemon_interrupted": False, "power_failure_tested": False}
    if type(value) is dict and value.get("scenario") == "interrupt-published-preparation":
        expected.update(published_local_journal_sealed=True, public_image_unchanged=True, service_disable_not_started=True)
    return (
        type(value) is dict and value.get("scenario") in SCENARIOS
        and value.get("runtime_predecessor_scenario") == PREDECESSOR_SCENARIOS[value["scenario"]]
        and set(value.get("checks", {})) == CHECKS
        and all(v is True for v in value["checks"].values())
        and value.get("production_ready") is False and value.get("real_account_login_tested") is False
        and value.get("installed_owner_machine") is False and value.get("failure_stage") is None
        and (value["scenario"] not in INTERRUPT_SCENARIOS or (
            type(interruption) is dict and set(interruption) == set(expected)
            and all(interruption[k] is v for k, v in expected.items())))
    )


def normalize_expansion(controller, stage):
    """Only the two fixed directories of this verified exclusive expansion."""
    controller.guard()
    f, h, require = controller.f, controller.h, controller.require
    f.verify_owned_stage(stage)
    fd = os.open(stage, f.DIRECTORY)
    try:
        for name in ("owner-upgrade-expanded", "Scripts"):
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


def run(*, controller, args, stage, report, output, command, publication=None):
    controller.guard()  # Must precede any path, process, or callback access.
    c, h, f, require = controller, controller.h, controller.f, controller.require
    require(callable(publication) and args.cohort == 91 and args.scenario == "install-reapply"
            and args.owner_scenario in SCENARIOS and args.runtime_scenario == PREDECESSOR_SCENARIOS[args.owner_scenario]
            and args.runtime_upgrade is not None and args.previous_owner_upgrade is not None
            and not os.path.lexists(NAMESPACE))
    revision = report["controller_revision"]

    def source(name):
        path = args.repository / name
        require(path.read_bytes() == h.git_bytes(args.repository, ["show", revision + ":" + name], maximum=2 * 1024**2))
        return path

    source("scripts/mac_owner_upgrade_installer_probe.py")
    runtime = runpy.run_path(str(source("scripts/mac_runtime_upgrade_installer_probe.py")))
    require(runtime["acceptance_passed"](report.get("runtime_upgrade")))
    require(report["runtime_upgrade"]["scenario"] == args.runtime_scenario)
    download = runpy.run_path(str(source("scripts/download_owner_upgrade_inputs.py")))
    raw = (args.owner_upgrade / "asset-contract.json").read_bytes()
    require(raw == h.git_bytes(args.repository, ["show", revision + ":" + download["CONTRACT"]], maximum=65536))
    contract = download["validate"](f.decode(raw))
    c.verify_assets(args.owner_upgrade, contract, download["FILES"], f.hash_file)
    previous_download = runpy.run_path(str(source("scripts/download_owner_upgrade97_inputs.py")))
    previous_raw = (args.previous_owner_upgrade / "asset-contract.json").read_bytes()
    require(previous_raw == h.git_bytes(args.repository,
        ["show", revision + ":" + previous_download["CONTRACT"]], maximum=65536))
    previous_contract = previous_download["validate"](f.decode(previous_raw))
    c.verify_assets(args.previous_owner_upgrade, previous_contract, previous_download["FILES"], f.hash_file)
    result = {"scenario": args.owner_scenario, "checks": dict.fromkeys(CHECKS, False),
              "controller_source": download["SOURCE"], "application_source": TARGET,
              "runtime_predecessor_scenario": args.runtime_scenario,
              "production_ready": False, "real_account_login_tested": False,
              "installed_owner_machine": False, "failure_stage": "inputs"}
    report["owner_upgrade"] = result
    result["checks"]["runtime_predecessor_accepted"] = True
    for name in download["FILES"]:
        h.stage_file(args.owner_upgrade / name, stage / name, contract["assets"][name]["sha256"], 1024**3)
    h.stage_file(args.previous_owner_upgrade / "owner-upgrade.pkg", stage / "owner-old-resource-root.pkg",
                 previous_contract["assets"]["owner-upgrade.pkg"]["sha256"], 1024**3)
    review = f.decode(h.read_file(stage / "owner-review.json", maximum=65536))
    require(review["status"] == "BUILT_PENDING_INSTALLER_QA" and review["controller_source"] == download["SOURCE"]
            and review["application_source"] == TARGET and review["plan_sha256"] == PLAN
            and review["before_manifest_sha256"] == BEFORE and review["after_manifest_sha256"] == AFTER
            and review["package_sha256"] == contract["assets"]["owner-upgrade.pkg"]["sha256"]
            and review["scripts_inventory_sha256"] == contract["assets"]["owner-scripts-inventory.json"]["sha256"]
            and review["installed"] is False and review["production_ready"] is False
            and review["packaging_source"] == PACKAGING
            and review["predecessor_resource_mode"] == "0755"
            and review["native_rebuilt_for_local_journal_ordering_fix"] is True
            and review["local_tree_intent_prepared_before_publication"] is True
            and type(review["preparation_regression_checks"]) is int and review["preparation_regression_checks"] == 21
            and review["postinstall_action"] == "none" and review["postinstall_timeout"] == 1800)
    require(c.digest(h.git_bytes(args.repository,
        ["show", revision + ":artifacts/owner-upgrade99-assembly.py.txt"], maximum=65536))
        == review["packaging_driver_sha256"])
    require(h.git_bytes(args.repository, ["show", PACKAGING + ":scripts/build_owner_upgrade_review.py"], maximum=65536)
            == source("scripts/build_owner_upgrade_review.py").read_bytes())
    for name, digest in review["source_sha256"].items():
        require(name.startswith("macos/") and ".." not in name
                and c.digest(h.git_bytes(args.repository, ["show", download["SOURCE"] + ":" + name], maximum=2 * 1024**2)) == digest)
    expanded = stage / "owner-upgrade-expanded"
    command(["/usr/sbin/pkgutil", "--expand-full", str(stage / "owner-upgrade.pkg"), str(expanded)], "owner-expand.log", 300)
    require({p.name for p in expanded.iterdir()} == {"PackageInfo", "Scripts"})
    info = ET.fromstring(h.read_file(expanded / "PackageInfo", maximum=65536))
    require(info.get("identifier") == "com.fainir.accountaccess.ownerupgrade99"
            and info.get("version") == "0.1.0" and info.get("auth") == "root"
            and info.get("postinstall-action") == "none"
            and info.find("scripts/postinstall").attrib == {"file": "./postinstall", "timeout": "1800"})
    restart = command(["/usr/sbin/installer", "-query", "RestartAction", "-pkg", str(stage / "owner-upgrade.pkg")], "owner-restart-policy.log")
    require(restart.stdout == b"None\n" and restart.stderr == b"")
    result["checks"]["no_restart_declared"] = True
    scripts = expanded / "Scripts"
    inventory = f.decode(h.read_file(stage / "owner-scripts-inventory.json", maximum=32 * 1024**2))
    require(f.inventory(scripts) == inventory)
    normalize_expansion(c, stage)
    require(f.inventory(scripts, normalize=True) == inventory)
    require(c.digest(h.read_file(scripts / "OwnerUpgradePlan.json", maximum=34 * 1024**2)) == PLAN
            and c.digest(h.read_file(scripts / "BaseManifest.json", maximum=16 * 1024**2)) == BEFORE
            and c.digest(h.read_file(scripts / "TargetManifest.json", maximum=16 * 1024**2)) == AFTER)
    result["checks"]["fixed_inputs"] = True
    command(["/usr/bin/codesign", "--verify", "--strict", "-R=anchor apple generic and identifier "
             '"com.fainir.accountaccess.componentupdate" and certificate leaf[subject.OU] = "WBULD6N4NQ" '
             'and !(entitlement["com.apple.security.get-task-allow"] exists)', str(scripts / "AccountAccess-ownerupgrade")], "owner-signature.log")
    require(c.digest(h.read_file(scripts / "AccountAccess-ownerupgrade", maximum=16 * 1024**2)) == review["helper_sha256"])
    result["checks"]["signature_verified"] = True
    builder = runpy.run_path(str(source("scripts/build_owner_upgrade_review.py")))
    previous = f.decode(h.read_file(stage / "upgrade-scripts-inventory.json", maximum=32 * 1024**2))
    projected = builder["proof_inventory"](previous)
    require(f.inventory(scripts / "Predecessor") == projected
            and c.digest(builder["encoded"](projected)) == review["predecessor_proof_inventory_sha256"])
    payload = f.decode(h.read_file(scripts / "TargetManifest.json", maximum=16 * 1024**2))
    payload["roots"][str(h.BASE)] = {name: node for name, node in payload["roots"][str(h.BASE)].items()
        if name in {"", "package-identity.json", "owner.app"} or name.startswith("owner.app/")}
    payload_raw = builder["encoded"](payload)
    require(c.digest(payload_raw) == review["payload_manifest_sha256"])
    builder["public_image"](f.inventory(scripts / "TargetImage"), f.decode(payload_raw))
    result["checks"]["compact_payload_verified"] = True
    fresh = runpy.run_path(str(source("scripts/mac_fresh_image_installer_probe.py")))
    fresh["live_service"].__globals__["h"] = h

    def history():
        values = {str(base): namespace_snapshot(c, base) for base in (c.NAMESPACE, runtime["NAMESPACE"])}
        return {"original": f.public_evidence(), "ancestors": values,
                "fictional_publication": publication(), "full_head": f.completed_history(f.CONFIGURATION_PINS),
                "roots": [(p.lstat().st_dev, p.lstat().st_ino) for p in (h.BASE, h.APP)]}

    def install(label, *, expected=0):
        result["failure_stage"] = label
        package = "owner-old-resource-root.pkg" if label == "owner-old-resource-root" else "owner-upgrade.pkg"
        delta = h.InstallerLogDelta()
        try:
            response = command(["/usr/sbin/installer", "-dumplog", "-verboseR", "-pkg", str(stage / package), "-target", "/"], label + ".log", 2100, check=False)
            require(response.returncode == 0 if expected == 0 else response.returncode != 0)
        finally:
            delta.capture(report=report, output=output, log=label + "-daemon.log")

    preserved = history()
    old_policy = h.policies()
    before_manifest = f.decode(h.read_file(scripts / "BaseManifest.json", maximum=16 * 1024**2))
    previous_image = fresh["public_snapshot"](before_manifest)
    install("owner-old-resource-root", expected=1)
    require_native_refusal(c, report, output, "owner-old-resource-root", "source")
    require(history() == preserved and fresh["public_snapshot"](before_manifest) == previous_image
            and h.policies() == old_policy and not os.path.lexists(NAMESPACE))
    fresh["live_service"](command, "after-owner-source-refusal")
    result["checks"]["old_package_resource_root_refused"] = True
    foreign = runtime["NAMESPACE"] / ("transition-" + runtime["PLAN"]) / "global/foreign-owner-fixture.json"
    foreign_bytes = b'{"schema":1,"foreign":true}'
    c.create_file(foreign, foreign_bytes)
    try:
        # The expected injected record is excluded only from the independent
        # before/after ancestor comparison, never from native qualification.
        with_foreign = history()
        install("owner-foreign-predecessor", expected=1)
        require_native_refusal(c, report, output, "owner-foreign-predecessor", "predecessor")
        require(history() == with_foreign and fresh["public_snapshot"](before_manifest) == previous_image
                and h.policies() == old_policy and not os.path.lexists(NAMESPACE / "head.json"))
        fresh["live_service"](command, "after-owner-predecessor-refusal")
        result["checks"]["foreign_predecessor_refused"] = True
    finally:
        require(h.read_file(foreign) == foreign_bytes)
        foreign.unlink()
    require(history() == preserved)
    if args.owner_scenario in INTERRUPT_SCENARIOS:
        result["failure_stage"] = "owned_helper_interruption"
        publication_case = args.owner_scenario == "interrupt-published-preparation"
        selected = {"interrupt-owner": "owner.app", "interrupt-identity": "package-identity.json", "interrupt-host": "broker/host.json",
                    "interrupt-published-preparation": "owner.app"}[args.owner_scenario]
        target = h.BASE / selected
        original_inode = target.lstat().st_ino
        out_path, err_path = stage / "owner-owned.stdout", stage / "owner-owned.stderr"
        child, stopped = None, False
        try:
            with out_path.open("xb") as out, err_path.open("xb") as err:
                child = subprocess.Popen([str(scripts / "AccountAccess-ownerupgrade")], stdin=subprocess.DEVNULL, stdout=out, stderr=err, env=c.ENV, start_new_session=True)
                deadline = time.monotonic() + 1800
                while time.monotonic() < deadline and child.poll() is None:
                    require(out_path.stat().st_size + err_path.stat().st_size < 65536)
                    global_dir = NAMESPACE / ("transition-" + PLAN) / "global"
                    boundary_reached = (os.path.lexists(global_dir / "intent.json") if publication_case
                                        else target.lstat().st_ino != original_inode)
                    if boundary_reached:
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
                        intent = f.decode(h.read_file(global_dir / "intent.json", maximum=256 * 1024))
                        require(intent["planSHA256"] == PLAN)
                        events = [f.decode(h.read_file(p)) for p in sorted(global_dir.glob("record-*.json"))]
                        if publication_case:
                            local = global_dir.parent / "trees/runtimeOwner/journal/intent.json"
                            require(intent["operations"][0]["tree"]["unit"] == "runtimeOwner"
                                    and f.decode(h.read_file(local, maximum=65536)) == intent["operations"][0]["tree"]
                                    and not events and target.lstat().st_ino == original_inode
                                    and fresh["public_snapshot"](before_manifest) == previous_image and h.policies() == old_policy)
                            fresh["live_service"](command, "owner-published-preparation-stopped")
                        else:
                            kind, unit = {"interrupt-owner": ("tree", "runtimeOwner"),
                                          "interrupt-identity": ("file", "packageIdentity"),
                                          "interrupt-host": ("file", "hostPolicy")}[args.owner_scenario]
                            selected_operations = [row[kind] for row in intent["operations"]
                                if isinstance(row.get(kind), dict) and row[kind].get("unit") == unit]
                            require(len(selected_operations) == 1
                                    and selected_operations[0]["after"]["inode"] == target.lstat().st_ino)
                            require(all(e.get("planSHA256") == PLAN for e in events)
                                    and any(e.get("service") == "disabled_quiescence_confirmed" for e in events)
                                    and not any(e.get("service") == "coherent_image_enable_intent" for e in events))
                        break
                    time.sleep(0.01)
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
                    label = "owner-owned-" + name + ".log"
                    output.write(label, data)
                    report["logs"][label] = c.digest(data)
        result["interruption"] = {"owned_child_only": True, "head_not_published": True,
                                  "installer_daemon_interrupted": False, "power_failure_tested": False}
        if publication_case:
            result["interruption"].update(published_local_journal_sealed=True, public_image_unchanged=True, service_disable_not_started=True)
    result["checks"]["scenario_exercised"] = True
    install("owner-upgrade-install")
    result["checks"]["actual_installer"] = True
    manifest = f.decode(h.read_file(scripts / "TargetManifest.json", maximum=16 * 1024**2))
    h.verify_image(manifest)
    head = f.decode(h.read_file(NAMESPACE / "head.json"))
    require(head["plan_sha256"] == PLAN and head["manifest_sha256"] == AFTER and head["source_commit"] == TARGET)
    result["checks"]["exact_public_image"] = True
    peers = f.decode(h.read_file(scripts / "TargetIdentity.json"))["signatures"]
    require(h.policies() == f.expected_policies(old_policy, peers))
    result["checks"]["policy_rotation"] = True
    require(history() == preserved)
    result["checks"]["roots_and_history_preserved"] = True
    fresh["live_service"](command, "owner-upgrade")
    result["checks"]["live_service"] = True
    result["ordinary_after_upgrade"] = owner_runtime_aliases(c, runtime, command, "after-upgrade")
    result["checks"]["ordinary_public_runtime"] = True
    image_snapshot, policies = fresh["public_snapshot"](manifest), h.policies()

    def owner_history():
        return namespace_snapshot(c, NAMESPACE)

    applied_history = owner_history()
    install("owner-upgrade-reapply")
    result["checks"]["exact_reapply"] = True
    require(fresh["public_snapshot"](manifest) == image_snapshot and h.policies() == policies
            and owner_history() == applied_history and history() == preserved)
    result["checks"]["unchanged_reapply"] = True
    result["ordinary_after_reapply"] = owner_runtime_aliases(c, runtime, command, "after-reapply")
    result["checks"]["ordinary_public_runtime_reapply"] = True
    foreign = NAMESPACE / ("transition-" + PLAN) / "global/foreign-audit-fixture.json"
    c.create_file(foreign, foreign_bytes)
    try:
        with_foreign = owner_history()
        install("owner-upgrade-foreign-audit", expected=1)
        require_native_refusal(c, report, output, "owner-upgrade-foreign-audit", "journal")
        require(fresh["public_snapshot"](manifest) == image_snapshot and h.policies() == policies
                and owner_history() == with_foreign and history() == preserved)
        result["checks"]["foreign_audit_refused"] = True
        fresh["live_service"](command, "after-owner-refusal")
        result["checks"]["service_after_refusal"] = True
    finally:
        require(h.read_file(foreign) == foreign_bytes)
        foreign.unlink()
    require(owner_history() == applied_history)
    result["failure_stage"] = None
    require(acceptance_passed(result))
