"""Qualify the runtime successor inside the already accepted hosted package91 fixture.

This module has no owner-machine entrypoint. Its caller first verifies the
disposable hosted root context and completes the exact predecessor Installer QA.
"""
import os
from pathlib import Path
import runpy
import signal
import subprocess
import time
import xml.etree.ElementTree as ET

CONTROLLER = "f9c0a80fd5bf28e4e92d005ef3777a6b44de1ab6"
TARGET = "7051ef225ff2f35d67576d0ddbbc3e0b107e00bf"
PLAN = "671c32eb5daacb79a1ec5f63d97cc29d2b6f34b5c75a773a1b477aca981ce6df"
BEFORE = "5a732de4623ba50aefa6d31c54e7b1eae660b2921341f95042c5675d922d808b"
AFTER = "03fb35eb2787ebd67079dd1cbe4dda125f430964540bdd2f2e9c81eda602fd7a"
NAMESPACE = Path("/Library/Application Support/Account Access Runtime Updates")
SCENARIOS = {"install-reapply", "interrupt-owner", "interrupt-runtime"}
CHECKS = {"fixed_inputs", "predecessor_fixture_accepted", "signature_verified", "scenario_exercised",
          "actual_installer", "exact_public_image", "policy_rotation", "roots_and_history_preserved",
          "live_service", "exact_reapply", "unchanged_reapply", "foreign_audit_refused", "service_after_refusal"}


def acceptance_passed(value):
    return (type(value) is dict and value.get("scenario") in SCENARIOS
            and set(value.get("checks", {})) == CHECKS and all(v is True for v in value["checks"].values())
            and value.get("production_ready") is False and value.get("real_account_login_tested") is False
            and value.get("installed_owner_machine") is False and value.get("failure_stage") is None)


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
            and review["installed"] is False and review["production_ready"] is False)
    for name, digest in review["source_sha256"].items():
        require(name.startswith("macos/") and ".." not in name
                and c.digest(h.git_bytes(args.repository, ["show", CONTROLLER + ":" + name], maximum=2 * 1024**2)) == digest)
    expanded = stage / "runtime-upgrade-expanded"
    command(["/usr/sbin/pkgutil", "--expand-full", str(stage / "runtime-upgrade.pkg"), str(expanded)], "upgrade-expand.log", 300)
    require({p.name for p in expanded.iterdir()} == {"PackageInfo", "Scripts"})
    info = ET.fromstring(h.read_file(expanded / "PackageInfo", maximum=65536))
    require(info.get("identifier") == "com.fainir.accountaccess.runtimeupgrade93"
            and info.get("version") == "0.1.0" and info.get("auth") == "root"
            and info.find("scripts/postinstall").attrib == {"file": "./postinstall", "timeout": "1800"})
    scripts = expanded / "Scripts"
    expected_inventory = f.decode(h.read_file(stage / "upgrade-scripts-inventory.json", maximum=32 * 1024**2))
    require(f.inventory(scripts) == expected_inventory
            and c.digest(h.read_file(scripts / "RuntimeUpgradePlan.json", maximum=34 * 1024**2)) == PLAN
            and c.digest(h.read_file(scripts / "TargetManifest.json", maximum=16 * 1024**2)) == AFTER)
    result["checks"]["fixed_inputs"] = True
    command(["/usr/bin/codesign", "--verify", "--strict", "-R=anchor apple generic and identifier "
        '\"com.fainir.accountaccess.componentupdate\" and certificate leaf[subject.OU] = \"WBULD6N4NQ\" '
        'and !(entitlement[\"com.apple.security.get-task-allow\"] exists)', str(scripts / "AccountAccess-runtimeupgrade")],
        "upgrade-signature.log")
    require(c.digest(h.read_file(scripts / "AccountAccess-runtimeupgrade", maximum=16 * 1024**2)) == review["helper_sha256"])
    result["checks"]["signature_verified"] = True
    def history():
        # Fixed public repair history only. Never inspect the account store.
        values = {str(p): c.snapshot(p, maximum=16 * 1024**2)
                  for p in c.NAMESPACE.rglob("*") if p.is_file()}
        return {"original": f.public_evidence(), "repair": values, "fictional_publication": publication(),
                "full_head": f.completed_history(f.CONFIGURATION_PINS),
                "roots": [(p.lstat().st_dev, p.lstat().st_ino) for p in (h.BASE, h.APP)]}
    preserved = history()
    old_policy = h.policies()
    def install(label, *, expected=0):
        result["failure_stage"] = label
        delta = h.InstallerLogDelta()
        try:
            response = command(["/usr/sbin/installer", "-dumplog", "-verboseR", "-pkg", str(stage / "runtime-upgrade.pkg"), "-target", "/"],
                               label + ".log", 2100, check=False)
            require(response.returncode == 0 if expected == 0 else response.returncode != 0)
        finally:
            delta.capture(report=report, output=output, log=label + "-daemon.log")
    if args.runtime_scenario != "install-reapply":
        f.normalize_owned_resource_ancestors(stage)
        f.inventory(scripts, normalize=True)
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
                        events = [f.decode(h.read_file(p)) for p in global_dir.glob("event-*.json")]
                        require(any(e.get("service") == "disabled_quiescence_confirmed" for e in events)
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
    head = f.decode(h.read_file(NAMESPACE / "head.json"))
    require(head["plan_sha256"] == PLAN and head["manifest_sha256"] == AFTER and head["source_commit"] == TARGET)
    result["checks"]["exact_public_image"] = True
    peers = f.decode(h.read_file(scripts / "TargetIdentity.json"))["signatures"]
    require(h.policies() == f.expected_policies(old_policy, peers))
    result["checks"]["policy_rotation"] = True
    require(history() == preserved)
    result["checks"]["roots_and_history_preserved"] = True
    fresh = runpy.run_path(str(source("scripts/mac_fresh_image_installer_probe.py")))
    fresh["live_service"].__globals__["h"] = h
    fresh["live_service"](command, "runtime-upgrade")
    result["checks"]["live_service"] = True
    image_snapshot = fresh["public_snapshot"](manifest)
    policy_snapshot = h.policies()
    upgrade_head = c.snapshot(NAMESPACE / "head.json")
    install("runtime-upgrade-reapply")
    result["checks"]["exact_reapply"] = True
    require(fresh["public_snapshot"](manifest) == image_snapshot and h.policies() == policy_snapshot
            and c.snapshot(NAMESPACE / "head.json") == upgrade_head and history() == preserved)
    result["checks"]["unchanged_reapply"] = True
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
    result["failure_stage"] = None
    require(acceptance_passed(result))
