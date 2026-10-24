"""Actual broker-repair Installer QA, exclusively in a fresh hosted ARM64 Mac.

Runs the existing base/component/volume-revalidation acceptance before the full
image and repair. Only this fresh VM receives fictional publication metadata.
No owner machine, real credential database, Keychain secret or account is used.
"""
import argparse
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
import uuid
import xml.etree.ElementTree as ET

SOURCE = "c4cf1b0918c1a51cbd4a38880364fcb71fa5980e"
PLAN = "3741aae23c6c23c9da33ae233d0657800454514042d59cba951e7bbf7d1d8ec1"
BEFORE = "05553235819dd43d76d8f1d506f3da16a57617e63c5f8c49bf58c298e11b55da"
AFTER = "5a732de4623ba50aefa6d31c54e7b1eae660b2921341f95042c5675d922d808b"
NAMESPACE = Path("/Library/Application Support/Account Access Broker Repair")
SCENARIOS = {"install-reapply", "interrupt-broker", "foreign-binding"}
CHECKS = {"fresh_predecessor_acceptance", "pinned_assets_and_sources", "exact_repair_resources", "native_signatures",
          "actual_full_image_installer", "completed_full_image", "fictional_legacy_publication",
          "scenario_exercised", "expected_public_image", "original_metadata_preserved",
          "same_package_reapplication", "reapplication_preserved_bytes_and_ids", "created_job_stopped"}
ENV = {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LANG": "C", "LC_ALL": "C"}
CONTROLLER88 = "eba805729025caa1dc0754112e21d6d5592e0113"
CONTROLLER90 = "4807187226c9701ca615634c2ad570f343dccc91"


def require(value):
    if not value:
        raise ValueError("broker_repair_installer_acceptance_failed")


def profile(cohort):
    require(type(cohort) is int and cohort in {87, 88, 90})
    sources = {87: SOURCE, 88: CONTROLLER88, 90: CONTROLLER90}
    downloads = {87: "download_broker_repair_installer_inputs.py",
                 88: "download_broker_repair_restart_inputs.py",
                 90: "download_broker_repair_progress_inputs.py"}
    return {"cohort": cohort, "controller_source": sources[cohort],
            "identifier": f"com.fainir.accountaccess.brokerrepair{cohort}",
            "download": downloads[cohort]}


def guard():
    require(sys.platform == "darwin" and platform.machine() == "arm64" and os.getuid() == os.geteuid() == 0
            and os.environ.get("GITHUB_ACTIONS") == "true" and os.environ.get("CI") == "true"
            and os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted" and os.environ.get("RUNNER_OS") == "macOS"
            and os.environ.get("RUNNER_ARCH") == "ARM64" and os.environ.get("GITHUB_REPOSITORY") == "fainir/account-access"
            and re.fullmatch("[1-9][0-9]{0,17}", os.environ.get("GITHUB_RUN_ID", ""))
            and re.fullmatch("[1-9][0-9]{0,9}", os.environ.get("GITHUB_RUN_ATTEMPT", ""))
            and re.fullmatch("[a-f0-9]{40}", os.environ.get("GITHUB_SHA", "")))


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def verify_assets(folder, contract, allowed, hash_file):
    require(isinstance(contract.get("assets"), dict) and set(contract["assets"]) == set(allowed))
    for name, row in contract["assets"].items():
        require(isinstance(name, str) and "/" not in name and name not in {"", ".", ".."}
                and hash_file(folder / name, 1024**3) == (row["sha256"], row["bytes"]))


def verify_review_identity(review, selected, *, package_sha256, inventory_sha256):
    require(review["status"] == "BUILT_PENDING_INSTALLER_QA" and review["source_commit"] == SOURCE
            and review.get("controller_source_commit", SOURCE) == selected["controller_source"]
            and review["plan_sha256"] == PLAN and review["before_manifest_sha256"] == BEFORE
            and review["after_manifest_sha256"] == AFTER and review["postinstall_timeout"] == 1800
            and review["package_sha256"] == package_sha256
            and review["scripts_inventory_sha256"] == inventory_sha256 and review["production_ready"] is False)


def acceptance_passed(report):
    return (report.get("scenario") in SCENARIOS and set(report.get("checks", {})) == CHECKS
            and all(value is True for value in report["checks"].values()) and "failure_reason" not in report
            and report.get("personal_accounts_used") == 0 and report.get("owner_GUI_qualified") is False
            and report.get("production_ready") is False
            and (report.get("scenario") != "foreign-binding" or report.get("foreign_binding_rollback") == {
                "verified_attempts": 2, "applied_per_attempt": 5, "restored_per_attempt": 5,
                "head_published": False}))


def verify_rollback_events(events, attempts):
    require(type(attempts) is int and attempts in {1, 2} and isinstance(events, list))
    expected = []
    for _ in range(attempts):
        expected.extend({"schema": 1, "event": event, "operation": i}
            for i in range(5) for event in ("apply_intent", "applied"))
        expected.extend({"schema": 1, "event": event, "operation": i}
            for i in reversed(range(5)) for event in ("rollback_intent", "rolled_back"))
        expected.append({"schema": 1, "event": "old_image_restored", "operation": -1})
    require(all(isinstance(row, dict) and type(row.get("schema")) is int
                and type(row.get("operation")) is int for row in events) and events == expected)


def read_rollback_evidence(attempts):
    transition = NAMESPACE / ("transition-" + PLAN)
    paths = sorted(transition.glob("event-*.json"))
    require([p.name for p in paths] == [f"event-{i:04d}.json" for i in range(21 * attempts)])
    verify_rollback_events([json.loads(h.read_file(p, maximum=4096)) for p in paths], attempts)
    require(not os.path.lexists(NAMESPACE / "head.json"))


def snapshot(path, *, maximum=8192, owner=0):
    # A refused transaction may exchange and restore the same inode. ctime
    # legitimately changes during that operation; contents, mtime and ID must not.
    return digest(h.read_file(path, maximum=maximum, owner=owner)), h.stamp(path.lstat())[:8]


def create_file(path, data, mode=0o600, uid=0):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, mode)
    try:
        with os.fdopen(os.dup(fd), "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.fchown(fd, uid, uid)
        os.fchmod(fd, mode)
        os.fsync(fd)
    finally:
        os.close(fd)


def fictional_publication(report, predecessor):
    guard()
    require(predecessor.get("status") == "PASSED" and h.acceptance_passed(predecessor)
            and all(predecessor["root_revalidation_checks"].values())
            and report["checks"]["completed_full_image"] is True and not os.path.lexists(NAMESPACE))
    install = h.policies()["install"]
    uid = install["broker_uid"]
    require(type(uid) is int and 450 <= uid < 500)
    vault, enrollment = install["vault_id"], install["enrollment_id"]
    require(all(str(uuid.UUID(value)) == value and uuid.UUID(value).int != 0 for value in (vault, enrollment)))
    parent = h.BASE / "vault"
    h.protected_metadata(parent.lstat(), mode=0o755)
    stage, data = parent / (".enrollment-" + enrollment), parent / "data"
    for path in (stage, data):
        if not os.path.lexists(path):
            path.mkdir(mode=0o700)
            os.chown(path, uid, uid)
        info = path.lstat()
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == info.st_gid == uid
                and stat.S_IMODE(info.st_mode) == 0o700 and not list(path.iterdir()))
    journal = parent / (stage.name + ".publication")
    if os.path.lexists(journal):
        h.protected_metadata(journal.lstat(), mode=0o700)
        require({p.name for p in journal.iterdir()} == {"plan.json"})
        # Only an unapproved, empty fixture created by this run's broker can be
        # replaced here. A ready or approved publication cannot reach this seam.
        old = json.loads(h.read_file(journal / "plan.json", maximum=4096))
        require(old.get("vault") == vault and old.get("enrollment") == enrollment
                and old.get("uid") == uid and old.get("gid") == uid
                and old.get("stagedIdentity") == {"device": stage.stat().st_dev, "inode": stage.stat().st_ino}
                and old.get("emptyIdentity") == {"device": data.stat().st_dev, "inode": data.stat().st_ino})
        (journal / "plan.json").unlink()
    else:
        journal.mkdir(mode=0o700)
    lock = parent / ".account-access-enrollment.lock"
    if not os.path.lexists(lock):
        create_file(lock, b"")
    h.protected_metadata(lock.lstat(), mode=0o600, directory=False)
    require(lock.stat().st_size == 0)
    legacy = json.loads(h.read_file(h.JOURNAL / "ready.json"))["roots"][str(h.BASE)][0]
    require(legacy != parent.stat().st_dev and legacy == parent.stat().st_dev + 1)
    record = {"schema": 1, "vault": vault, "enrollment": enrollment, "stage": stage.name, "destination": "data",
        "uid": uid, "gid": uid, "stagedIdentity": {"device": legacy, "inode": data.stat().st_ino},
        "emptyIdentity": {"device": legacy, "inode": stage.stat().st_ino}}
    create_file(journal / "plan.json", encoded(record))
    create_file(journal / "authorized", encoded({"schema": 1, "owner_uid": os.stat("/dev/console").st_uid}))
    create_file(journal / "ready", b"account-access-publication-ready-v1\n")
    sentinel = data / "fictional-repair-qa.txt"
    create_file(sentinel, b"Fictional disposable-VM migration sentinel; no credentials.\n", uid=uid)
    preserved = {name: snapshot(journal / name) for name in ("plan.json", "authorized", "ready")}
    preserved["sentinel"] = snapshot(sentinel, owner=uid)
    preserved["stage"] = h.stamp(stage.lstat())[:6]
    preserved["data"] = h.stamp(data.lstat())[:6]
    return journal, sentinel, uid, preserved


def preserved_publication(journal, sentinel, uid):
    value = {name: snapshot(journal / name) for name in ("plan.json", "authorized", "ready")}
    value["sentinel"] = snapshot(sentinel, owner=uid)
    value["stage"] = h.stamp(journal.parent.joinpath(journal.name.removesuffix(".publication")).lstat())[:6]
    value["data"] = h.stamp(sentinel.parent.lstat())[:6]
    return value


def interrupt(scripts, report, output, new_broker):
    stdout, stderr = scripts.parent / "owned-helper.stdout", scripts.parent / "owned-helper.stderr"
    child = None
    stopped = False
    try:
        with stdout.open("xb") as out, stderr.open("xb") as err:
            child = subprocess.Popen([str(scripts / "AccountAccess-brokerrepair")], stdin=subprocess.DEVNULL,
                stdout=out, stderr=err, env=ENV, start_new_session=True)
            until = time.monotonic() + 1500
            while time.monotonic() < until and child.poll() is None:
                require(stdout.stat().st_size + stderr.stat().st_size < 65536)
                if digest(h.read_file(h.BASE / "bin/AccountAccess-broker")) == new_broker:
                    # The child remains unreaped while signalled. No discovered
                    # process ID or Apple's Installer daemon is targeted.
                    os.kill(child.pid, signal.SIGSTOP)
                    deadline = time.monotonic() + 5
                    while time.monotonic() < deadline:
                        pid, state = os.waitpid(child.pid, os.WNOHANG | os.WUNTRACED)
                        if pid:
                            require(os.WIFSTOPPED(state))
                            stopped = True
                            break
                        time.sleep(0.01)
                    require(stopped and not os.path.lexists(NAMESPACE / "head.json"))
                    transition = NAMESPACE / ("transition-" + PLAN)
                    intent = json.loads(h.read_file(transition / "intent.json", maximum=65536))
                    require(intent["transition"]["planSHA256"] == PLAN
                            and digest(h.read_file(h.BASE / "bin/AccountAccess-broker")) == new_broker)
                    events = [json.loads(h.read_file(p)) for p in transition.glob("service-*.json")]
                    require(any(e.get("event") == "disabled_quiescence_confirmed" for e in events)
                            and not any(e.get("event") == "coherent_image_enable_intent" for e in events))
                    report["interruption"] = {"owned_child_only": True, "broker_replaced_before_head": True,
                        "installer_daemon_interrupted": False, "power_failure_tested": False}
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
        for label, path in (("stdout", stdout), ("stderr", stderr)):
            if path.exists():
                output.write("owned-helper-" + label + ".log", h.read_file(path, maximum=65536))


def run(args):
    guard()  # Before any file read or installed-state access.
    require(args.scenario in SCENARIOS)
    selected = profile(getattr(args, "cohort", 87))
    revision = os.environ["GITHUB_SHA"]
    global h, f
    h_path = args.repository / "scripts/mac_component_update_installer_probe.py"
    require(digest(h_path.read_bytes()) == "a4507756990cf6ff96e666653dab7aa7d636f1c37a01027dce9fae0e465311da")
    h = SimpleNamespace(**runpy.run_path(str(h_path)))
    for name in ("mac_broker_repair_installer_probe.py", "mac_full_image_installer_probe.py", selected["download"]):
        path = args.repository / "scripts" / name
        require(h.git_bytes(args.repository, ["show", revision + ":scripts/" + name], maximum=2 * 1024**2) == path.read_bytes())
    f = SimpleNamespace(**runpy.run_path(str(args.repository / "scripts/mac_full_image_installer_probe.py")))
    for value in vars(f).values():
        if callable(value) and hasattr(value, "__globals__"):
            value.__globals__["h"] = h
    download = runpy.run_path(str(args.repository / "scripts" / selected["download"]))
    rid = os.environ["GITHUB_RUN_ID"]
    suffix = str(selected["cohort"])
    output = h.RootOutput(h.report_path(rid + suffix), rid + suffix)
    report = {"schema": 1, "status": "FAILED", "scenario": args.scenario, "controller_revision": revision,
        "checks": dict.fromkeys(CHECKS, False), "logs": {}, "failure_stage": "inputs", "personal_accounts_used": 0,
        "owner_GUI_qualified": False, "production_ready": False, "fixture": "fictional-publication-metadata-only",
        "real_account_login_tested": False, "private_credential_database_read": False,
        "repair_cohort": selected["cohort"], "tested_controller_source": selected["controller_source"],
        "application_source": SOURCE}
    touched = False
    try:
        require(not os.path.lexists(NAMESPACE) and not os.path.lexists(f.FULL))
        extra_raw = (args.repair / "asset-contract.json").read_bytes()
        require(extra_raw == h.git_bytes(args.repository, ["show", revision + ":" + download["CONTRACT"]], maximum=65536))
        extra = download["validate"](f.decode(extra_raw))
        base_raw = (args.bundle / "asset-contract.json").read_bytes()
        require(base_raw == h.git_bytes(args.repository, ["show", revision + ":artifacts/full-image-installer85-inputs.json"], maximum=65536))
        base = f.decode(base_raw)
        for folder, contract, allowed in ((args.bundle, base, f.ASSET_FILES), (args.repair, extra, download["FILES"])):
            controller = f.decode((folder / "controller.json").read_bytes())
            require(controller["controller_revision"] == revision
                    and controller["contract_sha256"] == digest((folder / "asset-contract.json").read_bytes()))
            verify_assets(folder, contract, allowed, f.hash_file)
        with tempfile.TemporaryDirectory(prefix="account-access-full-image-acceptance-", dir="/private/tmp") as temporary:
            stage = Path(temporary)
            f.verify_owned_stage(stage)
            for folder, contract, names in ((args.bundle, base, {"full.pkg", "full-scripts-inventory.json"}),
                                            (args.repair, extra, download["FILES"])):
                for name in names:
                    h.stage_file(folder / name, stage / name, contract["assets"][name]["sha256"], 1024**3)
            def command(arguments, log, timeout=120, check=True):
                return h.command(arguments, report=report, output=output, log=log, timeout=timeout, check=check)
            def install(name, label, expected=0):
                delta = h.InstallerLogDelta()
                try:
                    result = command(["/usr/sbin/installer", "-dumplog", "-verboseR", "-pkg", str(stage / name), "-target", "/"],
                        label + ".log", 2100, check=False)
                    require(result.returncode == expected if expected == 0 else result.returncode != 0)
                    return result
                finally:
                    delta.capture(report=report, output=output, log=label + "-daemon.log")
            review = f.decode(h.read_file(stage / "repair-review.json"))
            verify_review_identity(review, selected, package_sha256=extra["assets"]["repair.pkg"]["sha256"],
                inventory_sha256=extra["assets"]["repair-scripts-inventory.json"]["sha256"])
            for source_map, source_commit in ((review["controller_sources"], selected["controller_source"]),
                                              (review["native_sources"], SOURCE)):
                require(isinstance(source_map, dict) and 1 <= len(source_map) <= 128)
                for path, sha in source_map.items():
                    require(re.fullmatch(r"macos/(?:source-fragments/)?[A-Za-z0-9_.-]+\.(?:swift|h|c|inc)", path)
                            and digest(h.git_bytes(args.repository, ["show", source_commit + ":" + path], maximum=2 * 1024**2)) == sha)
            report["checks"]["pinned_assets_and_sources"] = True
            report["failure_stage"] = "repair_expansion"
            full_stage = stage / "full-stage"
            full_stage.mkdir(mode=0o700)
            expanded = full_stage / "expanded"
            command(["/usr/sbin/pkgutil", "--expand-full", str(stage / "repair.pkg"), str(expanded)], "repair-expand.log", 600)
            require({p.name for p in expanded.iterdir()} == {"PackageInfo", "Scripts"})
            info = ET.fromstring((expanded / "PackageInfo").read_bytes())
            require(info.get("identifier") == selected["identifier"] and info.get("version") == "0.1.0"
                    and info.get("auth") == "root" and info.find("scripts/postinstall").attrib == {"file": "./postinstall", "timeout": "1800"})
            scripts = expanded / "Scripts"
            require(f.inventory(scripts) == f.decode(h.read_file(stage / "repair-scripts-inventory.json", maximum=64 * 1024**2))
                    and f.inventory(scripts / "CompletedImage") == f.decode(h.read_file(stage / "full-scripts-inventory.json", maximum=64 * 1024**2)))
            require(digest((scripts / "BrokerRepairPlan.json").read_bytes()) == PLAN
                    and digest((scripts / "BaseManifest.json").read_bytes()) == BEFORE
                    and digest((scripts / "TargetManifest.json").read_bytes()) == AFTER)
            report["checks"]["exact_repair_resources"] = True
            for name, identifier, key in (("AccountAccess-brokerrepair", "componentupdate", "helper_sha256"),
                                           ("AccountAccess-broker", "broker", "broker_sha256")):
                require(digest((scripts / name).read_bytes()) == review[key])
                requirement = ('anchor apple generic and identifier "com.fainir.accountaccess.' + identifier + '" '
                    'and certificate leaf[subject.OU] = "WBULD6N4NQ" and !(entitlement["com.apple.security.get-task-allow"] exists)')
                command(["/usr/bin/codesign", "--verify", "--strict", "--all-architectures", "-R=" + requirement,
                    str(scripts / name)], identifier + "-signature.log")
            report["checks"]["native_signatures"] = True
            report["failure_stage"] = "fresh_predecessor_acceptance"
            touched = True
            predecessor_args = SimpleNamespace(base=args.bundle / "base.pkg", base_manifest=args.bundle / "base-manifest.json",
                candidate=args.bundle / "component.pkg", review=args.bundle / "component-review.json", report=h.report_path(rid),
                repository=args.repository, source=f.COMPONENT_SOURCE, candidate_sha256=f.COMPONENT_SHA,
                review_sha256=base["assets"]["component-review.json"]["sha256"], root_revalidation=stage / "root-revalidation.pkg",
                root_revalidation_review=stage / "root-revalidation-review.json",
                root_revalidation_sha256=extra["assets"]["root-revalidation.pkg"]["sha256"],
                root_revalidation_review_sha256=extra["assets"]["root-revalidation-review.json"]["sha256"])
            require(h.run(predecessor_args) == 0)
            predecessor = json.loads(h.read_file(h.report_path(rid), maximum=256 * 1024))
            require(predecessor["status"] == "PASSED" and h.acceptance_passed(predecessor))
            report["checks"]["fresh_predecessor_acceptance"] = True
            command(["/bin/launchctl", "bootstrap", "system", str(h.JOB)], "predecessor-bootstrap.log")
            report["failure_stage"] = "actual_full_image_installer"
            install("full.pkg", "full-installer")
            report["checks"]["actual_full_image_installer"] = True
            h.verify_image(f.decode((scripts / "BaseManifest.json").read_bytes()))
            full_head = f.completed_history(f.CONFIGURATION_PINS)
            retained = f.public_evidence()
            original_policy = h.policies()
            report["checks"]["completed_full_image"] = True
            report["failure_stage"] = "fictional_publication"
            command(["/bin/launchctl", "bootout", "system/" + h.LABEL], "fixture-bootout.log")
            journal, sentinel, uid, preserved = fictional_publication(report, predecessor)
            binding = journal / "volume-v1.json"
            if args.scenario == "foreign-binding":
                create_file(binding, b'{"schema":1,"foreign":true}')
                foreign = snapshot(binding)
            command(["/bin/launchctl", "bootstrap", "system", str(h.JOB)], "fixture-bootstrap.log")
            report["checks"]["fictional_legacy_publication"] = True
            report["failure_stage"] = "repair_scenario"
            if args.scenario == "interrupt-broker":
                f.normalize_owned_resource_ancestors(stage)
                f.inventory(scripts, normalize=True)
                interrupt(scripts, report, output, review["broker_sha256"])
            foreign_case = args.scenario == "foreign-binding"
            install("repair.pkg", "repair-installer", 1 if foreign_case else 0)
            report["checks"]["scenario_exercised"] = True
            report["failure_stage"] = "post_repair_evidence"
            expected = f.decode((scripts / ("BaseManifest.json" if foreign_case else "TargetManifest.json")).read_bytes())
            h.verify_image(expected)
            if foreign_case:
                require(not os.path.lexists(NAMESPACE / "head.json") and h.policies() == original_policy and snapshot(binding) == foreign)
                read_rollback_evidence(1)
            else:
                head = json.loads(h.read_file(NAMESPACE / "head.json"))
                require(head.get("plan_sha256") == PLAN and head.get("manifest_sha256") == AFTER
                        and head.get("source_commit") == SOURCE and head.get("state") == "public_image_verified_gui_unverified")
                value = json.loads(h.read_file(binding, maximum=512))
                receipt = json.loads(h.read_file(h.REVALIDATION_RECEIPT))
                require(value["schema"] == 1 and value["recordSHA256"] == preserved["plan.json"][0]
                        and value["parentInode"] == journal.parent.stat().st_ino
                        and value["volumeUUID"] == receipt["roots"][str(h.BASE)]["volume_uuid"])
            command(["/bin/launchctl", "print", "system/" + h.LABEL], "live-broker.log")
            report["checks"]["expected_public_image"] = True
            require(preserved_publication(journal, sentinel, uid) == preserved and f.public_evidence() == retained
                    and f.completed_history(f.CONFIGURATION_PINS) == full_head)
            report["checks"]["original_metadata_preserved"] = True
            stable = {"binding": snapshot(binding), "broker": snapshot(h.BASE / "bin/AccountAccess-broker", maximum=16 * 1024**2),
                "owner": snapshot(h.BASE / "owner.json"), "install": snapshot(h.BASE / "broker/install.json")}
            if not foreign_case:
                stable["head"] = snapshot(NAMESPACE / "head.json")
            report["failure_stage"] = "repair_reapply"
            install("repair.pkg", "repair-reapply", 1 if foreign_case else 0)
            if foreign_case:
                read_rollback_evidence(2)
                report["foreign_binding_rollback"] = {"verified_attempts": 2, "applied_per_attempt": 5,
                    "restored_per_attempt": 5, "head_published": False}
            report["checks"]["same_package_reapplication"] = True
            h.verify_image(expected)
            require(snapshot(binding) == stable["binding"] and snapshot(h.BASE / "bin/AccountAccess-broker", maximum=16 * 1024**2) == stable["broker"]
                    and snapshot(h.BASE / "owner.json") == stable["owner"] and snapshot(h.BASE / "broker/install.json") == stable["install"]
                    and (foreign_case or snapshot(NAMESPACE / "head.json") == stable["head"])
                    and preserved_publication(journal, sentinel, uid) == preserved and f.public_evidence() == retained
                    and f.completed_history(f.CONFIGURATION_PINS) == full_head)
            report["checks"]["reapplication_preserved_bytes_and_ids"] = True
    except Exception as error:
        report["failure_reason"] = "actual_broker_repair_installer_acceptance_failed"
        report["exception_type"] = type(error).__name__
        # Only this guarded public/synthetic probe's traceback location, never
        # exception text or locals that could contain unbounded file contents.
        import traceback
        report["failure_locations"] = [{"file": Path(frame.filename).name, "line": frame.lineno, "function": frame.name}
            for frame in traceback.extract_tb(error.__traceback__)[-8:]]
    finally:
        if touched:
            try:
                h.command(["/bin/launchctl", "bootout", "system/" + h.LABEL], report=report, output=output, log="cleanup-bootout.log", check=False)
                absent = h.command(["/bin/launchctl", "print", "system/" + h.LABEL], report=report, output=output, log="cleanup-lookup.log", check=False)
                require(absent.returncode == 113)
                report["checks"]["created_job_stopped"] = True
            except Exception:
                report["cleanup_unverified"] = True
        if acceptance_passed(report):
            report["status"], report["failure_stage"] = "PASSED", None
        try:
            output.write("report.json", encoded(report) + b"\n")
            output.publish()
        finally:
            output.close()
    return 0 if report["status"] == "PASSED" else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", type=Path, required=True)
    parser.add_argument("--bundle", type=Path, required=True)
    parser.add_argument("--repair", type=Path, required=True)
    parser.add_argument("--scenario", choices=sorted(SCENARIOS), required=True)
    parser.add_argument("--cohort", type=int, choices=[87, 88, 90], default=87)
    args = parser.parse_args()
    try:
        return run(args)
    except Exception:
        print('{"schema":1,"status":"REFUSED","reason":"fresh_hosted_root_context_required"}')
        return 78


if __name__ == "__main__":
    raise SystemExit(main())
