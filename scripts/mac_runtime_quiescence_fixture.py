"""Hosted-only reproduction of a refused updater with its service disabled.

The fixture owns a distinct launchd job for Apple's distnoted and a direct sleep
child. Only the fresh disposable VM is changed; no PID discovered by inspection
is signalled. The production update remains responsible for all image changes.
"""
import os
import plistlib
import pwd
import re
import runpy
import subprocess
import time

LABEL = "com.fainir.accountaccess.qa-distnoted-witness"
PROGRAM = "/usr/sbin/distnoted"
RECOVERY_CHECKS = {"old_package_refused", "new_package_unknown_process_refused", "previous_image_unchanged",
                   "owned_disabled_intent_retained", "apple_witness_survived", "witness_removed"}


class Witness:
    def __init__(self, controller, stage, command, broker_uid):
        controller.guard()
        self.c, self.command = controller, command
        self.path = stage / "system-process-witness.plist"
        self.created, self.bootstrapped = False, False
        controller.f.verify_owned_stage(stage)
        account = pwd.getpwuid(broker_uid)
        controller.require(450 <= broker_uid < 500 and account.pw_name == "_accountaccess")
        absent = command(["/bin/launchctl", "print", "system/" + LABEL], "witness-absent.log", check=False)
        controller.require(absent.returncode == 113)
        self.raw = plistlib.dumps({"Label": LABEL, "ProgramArguments": [PROGRAM, "agent"],
            "UserName": "_accountaccess", "GroupName": "_accountaccess", "RunAtLoad": True, "KeepAlive": True,
            "MachServices": {"com.apple.distributed_notifications@Uv3": True},
            "ProcessType": "Background"})
        controller.create_file(self.path, self.raw, mode=0o644)
        self.created = True

    def start(self):
        self.c.guard()
        self.command(["/bin/launchctl", "bootstrap", "system", str(self.path)], "witness-bootstrap.log")
        self.bootstrapped = True
        self.pid = None
        for attempt in range(20):
            value = self.command(["/bin/launchctl", "print", "system/" + LABEL], f"witness-start-{attempt}.log")
            matches = re.findall(rb"(?m)^\tpid = ([1-9][0-9]*)$", value.stdout)
            if matches:
                self.c.require(len(matches) == 1)
                self.pid = int(matches[0])
                break
            time.sleep(0.25)
        self.c.require(self.pid is not None)
        self.verify("started")

    def verify(self, suffix):
        self.c.guard()
        value = self.command(["/bin/launchctl", "print", "system/" + LABEL], "witness-" + suffix + ".log")
        self.c.require(value.stdout.startswith(("system/" + LABEL + " = {\n").encode())
                       and b"\tprogram = /usr/sbin/distnoted\n" in value.stdout
                       and re.findall(rb"(?m)^\tpid = ([1-9][0-9]*)$", value.stdout) == [str(self.pid).encode()])

    def close(self):
        self.c.guard()
        if self.created:
            self.c.require(self.c.h.read_file(self.path) == self.raw)
            if self.bootstrapped:
                self.command(["/bin/launchctl", "bootout", "system", str(self.path)], "witness-bootout.log")
                result = self.command(["/bin/launchctl", "print", "system/" + LABEL], "witness-removed.log", check=False)
                self.c.require(result.returncode == 113)
            self.path.unlink()
            self.created = False


def prepare(*, controller, args, stage, source, install, result, unchanged):
    controller.guard()
    c, h, f = controller, controller.h, controller.f
    old = runpy.run_path(str(source("scripts/download_runtime_upgrade93_inputs.py")))
    raw = (args.previous_runtime_upgrade / "asset-contract.json").read_bytes()
    c.require(raw == h.git_bytes(args.repository, ["show", os.environ["GITHUB_SHA"] + ":" + old["CONTRACT"]], maximum=65536))
    contract = old["validate"](f.decode(raw))
    c.verify_assets(args.previous_runtime_upgrade, contract, old["FILES"], f.hash_file)
    h.stage_file(args.previous_runtime_upgrade / "runtime-upgrade.pkg", stage / "previous-runtime-upgrade.pkg",
                 contract["assets"]["runtime-upgrade.pkg"]["sha256"], 1024**3)
    result["quiescence_recovery"] = dict.fromkeys(RECOVERY_CHECKS, False)
    checks = result["quiescence_recovery"]
    uid = h.policies()["install"]["broker_uid"]
    # The direct child remains owned until wait() reaps it. It is deliberately
    # unknown to the production process classifier, even with a legitimate UID.
    blocker = subprocess.Popen(["/bin/sleep", "3000"], user=uid, group=uid, extra_groups=[],
        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True, env=c.ENV)
    try:
        for package, label, key in [("previous-runtime-upgrade.pkg", "runtime-old-quiescence", "old_package_refused"),
                                    ("runtime-upgrade.pkg", "runtime-new-unknown", "new_package_unknown_process_refused")]:
            c.require(blocker.poll() is None)
            install(label, expected=1, package=package)
            unchanged()
            checks[key] = True
        checks["previous_image_unchanged"] = True
    finally:
        if blocker.poll() is None:
            blocker.kill()
        blocker.wait(timeout=10)
    # The checks above require the matching durable disabled intent and absence
    # of all image mutations. The ordinary successor path must recover it.
    checks["owned_disabled_intent_retained"] = True
