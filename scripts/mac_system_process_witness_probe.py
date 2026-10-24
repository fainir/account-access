"""Exercise the system-job witness on a fresh hosted Mac without installing the app."""
import argparse
import grp
import os
from pathlib import Path
import pwd
import runpy
import tempfile
import time
from types import SimpleNamespace


def main():
    root = Path(__file__).resolve().parents[1]
    c = runpy.run_path(str(root / "scripts/mac_broker_repair_installer_probe.py"))
    c["guard"]()  # Refuse owner/root shells before any system lookup or write.
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--observer", type=Path, required=True)
    args = parser.parse_args()
    require = c["require"]
    require(not os.path.lexists("/Library/Application Support/Account Access"))
    for lookup, key in [(pwd.getpwnam, "_accountaccess"), (pwd.getpwuid, 450),
                        (grp.getgrnam, "_accountaccess"), (grp.getgrgid, 450)]:
        try:
            lookup(key)
        except KeyError:
            continue
        require(False)
    h = runpy.run_path(str(root / "scripts/mac_component_update_installer_probe.py"))
    f = runpy.run_path(str(root / "scripts/mac_full_image_installer_probe.py"))
    helper = SimpleNamespace(**h)
    f["verify_owned_stage"].__globals__["h"] = helper
    c.update(h=helper, f=SimpleNamespace(**f))
    fixture = runpy.run_path(str(root / "scripts/mac_runtime_quiescence_fixture.py"))
    run_id = os.environ["GITHUB_RUN_ID"] + "94"
    output = h["RootOutput"](h["report_path"](run_id), run_id)
    report = {"schema": 1, "status": "FAILED", "logs": {}, "stage": "create_fixture_user",
              "owner_machine": False, "account_records_read": False, "production_ready": False}
    witness, scratch = None, None
    def command(arguments, log, timeout=120, check=True):
        return h["command"](arguments, report=report, output=output, log=log, timeout=timeout, check=check)
    try:
        fields = [("Groups", "PrimaryGroupID", "450"), ("Groups", "Password", "*"),
                  ("Users", "UniqueID", "450"), ("Users", "PrimaryGroupID", "450"),
                  ("Users", "NFSHomeDirectory", "/var/empty"), ("Users", "UserShell", "/usr/bin/false"),
                  ("Users", "IsHidden", "1")]
        for index, (kind, field, value) in enumerate(fields):
            command(["/usr/bin/dscl", ".", "-create", "/" + kind + "/_accountaccess", field, value], f"create-identity-{index}.log")
        require(pwd.getpwnam("_accountaccess").pw_uid == 450 and grp.getgrnam("_accountaccess").gr_gid == 450)
        scratch = tempfile.TemporaryDirectory(prefix="account-access-full-image-acceptance-", dir="/private/tmp")
        witness = fixture["Witness"](SimpleNamespace(**c), Path(scratch.name), command, 450)
        report["stage"] = "start_witness"
        witness.start()
        report["stage"] = "remove_user_domain"
        for attempt in range(81):
            removed = command(["/bin/launchctl", "bootout", "user/450"], f"domain-remove-{attempt}.log", check=False)
            if removed.returncode == 0:
                break
            require(removed.returncode == 124 and removed.stderr == b"Boot-out failed: 124: Domain is tearing down\n")
            time.sleep(0.25)
        require(removed.returncode == 0)
        report["stage"] = "attest_surviving_witness"
        env = ["/usr/bin/env", "GITHUB_ACTIONS=true", "RUNNER_ENVIRONMENT=github-hosted", "GITHUB_REPOSITORY=fainir/account-access"]
        for attempt in range(40):
            observed = command([*env, str(args.observer), "--witness450"], f"dedicated-observer-{attempt}.log", check=False)
            if observed.returncode == 0:
                break
            time.sleep(0.25)
        require(observed.returncode == 0)
        value = f["decode"](observed.stdout)
        require(value["status"] == "PASSED" and value["checks"] == {"dedicated_uid_live_apple_process": True})
        witness.verify("survived-domain-removal")
        report["stage"] = "remove_witness"
        witness.close()
        witness = None
        report.update(status="PASSED", stage="complete", production_observer_accepted_surviving_system_job=True)
    finally:
        if witness is not None:
            witness.close()
        if scratch is not None:
            scratch.cleanup()
        output.write("report.json", c["encoded"](report))
        output.publish()
        output.close()


if __name__ == "__main__":
    main()
