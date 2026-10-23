"""Qualify Installer script deadlines in a disposable GitHub-hosted Mac only.

Two no-payload packages run fixed sleeps. The short deadline must terminate its
script, then the long deadline must permit completion beyond the default ten
minutes. No Account Access helper is executed and no owner account is enrolled.
This experiment does not qualify a changed application installer.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import runpy
import sys
import tempfile
import time
from types import SimpleNamespace
import xml.etree.ElementTree as ET

HARNESS_SHA = "a4507756990cf6ff96e666653dab7aa7d636f1c37a01027dce9fae0e465311da"
CASES = {"short": (15, 25), "long": (900, 610)}
PREFIX = "com.fainir.accountaccess.installer-timeout-qa."


def require(condition):
    if not condition:
        raise ValueError("installer_timeout_acceptance_failed")


def guard():
    # Keep this ahead of path reads, output creation and subprocess invocation.
    require(sys.platform == "darwin" and platform.machine() == "arm64"
        and os.getuid() == os.geteuid() == 0
        and os.environ.get("GITHUB_ACTIONS") == "true" and os.environ.get("CI") == "true"
        and os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted"
        and os.environ.get("RUNNER_OS") == "macOS" and os.environ.get("RUNNER_ARCH") == "ARM64"
        and os.environ.get("GITHUB_REPOSITORY") == "fainir/account-access"
        and re.fullmatch(r"[1-9][0-9]{0,19}", os.environ.get("GITHUB_RUN_ID", "")) is not None
        and re.fullmatch(r"[1-9][0-9]{0,9}", os.environ.get("GITHUB_RUN_ATTEMPT", "")) is not None
        and re.fullmatch(r"[a-f0-9]{40}", os.environ.get("GITHUB_SHA", "")) is not None)


def script(case):
    require(case in CASES)
    return ("#!/bin/sh\nset -eu\n/bin/sleep " + str(CASES[case][1]) + "\nexit 0\n").encode()


def with_deadline(raw, case):
    """Change exactly the generated postinstall timeout in a no-payload fixture."""
    require(case in CASES and isinstance(raw, bytes) and len(raw) <= 65536
            and b"<!" not in raw)
    tree = ET.fromstring(raw)
    empty_tags = {"bundle-version", "upgrade-bundle", "update-bundle", "atomic-update-bundle",
                  "strict-identifier", "relocate"}
    require(tree.tag == "pkg-info" and tree.get("identifier") == PREFIX + case
            and tree.get("auth") == "root" and tree.get("version") == "1"
            and {child.tag for child in tree} <= {"payload", "scripts"} | empty_tags)
    for tag in empty_tags:
        entries = tree.findall(tag)
        require(len(entries) <= 1 and all(not len(item) and not item.attrib for item in entries))
    require(len(tree.findall("payload")) <= 1 and len(tree.findall("scripts")) == 1)
    payload = tree.find("payload")
    require(payload is None or (not len(payload) and set(payload.attrib) == {"numberOfFiles", "installKBytes"}
            and all(payload.get(key) == "0" for key in payload.attrib)))
    phases = tree.find("scripts")
    require(not phases.attrib and len(phases) == 1 and phases[0].tag == "postinstall"
            and not len(phases[0]) and phases[0].attrib in (
                {"file": "./postinstall"}, {"file": "./postinstall", "timeout": "600"}))
    phases[0].set("timeout", str(CASES[case][0]))
    return ET.tostring(tree, encoding="utf-8", xml_declaration=True)


def accepted(case, returncode, elapsed):
    require(case in CASES)
    if case == "short":
        return returncode != 0 and 14 <= elapsed < 75
    return returncode == 0 and 610 <= elapsed < 960


def verify_scripts(h, directory, case):
    # pkgutil --expand expands Scripts into a directory even without --expand-full.
    h.protected_metadata(directory.lstat(), mode=0o755)
    names = {path.name for path in directory.iterdir()}
    require(names in ({"postinstall"}, {"postinstall", "._postinstall"}))
    leaf = directory / "postinstall"
    h.protected_metadata(leaf.lstat(), mode=0o755, directory=False)
    require(h.read_file(leaf, maximum=4096) == script(case))
    result = {"postinstall": hashlib.sha256(script(case)).hexdigest()}
    if "._postinstall" in names:
        # macOS may preserve its provenance attribute in an AppleDouble sidecar.
        # It is never referenced as a script; preserve its exact bytes across flatten.
        sidecar = directory / "._postinstall"
        h.protected_metadata(sidecar.lstat(), mode=0o644, directory=False)
        raw = h.read_file(sidecar, maximum=65536)
        require(raw.startswith(bytes.fromhex("0005160700020000")))
        result["._postinstall"] = hashlib.sha256(raw).hexdigest()
    return result


def run(repository):
    guard()
    require(repository.is_absolute())
    harness = repository / "scripts/mac_component_update_installer_probe.py"
    require(hashlib.sha256(harness.read_bytes()).hexdigest() == HARNESS_SHA)
    h = SimpleNamespace(**runpy.run_path(str(harness)))
    h.guard()
    revision = os.environ["GITHUB_SHA"]
    for name in ("scripts/mac_installer_timeout_probe.py", "scripts/mac_component_update_installer_probe.py"):
        require(h.git_bytes(repository, ["show", revision + ":" + name], maximum=2 * 1024**2)
                == (repository / name).read_bytes())
    report = {"schema": 1, "status": "FAILED", "controller_revision": revision,
        "macos_version": platform.mac_ver()[0], "checks": {}, "cases": {}, "logs": {},
        "owner_data_accessed": False, "application_installer_qualified": False,
        "production_ready": False, "failure_stage": "fresh_host_preflight"}
    output = h.RootOutput(h.report_path(os.environ["GITHUB_RUN_ID"]), os.environ["GITHUB_RUN_ID"])
    try:
        for path in (h.BASE, h.APP, h.JOB, h.JOURNAL, h.COMPONENTS, h.REVALIDATION_NAMESPACE,
                     Path("/Library/Application Support/Account Access Full Images")):
            require(not os.path.lexists(path))
        import pwd
        console = os.stat("/dev/console").st_uid
        person = pwd.getpwuid(console)
        require(console > 0 and person.pw_name == "runner" and person.pw_dir == "/Users/runner")
        report["checks"]["fresh_hosted_vm"] = True
        with tempfile.TemporaryDirectory(prefix="account-access-timeout-qa-", dir="/private/tmp") as temporary:
            stage = Path(temporary)
            h.protected_metadata(stage.lstat(), mode=0o700)

            def command(arguments, log, timeout=60, check=True):
                return h.command(arguments, report=report, output=output, log=log,
                                 timeout=timeout, check=check)

            for case in CASES:
                report["failure_stage"] = case + "_package"
                folder = stage / case
                folder.mkdir(mode=0o700)
                scripts = folder / "scripts"
                scripts.mkdir(mode=0o700)
                (scripts / "postinstall").write_bytes(script(case))
                (scripts / "postinstall").chmod(0o755)
                package, expanded = folder / "original.pkg", folder / "expanded"
                command(["/usr/bin/pkgbuild", "--nopayload", "--identifier", PREFIX + case,
                         "--version", "1", "--scripts", str(scripts), str(package)], case + "-build.log")
                command(["/usr/sbin/pkgutil", "--expand", str(package), str(expanded)], case + "-expand.log")
                require({path.name for path in expanded.iterdir()} == {"PackageInfo", "Scripts"})
                script_inventory = verify_scripts(h, expanded / "Scripts", case)
                info = expanded / "PackageInfo"
                altered = with_deadline(h.read_file(info, maximum=65536), case)
                info.write_bytes(altered)
                package = folder / "deadline.pkg"
                command(["/usr/sbin/pkgutil", "--flatten", str(expanded), str(package)], case + "-flatten.log")
                check = folder / "reexpanded"
                command(["/usr/sbin/pkgutil", "--expand", str(package), str(check)], case + "-reexpand.log")
                require({path.name for path in check.iterdir()} == {"PackageInfo", "Scripts"}
                        and h.read_file(check / "PackageInfo", maximum=65536) == altered)
                require(verify_scripts(h, check / "Scripts", case) == script_inventory)
                report["checks"][case + "_exact_package"] = True
                report["failure_stage"] = case + "_actual_installer"
                start = time.monotonic()
                result = command(["/usr/sbin/installer", "-dumplog", "-verboseR", "-pkg", str(package),
                                  "-target", "/"], case + "-installer.log",
                                 timeout=75 if case == "short" else 960, check=False)
                elapsed = time.monotonic() - start
                report["cases"][case] = {"script_timeout_seconds": CASES[case][0],
                    "script_sleep_seconds": CASES[case][1], "installer_exit_code": result.returncode,
                    "elapsed_seconds": round(elapsed, 3),
                    "package_sha256": hashlib.sha256(h.read_file(package, maximum=1024**2)).hexdigest()}
                require(accepted(case, result.returncode, elapsed))
                if case == "short":
                    # A generic early package failure cannot qualify enforcement.
                    require(b"PKInstallErrorDomain Code=112" in result.stdout + result.stderr)
                report["checks"][case + "_actual_deadline"] = True
        report["status"], report["failure_stage"] = "PASSED", None
    except Exception:
        pass  # Fixed stage and bounded command evidence retain the failure.
    finally:
        try:
            output.write("report.json", json.dumps(report, indent=2, sort_keys=True).encode() + b"\n")
            output.publish()
        finally:
            output.close()
    return 0 if report["status"] == "PASSED" else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", type=Path, required=True)
    return run(parser.parse_args().repository)


if __name__ == "__main__":
    raise SystemExit(main())
