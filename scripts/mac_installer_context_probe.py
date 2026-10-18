"""Disposable Mac CI: diagnose native verification in Apple's script sandbox.

Only tiny public synthetic files use the fresh fixed installation paths. This
never provisions a service/account, opens a vault or executes supplied Python.
"""
import argparse
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile

from account_access.package_manifest import APPLICATION_TARGET, CANONICAL_APP, OWNER_APP, SUPPORT, build

BASE = Path("/") / SUPPORT
APP = Path("/") / OWNER_APP
JOB = Path("/Library/LaunchDaemons/com.fainir.accountaccess.broker.plist")

POSTINSTALL = '''#!/bin/sh
set -eu
PATH=/usr/bin:/bin:/usr/sbin:/sbin
export PATH
[ "$(/usr/bin/id -u)" = 0 ] && [ "${3:-}" = / ] || exit 1
AC_PROBE_BASE="/Library/Application Support/Account Access"
AC_PROBE_SCRIPTS=$(CDPATH= cd "$(/usr/bin/dirname "$0")" && /bin/pwd -P)
AC_PROBE_STATUS=0
AC_PROBE_RESULT=$("$AC_PROBE_SCRIPTS/AccountAccess-installerverify") || AC_PROBE_STATUS=$?
(set -C; /usr/bin/printf '%s\\n' "$AC_PROBE_RESULT" > "$AC_PROBE_BASE/install-verification.json")
# CI-only metadata about public/synthetic objects; no file contents or accounts.
(
  AC_PROBE_CURRENT="$AC_PROBE_SCRIPTS"
  while :; do
    /usr/bin/stat -f '%u %g %Sp %N' "$AC_PROBE_CURRENT"
    /bin/ls -lde "$AC_PROBE_CURRENT"
    [ "$AC_PROBE_CURRENT" = / ] && break
    AC_PROBE_CURRENT=$(/usr/bin/dirname "$AC_PROBE_CURRENT")
  done
  /usr/bin/stat -f '%u %g %Sp %N' "$AC_PROBE_SCRIPTS/RecoveryManifest.json"
  /bin/ls -lARe "$AC_PROBE_BASE" "/Applications/Account Access.app"
) > "$AC_PROBE_BASE/native-context.txt"
exit "$AC_PROBE_STATUS"
'''

SOURCE_POSTINSTALL = '''#!/bin/sh
set -eu
PATH=/usr/bin:/bin:/usr/sbin:/sbin
export PATH
[ "$(/usr/bin/id -u)" = 0 ] && [ "${3:-}" = / ] || exit 1
AC_SOURCE_BASE="/Library/Application Support/Account Access"
AC_SOURCE_SCRIPTS=$(CDPATH= cd "$(/usr/bin/dirname "$0")" && /bin/pwd -P)
export ACCOUNT_ACCESS_UNRELATED_ENV=public-probe-sentinel
export PYTHONPATH=/unrelated-public-probe
exec 200< "$AC_SOURCE_SCRIPTS/RecoveryManifest.json"
AC_SOURCE_STATUS=0
AC_SOURCE_RESULT=$("$AC_SOURCE_SCRIPTS/AccountAccess-installerverify" --install) || AC_SOURCE_STATUS=$?
/bin/mkdir "$AC_SOURCE_BASE"
/usr/bin/printf '%s\\n' "$AC_SOURCE_RESULT" > "$AC_SOURCE_BASE/native-source-handoff.json"
/bin/ls -lARe "$AC_SOURCE_SCRIPTS/PublicImage" > "$AC_SOURCE_BASE/native-source-context.txt"
exit "$AC_SOURCE_STATUS"
'''


def source_handoff(source, scratch, root, helper, output):
    """Actual native SETEXEC and public-FD transfer; the interpreter is a fixture."""
    scripts = scratch / "source-scripts"
    scripts.mkdir()
    root.rename(scripts / "PublicImage")
    image = scripts / "PublicImage"
    interpreter = image / SUPPORT / "runtime/bin/python"
    interpreter.parent.mkdir(parents=True)
    subprocess.run(["xcrun", "swiftc", "-O", "-parse-as-library", "-warnings-as-errors",
                    "-framework", "Foundation", "-framework", "CryptoKit",
                    str(source / "macos/Tests/InstallerSourceHandoff.swift"), "-o", str(interpreter)],
                   check=True, capture_output=True, timeout=120)
    subprocess.run(["/usr/bin/codesign", "--force", "--options", "runtime", "--sign", "-", str(interpreter)],
                   check=True, capture_output=True, timeout=30)
    shutil.copy2(helper, scripts / helper.name)
    (scripts / "RecoveryManifest.json").write_bytes(build(image, "0.8.0", "arm64"))
    (scripts / "postinstall").write_text(SOURCE_POSTINSTALL)
    (scripts / "postinstall").chmod(0o755)
    package = scratch / "source-handoff.pkg"
    subprocess.run(["/usr/bin/pkgbuild", "--nopayload", "--scripts", str(scripts),
                    "--identifier", "com.fainir.accountaccess.qa.source-handoff", "--version", "0.8.0",
                    "--ownership", "recommended", "--install-location", "/", str(package)],
                   check=True, capture_output=True, timeout=120)
    try:
        result = subprocess.run(["/usr/bin/sudo", "-n", "/usr/sbin/installer", "-pkg", str(package), "-target", "/"],
                                capture_output=True, timeout=180)
        for filename in ["native-source-handoff.json", "native-source-context.txt"]:
            path = BASE / filename
            if path.is_file() and not path.is_symlink() and path.stat().st_size <= 65536:
                shutil.copyfile(path, output / filename)
        path = output / "native-source-handoff.json"
        value = json.loads(path.read_bytes()) if path.exists() else {"status": "MISSING"}
        return {"status": "PASSED" if result.returncode == 0 and value.get("status") == "PASSED" else "FAILED",
                "actual_installer_exit_code": result.returncode, "native_result": value,
                "actual_python_or_provisioning_executed": False, "target_image_materialized": False}
    finally:
        if not (BASE / "vault").exists() and not (BASE / "broker").exists() and not JOB.exists():
            if BASE.exists() and not BASE.is_symlink():
                subprocess.run(["/usr/bin/sudo", "-n", "/bin/rm", "-rf", "--", str(BASE)], check=True, timeout=30)
        assert not BASE.exists() and not APP.exists() and not APP.is_symlink()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if (sys.platform != "darwin" or os.getuid() == 0 or os.getuid() != os.geteuid()
            or os.environ.get("GITHUB_ACTIONS") != "true" or os.environ.get("RUNNER_OS") != "macOS"):
        parser.error("Requires an ordinary runner in a disposable Mac CI VM")
    if any(path.exists() or path.is_symlink() for path in [BASE, APP, JOB]):
        parser.error("Requires fresh fixed public namespaces")
    output = args.output.absolute()
    if output.exists() or output.is_symlink():
        parser.error("Requires a new evidence directory")
    output.mkdir(mode=0o700)
    source = Path(__file__).resolve().parents[1]
    parents = [Path("/Library"), Path("/Library/Application Support"), Path("/Applications")]
    parent_state = {str(path): (path.stat().st_uid, path.stat().st_gid, stat.S_IMODE(path.stat().st_mode)) for path in parents}
    with tempfile.TemporaryDirectory(prefix="account-access-installer-context-") as temporary:
        scratch = Path(temporary)
        root, scripts = scratch / "public-image", scratch / "scripts"
        (root / SUPPORT / "bin").mkdir(parents=True)
        (root / CANONICAL_APP / "Contents/MacOS").mkdir(parents=True)
        (root / OWNER_APP).parent.mkdir(parents=True)
        (root / OWNER_APP).symlink_to(APPLICATION_TARGET)
        scripts.mkdir()
        helper = scripts / "AccountAccess-installerverify"
        try:
            subprocess.run(["xcrun", "swiftc", "-O", "-parse-as-library", "-warnings-as-errors",
                            "-D", "ACCOUNT_ACCESS_INSTALL_VERIFIER_MAIN", "-framework", "Foundation", "-framework", "CryptoKit",
                            str(source / "macos/InstallerPayload.swift"), "-o", str(helper)],
                           check=True, capture_output=True, timeout=120)
        except subprocess.CalledProcessError as error:
            # The input is public repository source, never credential-bearing
            # owner state. Preserve bounded compiler diagnostics for CI review.
            diagnostics = (error.stdout + error.stderr)[:65536]
            (output / "compiler-diagnostics.txt").write_bytes(diagnostics)
            print(diagnostics[:16384].decode("utf-8", errors="replace"))
            raise
        subprocess.run(["/usr/bin/codesign", "--force", "--options", "runtime", "--sign", "-", str(helper)],
                       check=True, capture_output=True, timeout=30)
        shutil.copy2(helper, root / SUPPORT / "bin/AccountAccess-installerverify")
        (root / SUPPORT / "public-fixture.txt").write_text("Synthetic public installation input\n")
        (root / CANONICAL_APP / "Contents/MacOS/AccountAccess").write_text("Synthetic app fixture; never executed\n")
        for path in [root, *root.rglob("*")]:
            if not path.is_symlink():
                path.chmod(path.stat().st_mode & 0o777 & ~0o022)
        manifest = build(root, "0.8.0", "arm64")
        (scripts / "RecoveryManifest.json").write_bytes(manifest)
        (scripts / "postinstall").write_text(POSTINSTALL)
        (scripts / "postinstall").chmod(0o755)
        package = scratch / "context.pkg"
        subprocess.run(["/usr/bin/pkgbuild", "--root", str(root), "--scripts", str(scripts),
                        "--identifier", "com.fainir.accountaccess.qa.installer-context", "--version", "0.8.0",
                        "--ownership", "recommended", "--install-location", "/", str(package)],
                       check=True, capture_output=True, timeout=120)
        try:
            result = subprocess.run(["/usr/bin/sudo", "-n", "/usr/sbin/installer", "-pkg", str(package), "-target", "/"],
                                    capture_output=True, timeout=180)
            for filename in ["install-verification.json", "native-context.txt"]:
                path = BASE / filename
                if path.is_file() and not path.is_symlink() and path.stat().st_size <= 65536:
                    shutil.copyfile(path, output / filename)
            receipt_path = output / "install-verification.json"
            value = json.loads(receipt_path.read_bytes()) if receipt_path.exists() else {"status": "MISSING"}
            report = {"status": "PASSED" if value.get("status") == "VERIFIED" and result.returncode == 0 else "FAILED",
                      "environment": "disposable-ci-public-synthetic-image", "private_signins": 0,
                      "production_ready": False, "actual_installer_used": True, "installer_exit_code": result.returncode,
                      "native_result": value, "provisioning_or_account_setup_executed": False}
        finally:
            if not (BASE / "vault").exists() and not (BASE / "broker").exists() and not JOB.exists():
                if APP.exists() or APP.is_symlink():
                    if not APP.is_symlink() or os.readlink(APP) != APPLICATION_TARGET:
                        raise RuntimeError("installer_context_public_alias_changed")
                    subprocess.run(["/usr/bin/sudo", "-n", "/bin/rm", "--", str(APP)], check=True, timeout=30)
                if BASE.exists() and not BASE.is_symlink():
                    subprocess.run(["/usr/bin/sudo", "-n", "/bin/rm", "-rf", "--", str(BASE)], check=True, timeout=30)
        assert not BASE.exists() and not APP.exists() and not APP.is_symlink()
        if report["status"] == "PASSED":
            report["source_handoff"] = source_handoff(source, scratch, root, helper, output)
            if report["source_handoff"]["status"] != "PASSED":
                report["status"] = "FAILED"
        assert all(parent_state[str(path)] == (path.stat().st_uid, path.stat().st_gid, stat.S_IMODE(path.stat().st_mode)) for path in parents)
        report["temporary_public_image_removed"] = True
        report["shared_parent_permissions_preserved"] = True
        (output / "report.json").write_text(json.dumps(report, indent=2) + "\n")
        print(json.dumps(report))
        return 0 if report["status"] == "PASSED" else 1


if __name__ == "__main__":
    raise SystemExit(main())
