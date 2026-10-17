"""Disposable CI only: install a development package, verify fail-closed behavior.

This does not validate a publisher-signed/notarized package or positive owner
setup. It installs no credentials and never runs against the operator's Mac.
"""

import argparse
import grp
import hashlib
import json
import os
from pathlib import Path
import pwd
import stat
import subprocess
import sys


BASE = Path("/Library/Application Support/Account Access")
APP = Path("/Applications/Account Access.app")
JOB = Path("/Library/LaunchDaemons/com.fainir.accountaccess.broker.plist")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("package", type=Path)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    if (
        sys.platform != "darwin"
        or os.getuid() == 0
        or os.environ.get("GITHUB_ACTIONS") != "true"
        or os.environ.get("RUNNER_OS") != "macOS"
    ):
        parser.error("Requires an ordinary runner in a disposable GitHub Mac VM")
    if any(path.exists() or path.is_symlink() for path in [BASE, APP, JOB]):
        parser.error("Requires a fresh system namespace")
    for lookup in [pwd.getpwnam, grp.getgrnam]:
        try:
            lookup("_accountaccess")
        except KeyError:
            pass
        else:
            parser.error("Service identity already exists")
    package = args.package.resolve(strict=True)
    metadata = json.loads((package.parent / "package.json").read_bytes())
    if (
        metadata.get("development") is not True
        or metadata.get("installed") is not False
        or hashlib.sha256(package.read_bytes()).hexdigest() != metadata.get("sha256")
    ):
        parser.error("Requires the exact development package from this build")
    checks = {}
    parents = [Path("/Library"), Path("/Library/Application Support"), Path("/Applications")]

    def ownership(path):
        info = path.stat()
        return info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)

    parent_state = {path: ownership(path) for path in parents}
    try:
        result = subprocess.run(
            ["/usr/bin/sudo", "-n", "/usr/sbin/installer", "-pkg", str(package), "-target", "/"],
            capture_output=True,
            timeout=360,
        )
        checks["actual_development_package_refused_before_owner_setup"] = result.returncode != 0
        python = BASE / "runtime/bin/python"
        checks["offline_runtime_installed_at_final_path"] = python.is_file()
        probe = subprocess.run(
            [
                str(python),
                "-I",
                "-B",
                "-c",
                "import ssl,sqlite3,cryptography,playwright,account_access.system_provision;"
                "from account_access.worker_bootstrap import root_managed_path;"
                'import sys;root_managed_path(sys.prefix);print("OFFLINE_RUNTIME_OK")',
            ],
            capture_output=True,
            timeout=30,
        )
        checks["installed_runtime_loads_dependencies_with_protected_paths"] = (
            probe.returncode == 0 and probe.stdout.strip() == b"OFFLINE_RUNTIME_OK"
        )
        browser = subprocess.run(
            [
                str(python),
                "-I",
                "-B",
                "-c",
                "from playwright.sync_api import sync_playwright;"
                "p=sync_playwright().start();b=p.chromium.launch(chromium_sandbox=True);"
                "page=b.new_page();page.set_content('<h1>Package fixture</h1>');"
                "assert page.locator('h1').inner_text()=='Package fixture';"
                "b.close();p.stop();print('PACKAGE_BROWSER_OK')",
            ],
            capture_output=True,
            timeout=45,
            env={
                "PATH": "/usr/bin:/bin",
                "HOME": str(Path.home()),
                "PLAYWRIGHT_BROWSERS_PATH": str(BASE / "browsers"),
            },
        )
        checks["relocated_package_browser_runs_sandboxed_without_credentials"] = (
            browser.returncode == 0 and browser.stdout.strip() == b"PACKAGE_BROWSER_OK"
        )
        # The ad-hoc application cannot authorize a production service. Neither
        # payload installation nor dependency installation may create a store.
        checks["development_package_creates_no_vault_or_registration"] = (
            not (BASE / "vault").exists() and not (BASE / "broker").exists() and not JOB.exists()
        )
        for lookup, name in [(pwd.getpwnam, "user"), (grp.getgrnam, "group")]:
            try:
                lookup("_accountaccess")
            except KeyError:
                checks["development_package_creates_no_service_" + name] = True
            else:
                checks["development_package_creates_no_service_" + name] = False
        checks["protected_app_payload_present"] = APP.is_dir()
        checks["shared_system_parent_ownership_and_modes_preserved"] = all(
            ownership(path) == before for path, before in parent_state.items()
        )
        assert checks and all(value is True for value in checks.values())
    finally:
        # Never turn this into a general uninstall path. Only fresh CI payloads,
        # with no credential store, can be removed by this negative journey.
        if not (BASE / "vault").exists() and not (BASE / "broker").exists() and not JOB.exists():
            for path in [BASE, APP]:
                if path.exists():
                    subprocess.run(
                        ["/usr/bin/sudo", "-n", "/bin/rm", "-rf", "--", str(path)], check=True
                    )
    checks["temporary_package_payload_removed"] = not BASE.exists() and not APP.exists()
    assert all(value is True for value in checks.values())
    args.report.write_text(
        json.dumps(
            {
                "status": "PASSED",
                "environment": "controlled-demo",
                "production_ready": False,
                "private_signins": 0,
                "actual_installer_used": True,
                "positive_consumer_install_verified": False,
                "publisher_signed_package": False,
                "genuine_owner_approval_verified": False,
                "checks": checks,
            },
            indent=2,
        )
        + "\n"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
