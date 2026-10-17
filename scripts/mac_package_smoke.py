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
import plistlib
import pwd
import re
import stat
import subprocess
import sys
import zipfile

from account_access.worker_bootstrap import root_managed_path


BASE = Path("/Library/Application Support/Account Access")
APP = Path("/Applications/Account Access.app")
JOB = Path("/Library/LaunchDaemons/com.fainir.accountaccess.broker.plist")

PREPARED_PROBE = """import sys
def checkpoint(name):
    sys.stderr.write('PREPARED_STAGE:' + name + '\\n'); sys.stderr.flush()
checkpoint('imports')
import ctypes, ssl, sqlite3
from cffi import FFI
from cryptography.hazmat.primitives import hashes
from greenlet import greenlet
from pydantic import create_model
import pyotp
ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
with sqlite3.connect(':memory:') as connection:
    assert connection.execute('select 41 + 1').fetchone() == (42,)
ffi = FFI()
checkpoint('cffi_callback')
callback = ffi.callback('int(int)', lambda value: value + 1)
assert callback(41) == 42
checkpoint('ctypes_callback')
callback2 = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.c_int)(lambda value: value + 1)
assert callback2(41) == 42
checkpoint('crypto')
value = hashes.Hash(hashes.SHA256()); value.update(b'fixture')
assert len(value.finalize()) == 32
checkpoint('greenlet')
assert greenlet(lambda: 'fixture').switch() == 'fixture'
checkpoint('pydantic')
assert create_model('Fixture', value=(int, ...))(value='42').value == 42
checkpoint('totp')
assert len(pyotp.TOTP('JBSWY3DPEHPK3PXP').at(0)) == 6
print('PREPARED_NATIVE_OK')
"""


def sha256(path):
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def prepared_checks(base, app, metadata):
    """Verify public installed code; no credential or account store is read."""
    receipt = metadata.get("runtime_preparation")
    if (
        type(receipt) is not dict
        or type(receipt.get("schema")) is not int
        or receipt["schema"] != 1
        or receipt.get("transform") != "account-access-native-signing-and-wheel-record-v1"
        or receipt.get("development") is not True
        or receipt.get("publisher_team") != "fixture"
        or receipt.get("notarization_verified") is not False
        or receipt.get("installed_runtime_verified") is not False
    ):
        raise ValueError("prepared_fixture_receipt_required")
    installed = json.loads((base / "runtime-preparation.json").read_bytes())
    assert installed == receipt
    checks = {"prepared_receipt_matches_installed_package_metadata": True}
    requirements = (base / "package-requirements.txt").read_bytes()
    parts = requirements.rsplit(b"\naccount-access==", 1)
    assert (
        len(parts) == 2
        and hashlib.sha256(parts[0]).hexdigest() == receipt["prepared_requirements_sha256"]
    )
    checks["derived_requirements_match_preparation_receipt"] = True
    project = receipt["project_wheel"]
    assert type(project) is dict and type(project.get("filename")) is str
    assert Path(project["filename"]).name == project["filename"] and project["filename"].endswith(
        ".whl"
    )
    pin = plistlib.loads((app / "Contents/Info.plist").read_bytes())["AccountAccessWheelSHA256"]
    assert pin == project["sha256"] == sha256(base / "wheels" / project["filename"])
    with zipfile.ZipFile(base / "wheels" / project["filename"]) as archive:
        original = archive.read("account_access/runtime-requirements.txt")
    assert hashlib.sha256(original).hexdigest() == receipt["original_requirements_sha256"]
    checks["app_pinned_project_and_original_source_lock_preserved"] = True

    def destination(value):
        assert type(value) is str and "\\" not in value and "\0" not in value
        components = value.split("/")
        assert components and all(part not in {"", ".", ".."} for part in components)
        if components[0] == "wheels":
            assert len(components) >= 3 and components[1].endswith(".whl")
            target = base / "runtime/lib/python3.12/site-packages" / "/".join(components[2:])
        else:
            assert components[0] in {"python", "browsers"}
            target = base / value
        assert target.resolve(strict=True).is_relative_to(base.resolve(strict=True))
        return target

    rows = receipt["native_files"]
    assert type(receipt["native_files_signed"]) is int and receipt["native_files_signed"] > 0
    assert type(rows) is list and len(rows) == receipt["native_files_signed"]
    targets = set()
    for row in rows:
        assert type(row) is dict and set(row) == {
            "path",
            "kind",
            "original_sha256",
            "prepared_sha256",
        }
        assert type(row["kind"]) is int and row["kind"] in {2, 6, 8}
        assert all(
            type(row[key]) is str and re.fullmatch(r"[a-f0-9]{64}", row[key])
            for key in ["original_sha256", "prepared_sha256"]
        )
        target = destination(row["path"])
        assert target not in targets and target.is_file()
        targets.add(target)
        assert sha256(target) == row["prepared_sha256"]
        root_managed_path(target)
        assert target.stat().st_mode & 0o6000 == 0
        subprocess.run(
            [
                "/usr/bin/codesign",
                "--verify",
                "--strict",
                "--all-architectures",
                '-R=!(entitlement["com.apple.security.get-task-allow"] exists)',
                str(target),
            ],
            check=True,
            capture_output=True,
            timeout=20,
        )
        info = subprocess.run(
            ["/usr/bin/codesign", "-d", "--verbose=4", str(target)],
            check=True,
            capture_output=True,
            timeout=20,
        )
        metadata_text = info.stdout + info.stderr
        assert len(metadata_text) <= 65536
        assert re.findall(rb"^TeamIdentifier=(.+)$", metadata_text, re.MULTILINE) == [b"not set"]
        if row["kind"] == 2:
            flags = re.findall(rb"\bflags=0x([0-9a-fA-F]+)", metadata_text)
            assert len(flags) == 1 and int(flags[0], 16) & 0x10000
    checks["prepared_native_bytes_preserved_at_final_install_paths"] = True
    checks["prepared_code_is_root_controlled_without_privileged_modes"] = True
    bundles = receipt["bundles"]
    assert type(bundles) is list and type(receipt["bundle_seals_signed"]) is int
    assert len(bundles) == len(set(bundles)) == receipt["bundle_seals_signed"]
    for value in bundles:
        assert value.startswith(("python/", "browsers/"))
        target = destination(value)
        root_managed_path(target)
        subprocess.run(
            [
                "/usr/bin/codesign",
                "--verify",
                "--deep",
                "--strict",
                "--all-architectures",
                str(target),
            ],
            check=True,
            capture_output=True,
            timeout=30,
        )
    checks["prepared_signatures_and_bundle_seals_valid_after_install"] = True
    return checks


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("package", type=Path)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--prepared-runtime", action="store_true")
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
    if args.prepared_runtime and type(metadata.get("runtime_preparation")) is not dict:
        parser.error("Requires a package with explicit runtime preparation")
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
        if args.prepared_runtime:
            checks.update(prepared_checks(BASE, APP, metadata))
            native = subprocess.run(
                [str(python), "-I", "-B", "-c", PREPARED_PROBE], capture_output=True, timeout=30
            )
            checks["prepared_native_callbacks_crypto_and_validation_work"] = (
                native.returncode == 0 and native.stdout.strip() == b"PREPARED_NATIVE_OK"
            )
            if not checks["prepared_native_callbacks_crypto_and_validation_work"]:
                checkpoints = re.findall(
                    rb"^PREPARED_STAGE:([a-z_]+)$", native.stderr, re.MULTILINE
                )
                print(
                    json.dumps(
                        {
                            "stage": "prepared_native_probe",
                            "exit_code": native.returncode,
                            "last_checkpoint": checkpoints[-1].decode() if checkpoints else None,
                        }
                    ),
                    file=sys.stderr,
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
        if not checks or not all(value is True for value in checks.values()):
            raise RuntimeError(
                "package_fixture_checks_failed:"
                + ",".join(sorted(key for key, value in checks.items() if value is not True))
            )
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
                "prepared_runtime_executed": args.prepared_runtime,
                "fixture_library_validation_exception": args.prepared_runtime,
                "checks": checks,
            },
            indent=2,
        )
        + "\n"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
