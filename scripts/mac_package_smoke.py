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
import signal
import stat
import subprocess
import sys
import tempfile
import time
import zipfile

from account_access.package_manifest import MAX_MANIFEST_BYTES, build as build_manifest, inventory_digest
from account_access.worker_bootstrap import root_managed_path


BASE = Path("/Library/Application Support/Account Access")
APP = BASE / "owner.app"
PUBLIC_APP = Path("/Applications/Account Access.app")
PUBLIC_TARGET = "../Library/Application Support/Account Access/owner.app"
JOB = Path("/Library/LaunchDaemons/com.fainir.accountaccess.broker.plist")
JOURNAL = Path("/Library/Application Support/Account Access Installer")

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
checkpoint('onepassword_native_child')
from onepassword.core import UniffiCore
UniffiCore()
from account_access.onepassword_source import fetch
from account_access.errors import AccessError
try:
    fetch({'token': 'synthetic-invalid-token', 'vault': 'a' * 26, 'item': 'b' * 26},
          'https://example.test')
except AccessError as error:
    assert error.status == 'DENIED' and error.reason == 'password_source_access_removed'
else:
    raise AssertionError('synthetic_service_token_accepted')
print('PREPARED_NATIVE_OK')
"""


def sha256(path):
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def verify_package_manifest(package, metadata):
    """Bind the recovery inventory to all actual public bytes in this package."""
    expected = metadata.get("payload_manifest_sha256")
    if type(expected) is not str or re.fullmatch(r"[a-f0-9]{64}", expected) is None:
        raise ValueError("package_recovery_manifest_pin_required")
    if metadata.get("installation_strategy") != "verified-script-image-v1":
        raise ValueError("verified_script_image_package_required")
    with tempfile.TemporaryDirectory(prefix="account-access-package-manifest-") as temporary:
        expanded = Path(temporary) / "expanded"
        subprocess.run(
            ["/usr/sbin/pkgutil", "--expand-full", str(package), str(expanded)],
            check=True, capture_output=True, timeout=120,
        )
        component = expanded / "payload.pkg"
        payload = component / "Payload"
        if payload.is_symlink() or payload.exists() and (not payload.is_dir() or any(payload.iterdir())):
            raise ValueError("unexpected_automatic_package_payload")
        source = component / "Scripts/PublicImage"
        path = component / "Scripts/RecoveryManifest.json"
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or not 0 < info.st_size <= MAX_MANIFEST_BYTES:
            raise ValueError("unsafe_package_recovery_manifest")
        encoded = path.read_bytes()
        if hashlib.sha256(encoded).hexdigest() != expected:
            raise ValueError("package_recovery_manifest_changed")
        actual = build_manifest(source, metadata["version"], metadata["architecture"])
        if actual != encoded:
            raise ValueError("package_recovery_payload_changed")
        verifier = component / "Scripts/AccountAccess-installerverify"
        info = verifier.lstat()
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                or info.st_mode & 0o6022 or not info.st_mode & 0o111
                or not 0 < info.st_size <= 64 * 1024 * 1024):
            raise ValueError("unsafe_package_native_verifier")
        checksum = sha256(verifier)
        if (checksum != metadata.get("installer_verifier_sha256")
                or checksum != sha256(source / "Library/Application Support/Account Access/bin/AccountAccess-installerverify")):
            raise ValueError("package_native_verifier_changed")
    return True


def interrupt_installer(package, metadata):
    """Kill only this fresh disposable package's coordinator after its intent.

    No production fault switch, path override or owner data is involved. The
    exact public manifest binds process selection, then SIGKILL exercises the
    same journal and lease that a terminated installation leaves behind.
    """
    expected = metadata["payload_manifest_sha256"]
    if re.fullmatch(r"[a-f0-9]{64}", expected) is None:
        raise ValueError("invalid_package_manifest")
    child = subprocess.Popen(["/usr/bin/sudo", "-n", "/usr/sbin/installer", "-pkg", str(package), "-target", "/"],
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    killed = False
    try:
        deadline = time.monotonic() + 180
        while child.poll() is None and time.monotonic() < deadline:
            observed = subprocess.run(["/bin/ps", "-ww", "-axo", "pid=,uid=,args="], capture_output=True, text=True,
                                      check=True, timeout=10).stdout
            matches = []
            for line in observed.splitlines():
                fields = line.strip().split(None, 2)
                if len(fields) != 3 or not fields[0].isdigit() or fields[1] != "0":
                    continue
                command = fields[2]
                if (command.startswith("/private/tmp/PKInstallSandbox.")
                        and "/Scripts/com.fainir.accountaccess.system." in command
                        and "/PublicImage/Library/Application Support/Account Access/runtime/bin/python -I -B -m account_access.install_transaction --source-fd " in command
                        and command.endswith(" --manifest-sha256 " + expected)):
                    matches.append(int(fields[0]))
            if len(matches) > 1:
                raise ValueError("ambiguous_install_coordinator")
            if matches and not BASE.exists():
                recorded = subprocess.run(["/usr/bin/sudo", "-n", "/bin/test", "-f", str(JOURNAL / "intent.json")],
                                          capture_output=True, timeout=10)
                if recorded.returncode == 0:
                    subprocess.run(["/usr/bin/sudo", "-n", "/bin/kill", "-" + str(signal.SIGKILL), str(matches[0])],
                                   check=True, capture_output=True, timeout=10)
                    killed = True
                    break
            time.sleep(0.05)
        child.communicate(timeout=180)
        if not killed or child.returncode == 0:
            raise ValueError("actual_install_interruption_not_observed")
    finally:
        if child.poll() is None:
            child.kill()
            child.communicate(timeout=30)
    return True


def verify_install_receipt(base, metadata, *, owner_uid=0):
    """Read public evidence below an already validated installed directory.

    owner_uid is a read-only fixture selector; main always requires root. No
    status here grants account access, installer retry or overwrite authority.
    """
    if type(owner_uid) is not int or owner_uid < 0:
        raise ValueError("invalid_native_installer_receipt_owner")
    directory = os.open(base, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        parent = os.fstat(directory)
        if parent.st_uid != owner_uid or parent.st_mode & 0o6022:
            raise ValueError("unsafe_native_installer_receipt_parent")
        descriptor = os.open("install-verification.json", os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK,
                             dir_fd=directory)
    finally:
        os.close(directory)
    with os.fdopen(descriptor, "rb") as stream:
        before = os.fstat(stream.fileno())
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != owner_uid or before.st_nlink != 1
                or stat.S_IMODE(before.st_mode) != 0o644 or not 0 < before.st_size <= 4096):
            raise ValueError("unsafe_native_installer_receipt")
        encoded = stream.read(4097)
        after = os.fstat(stream.fileno())
        if (len(encoded) != before.st_size or any(getattr(before, key) != getattr(after, key) for key in
                ["st_dev", "st_ino", "st_size", "st_uid", "st_mode", "st_nlink", "st_mtime_ns", "st_ctime_ns"])):
            raise ValueError("native_installer_receipt_changed")
    value = json.loads(encoded)
    if type(value) is dict and value.get("status") == "FAILED":
        allowed = {"installer_verifier_context_required", "invalid_installer_payload_manifest", "unsafe_installer_payload_path",
                   "unsafe_installer_payload_object", "installer_payload_changed", "installer_payload_limit"}
        reason = value.get("reason")
        raise ValueError("native_installer_payload_not_verified:" + (
            reason if type(reason) is str and reason in allowed else "unrecognized_reason"))
    if (type(value) is not dict or set(value) != {"schema", "status", "manifest_sha256", "files", "directories", "aliases"}
            or type(value["schema"]) is not int or value["schema"] != 1 or value["status"] != "VERIFIED"
            or value["manifest_sha256"] != metadata["payload_manifest_sha256"]
            or any(type(value[key]) is not int or not 0 <= value[key] <= 100_000
                   or value[key] != metadata["payload_manifest_counts"][key] for key in ["files", "directories", "aliases"])):
        raise ValueError("native_installer_payload_not_verified")
    return True


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
            relative = components[2:]
            if relative[0].endswith(".data"):
                from packaging.utils import parse_wheel_filename

                parse_wheel_filename(components[1])
                wheel_parts = components[1].split("-")
                assert len(relative) >= 3 and relative[0] == "-".join(wheel_parts[:2]) + ".data"
                # Wheel library schemes are relocated by the static installer.
                # Other native .data schemes need their own reviewed check.
                if relative[1] not in {"platlib", "purelib"}:
                    raise ValueError("prepared_wheel_data_scheme_refused")
                relative = relative[2:]
            target = base / "runtime/lib/python3.12/site-packages" / "/".join(relative)
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
            flags = re.findall(
                rb"^CodeDirectory[ \t]+[^\r\n]*\bflags=0x([0-9a-fA-F]+)\b",
                metadata_text,
                re.MULTILINE,
            )
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
    if any(path.exists() or path.is_symlink() for path in [BASE, PUBLIC_APP, JOB, JOURNAL]):
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
    checks = {"recovery_manifest_matches_complete_public_package_payload": verify_package_manifest(package, metadata)}
    parents = [Path("/Library"), Path("/Library/Application Support"), Path("/Applications")]

    def ownership(path):
        info = path.stat()
        return info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)

    parent_state = {path: ownership(path) for path in parents}
    snapshot = {}
    try:
        checks["actual_installer_coordinator_killed_after_protected_intent"] = interrupt_installer(package, metadata)
        result = subprocess.run(
            ["/usr/bin/sudo", "-n", "/usr/sbin/installer", "-pkg", str(package), "-target", "/"],
            capture_output=True,
            timeout=360,
        )
        checks["actual_development_package_refused_before_owner_setup"] = result.returncode != 0
        root_managed_path(BASE)
        checks["native_verified_source_and_installed_image_before_provisioning"] = verify_install_receipt(BASE, metadata)
        checks["same_package_resumes_after_actual_process_interruption"] = True
        snapshot = {path: (path.lstat().st_dev, path.lstat().st_ino)
                    for path in [BASE, APP, PUBLIC_APP, BASE / "install-verification.json"]}
        repeated = subprocess.run(["/usr/bin/sudo", "-n", "/usr/sbin/installer", "-pkg", str(package), "-target", "/"],
                                  capture_output=True, timeout=360)
        checks["same_package_rechecks_published_image_without_replacing_it"] = (
            repeated.returncode != 0 and verify_install_receipt(BASE, metadata)
            and all((path.lstat().st_dev, path.lstat().st_ino) == identity for path, identity in snapshot.items())
        )
        python = BASE / "runtime/bin/python"
        checks["offline_runtime_installed_at_final_path"] = python.is_file()
        image = metadata["runtime_image"]
        assert image["schema"] == 1 and image["transform"] == "account-access-static-runtime-image-v1"
        assert image["bytecode_compiled"] is False and image["wheel_installation_executes_package_code"] is False
        assert json.loads((BASE / "runtime-image.json").read_bytes()) == image
        root_managed_path(BASE / "runtime")
        checks["complete_runtime_image_matches_installed_public_files_and_modes"] = (
            inventory_digest(BASE / "runtime", owner_uid=0) == image["runtime_manifest_sha256"]
        )
        probe = subprocess.run(
            [
                str(python),
                "-I",
                "-B",
                "-c",
                "import ssl,sqlite3,cryptography,playwright,onepassword,account_access.onepassword_source,account_access.system_provision;"
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
        checks["protected_app_payload_present"] = (
            APP.is_dir() and root_managed_path(APP) == APP
            and PUBLIC_APP.is_symlink() and os.readlink(PUBLIC_APP) == PUBLIC_TARGET
            and PUBLIC_APP.resolve(strict=True) == APP
        )
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
            if PUBLIC_APP.exists() or PUBLIC_APP.is_symlink():
                alias_info = PUBLIC_APP.lstat()
                if (snapshot.get(PUBLIC_APP) != (alias_info.st_dev, alias_info.st_ino)
                        or alias_info.st_uid != 0 or alias_info.st_nlink != 1
                        or not stat.S_ISLNK(alias_info.st_mode)
                        or os.readlink(PUBLIC_APP) != PUBLIC_TARGET):
                    raise RuntimeError("package_fixture_public_alias_changed")
                subprocess.run(["/usr/bin/sudo", "-n", "/bin/rm", "--", str(PUBLIC_APP)], check=True)
            for path in [BASE, JOURNAL]:
                if path.exists():
                    subprocess.run(
                        ["/usr/bin/sudo", "-n", "/bin/rm", "-rf", "--", str(path)], check=True
                    )
    checks["temporary_package_payload_removed"] = (
        not BASE.exists() and not PUBLIC_APP.exists() and not PUBLIC_APP.is_symlink()
    )
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
