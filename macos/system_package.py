"""Assemble an offline, fresh-install Mac package; never install it on this host."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import plistlib
import shutil
import subprocess
import sys
import tempfile
import traceback
import zipfile
from xml.sax.saxutils import escape

from account_access.system_provision import signature
from macos.payload_audit import audit_payload, binary_type, tree_files

BASE = Path("Library/Application Support/Account Access")
IDENTIFIER = "com.fainir.accountaccess.system"

# Installer provides the target volume as argument 3. This first installer does
# not adopt, remove or overwrite existing installation/account data.
PREINSTALL = """#!/bin/sh
set -eu
PATH=/usr/bin:/bin:/usr/sbin:/sbin
export PATH
[ "$(/usr/bin/id -u)" = 0 ] && [ "${3:-}" = / ] || exit 1
for directory in / /Library "/Library/Application Support"; do
  [ -d "$directory" ] && [ ! -L "$directory" ] || exit 1
  [ "$(/usr/bin/stat -f %u "$directory")" = 0 ] || exit 1
  permissions=$(/usr/bin/stat -f %p "$directory")
  [ "$((0$permissions & 022))" = 0 ] || exit 1
  # Before any bundled interpreter executes, require ordinary protected
  # installation parents. Runtime validation can allow restrictive deny ACLs;
  # this bootstrap conservatively refuses all nonstandard parent ACLs.
  listing=$(/bin/ls -lde "$directory")
  /usr/bin/printf '%s\\n' "$listing" | /usr/bin/awk 'NR > 1 { bad=1 } END { exit bad }' || exit 1
done
for location in "/Library/Application Support/Account Access" "/Applications/Account Access.app" "/Library/LaunchDaemons/com.fainir.accountaccess.broker.plist"; do
  [ ! -e "$location" ] && [ ! -L "$location" ] || exit 1
done
for record in /Users/_accountaccess /Groups/_accountaccess; do
  if /usr/bin/dscl -plist . -read "$record" RecordName >/dev/null 2>&1; then
    exit 1
  else
    [ "$?" = 56 ] || exit 1
  fi
done
"""
POSTINSTALL = """#!/bin/sh
set -eu
PATH=/usr/bin:/bin:/usr/sbin:/sbin
export PATH
umask 022
[ "$(/usr/bin/id -u)" = 0 ] && [ "${3:-}" = / ] || exit 1
AC_PACKAGE_BASE="/Library/Application Support/Account Access"
[ -d "$AC_PACKAGE_BASE/runtime" ] && [ ! -L "$AC_PACKAGE_BASE/runtime" ] || exit 1
[ -x "$AC_PACKAGE_BASE/runtime/bin/python" ] || exit 1
"$AC_PACKAGE_BASE/runtime/bin/python" -I -B -m account_access.system_provision
AC_PACKAGE_OWNER=$(/usr/bin/stat -f %u /dev/console)
[ "$AC_PACKAGE_OWNER" -gt 0 ] || exit 1
/bin/launchctl asuser "$AC_PACKAGE_OWNER" /usr/bin/sudo -n -H -u "#$AC_PACKAGE_OWNER" -- /usr/bin/open -a "/Applications/Account Access.app"
"""


def command(arguments):
    return subprocess.run(
        arguments,
        check=True,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        timeout=600,
        env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LANG": "C"},
    )


def bundle_rules(values):
    if type(values) is not list:
        raise ValueError("invalid_component_analysis")
    for value in values:
        value["BundleIsRelocatable"] = False
        value["BundleHasStrictIdentifier"] = True
        for child in value.get("ChildBundles", []):
            bundle_rules([child])
    return values


def distribution(version, architecture):
    if architecture not in {"arm64", "x86_64"}:
        raise ValueError("unsupported_package_architecture")
    return f'''<?xml version="1.0" encoding="utf-8"?>
<installer-gui-script minSpecVersion="2">
<title>Account Access</title>
<options customize="never" require-scripts="true" hostArchitectures="{architecture}"/>
<domains enable_anywhere="false" enable_currentUserHome="false" enable_localSystem="true"/>
<volume-check><allowed-os-versions><os-version min="14.0"/></allowed-os-versions></volume-check>
<choices-outline><line choice="default"/></choices-outline>
<choice id="default" title="Account Access" visible="false"><pkg-ref id="{IDENTIFIER}"/></choice>
<pkg-ref id="{IDENTIFIER}" version="{escape(version)}" onConclusion="none">payload.pkg</pkg-ref>
</installer-gui-script>
'''


def inspect_app(app, *, development):
    info = plistlib.loads((app / "Contents/Info.plist").read_bytes())
    if (
        info.get("CFBundleIdentifier") != "com.fainir.accountaccess"
        or info.get("AccountAccessSystemInstallationRequired") is not True
        or info.get("CFBundleShortVersionString") != "0.8.0"
    ):
        raise ValueError("protected_owner_app_required")
    signed = signature(app, "com.fainir.accountaccess", fixture=development)
    wheel = app / "Contents/Resources/account_access.whl"
    if hashlib.sha256(wheel.read_bytes()).hexdigest() != info.get("AccountAccessWheelSHA256"):
        raise ValueError("owner_wheel_pin_mismatch")
    with zipfile.ZipFile(wheel) as archive:
        requirements = archive.read("account_access/runtime-requirements.txt")
    if not requirements or len(requirements) > 2_000_000:
        raise ValueError("runtime_lock_required")
    return info["CFBundleShortVersionString"], signed["team"], wheel, requirements


def verify_source_inventory(before, after):
    original, complete = json.loads(before), json.loads(after)
    rows = complete["roots"]["/" + str(BASE)]
    complete["roots"]["/" + str(BASE)] = {
        name: value for name, value in rows.items()
        if name not in {"runtime", "runtime-image.json"} and not name.startswith("runtime/")
    }
    if complete != original:
        raise ValueError("runtime_image_source_payload_changed")


def assemble(args):
    if sys.platform != "darwin" or os.getuid() == 0:
        raise ValueError("ordinary_mac_build_context_required")
    app, native, python, browsers, wheels = [
        Path(getattr(args, name)).resolve(strict=True)
        for name in ["app", "native", "python", "browsers", "wheels"]
    ]
    output = Path(args.output).absolute()
    if output.exists() or output.is_symlink():
        raise ValueError("new_output_directory_required")
    version, team, wheel, requirements = inspect_app(app, development=args.development)
    original_requirements = requirements
    for name, identifier in [
        ("broker", "com.fainir.accountaccess.broker"),
        ("bootstrap", "com.fainir.accountaccess.bootstrap"),
    ]:
        signed = signature(native / ("AccountAccess-" + name), identifier, fixture=args.development)
        if signed["team"] != team:
            raise ValueError("payload_publishers_disagree")
    executable = python / "bin/python3.12"
    executable.resolve(strict=True).relative_to(python)
    if not (python / "lib/python3.12/os.py").is_file() or not browsers.is_dir():
        raise ValueError("standalone_python_and_browsers_required")
    source_wheels = list(wheels.iterdir())
    if not source_wheels or any(
        p.is_symlink() or not p.is_file() or p.suffix != ".whl" for p in source_wheels
    ):
        raise ValueError("binary_wheelhouse_required")
    if (
        not args.development
        and not args.installer_identity
        and not getattr(args, "inspect_runtime", False)
    ):
        raise ValueError("developer_id_installer_identity_required")
    output.mkdir(mode=0o700)
    with tempfile.TemporaryDirectory(prefix="account-access-system-package-") as temporary:
        scratch = Path(temporary)
        root, scripts = scratch / "root", scratch / "scripts"
        payload = root / BASE
        payload.mkdir(parents=True)
        (root / "Applications").mkdir()
        shutil.copytree(app, root / "Applications/Account Access.app", symlinks=True)
        shutil.copytree(python, payload / "python", symlinks=True)
        shutil.copytree(browsers, payload / "browsers", symlinks=True)
        (payload / "bin").mkdir()
        for name in ["broker", "bootstrap"]:
            shutil.copy2(
                native / ("AccountAccess-" + name), payload / "bin" / ("AccountAccess-" + name)
            )
        (payload / "wheels").mkdir()
        for source in source_wheels:
            shutil.copy2(source, payload / "wheels" / source.name)
        project = payload / "wheels" / f"account_access-{version}-py3-none-any.whl"
        if project.exists() and project.read_bytes() != wheel.read_bytes():
            raise ValueError("wheelhouse_project_mismatch")
        shutil.copy2(wheel, project)
        pin = hashlib.sha256(project.read_bytes()).hexdigest()
        # Do not ship ACL grants inherited from a maintainer's build folders.
        # This changes only our private copied payload, never source artifacts.
        command(["/bin/chmod", "-RN", str(root)])
        copied_python = payload / "python/bin/python3.12"
        if binary_type(copied_python) != 2 or not any(
            binary_type(path) == 2 for path in tree_files(payload / "browsers")
        ):
            raise ValueError("native_python_and_browser_executables_required")
        runtime_preparation = None
        runtime_identity = getattr(args, "runtime_identity", None)
        runtime_plan = getattr(args, "runtime_plan", None)
        if getattr(args, "inspect_runtime", False):
            if runtime_identity or runtime_plan:
                raise ValueError("runtime_inspection_cannot_sign")
            from .runtime_prepare import preparation_plan

            plan = preparation_plan(payload, requirements, project.name, pin)
            plan_file = output / "runtime-signing-plan.json"
            plan_file.write_text(json.dumps(plan, indent=2) + "\n")
            return {
                "status": "INSPECTED",
                "plan_file": str(plan_file),
                "production_ready": False,
                "notarized": False,
                "installed": False,
            }
        if bool(runtime_identity) != bool(runtime_plan):
            raise ValueError("runtime_signing_identity_and_plan_required")
        if runtime_identity:
            from .runtime_prepare import prepare

            plan_path = Path(runtime_plan)
            if plan_path.stat().st_size > 2_000_000:
                raise ValueError("runtime_signing_plan_too_large")

            def unique(values):
                result = {}
                for key, value in values:
                    if key in result:
                        raise ValueError("duplicate_runtime_signing_plan_key")
                    result[key] = value
                return result

            plan = json.loads(plan_path.read_bytes(), object_pairs_hook=unique)
            requirements, runtime_preparation = prepare(
                payload,
                requirements,
                project.name,
                pin,
                runtime_identity,
                team,
                plan,
                command,
                development=args.development,
            )
            (payload / "runtime-preparation.json").write_text(
                json.dumps(runtime_preparation, indent=2) + "\n"
            )
        (payload / "package-requirements.txt").write_bytes(
            requirements + f"\naccount-access=={version} --hash=sha256:{pin}\n".encode()
        )
        # Inspect the actual immutable build copies, including native code
        # inside dependency archives, before running the supplied interpreter.
        runtime_audit = audit_payload(
            [
                root / "Applications/Account Access.app",
                payload / "python",
                payload / "browsers",
                payload / "bin",
            ],
            sorted((payload / "wheels").glob("*.whl")),
            args.architecture,
            command,
            development=args.development,
        )
        from account_access.package_manifest import build as install_manifest

        # Refuse writable/special payload objects before the supplied
        # interpreter runs; preparation receipts retain their exact tree modes.
        source_manifest = install_manifest(root, version, args.architecture)
        from macos.runtime_image import assemble as runtime_image, verify_origins

        origins = verify_origins(payload / "wheels", original_requirements, project.name, pin,
                                 runtime_preparation)
        found = json.loads(
            command(
                [
                    str(copied_python),
                    "-I",
                    "-B",
                    "-c",
                    "import json,platform,sys;print(json.dumps([list(sys.version_info[:3]),platform.machine(),sys.prefix==sys.base_prefix and sys.version_info.releaselevel=='final' and sys.version_info.serial==0]))",
                ]
            ).stdout
        )
        if (type(found) is not list or len(found) != 3 or type(found[0]) is not list
                or len(found[0]) != 3 or found[0][:2] != [3, 12]
                or any(type(value) is not int or value < 0 for value in found[0])
                or found[1] != args.architecture or found[2] is not True):
            raise ValueError("matching_standalone_python_required")
        image = runtime_image(payload, requirements, project.name, pin, args.architecture,
                              ".".join(map(str, found[0])), origins=origins)
        (payload / "runtime-image.json").write_text(json.dumps(image, indent=2) + "\n")
        if binary_type(payload / "runtime/lib/python3.12/site-packages/playwright/driver/node") != 2:
            raise ValueError("runtime_image_native_browser_driver_required")
        runtime_audit = audit_payload(
            [root / "Applications/Account Access.app", payload / "python", payload / "runtime",
             payload / "browsers", payload / "bin"],
            sorted((payload / "wheels").glob("*.whl")), args.architecture, command,
            development=args.development,
        )
        manifest = install_manifest(root, version, args.architecture)
        verify_source_inventory(source_manifest, manifest)
        scripts.mkdir()
        (scripts / "RecoveryManifest.json").write_bytes(manifest)
        for name, contents in [("preinstall", PREINSTALL), ("postinstall", POSTINSTALL)]:
            target = scripts / name
            target.write_text(contents)
            target.chmod(0o755)
        components = scratch / "components.plist"
        command(["/usr/bin/pkgbuild", "--analyze", "--root", str(root), str(components)])
        components.write_bytes(
            plistlib.dumps(bundle_rules(plistlib.loads(components.read_bytes())))
        )
        command(
            [
                "/usr/bin/pkgbuild",
                "--root",
                str(root),
                "--component-plist",
                str(components),
                "--identifier",
                IDENTIFIER,
                "--version",
                version,
                "--install-location",
                "/",
                "--ownership",
                "recommended",
                "--scripts",
                str(scripts),
                str(scratch / "payload.pkg"),
            ]
        )
        xml = scratch / "Distribution.xml"
        xml.write_text(distribution(version, args.architecture))
        result = output / (
            "Account-Access-"
            + args.architecture
            + ("-development" if args.development else "")
            + ".pkg"
        )
        command(
            [
                "/usr/bin/productbuild",
                "--distribution",
                str(xml),
                "--package-path",
                str(scratch),
                *([] if args.development else ["--sign", args.installer_identity]),
                str(result),
            ]
        )
        if not args.development:
            command(["/usr/sbin/pkgutil", "--check-signature", str(result)])
        report = {
            "status": "BUILT",
            "version": version,
            "architecture": args.architecture,
            "development": args.development,
            "offline_runtime": True,
            "fresh_install_only": True,
            "production_ready": False,
            "notarized": False,
            "installed": False,
            "native_payload_audit": runtime_audit,
            "runtime_preparation": runtime_preparation,
            "runtime_image": image,
            "payload_manifest_sha256": hashlib.sha256(manifest).hexdigest(),
            "sha256": hashlib.sha256(result.read_bytes()).hexdigest(),
        }
        (output / "package.json").write_text(json.dumps(report, indent=2) + "\n")
        return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ["app", "native", "python", "browsers", "wheels", "output"]:
        parser.add_argument("--" + name, required=True)
    parser.add_argument("--architecture", choices=["arm64", "x86_64"], required=True)
    parser.add_argument("--development", action="store_true")
    parser.add_argument("--installer-identity")
    parser.add_argument("--runtime-identity")
    parser.add_argument("--runtime-plan")
    parser.add_argument("--inspect-runtime", action="store_true")
    args = parser.parse_args()
    try:
        print(json.dumps(assemble(args)))
        return 0
    except Exception as exc:
        diagnostic = {
            "status": "FAILED",
            "reason": "system_package_not_built",
            "type": type(exc).__name__,
        }
        frames = traceback.extract_tb(exc.__traceback__)
        if frames:
            diagnostic["source"] = {
                "file": Path(frames[-1].filename).name,
                "line": frames[-1].lineno,
                "function": frames[-1].name,
            }
        if isinstance(exc, subprocess.CalledProcessError):
            executable = Path(exc.cmd[0]).name
            if executable in {
                "pkgbuild",
                "productbuild",
                "python3.12",
                "codesign",
                "chmod",
                "lipo",
                "pkgutil",
            }:
                diagnostic["tool"] = executable
                diagnostic["exit_code"] = exc.returncode
        print(json.dumps(diagnostic), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
