"""Assemble an offline Mac package with protected same-image install recovery."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import plistlib
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import traceback
import zipfile
from xml.sax.saxutils import escape

from account_access.system_provision import signature
from account_access.install_image import ImageManifest
from account_access.package_manifest import APPLICATION_TARGET, CANONICAL_APP, OWNER_APP
from macos.payload_audit import audit_payload, binary_type, tree_files

BASE = Path("Library/Application Support/Account Access")
IDENTIFIER = "com.fainir.accountaccess.system"
# Maintainer-only reuse of these independently reviewed complete images. Another
# cohort requires source review; a caller-supplied digest cannot widen it.
PREASSEMBLED_MANIFEST_SHA256 = "d1f74db86890b306f989b65a8c521ce3b0879f261ded122dd409be2ca2fbe317"
PREASSEMBLED_CONFIGURATION_MANIFEST_SHA256 = "05553235819dd43d76d8f1d506f3da16a57617e63c5f8c49bf58c298e11b55da"

# Installer provides the target volume as argument 3. The verified coordinator
# owns all image publication and recovery; PackageKit writes no target payload.
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
"""
POSTINSTALL = """#!/bin/sh
set -eu
PATH=/usr/bin:/bin:/usr/sbin:/sbin
export PATH
umask 022
[ "$(/usr/bin/id -u)" = 0 ] && [ "${3:-}" = / ] || exit 1
AC_PACKAGE_SCRIPTS=$(CDPATH= cd "$(/usr/bin/dirname "$0")" && /bin/pwd -P)
exec "$AC_PACKAGE_SCRIPTS/AccountAccess-installerverify" --install
"""


def command(arguments, *, input_data=None):
    return subprocess.run(
        arguments,
        check=True,
        stdin=subprocess.DEVNULL if input_data is None else None,
        input=input_data,
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


def distribution(version, architecture, *, install_bytes):
    if architecture not in {"arm64", "x86_64"}:
        raise ValueError("unsupported_package_architecture")
    if type(install_bytes) is not int or install_bytes <= 0:
        raise ValueError("invalid_install_space_requirement")
    install_kbytes = (install_bytes + 1023) // 1024
    required_gb = (install_bytes + 100_000_000 - 1) // 100_000_000
    space_label = f"{required_gb // 10}.{required_gb % 10} GB"
    return f'''<?xml version="1.0" encoding="utf-8"?>
<installer-gui-script minSpecVersion="2">
<title>Account Access</title>
<options customize="never" require-scripts="true" hostArchitectures="{architecture}"/>
<domains enable_anywhere="false" enable_currentUserHome="false" enable_localSystem="true"/>
<volume-check script="accountAccessSpaceCheck()"><allowed-os-versions><os-version min="14.0"/></allowed-os-versions></volume-check>
<choices-outline><line choice="default"/></choices-outline>
<choice id="default" title="Account Access" visible="false"><pkg-ref id="{IDENTIFIER}"/></choice>
<pkg-ref id="{IDENTIFIER}" version="{escape(version)}" installKBytes="{install_kbytes}" onConclusion="none">payload.pkg</pkg-ref>
<script><![CDATA[
function accountAccessSpaceCheck() {{
  // This historical property is misnamed: current native Installer returns
  // bytes. An inert native preflight test verifies the units and both branches.
  // The protected coordinator rechecks its pinned volume using fstatvfs.
  var available = my.target.availableKilobytes;
  if (my.target.mountpoint === "/" && typeof available === "number" &&
      isFinite(available) && available >= {install_bytes}) return true;
  my.result.type = "Fatal";
  my.result.title = "Free some space to install Account Access";
  my.result.message = "Account Access needs at least {space_label} of free space while installing. Free some space, then reopen this installer. Your existing setup is preserved.";
  return false;
}}
]]></script>
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


def manifest_counts(encoded):
    return {
        kind: sum(row["kind"] == word for tree in json.loads(encoded)["roots"].values() for row in tree.values())
        for kind, word in [("files", "file"), ("directories", "directory"), ("aliases", "symlink")]
    }


def native_manifest_preflight(verifier, encoded):
    expected = {"schema": 1, "status": "INSPECTED", "manifest_sha256": hashlib.sha256(encoded).hexdigest(),
                **manifest_counts(encoded)}
    result = command([str(verifier), "--inspect-manifest"], input_data=encoded)
    if len(result.stdout) > 4096:
        raise ValueError("native_manifest_preflight_mismatch")
    value = json.loads(result.stdout)
    if (type(value) is not dict or value != expected
            or any(type(value[key]) is not int for key in ["schema", "files", "directories", "aliases"])):
        raise ValueError("native_manifest_preflight_mismatch")


def stage_bitwarden(args, payload):
    """A consumer build cannot silently omit its pinned password provider."""
    values = [getattr(args, name, None) for name in ["bitwarden_archive", "bitwarden_sources", "bitwarden_source_sha256"]]
    if args.development and not any(values):
        return None  # Explicit unrelated disposable CI fixture, not a consumer runtime.
    if not all(values):
        raise ValueError("bitwarden_runtime_and_corresponding_source_required")
    from .bitwarden_runtime import stage

    return stage(payload, *values)


def stage_runtime_ca(args, payload):
    wheel = getattr(args, "pip_wheel", None)
    if args.development and not wheel:
        return None  # Unrelated inert CI fixtures do not ship consumer Python.
    if not wheel:
        raise ValueError("runtime_ca_pinned_pip_wheel_required")
    from .runtime_ca import refresh

    return refresh(payload, wheel)


def build_context(args):
    if sys.platform != "darwin" or os.getuid() == 0 or os.getuid() != os.geteuid():
        raise ValueError("ordinary_mac_build_context_required")
    if args.architecture != "arm64":
        raise ValueError("apple_silicon_binary_runtime_required")
    unsigned_package = getattr(args, "unsigned_package", False)
    if unsigned_package and (args.development or args.installer_identity):
        raise ValueError("unsigned_package_conflicts_with_signing_mode")
    if (not args.development and not unsigned_package and not args.installer_identity
            and not getattr(args, "inspect_runtime", False)):
        raise ValueError("developer_id_installer_identity_required")
    return unsigned_package


def package_image(args, root, scripts, manifest, output, version):
    """Unchanged protected same-image Installer envelope for either build route."""
    install_bytes = ImageManifest(manifest, hashlib.sha256(manifest).hexdigest()).required_space(copies=2)
    scripts.mkdir()
    (scripts / "RecoveryManifest.json").write_bytes(manifest)
    verifier = root / BASE / "bin/AccountAccess-installerverify"
    shutil.copy2(verifier, scripts / verifier.name)
    verifier_digest = hashlib.sha256(verifier.read_bytes()).hexdigest()
    for name, contents in [("preinstall", PREINSTALL), ("postinstall", POSTINSTALL)]:
        target = scripts / name
        target.write_text(contents)
        target.chmod(0o755)
    root.rename(scripts / "PublicImage")
    scratch = scripts.parent
    command(["/usr/bin/pkgbuild", "--nopayload", "--identifier", IDENTIFIER,
             "--version", version, "--install-location", "/", "--ownership", "recommended",
             "--scripts", str(scripts), str(scratch / "payload.pkg")])
    xml = scratch / "Distribution.xml"
    xml.write_text(distribution(version, args.architecture, install_bytes=install_bytes))
    unsigned_package = getattr(args, "unsigned_package", False)
    result = output / ("Account-Access-" + args.architecture
        + ("-development" if args.development else "-unsigned" if unsigned_package else "") + ".pkg")
    command(["/usr/bin/productbuild", "--distribution", str(xml), "--package-path", str(scratch),
             *([] if args.development or unsigned_package else ["--sign", args.installer_identity]), str(result)])
    if not args.development and not unsigned_package:
        command(["/usr/sbin/pkgutil", "--check-signature", str(result)])
    return result, verifier_digest, install_bytes


def preassembled_manifest(path, expected):
    if (not isinstance(expected, str) or re.fullmatch("[a-f0-9]{64}", expected) is None
            or expected not in {PREASSEMBLED_MANIFEST_SHA256, PREASSEMBLED_CONFIGURATION_MANIFEST_SHA256}):
        raise ValueError("reviewed_preassembled_image_required")
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        before = os.fstat(descriptor)
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.getuid() or before.st_nlink != 1
                or stat.S_IMODE(before.st_mode) not in {0o600, 0o644}
                or not 0 < before.st_size <= 16 * 1024 * 1024):
            raise ValueError("unsafe_preassembled_manifest")
        with os.fdopen(os.dup(descriptor), "rb") as stream:
            raw = stream.read(before.st_size + 1)
        def fields(value):
            return (value.st_dev, value.st_ino, value.st_mode, value.st_uid, value.st_gid,
                    value.st_nlink, value.st_size, value.st_mtime_ns, value.st_ctime_ns)
        if (len(raw) != before.st_size or fields(before) != fields(os.fstat(descriptor))
                or fields(before) != fields(Path(path).lstat())):
            raise ValueError("preassembled_manifest_changed")
        ImageManifest(raw, expected)
        return raw
    finally:
        os.close(descriptor)


def preassembled_inventory(root, manifest):
    from account_access.package_manifest import build as install_manifest

    expected = {Path(): {"Library", "Applications"}, Path("Library"): {"Application Support"},
                Path("Library/Application Support"): {"Account Access"}, Path("Applications"): {"Account Access.app"}}
    for relative, children in expected.items():
        directory = root / relative
        info = directory.lstat()
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o6022
                or {path.name for path in directory.iterdir()} != children):
            raise ValueError("preassembled_image_envelope_changed")
    if install_manifest(root, "0.8.0", "arm64") != manifest:
        raise ValueError("preassembled_image_changed")


def assemble_preassembled(args):
    """Package one reviewed immutable cohort; never transform or run its runtime."""
    unsigned_package = build_context(args)
    if args.development:
        raise ValueError("preassembled_production_payload_required")
    if (any(getattr(args, name, None) is not None for name in
            ["app", "native", "python", "browsers", "wheels", "runtime_identity", "runtime_plan",
             "pip_wheel", "bitwarden_archive", "bitwarden_sources", "bitwarden_source_sha256"])
            or getattr(args, "inspect_runtime", False)):
        raise ValueError("preassembled_and_transform_inputs_conflict")
    if not getattr(args, "preassembled_image", None) or not getattr(args, "preassembled_manifest", None):
        raise ValueError("reviewed_preassembled_image_required")
    manifest_path = Path(args.preassembled_manifest).absolute()
    manifest = preassembled_manifest(manifest_path, getattr(args, "preassembled_sha256", None))
    source = Path(args.preassembled_image).absolute()
    if source.is_symlink():
        raise ValueError("unsafe_preassembled_image")
    source = source.resolve(strict=True)
    output = Path(args.output).absolute()
    if output.exists() or output.is_symlink():
        raise ValueError("new_output_directory_required")
    if output.is_relative_to(source):
        raise ValueError("preassembled_output_inside_source")
    preassembled_inventory(source, manifest)
    output.mkdir(mode=0o700)
    with tempfile.TemporaryDirectory(prefix="account-access-preassembled-package-") as temporary:
        scratch = Path(temporary)
        root, scripts = scratch / "root", scratch / "scripts"
        shutil.copytree(source, root, symlinks=True)
        command(["/bin/chmod", "-RN", str(root)])  # Private copy only, as in raw assembly.
        preassembled_inventory(root, manifest)
        payload, owner_app = root / BASE, root / CANONICAL_APP
        version, team, wheel, _ = inspect_app(owner_app, development=False)
        identities = {"owner": signature(owner_app, "com.fainir.accountaccess", fixture=False)}
        for name, identifier in [("broker", "com.fainir.accountaccess.broker"),
                                 ("bootstrap", "com.fainir.accountaccess.bootstrap"),
                                 ("installerverify", "com.fainir.accountaccess.installerverify")]:
            signed = signature(payload / ("bin/AccountAccess-" + name), identifier, fixture=False)
            if signed["team"] != team:
                raise ValueError("payload_publishers_disagree")
            if name != "installerverify":
                identities[name] = signed
        from account_access.install_transaction import _peer_identity

        descriptor = os.open(payload, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            if _peer_identity(descriptor, os.getuid()) != identities:
                raise ValueError("preassembled_peer_identity_changed")
        finally:
            os.close(descriptor)
        project = payload / "wheels" / f"account_access-{version}-py3-none-any.whl"
        if project.read_bytes() != wheel.read_bytes():
            raise ValueError("wheelhouse_project_mismatch")
        wheels = list((payload / "wheels").iterdir())
        if not wheels or any(path.is_symlink() or not path.is_file() or path.suffix != ".whl" for path in wheels):
            raise ValueError("binary_wheelhouse_required")
        if (binary_type(payload / "python/bin/python3.12") != 2
                or binary_type(payload / "runtime/bin/python3.12") != 2
                or binary_type(payload / "runtime/lib/python3.12/site-packages/playwright/driver/node") != 2
                or not any(binary_type(path) == 2 for path in tree_files(payload / "browsers"))):
            raise ValueError("native_python_and_browser_executables_required")
        runtime_audit = audit_payload(
            [owner_app, payload / "python", payload / "runtime", payload / "browsers", payload / "bin"],
            sorted(wheels), args.architecture, command, development=False)
        native_manifest_preflight(payload / "bin/AccountAccess-installerverify", manifest)
        preassembled_inventory(root, manifest)
        preassembled_inventory(source, manifest)
        result, verifier_digest, install_bytes = package_image(args, root, scripts, manifest, output, version)
        preassembled_inventory(source, manifest)
        if preassembled_manifest(manifest_path, args.preassembled_sha256) != manifest:
            raise ValueError("preassembled_manifest_changed")
        report = {"status": "BUILT", "version": version, "architecture": args.architecture,
            "development": False, "offline_runtime": True, "fresh_install_only": False,
            "installation_strategy": "verified-script-image-v1", "recovery_scope": "same-image-same-owner-only",
            "preassembled_image": True, "preassembled_source_unchanged": True, "runtime_transformed": False,
            "production_ready": False, "notarized": False, "installed": False,
            "native_payload_audit": runtime_audit, "payload_manifest_sha256": args.preassembled_sha256,
            "installer_verifier_sha256": verifier_digest, "payload_manifest_counts": manifest_counts(manifest),
            "required_install_bytes": install_bytes, "native_manifest_preflight": True,
            "sha256": hashlib.sha256(result.read_bytes()).hexdigest()}
        if unsigned_package:
            report.update(unsigned_package=True, installer_signed=False)
        (output / "package.json").write_text(json.dumps(report, indent=2) + "\n")
        return report


def assemble(args):
    unsigned_package = build_context(args)
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
        ("installerverify", "com.fainir.accountaccess.installerverify"),
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
    output.mkdir(mode=0o700)
    with tempfile.TemporaryDirectory(prefix="account-access-system-package-") as temporary:
        scratch = Path(temporary)
        root, scripts = scratch / "root", scratch / "scripts"
        payload = root / BASE
        payload.mkdir(parents=True)
        (root / "Applications").mkdir()
        owner_app = root / CANONICAL_APP
        shutil.copytree(app, owner_app, symlinks=True)
        (root / OWNER_APP).symlink_to(APPLICATION_TARGET)
        shutil.copytree(python, payload / "python", symlinks=True)
        shutil.copytree(browsers, payload / "browsers", symlinks=True)
        (payload / "bin").mkdir()
        for name in ["broker", "bootstrap", "installerverify"]:
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
        runtime_ca_refresh = stage_runtime_ca(args, payload)
        bitwarden_runtime = stage_bitwarden(args, payload)
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
                "bitwarden_runtime": bitwarden_runtime,
                "runtime_ca_refresh": runtime_ca_refresh,
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
                owner_app,
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

        identities = {
            key: signature(path, identifier, fixture=args.development)
            for key, path, identifier in [
                ("owner", owner_app, "com.fainir.accountaccess"),
                ("broker", payload / "bin/AccountAccess-broker", "com.fainir.accountaccess.broker"),
                ("bootstrap", payload / "bin/AccountAccess-bootstrap", "com.fainir.accountaccess.bootstrap"),
            ]
        }
        (payload / "package-identity.json").write_text(json.dumps({
            "schema": 1, "managed_by": "account-access-package-identity-v1", "signatures": identities,
        }, sort_keys=True) + "\n")

        # Refuse writable/special payload objects before the supplied
        # interpreter runs; preparation receipts retain their exact tree modes.
        source_manifest = install_manifest(root, version, args.architecture)
        native_manifest_preflight(payload / "bin/AccountAccess-installerverify", source_manifest)
        from account_access.install_transaction import _peer_identity
        directory = os.open(payload, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            _peer_identity(directory, os.getuid())
        finally:
            os.close(directory)
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
        if runtime_ca_refresh is not None:
            from .runtime_ca import verify_generated_runtime

            verify_generated_runtime(payload, runtime_ca_refresh)
        (payload / "runtime-image.json").write_text(json.dumps(image, indent=2) + "\n")
        if binary_type(payload / "runtime/lib/python3.12/site-packages/playwright/driver/node") != 2:
            raise ValueError("runtime_image_native_browser_driver_required")
        runtime_audit = audit_payload(
            [owner_app, payload / "python", payload / "runtime",
             payload / "browsers", payload / "bin"],
            sorted((payload / "wheels").glob("*.whl")), args.architecture, command,
            development=args.development,
        )
        manifest = install_manifest(root, version, args.architecture)
        verify_source_inventory(source_manifest, manifest)
        native_manifest_preflight(payload / "bin/AccountAccess-installerverify", manifest)
        # --nopayload hides PublicImage's extracted runtime from PackageKit's
        # automatic size estimate. Both that source and our destination coexist
        # during installation, so declare their manifest-derived requirement.
        # No PackageKit payload can overwrite existing paths before our lease,
        # journal and exclusive publication checks. The native helper verifies
        # this private source before its interpreter can run.
        result, verifier_digest, install_bytes = package_image(args, root, scripts, manifest, output, version)
        report = {
            "status": "BUILT",
            "version": version,
            "architecture": args.architecture,
            "development": args.development,
            "offline_runtime": True,
            "fresh_install_only": False,
            "installation_strategy": "verified-script-image-v1",
            "recovery_scope": "same-image-same-owner-only",
            "production_ready": False,
            "notarized": False,
            "installed": False,
            "native_payload_audit": runtime_audit,
            "runtime_preparation": runtime_preparation,
            "bitwarden_runtime": bitwarden_runtime,
            "runtime_ca_refresh": runtime_ca_refresh,
            "runtime_image": image,
            "payload_manifest_sha256": hashlib.sha256(manifest).hexdigest(),
            "installer_verifier_sha256": verifier_digest,
            "payload_manifest_counts": manifest_counts(manifest),
            "required_install_bytes": install_bytes,
            "native_manifest_preflight": True,
            "sha256": hashlib.sha256(result.read_bytes()).hexdigest(),
        }
        if unsigned_package:
            # The container has no Installer signature. Every payload/runtime
            # verification above still used the production publisher policy.
            report.update({"unsigned_package": True, "installer_signed": False})
        (output / "package.json").write_text(json.dumps(report, indent=2) + "\n")
        return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ["app", "native", "python", "browsers", "wheels"]:
        parser.add_argument("--" + name)
    parser.add_argument("--output", required=True)
    parser.add_argument("--preassembled-image", help="Reuse only the reviewed immutable complete-image cohort")
    parser.add_argument("--preassembled-manifest")
    parser.add_argument("--preassembled-sha256")
    parser.add_argument("--architecture", choices=["arm64"], required=True)
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument("--development", action="store_true")
    modes.add_argument("--unsigned-package", action="store_true",
                       help="Keep production-signed payload checks; omit only the Installer container signature")
    parser.add_argument("--installer-identity")
    parser.add_argument("--runtime-identity")
    parser.add_argument("--runtime-plan")
    parser.add_argument("--inspect-runtime", action="store_true")
    parser.add_argument("--bitwarden-archive", help="Exact pinned official OSS npm CLI tgz; never downloaded during packaging")
    parser.add_argument("--bitwarden-sources", help="Complete corresponding-source release archive prepared before packaging")
    parser.add_argument("--bitwarden-source-sha256", help="Explicit reviewed digest of the corresponding-source release archive")
    parser.add_argument("--pip-wheel", help="Exact pinned official pip wheel for active and ensurepip CA refresh; never executed")
    args = parser.parse_args()
    try:
        prepared = any(getattr(args, name) is not None for name in
                       ["preassembled_image", "preassembled_manifest", "preassembled_sha256"])
        if prepared:
            report = assemble_preassembled(args)
        else:
            if any(getattr(args, name) is None for name in ["app", "native", "python", "browsers", "wheels"]):
                raise ValueError("raw_package_inputs_required")
            report = assemble(args)
        print(json.dumps(report))
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
                "AccountAccess-installerverify",
            }:
                diagnostic["tool"] = executable
                diagnostic["exit_code"] = exc.returncode
        print(json.dumps(diagnostic), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
