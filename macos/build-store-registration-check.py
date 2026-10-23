"""Build/review a read-only diagnostic package, without executing its helper."""

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parent.parent
HELPER = ROOT / "macos/store_registration_check.py"
TEMPLATE = ROOT / "macos/build-startup-check.py"
IDENTIFIER = "com.fainir.accountaccess.registrationcheck85"
VERSION = "0.1.0"
PACKAGE = "Account Access Registration Check.pkg"
ENV = {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LANG": "C"}
MANIFEST = ROOT / "dist/qa-full-image-package84/build-v1/scripts/TargetManifest.json"
MANIFEST_SHA256 = "05553235819dd43d76d8f1d506f3da16a57617e63c5f8c49bf58c298e11b55da"


def digest(data):
    return hashlib.sha256(data).hexdigest()


def command(arguments):
    return subprocess.run(
        arguments, check=True, capture_output=True, stdin=subprocess.DEVNULL, env=ENV, timeout=120
    )


def source_files(source):
    if not re.fullmatch(r"[a-f0-9]{40}", source):
        raise ValueError("exact_source_required")
    if (
        command(["/usr/bin/git", "-C", str(ROOT), "rev-parse", "HEAD"]).stdout.decode().strip()
        != source
    ):
        raise ValueError("source_head_changed")
    result = {}
    for path in [Path(__file__).resolve(), HELPER, TEMPLATE]:
        name = str(path.relative_to(ROOT))
        raw = command(["/usr/bin/git", "-C", str(ROOT), "show", source + ":" + name]).stdout
        if raw != path.read_bytes():
            raise ValueError("source_file_changed")
        result[name] = digest(raw)
    return result


def wrapper(template, helper_sha):
    if not re.fullmatch(r"[a-f0-9]{64}", helper_sha):
        raise ValueError("helper_pin_required")
    raw = template.postinstall(helper_sha)
    if raw.count(b"/startup_check.py") != 1 or raw.count(b" --inspect-retained") != 1:
        raise ValueError("reviewed_wrapper_changed")
    return raw.replace(b"/startup_check.py", b"/store_registration_check.py").replace(
        b" --inspect-retained", b""
    )


def review_python(template):
    raw = MANIFEST.read_bytes()
    if digest(raw) != MANIFEST_SHA256:
        raise ValueError("reviewed_image_manifest_changed")
    node = json.loads(raw)["roots"][str(template.INSTALL_ROOT)]["runtime/bin/python3.12"]
    if node["kind"] != "file" or node["sha256"] != template.PYTHON_SHA256 or node["mode"] != 0o755:
        raise ValueError("reviewed_python_pin_changed")
    template.protected_metadata(template.PYTHON)
    if digest(template.PYTHON.read_bytes()) != template.PYTHON_SHA256:
        raise ValueError("installed_public_python_changed")
    command(
        [
            "/usr/bin/codesign",
            "--verify",
            "--strict",
            "-R",
            "=" + template.REQUIREMENT,
            str(template.PYTHON),
        ]
    )
    return {
        "path": str(template.PYTHON),
        "sha256": template.PYTHON_SHA256,
        "signature_requirement": template.REQUIREMENT,
        "manifest_sha256": MANIFEST_SHA256,
    }


def build(output, source):
    if sys.platform != "darwin" or os.getuid() == 0 or os.geteuid() != os.getuid():
        raise ValueError("ordinary_mac_build_required")
    if output.exists():
        raise ValueError("fresh_output_required")
    sources = source_files(source)
    spec = importlib.util.spec_from_file_location("registration_package_wrapper", TEMPLATE)
    template = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(template)
    python = review_python(template)  # Public interpreter only; no owner data.
    raw = HELPER.read_bytes()
    compile(raw, str(HELPER), "exec")  # Syntax only; never import or execute the helper.
    output.mkdir(mode=0o700, parents=True)
    scripts = output / "scripts"
    scripts.mkdir(mode=0o700)
    (scripts / HELPER.name).write_bytes(raw)
    (scripts / HELPER.name).chmod(0o644)
    (scripts / "postinstall").write_bytes(wrapper(template, digest(raw)))
    (scripts / "postinstall").chmod(0o755)
    command(["/bin/sh", "-n", str(scripts / "postinstall")])
    expected = template.snapshot_scripts(scripts)
    package = output / PACKAGE
    built = command(
        [
            "/usr/bin/pkgbuild",
            "--nopayload",
            "--identifier",
            IDENTIFIER,
            "--version",
            VERSION,
            "--scripts",
            str(scripts),
            str(package),
        ]
    )
    (output / "pkgbuild.log").write_bytes(built.stdout + built.stderr)
    expanded = output / "expanded"
    result = command(["/usr/sbin/pkgutil", "--expand-full", str(package), str(expanded)])
    (output / "expand.log").write_bytes(result.stdout + result.stderr)
    actual = template.snapshot_scripts(expanded / "Scripts")
    info_raw = (expanded / "PackageInfo").read_bytes()
    info = ET.fromstring(info_raw)
    if (
        actual != expected
        or (expanded / "Payload").exists()
        or info.get("identifier") != IDENTIFIER
        or info.get("version") != VERSION
    ):
        raise ValueError("package_expansion_mismatch")
    payload = info.find("payload")
    if payload is not None and any(
        int(payload.get(key, "0")) != 0 for key in ["numberOfFiles", "installKBytes"]
    ):
        raise ValueError("unexpected_payload")
    signed = subprocess.run(
        ["/usr/sbin/pkgutil", "--check-signature", str(package)],
        capture_output=True,
        stdin=subprocess.DEVNULL,
        env=ENV,
        timeout=120,
    )
    if b"no signature" not in (signed.stdout + signed.stderr).lower():
        raise ValueError("unexpected_container_signature")
    if source_files(source) != sources:
        raise ValueError("source_changed_during_assembly")
    review = {
        "schema": 1,
        "status": "ASSEMBLED_AND_EXPANSION_REVIEWED",
        "source_commit": source,
        "source_files": sources,
        "scripts": expected,
        "expanded_scripts": actual,
        "package_info_sha256": digest(info_raw),
        "package_sha256": digest(package.read_bytes()),
        "package_bytes": package.stat().st_size,
        "installed_python": python,
        "unsigned": True,
        "helper_executed": False,
        "owner_data_read": False,
        "installed": False,
        "credential_contents_read": False,
        "keychain_accessed": False,
        "service_actions": False,
        "diagnostic_reads_registration_metadata": True,
        "diagnostic_modifies_files": False,
        "production_ready": False,
    }
    (output / "review.json").write_text(json.dumps(review, indent=2, sort_keys=True) + "\n")
    return package, review


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", required=True)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    package, review = build(args.output, args.source)
    print(
        json.dumps(
            {"package": str(package), "sha256": review["package_sha256"], "installed": False}
        )
    )
