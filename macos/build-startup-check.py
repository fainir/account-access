"""Build a nopayload, local-only retained-capture inspection; never install it.

The package uses only the already installed, exact build 76 interpreter. The
owner must review and explicitly install the resulting unsigned package in the
native Installer. This builder refuses root and never invokes the helper.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import xml.etree.ElementTree as ET


ROOT = Path(__file__).resolve().parent.parent
HELPER = ROOT / "macos/startup_check.py"
MANIFEST = ROOT / "dist/release-080-review-build76/actual-package-manifest.json"
MANIFEST_SHA256 = "5618053e6f8ed0a8720a9d2f7dde317425cecda6a970abd90c499fbfe27b43a8"
INSTALL_ROOT = Path("/Library/Application Support/Account Access")
PYTHON = INSTALL_ROOT / "runtime/bin/python3.12"
PYTHON_SHA256 = "b21371592c32af6f23b2967c54ffc141f4e14fe1ce73cf45dfb69e5b71c5d762"
PYTHON_IDENTIFIER = "com.fainir.accountaccess.runtime.3274dde21f9767655564"
TEAM = "WBULD6N4NQ"
IDENTIFIER = "com.fainir.accountaccess.startupcaptureinspect"
VERSION = "0.1.0"
PACKAGE_NAME = "Account-Access-Startup-Capture-Inspect-local-unsigned.pkg"
ENV = {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LANG": "C"}
REQUIREMENT = (
    'anchor apple generic and identifier "' + PYTHON_IDENTIFIER + '" '
    'and certificate 1[field.1.2.840.113635.100.6.2.6] exists '
    'and certificate leaf[field.1.2.840.113635.100.6.1.13] exists '
    'and certificate leaf[subject.OU] = "' + TEAM + '"'
)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def command(arguments):
    return subprocess.run(
        arguments, check=True, stdin=subprocess.DEVNULL, capture_output=True,
        env=ENV, timeout=120,
    )


def protected_metadata(path):
    """Check public installed paths without loading Python or owner data."""
    current = path
    while True:
        info = current.lstat()
        if info.st_uid != 0 or stat.S_ISLNK(info.st_mode) or info.st_mode & 0o7022:
            raise ValueError("installed_python_path_not_protected")
        listing = command(["/bin/ls", "-lde", str(current)]).stdout
        if len(listing.splitlines()) != 1:
            raise ValueError("installed_python_path_has_acl")
        if current == Path("/"):
            break
        current = current.parent
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or not info.st_mode & 0o111:
        raise ValueError("installed_python_not_regular_executable")


def review_installed_python():
    manifest_data = MANIFEST.read_bytes()
    if digest(manifest_data) != MANIFEST_SHA256:
        raise ValueError("build76_manifest_pin_mismatch")
    manifest = json.loads(manifest_data)
    expected = manifest["roots"][str(INSTALL_ROOT)]["runtime/bin/python3.12"]
    if expected["kind"] != "file" or expected["sha256"] != PYTHON_SHA256:
        raise ValueError("build76_python_pin_mismatch")
    protected_metadata(PYTHON)
    if digest(PYTHON.read_bytes()) != PYTHON_SHA256:
        raise ValueError("installed_python_hash_mismatch")
    command(["/usr/bin/codesign", "--verify", "--strict", "-R", "=" + REQUIREMENT, str(PYTHON)])
    return {"path": str(PYTHON), "sha256": PYTHON_SHA256, "signature_requirement": REQUIREMENT}


def postinstall(helper_sha256):
    # All executable paths and pins are literals, never root-time policy input.
    # PackageKit script argument 3 binds this diagnostic to the running volume.
    return f'''#!/bin/sh
set -eu
PATH=/usr/bin:/bin:/usr/sbin:/sbin
export PATH
umask 077
[ "$(/usr/bin/id -u)" = 0 ] && [ "${{3:-}}" = / ] || exit 1
AC_CHECK_SCRIPTS=$(CDPATH= cd "$(/usr/bin/dirname "$0")" && /bin/pwd -P)
AC_CHECK_HELPER="$AC_CHECK_SCRIPTS/startup_check.py"
AC_CHECK_PYTHON='{PYTHON}'
for path in / /Library "/Library/Application Support" "/Library/Application Support/Account Access" "/Library/Application Support/Account Access/runtime" "/Library/Application Support/Account Access/runtime/bin" "$AC_CHECK_PYTHON" "$AC_CHECK_SCRIPTS" "$AC_CHECK_HELPER"; do
  [ ! -L "$path" ] && [ "$(/usr/bin/stat -f %u "$path")" = 0 ] || exit 1
  permissions=$(/usr/bin/stat -f %p "$path")
  [ "$((0$permissions & 07022))" = 0 ] || exit 1
  listing=$(/bin/ls -lde "$path")
  /usr/bin/printf '%s\\n' "$listing" | /usr/bin/awk 'NR > 1 {{ bad=1 }} END {{ exit bad }}' || exit 1
done
[ -f "$AC_CHECK_HELPER" ] && [ "$(/usr/bin/stat -f %l "$AC_CHECK_HELPER")" = 1 ] || exit 1
[ -f "$AC_CHECK_PYTHON" ] && [ -x "$AC_CHECK_PYTHON" ] && [ "$(/usr/bin/stat -f %l "$AC_CHECK_PYTHON")" = 1 ] || exit 1
[ "$(/usr/bin/env -i PATH=/usr/bin:/bin:/usr/sbin:/sbin /usr/bin/shasum -a 256 "$AC_CHECK_HELPER" | /usr/bin/awk '{{print $1}}')" = '{helper_sha256}' ] || exit 1
[ "$(/usr/bin/env -i PATH=/usr/bin:/bin:/usr/sbin:/sbin /usr/bin/shasum -a 256 "$AC_CHECK_PYTHON" | /usr/bin/awk '{{print $1}}')" = '{PYTHON_SHA256}' ] || exit 1
/usr/bin/env -i PATH=/usr/bin:/bin:/usr/sbin:/sbin /usr/bin/codesign --verify --strict -R '={REQUIREMENT}' "$AC_CHECK_PYTHON" || exit 1
exec /usr/bin/env -i PATH=/usr/bin:/bin:/usr/sbin:/sbin LANG=C "$AC_CHECK_PYTHON" -I -S "$AC_CHECK_HELPER" --inspect-retained
'''.encode()


def snapshot_scripts(directory):
    result = {}
    for path in sorted(directory.iterdir()):
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise ValueError("unexpected_package_script_object")
        result[path.name] = {"sha256": digest(path.read_bytes()), "mode": stat.S_IMODE(info.st_mode), "size": info.st_size}
    return result


def review_source(source):
    if not re.fullmatch("[0-9a-f]{40}", source):
        raise ValueError("full_source_commit_required")
    head = command(["/usr/bin/git", "-C", str(ROOT), "rev-parse", "HEAD"]).stdout.decode().strip()
    if head != source:
        raise ValueError("source_commit_is_not_git_head")
    result = {}
    for path in [Path(__file__).resolve(), HELPER]:
        relative = str(path.relative_to(ROOT))
        committed = command(["/usr/bin/git", "-C", str(ROOT), "show", source + ":" + relative]).stdout
        if path.read_bytes() != committed:
            raise ValueError("diagnostic_source_does_not_match_commit")
        result[relative] = digest(committed)
    return result


def build(output, source):
    if os.getuid() == 0 or os.geteuid() == 0:
        raise ValueError("startup_check_builder_forbids_root")
    if sys.platform != "darwin":
        raise ValueError("startup_check_builder_requires_macos")
    if output.exists():
        raise ValueError("startup_check_output_already_exists")
    source_files = review_source(source)
    python_review = review_installed_python()
    helper_info = HELPER.lstat()
    if not stat.S_ISREG(helper_info.st_mode) or helper_info.st_nlink != 1:
        raise ValueError("startup_helper_must_be_regular")
    helper_data = HELPER.read_bytes()
    if not helper_data or len(helper_data) > 100_000:
        raise ValueError("startup_helper_size_invalid")
    # Compile in memory only; this does not import or execute the helper.
    compile(helper_data, str(HELPER), "exec")
    output.mkdir(parents=True, mode=0o700)
    scripts = output / "scripts"
    scripts.mkdir(mode=0o700)
    (scripts / "startup_check.py").write_bytes(helper_data)
    (scripts / "startup_check.py").chmod(0o644)
    post = postinstall(digest(helper_data))
    (scripts / "postinstall").write_bytes(post)
    (scripts / "postinstall").chmod(0o755)
    command(["/bin/sh", "-n", str(scripts / "postinstall")])
    expected = snapshot_scripts(scripts)
    package = output / PACKAGE_NAME
    result = command([
        "/usr/bin/pkgbuild", "--nopayload", "--identifier", IDENTIFIER,
        "--version", VERSION, "--scripts", str(scripts), str(package),
    ])
    (output / "pkgbuild.log").write_bytes(result.stdout + result.stderr)
    expanded = output / "expanded"
    result = command(["/usr/sbin/pkgutil", "--expand-full", str(package), str(expanded)])
    (output / "expand.log").write_bytes(result.stdout + result.stderr)
    actual = snapshot_scripts(expanded / "Scripts")
    if actual != expected:
        raise ValueError("expanded_scripts_differ_from_reviewed_inputs")
    if (expanded / "Payload").exists():
        raise ValueError("diagnostic_package_must_have_no_payload")
    package_info = (expanded / "PackageInfo").read_bytes()
    info = ET.fromstring(package_info)
    if info.get("identifier") != IDENTIFIER or info.get("version") != VERSION:
        raise ValueError("diagnostic_package_identifier_mismatch")
    payload = info.find("payload")
    if payload is not None and any(int(payload.get(key, "0")) != 0 for key in ["numberOfFiles", "installKBytes"]):
        raise ValueError("diagnostic_package_must_have_zero_payload_files")
    signature = subprocess.run(
        ["/usr/sbin/pkgutil", "--check-signature", str(package)],
        check=False, stdin=subprocess.DEVNULL, capture_output=True, env=ENV, timeout=120,
    )
    signature_output = signature.stdout + signature.stderr
    if b"no signature" not in signature_output.lower():
        raise ValueError("diagnostic_package_unsigned_status_unexpected")
    (output / "container-signature.txt").write_bytes(signature_output)
    if review_source(source) != source_files:
        raise ValueError("diagnostic_source_changed_during_assembly")
    record = {
        "schema": 1, "status": "ASSEMBLED_AND_EXPANSION_REVIEWED", "not_installed": True,
        "unsigned": True, "identifier": IDENTIFIER, "version": VERSION,
        "source_commit": source, "source_files": source_files,
        "source_files_match_commit": True, "source_git_head_matched": True,
        "builder_sha256": digest(Path(__file__).read_bytes()),
        "helper_source": str(HELPER.relative_to(ROOT)), "helper_sha256": digest(helper_data),
        "build76_manifest_sha256": MANIFEST_SHA256, "installed_python": python_review,
        "scripts": expected, "expanded_scripts": actual,
        "package_info_sha256": digest(package_info),
        "package": str(package), "package_size": package.stat().st_size,
        "package_sha256": digest(package.read_bytes()),
        "helper_executed": False, "owner_data_read": False,
        "execution_mode": "inspect-retained", "launchctl_mutations_permitted": False,
    }
    (output / "review.json").write_text(json.dumps(record, sort_keys=True, indent=2) + "\n")
    print(json.dumps(record, sort_keys=True))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", required=True, help="Exact committed HEAD containing the helper and builder")
    parser.add_argument("--output", type=Path, default=ROOT / "dist/qa-startup-20261020/package-inspect-retained")
    args = parser.parse_args()
    build(args.output.resolve(), args.source)


if __name__ == "__main__":
    main()
