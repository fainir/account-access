"""Prepare, never install, the exact build76 cache-only nopayload repair."""

import argparse
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parent.parent
BASE_BUILDER = ROOT / "macos/build-startup-check.py"
spec = importlib.util.spec_from_file_location("cache_repair_build_common", BASE_BUILDER)
base = importlib.util.module_from_spec(spec)
spec.loader.exec_module(base)
INPUTS = ROOT / "macos/runtime-cache-repair-76"
HELPER = ROOT / "macos/runtime_cache_repair.py"
CHECKER = ROOT / "dist/qa-public-tree-20261020/runtime-public-plan-check"
CHECKER_SHA256 = "e5e544ef218d4787ce897b82e7cef63c851b3ac3a8848c4ae1984e0b8cfefef7"
CHECKER_SOURCES = {
    "macos/RuntimePublicPlanCheck.swift": "cfe278bd2b69ba4b583fce8b760cbf18bd8e55c2b296a1d96f3b58b65cc510fb",
    "macos/WorkerBootstrap.swift": "86f3466bb6d217366f3817ca91ebf0da69e7ea444e3503be2e2898cdf1847c84",
}
CHECKER_REQUIREMENT = (
    'anchor apple generic and identifier "runtime-public-plan-check" '
    'and certificate 1[field.1.2.840.113635.100.6.2.6] exists '
    'and certificate leaf[field.1.2.840.113635.100.6.1.13] exists '
    'and certificate leaf[subject.OU] = "WBULD6N4NQ"'
)
IDENTIFIER = "com.fainir.accountaccess.runtimecacherepair76"
PACKAGE_NAME = "Account-Access-Build76-Cache-Repair-local-unsigned.pkg"
REPORTS = "/Library/Logs/AccountAccessRuntimeRepairs76"


def source_paths():
    return [Path(__file__).resolve(), HELPER, BASE_BUILDER, base.HELPER,
            *sorted(INPUTS.iterdir()), *(ROOT / name for name in CHECKER_SOURCES)]


def review_source(source):
    if not re.fullmatch("[0-9a-f]{40}", source):
        raise ValueError("full_source_commit_required")
    head = base.command(["/usr/bin/git", "-C", str(ROOT), "rev-parse", "HEAD"]).stdout.decode().strip()
    if head != source:
        raise ValueError("source_commit_is_not_git_head")
    reviewed = {}
    for path in source_paths():
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > 128 * 1024:
            raise ValueError("repair_source_object_changed")
        relative = str(path.relative_to(ROOT))
        committed = base.command(["/usr/bin/git", "-C", str(ROOT), "show", source + ":" + relative]).stdout
        if path.read_bytes() != committed:
            raise ValueError("repair_source_does_not_match_commit")
        reviewed[relative] = base.digest(committed)
    if any(reviewed[name] != expected for name, expected in CHECKER_SOURCES.items()):
        raise ValueError("checker_source_binding_changed")
    return reviewed


def reviewed_inputs():
    plan_bytes = (INPUTS / "plan.json").read_bytes()
    plan = json.loads(plan_bytes)
    # Read the helper as source/data; never import or execute it in this builder.
    helper = HELPER.read_bytes()
    if not helper or len(helper) > 100_000:
        raise ValueError("repair_helper_size_invalid")
    compile(helper, str(HELPER), "exec")
    if f'PLAN_SHA256 = "{base.digest(plan_bytes)}"'.encode() not in helper:
        raise ValueError("repair_plan_pin_changed")
    if (plan["target_build"] != 76 or plan["schema"] != 1
            or plan["manifest_sha256"] != base.MANIFEST_SHA256
            or plan["common_sha256"] != base.digest(base.HELPER.read_bytes())
            or len(plan["baseline"]) != 3 or len(plan["extra_directories"]) != 8):
        raise ValueError("repair_plan_binding_changed")
    inputs = {"runtime_cache_repair.py": (helper, 0o644),
              "startup_check.py": (base.HELPER.read_bytes(), 0o644),
              "plan.json": (plan_bytes, 0o644),
              "PSF-LICENSE.txt": ((INPUTS / "PSF-LICENSE.txt").read_bytes(), 0o644)}
    for row in plan["baseline"]:
        name = row["package_file"]
        if not re.fullmatch(r"baseline-[A-Za-z0-9_.-]+\.bin", name):
            raise ValueError("repair_baseline_name_changed")
        data = (INPUTS / name).read_bytes()
        if len(data) != row["size"] or base.digest(data) != row["sha256"]:
            raise ValueError("repair_baseline_pin_changed")
        inputs[name] = (data, 0o644)
    info = CHECKER.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or not info.st_mode & 0o111:
        raise ValueError("native_checker_object_changed")
    binary = CHECKER.read_bytes()
    if len(binary) > 512 * 1024 or base.digest(binary) != CHECKER_SHA256:
        raise ValueError("native_checker_pin_changed")
    base.command(["/usr/bin/codesign", "--verify", "--strict", "-R", "=" + CHECKER_REQUIREMENT, str(CHECKER)])
    inputs["runtime-public-plan-check"] = (binary, 0o755)
    return inputs


def postinstall(inputs):
    validations = []
    for name, (data, mode) in sorted(inputs.items()):
        if not re.fullmatch(r"[A-Za-z0-9_.-]+", name):
            raise ValueError("repair_script_name_changed")
        validations.append(f'''check_path "$AC_REPAIR_SCRIPTS/{name}"
[ -f "$AC_REPAIR_SCRIPTS/{name}" ] && [ "$(/usr/bin/stat -f %l "$AC_REPAIR_SCRIPTS/{name}")" = 1 ] || exit 1
[ "$(/usr/bin/stat -f %Lp "$AC_REPAIR_SCRIPTS/{name}")" = {mode:o} ] || exit 1
[ "$(/usr/bin/env -i PATH=/usr/bin:/bin:/usr/sbin:/sbin /usr/bin/shasum -a 256 "$AC_REPAIR_SCRIPTS/{name}" | /usr/bin/awk '{{print $1}}')" = '{base.digest(data)}' ] || exit 1''')
    return f'''#!/bin/sh
set -eu
PATH=/usr/bin:/bin:/usr/sbin:/sbin
export PATH
umask 077
[ "$(/usr/bin/id -u)" = 0 ] && [ "${{3:-}}" = / ] || exit 1
AC_REPAIR_SCRIPTS=$(CDPATH= cd "$(/usr/bin/dirname "$0")" && /bin/pwd -P)
AC_REPAIR_PYTHON='{base.PYTHON}'
AC_REPAIR_REPORTS='{REPORTS}'
check_path() {{
  [ ! -L "$1" ] && [ "$(/usr/bin/stat -f %u "$1")" = 0 ] || exit 1
  permissions=$(/usr/bin/stat -f %p "$1")
  [ "$((0$permissions & 07022))" = 0 ] || exit 1
  listing=$(/bin/ls -lde "$1")
  /usr/bin/printf '%s\\n' "$listing" | /usr/bin/awk 'NR > 1 {{ bad=1 }} END {{ exit bad }}' || exit 1
}}
for path in / /Library /Library/Logs "/Library/Application Support" "/Library/Application Support/Account Access" "/Library/Application Support/Account Access/runtime" "/Library/Application Support/Account Access/runtime/bin" "$AC_REPAIR_PYTHON" "$AC_REPAIR_SCRIPTS"; do
  check_path "$path"
done
{chr(10).join(validations)}
[ -f "$AC_REPAIR_PYTHON" ] && [ -x "$AC_REPAIR_PYTHON" ] && [ "$(/usr/bin/stat -f %l "$AC_REPAIR_PYTHON")" = 1 ] || exit 1
[ "$(/usr/bin/env -i PATH=/usr/bin:/bin:/usr/sbin:/sbin /usr/bin/shasum -a 256 "$AC_REPAIR_PYTHON" | /usr/bin/awk '{{print $1}}')" = '{base.PYTHON_SHA256}' ] || exit 1
/usr/bin/env -i PATH=/usr/bin:/bin:/usr/sbin:/sbin /usr/bin/codesign --verify --strict -R '={base.REQUIREMENT}' "$AC_REPAIR_PYTHON" || exit 1
/usr/bin/env -i PATH=/usr/bin:/bin:/usr/sbin:/sbin /usr/bin/codesign --verify --strict -R '={CHECKER_REQUIREMENT}' "$AC_REPAIR_SCRIPTS/runtime-public-plan-check" || exit 1
if [ ! -e "$AC_REPAIR_REPORTS" ] && [ ! -L "$AC_REPAIR_REPORTS" ]; then
  /bin/mkdir -m 755 "$AC_REPAIR_REPORTS"
fi
check_path "$AC_REPAIR_REPORTS"
[ -d "$AC_REPAIR_REPORTS" ] && [ "$(/usr/bin/stat -f %Lp "$AC_REPAIR_REPORTS")" = 755 ] || exit 1
AC_REPAIR_PREFIX=$(/usr/bin/mktemp -d "$AC_REPAIR_REPORTS/bootstrap-XXXXXXXXXXXX")
check_path "$AC_REPAIR_PREFIX"
[ -d "$AC_REPAIR_PREFIX" ] && [ "$(/usr/bin/stat -f %Lp "$AC_REPAIR_PREFIX")" = 700 ] || exit 1
[ -z "$(/bin/ls -A "$AC_REPAIR_PREFIX")" ] || exit 1
# No installed cached module is read. Prefix is exclusive, empty and preserved.
/usr/bin/env -i PATH=/usr/bin:/bin:/usr/sbin:/sbin LANG=C "$AC_REPAIR_PYTHON" -I -B -S -X "pycache_prefix=$AC_REPAIR_PREFIX" "$AC_REPAIR_SCRIPTS/runtime_cache_repair.py" || exit 1
# This fixed signed checker only observes public metadata after a successful repair.
AC_REPAIR_CHECK=$(/usr/bin/mktemp "$AC_REPAIR_REPORTS/public-plan-XXXXXXXXXXXX")
if /usr/bin/env -i PATH=/usr/bin:/bin:/usr/sbin:/sbin LANG=C "$AC_REPAIR_SCRIPTS/runtime-public-plan-check" > "$AC_REPAIR_CHECK"; then
  /bin/chmod 644 "$AC_REPAIR_CHECK"
else
  exit 1
fi
'''.encode()


def build(output, source):
    if os.getuid() == 0 or os.geteuid() == 0 or sys.platform != "darwin":
        raise ValueError("ordinary_macos_builder_required")
    if output.exists():
        raise ValueError("repair_output_already_exists")
    source_files = review_source(source)
    python = base.review_installed_python()
    inputs = reviewed_inputs()
    inputs["postinstall"] = (postinstall(inputs), 0o755)
    output.mkdir(parents=True, mode=0o700)
    scripts = output / "scripts"
    scripts.mkdir(mode=0o700)
    for name, (data, mode) in inputs.items():
        path = scripts / name
        path.write_bytes(data)
        path.chmod(mode)
    base.command(["/bin/sh", "-n", str(scripts / "postinstall")])
    expected = base.snapshot_scripts(scripts)
    package = output / PACKAGE_NAME
    result = base.command(["/usr/bin/pkgbuild", "--nopayload", "--identifier", IDENTIFIER,
                           "--version", "0.1.0", "--scripts", str(scripts), str(package)])
    (output / "pkgbuild.log").write_bytes(result.stdout + result.stderr)
    expanded = output / "expanded"
    base.command(["/usr/sbin/pkgutil", "--expand-full", str(package), str(expanded)])
    actual = base.snapshot_scripts(expanded / "Scripts")
    if actual != expected or (expanded / "Payload").exists():
        raise ValueError("repair_package_inputs_changed")
    package_info = (expanded / "PackageInfo").read_bytes()
    info = ET.fromstring(package_info)
    if info.get("identifier") != IDENTIFIER or info.get("version") != "0.1.0":
        raise ValueError("repair_package_identity_changed")
    payload = info.find("payload")
    if payload is not None and any(int(payload.get(key, "0")) for key in ("numberOfFiles", "installKBytes")):
        raise ValueError("repair_package_has_payload")
    signature = subprocess.run(["/usr/sbin/pkgutil", "--check-signature", str(package)],
                               capture_output=True, stdin=subprocess.DEVNULL, env=base.ENV, timeout=120)
    if b"no signature" not in (signature.stdout + signature.stderr).lower():
        raise ValueError("repair_unsigned_status_unexpected")
    if review_source(source) != source_files or reviewed_inputs() != {k: v for k, v in inputs.items() if k != "postinstall"}:
        raise ValueError("repair_inputs_changed_during_build")
    record = {
        "schema": 1, "status": "ASSEMBLED_AND_EXPANSION_REVIEWED", "not_installed": True,
        "source_commit": source, "source_files": source_files,
        "package": str(package), "package_sha256": base.digest(package.read_bytes()),
        "package_size": package.stat().st_size, "unsigned": True, "nopayload": True,
        "identifier": IDENTIFIER, "scripts": expected, "expanded_scripts": actual,
        "package_info_sha256": base.digest(package_info), "installed_python": python,
        "native_checker_sha256": CHECKER_SHA256, "native_checker_requirement": CHECKER_REQUIREMENT,
        "target_build": 76, "baseline_files": 3, "extra_cache_directories": 8,
        "automatic_crash_recovery": False, "journal_recovery": "manual_review_only",
        "helper_executed": False, "root_execution": False, "owner_data_read": False,
        "service_start_stop_permitted": False, "default_stdout_cleanup_permitted": False,
    }
    (output / "review.json").write_text(json.dumps(record, sort_keys=True, indent=2) + "\n")
    print(json.dumps(record, sort_keys=True))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", required=True)
    parser.add_argument("--output", type=Path, default=ROOT / "dist/qa-runtime-cache-repair-76/package")
    args = parser.parse_args()
    build(args.output.resolve(), args.source)


if __name__ == "__main__":
    main()
