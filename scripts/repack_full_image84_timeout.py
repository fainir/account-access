"""Prepare an uninstalled deadline-only derivative of the exact reviewed package.

Runs as an ordinary user. It changes one PackageInfo attribute and preserves the
compressed Scripts member byte-for-byte. It never executes Installer or helpers.
The derivative still requires independent review and actual Installer acceptance.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import xml.etree.ElementTree as ET

BASE_SHA = "de6769837c00f41e307b5342ab86021c6e2aac27ba7fd99914f670ab2bd99d95"
BASE_BYTES = 295994062
IDENTIFIER = "com.fainir.accountaccess.fullimageupdate84"
DEADLINE = 1800
ENV = {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LANG": "C", "LC_ALL": "C"}


def require(value):
    if not value:
        raise ValueError("deadline_repack_refused")


def guard():
    require(sys.platform == "darwin" and os.getuid() == os.geteuid() != 0)


def fingerprint(path, maximum=512 * 1024**2):
    def stable(info):
        return (info.st_dev, info.st_ino, info.st_uid, info.st_gid, info.st_mode,
                info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and before.st_uid == os.getuid()
                and before.st_nlink == 1 and 0 <= before.st_size <= maximum)
        digest = hashlib.sha256()
        total = 0
        while chunk := os.read(fd, 1024**2):
            total += len(chunk)
            require(total <= maximum)
            digest.update(chunk)
        after = os.fstat(fd)
        require(stable(before) == stable(after) == stable(path.lstat()) and total == before.st_size)
        return {"sha256": digest.hexdigest(), "bytes": total, "mode": stat.S_IMODE(before.st_mode)}
    finally:
        os.close(fd)


def extend_deadline(raw):
    require(type(raw) is bytes and len(raw) <= 65536 and b"<!" not in raw)
    info = ET.fromstring(raw)
    require(info.tag == "pkg-info" and info.get("identifier") == IDENTIFIER
            and info.get("version") == "0.1.0" and info.get("auth") == "root")
    payload = info.find("payload")
    require(payload is None or (not len(payload) and payload.attrib == {"numberOfFiles": "0", "installKBytes": "0"}))
    scripts = info.findall("scripts")
    require(len(scripts) == 1 and not scripts[0].attrib and len(scripts[0]) == 1
            and scripts[0][0].tag == "postinstall" and not len(scripts[0][0])
            and scripts[0][0].attrib == {"file": "./postinstall", "timeout": "600"}
            and raw.count(b'timeout="600"') == 1)
    changed = raw.replace(b'timeout="600"', b'timeout="1800"')
    after = ET.fromstring(changed)
    after.find("scripts/postinstall").set("timeout", "600")
    require(ET.tostring(after) == ET.tostring(info))
    return changed


def run(base, output):
    guard()
    root = Path(__file__).resolve().parents[1]
    parent = root / "dist/qa-full-image84-timeout"
    require(output.parent == parent and output.name.startswith("build-v")
            and output.name.removeprefix("build-v").isdigit() and base.is_absolute())
    for ancestor in (root, root / "dist"):
        require(stat.S_ISDIR(ancestor.lstat().st_mode) and ancestor.lstat().st_uid == os.getuid())
    source = fingerprint(base)
    require(source["sha256"] == BASE_SHA and source["bytes"] == BASE_BYTES)
    parent.mkdir(mode=0o700, exist_ok=True)
    require(stat.S_ISDIR(parent.lstat().st_mode) and parent.lstat().st_uid == os.getuid())
    output.mkdir(mode=0o700)  # Refuse existing destinations and retain failed attempts.
    report = {"schema": 1, "status": "FAILED", "failure_stage": "source_archive",
        "parent_package_sha256": BASE_SHA, "parent_package_bytes": BASE_BYTES,
        "old_timeout_seconds": 600, "new_timeout_seconds": DEADLINE,
        "repacker_sha256": fingerprint(Path(__file__), maximum=65536)["sha256"],
        "installed_or_helper_executed": False, "owner_data_read": False,
        "actual_installer_qualified": False, "production_ready": False, "commands": {}}

    def command(name, arguments, *, cwd=None, expected=0):
        result = subprocess.run(arguments, cwd=cwd, env=ENV, stdin=subprocess.DEVNULL,
                                capture_output=True, timeout=300, check=False)
        require(len(result.stdout) + len(result.stderr) <= 65536)
        report["commands"][name] = {"returncode": result.returncode,
            "stdout_sha256": hashlib.sha256(result.stdout).hexdigest(),
            "stderr_sha256": hashlib.sha256(result.stderr).hexdigest()}
        require(result.returncode == expected)
        return result

    try:
        listing = command("list-parent", ["/usr/bin/xar", "-tf", str(base)]).stdout.splitlines()
        require(len(listing) == 2 and set(listing) == {b"PackageInfo", b"Scripts"})
        raw = output / "original-members"
        raw.mkdir(mode=0o700)
        command("extract-parent", ["/usr/bin/xar", "-xf", str(base), "-C", str(raw)])
        require({path.name for path in raw.iterdir()} == {"PackageInfo", "Scripts"})
        archive = fingerprint(raw / "Scripts")
        info_record = fingerprint(raw / "PackageInfo", maximum=65536)
        info = (raw / "PackageInfo").read_bytes()
        require(hashlib.sha256(info).hexdigest() == info_record["sha256"])
        changed = extend_deadline(info)
        report["failure_stage"] = "candidate_archive"
        (output / "original-PackageInfo.xml").write_bytes(info)
        (raw / "PackageInfo").write_bytes(changed)
        package = output / "Account-Access-Update-84-long-deadline-local-unsigned.pkg"
        command("repack", ["/usr/bin/xar", "--compression=none", "-cf", str(package),
                           "PackageInfo", "Scripts"], cwd=raw)
        listing = command("list-candidate", ["/usr/bin/xar", "-tf", str(package)]).stdout.splitlines()
        require(len(listing) == 2 and set(listing) == {b"PackageInfo", b"Scripts"})
        check = output / "candidate-members"
        check.mkdir(mode=0o700)
        command("extract-candidate", ["/usr/bin/xar", "-xf", str(package), "-C", str(check)])
        require({path.name for path in check.iterdir()} == {"PackageInfo", "Scripts"}
                and fingerprint(check / "Scripts") == archive
                and fingerprint(raw / "Scripts") == archive
                and (check / "PackageInfo").read_bytes() == changed
                and fingerprint(base) == source)
        signature = command("unsigned-container", ["/usr/sbin/pkgutil", "--check-signature", str(package)], expected=1)
        require(b"no signature" in (signature.stdout + signature.stderr).lower())
        candidate = fingerprint(package)
        report.update(status="REPACKED_REQUIRES_INDEPENDENT_REVIEW_AND_INSTALLER_QA", failure_stage=None,
            package_sha256=candidate["sha256"], package_bytes=candidate["bytes"],
            script_archive_sha256=archive["sha256"], script_archive_bytes=archive["bytes"],
            compressed_scripts_unchanged=True, only_timeout_attribute_changed=True,
            package_info_before_sha256=info_record["sha256"],
            package_info_after_sha256=hashlib.sha256(changed).hexdigest())
    except Exception:
        pass
    finally:
        with (output / "review.json").open("x") as stream:
            json.dump(report, stream, indent=2, sort_keys=True)
            stream.write("\n")
    print(json.dumps(report))
    return 0 if report["failure_stage"] is None else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    return run(args.base, args.output)


if __name__ == "__main__":
    raise SystemExit(main())
