"""Maintainer signing of private build copies with original-wheel provenance.

No source input is modified. This module neither installs a service nor accesses
an account vault. A receipt records transformations; it is not notarization or
installed-runtime acceptance.
"""

import csv
import base64
import hashlib
import io
import json
import os
from pathlib import Path
import plistlib
import re
import shutil
import stat
import sys
import tempfile
import zipfile

from .payload_audit import BUNDLES, binary_type, canonical_root, tree_files, wheel_entries


ENTITLEMENTS = {
    "com.apple.security.cs.allow-jit",
    "com.apple.security.cs.allow-unsigned-executable-memory",
    "com.apple.security.cs.disable-library-validation",
}


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def tree_digest(root):
    root = canonical_root(root)
    list(tree_files(root))  # Apply the same alias/type/size-of-tree bounds first.
    values = []
    for directory, folders, files in os.walk(root, followlinks=False):
        for name in folders + files:
            path = Path(directory) / name
            info = path.lstat()
            kind = "link" if path.is_symlink() else "file" if path.is_file() else "directory"
            content = (
                os.readlink(path) if kind == "link" else digest(path) if kind == "file" else ""
            )
            values.append(
                [path.relative_to(root).as_posix(), kind, stat.S_IMODE(info.st_mode), content]
            )
    return hashlib.sha256(json.dumps(sorted(values), separators=(",", ":")).encode()).hexdigest()


def build_stage(payload):
    if sys.platform != "darwin" or os.getuid() == 0 or os.getuid() != os.geteuid():
        raise ValueError("ordinary_mac_runtime_preparation_required")
    payload = canonical_root(payload)
    base = Path(tempfile.gettempdir()).resolve(strict=True)
    try:
        relative = payload.relative_to(base)
    except ValueError:
        raise ValueError("private_package_build_copy_required") from None
    if not relative.parts or not relative.parts[0].startswith("account-access-system-package-"):
        raise ValueError("private_package_build_copy_required")
    scratch = base / relative.parts[0]
    info = scratch.stat()
    if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
        raise ValueError("private_package_build_copy_required")
    return payload


def bundle_main(bundle):
    locations = (
        [bundle / "Resources/Info.plist"]
        if bundle.suffix.lower() == ".framework"
        else [bundle / "Contents/Info.plist"]
    )
    for info in locations:
        if info.is_file():
            if info.stat().st_size > 1_000_000:
                raise ValueError("runtime_bundle_identity_required")
            data = plistlib.loads(info.read_bytes())
            name = data.get("CFBundleExecutable")
            identifier = data.get("CFBundleIdentifier")
            if (
                type(name) is not str
                or not name
                or any(c in name for c in "/\\\0")
                or type(identifier) is not str
                or re.fullmatch(r"[A-Za-z0-9.-]+", identifier) is None
            ):
                raise ValueError("runtime_bundle_identity_required")
            executable = (
                bundle / name
                if bundle.suffix.lower() == ".framework"
                else bundle / "Contents/MacOS" / name
            )
            executable = executable.resolve(strict=True)
            if not executable.is_relative_to(bundle):
                raise ValueError("unsafe_runtime_bundle_executable")
            return executable, identifier
    raise ValueError("runtime_bundle_identity_required")


def unpack_wheel(source, destination):
    with zipfile.ZipFile(source) as archive:
        entries = list(wheel_entries(archive))
        for entry in entries:
            target = destination / entry.filename
            target.parent.mkdir(parents=True, exist_ok=True)
            with archive.open(entry) as incoming, target.open("xb") as outgoing:
                # Validated ZIP sizes bound every copy; ZipFile verifies CRCs.
                shutil.copyfileobj(incoming, outgoing)
            target.chmod((entry.external_attr >> 16) & 0o777 or 0o644)
        return archive.infolist()


def record_path(entries):
    records = [entry.filename for entry in entries if entry.filename.endswith(".dist-info/RECORD")]
    if len(records) != 1:
        raise ValueError("runtime_wheel_record_required")
    return records[0]


def repack_wheel(target, directory, entries):
    record = record_path(entries)
    removed = {record + suffix for suffix in [".jws", ".p7s"]}
    files = [entry for entry in entries if not entry.is_dir() and entry.filename not in removed]
    text = io.StringIO(newline="")
    writer = csv.writer(text, lineterminator="\n")
    for entry in sorted(files, key=lambda value: value.filename):
        path = directory / entry.filename
        if entry.filename == record:
            writer.writerow([record, "", ""])
        else:
            checksum = base64.urlsafe_b64encode(bytes.fromhex(digest(path))).decode().rstrip("=")
            writer.writerow([entry.filename, "sha256=" + checksum, path.stat().st_size])
    (directory / record).write_text(text.getvalue(), newline="")
    replacement = target.with_suffix(".prepared")
    with zipfile.ZipFile(replacement, "x", compression=zipfile.ZIP_DEFLATED) as archive:
        for entry in entries:
            if entry.filename in removed:
                continue
            archive.writestr(
                entry, b"" if entry.is_dir() else (directory / entry.filename).read_bytes()
            )
    os.replace(replacement, target)


def collect(payload, requirements, project_name, project_hash, scratch):
    allowed = set(re.findall(rb"--hash=sha256:([a-f0-9]{64})", requirements))
    originals, pieces, bundles, wheels, labels = {}, {}, set(), [], {}
    for root in [payload / "python", payload / "browsers"]:
        for path in tree_files(root):
            if path.stat().st_nlink != 1:
                raise ValueError("runtime_copy_must_not_share_source_inodes")
            kind = binary_type(path)
            if kind is None:
                continue
            pieces[path] = (kind, digest(path))
            labels[path] = root.name + "/" + path.relative_to(root).as_posix()
            for parent in path.parents:
                if not parent.is_relative_to(root):
                    break
                if parent.suffix.lower() in BUNDLES:
                    bundles.add(parent)
                if parent == root:
                    break
    wheel_root = canonical_root(payload / "wheels")
    if not wheel_root.is_relative_to(payload):
        raise ValueError("runtime_wheelhouse_must_be_private_copy")
    for index, wheel in enumerate(sorted(wheel_root.glob("*.whl"))):
        if wheel.is_symlink() or not wheel.is_file() or wheel.stat().st_nlink != 1:
            raise ValueError("runtime_wheel_must_be_private_copy")
        checksum = digest(wheel)
        if wheel.name == project_name:
            if checksum != project_hash:
                raise ValueError("runtime_project_wheel_changed")
            continue  # The app-pinned project wheel remains byte-for-byte intact.
        if checksum.encode() not in allowed:
            raise ValueError("runtime_wheel_not_in_original_lock")
        if checksum in originals.values():
            raise ValueError("duplicate_runtime_wheel_artifact")
        originals[wheel.name] = checksum
        directory = scratch / ("wheel-" + str(index))
        directory.mkdir()
        entries = unpack_wheel(wheel, directory)
        native = []
        for path in tree_files(directory):
            kind = binary_type(path)
            if kind is not None:
                pieces[path] = (kind, digest(path))
                labels[path] = "wheels/" + wheel.name + "/" + path.relative_to(directory).as_posix()
                native.append(path)
        if native:
            record_path(entries)
        wheels.append((wheel, directory, entries, native))
    return originals, pieces, bundles, wheels, labels


def executable_plan(pieces, labels):
    result = {}
    for path, (kind, checksum) in pieces.items():
        if kind == 2:
            result.setdefault(checksum, {"paths": [], "entitlements": {}})["paths"].append(
                labels[path]
            )
    for value in result.values():
        value["paths"].sort()
    return result


def preparation_plan(payload, requirements, project_name, project_hash):
    payload = build_stage(payload)
    with tempfile.TemporaryDirectory(prefix="runtime-inspect-", dir=payload.parent) as temporary:
        _, pieces, _, _, labels = collect(
            payload, requirements, project_name, project_hash, Path(temporary)
        )
    return {
        "schema": 1,
        "python_sha256": tree_digest(payload / "python"),
        "browsers_sha256": tree_digest(payload / "browsers"),
        "executables": executable_plan(pieces, labels),
    }


def prepare(
    payload, requirements, project_name, project_hash, identity, team, plan, command, *, development
):
    payload = build_stage(payload)
    if (development and (identity != "-" or team != "fixture")) or (
        not development
        and (not identity or identity == "-" or re.fullmatch(r"[A-Z0-9]{10}", team) is None)
    ):
        raise ValueError("matching_runtime_signing_identity_required")
    if (
        type(plan) is not dict
        or set(plan) != {"schema", "python_sha256", "browsers_sha256", "executables"}
        or type(plan["schema"]) is not int
        or plan["schema"] != 1
        or type(plan["executables"]) is not dict
    ):
        raise ValueError("invalid_runtime_signing_plan")
    roots = [payload / "python", payload / "browsers"]
    original_trees = {root.name: tree_digest(root) for root in roots}
    for name, value in original_trees.items():
        if plan[name + "_sha256"] != value:
            raise ValueError("runtime_source_plan_changed")
    for checksum, value in plan["executables"].items():
        if (
            type(checksum) is not str
            or re.fullmatch(r"[a-f0-9]{64}", checksum) is None
            or type(value) is not dict
            or set(value) != {"paths", "entitlements"}
            or type(value["paths"]) is not list
            or any(type(path) is not str for path in value["paths"])
            or type(value["entitlements"]) is not dict
            or not set(value["entitlements"]) <= ENTITLEMENTS
            or any(flag is not True for flag in value["entitlements"].values())
        ):
            raise ValueError("invalid_runtime_entitlement_plan")
    with tempfile.TemporaryDirectory(prefix="runtime-signing-", dir=payload.parent) as temporary:
        scratch = Path(temporary)
        originals, pieces, bundles, wheels, labels = collect(
            payload, requirements, project_name, project_hash, scratch
        )
        observed = executable_plan(pieces, labels)
        if set(observed) != set(plan["executables"]) or any(
            observed[key]["paths"] != plan["executables"][key]["paths"] for key in observed
        ):
            raise ValueError("runtime_executable_plan_changed")
        # Resolve and bind every bundle main before modifying any code.
        mains = {bundle: bundle_main(bundle) for bundle in bundles}
        if any(main not in pieces for main, _ in mains.values()):
            raise ValueError("runtime_bundle_main_not_in_inventory")

        def sign(path, kind, checksum, identifier):
            entitlements = plan["executables"][checksum]["entitlements"] if kind == 2 else {}
            entitlement_file = scratch / "entitlements.plist"
            entitlement_file.write_bytes(plistlib.dumps(entitlements))
            arguments = [
                "/usr/bin/codesign",
                "--force",
                "--sign",
                identity,
                "--timestamp=none" if development else "--timestamp",
                "--identifier",
                identifier,
                "--entitlements",
                str(entitlement_file),
            ]
            if kind == 2:
                arguments += ["--options", "runtime"]
            command(arguments + [str(path)])
            command(
                [
                    "/usr/bin/codesign",
                    "--verify",
                    "--strict",
                    "--all-architectures",
                    '-R=!(entitlement["com.apple.security.get-task-allow"] exists)',
                    str(path),
                ]
            )
            result = command(["/usr/bin/codesign", "-d", "--verbose=4", str(path)])
            metadata = result.stdout + result.stderr
            if len(metadata) > 65536:
                raise ValueError("runtime_signature_metadata_limit")
            found = re.findall(rb"^TeamIdentifier=(.+)$", metadata, re.MULTILINE)
            if found != [b"not set" if development else team.encode()]:
                raise ValueError("runtime_signing_publisher_mismatch")

        for path, (kind, checksum) in pieces.items():
            sign(path, kind, checksum, "com.fainir.accountaccess.runtime." + checksum[:20])
        for bundle in sorted(bundles, key=lambda path: len(path.parts), reverse=True):
            main, identifier = mains[bundle]
            sign(bundle, *pieces[main], identifier)
        for wheel, directory, entries, native in wheels:
            if native:
                repack_wheel(wheel, directory, entries)
        replacements = {originals[wheel.name]: digest(wheel) for wheel, *_ in wheels}
    derived = re.sub(
        rb"--hash=sha256:([a-f0-9]{64})",
        lambda match: (
            b"--hash=sha256:" + replacements.get(match[1].decode(), match[1].decode()).encode()
        ),
        requirements,
    )
    receipt = {
        "schema": 1,
        "development": development,
        "publisher_team": team,
        "transform": "account-access-native-signing-and-wheel-record-v1",
        "native_files_signed": len(pieces),
        "bundle_seals_signed": len(bundles),
        "notarization_verified": False,
        "installed_runtime_verified": False,
        "signing_plan_sha256": hashlib.sha256(
            json.dumps(plan, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest(),
        "source_trees": original_trees,
        "prepared_trees": {root.name: tree_digest(root) for root in roots},
        "wheels": [
            {
                "filename": name,
                "original_sha256": checksum,
                "prepared_sha256": replacements[checksum],
            }
            for name, checksum in originals.items()
        ],
        "original_requirements_sha256": hashlib.sha256(requirements).hexdigest(),
        "prepared_requirements_sha256": hashlib.sha256(derived).hexdigest(),
    }
    return derived, receipt
