"""Inspect immutable build copies; never execute or sign supplied runtime code.

Developer-ID preparation, notarization and installed-runtime acceptance are
separate steps. Development inventory never represents publisher acceptance.
"""

import os
from pathlib import Path
import re
import shutil
import stat
import struct
import tempfile
import unicodedata
import zipfile


THIN = {
    b"\xce\xfa\xed\xfe": ("<", 28),
    b"\xcf\xfa\xed\xfe": ("<", 32),
    b"\xfe\xed\xfa\xce": (">", 28),
    b"\xfe\xed\xfa\xcf": (">", 32),
}
FAT = {
    b"\xca\xfe\xba\xbe": (">", 20),
    b"\xbe\xba\xfe\xca": ("<", 20),
    b"\xca\xfe\xba\xbf": (">", 32),
    b"\xbf\xba\xfe\xca": ("<", 32),
}
MAGIC = set(THIN) | set(FAT)
MAX_BINARY = 512 * 1024 * 1024
MAX_WHEEL = 2 * 1024 * 1024 * 1024
BUNDLES = {".app", ".framework", ".xpc", ".bundle"}
REQUIREMENT = (
    "anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] exists "
    "and certificate leaf[field.1.2.840.113635.100.6.1.13] exists "
    'and !(entitlement["com.apple.security.get-task-allow"] exists)'
)


def binary_type(path):
    """Return a runtime Mach-O file type, or None for data/static object files."""
    size = path.stat().st_size
    with path.open("rb") as stream:
        magic = stream.read(4)
        if magic not in MAGIC:
            return None
        if size > MAX_BINARY:
            raise ValueError("native_payload_too_large")

        def thin(offset, length):
            stream.seek(offset)
            header = stream.read(min(length, 32))
            rule = THIN.get(header[:4])
            if rule is None or len(header) < rule[1]:
                raise ValueError("invalid_native_payload")
            return struct.unpack_from(rule[0] + "I", header, 12)[0]

        if magic in THIN:
            kinds = {thin(0, size)}
        else:
            endian, entry_size = FAT[magic]
            count_raw = stream.read(4)
            if len(count_raw) != 4:
                raise ValueError("invalid_native_payload")
            count = struct.unpack(endian + "I", count_raw)[0]
            if not 1 <= count <= 8:
                raise ValueError("invalid_native_payload")
            entries = stream.read(entry_size * count)
            if len(entries) != entry_size * count:
                raise ValueError("invalid_native_payload")
            ranges = []
            for index in range(count):
                offset, length = struct.unpack_from(
                    endian + ("II" if entry_size == 20 else "QQ"),
                    entries,
                    index * entry_size + 8,
                )
                if offset < 8 + len(entries) or length < 28 or offset + length > size:
                    raise ValueError("invalid_native_payload")
                ranges.append((offset, offset + length))
            ordered = sorted(ranges)
            if any(left[1] > right[0] for left, right in zip(ordered, ordered[1:])):
                raise ValueError("invalid_native_payload")
            kinds = {thin(start, end - start) for start, end in ranges}
        if len(kinds) != 1:
            raise ValueError("mixed_native_payload_types")
        kind = kinds.pop()
        if kind in {1, 10}:  # MH_OBJECT and MH_DSYM are not loadable runtime code.
            return None
        if kind not in {2, 6, 8}:  # MH_EXECUTE, MH_DYLIB, MH_BUNDLE.
            raise ValueError("unsupported_native_payload_type")
        return kind


def verify_code(path, kind, architecture, command):
    result = command(["/usr/bin/lipo", "-archs", str(path)])
    if len(result.stdout) > 1024:
        raise ValueError("native_payload_metadata_limit")
    architectures = result.stdout.decode().split()
    if (
        not architectures
        or len(architectures) != len(set(architectures))
        or not set(architectures) <= {"arm64", "x86_64"}
        or architecture not in architectures
    ):
        raise ValueError("native_payload_architecture_mismatch")
    command(
        [
            "/usr/bin/codesign",
            "--verify",
            "--strict",
            "--all-architectures",
            "-R=" + REQUIREMENT,
            str(path),
        ]
    )
    teams = set()
    for arch in architectures:
        result = command(["/usr/bin/codesign", "-d", "--verbose=4", "--arch", arch, str(path)])
        if len(result.stdout) + len(result.stderr) > 65536:
            raise ValueError("native_payload_metadata_limit")
        text = (result.stdout + result.stderr).decode("utf-8", errors="strict")

        def field(name):
            values = re.findall(r"^" + re.escape(name) + r"=(.+)$", text, re.MULTILINE)
            return values[0].strip() if len(values) == 1 else ""

        flags = re.findall(r"\bflags=0x([0-9a-fA-F]+)", text)
        team = field("TeamIdentifier")
        if (
            re.fullmatch(r"[A-Z0-9]{10}", team) is None
            or not re.search(r"^Authority=Developer ID Application:", text, re.MULTILINE)
            or field("Timestamp") in {"", "none"}
            or re.fullmatch(r"[a-f0-9]{40}", field("CDHash")) is None
            or (kind == 2 and (len(flags) != 1 or not int(flags[0], 16) & 0x10000))
        ):
            raise ValueError("native_publisher_runtime_timestamp_required")
        teams.add(team)
    if len(teams) != 1:
        raise ValueError("native_payload_publishers_disagree")


def canonical_root(root):
    root = Path(root).absolute()
    if root.is_symlink():
        raise ValueError("unsafe_native_payload_path")
    # macOS's /tmp and /var are ordinary ancestor aliases. Compare every child
    # against the same canonical root, while refusing a redirected input itself.
    return root.resolve(strict=True)


def tree_files(root):
    root = canonical_root(root)
    if root.stat().st_mode & 0o6000:
        raise ValueError("privileged_payload_mode_refused")
    if root.is_file():
        yield root
        return
    if not root.is_dir():
        raise ValueError("unsafe_native_payload_path")
    count = 0
    for folder, directories, files in os.walk(root, followlinks=False):
        for name in directories + files:
            count += 1
            if count > 100_000:
                raise ValueError("native_payload_file_limit")
            path = Path(folder) / name
            info = path.lstat()
            if not stat.S_ISLNK(info.st_mode) and info.st_mode & 0o6000:
                raise ValueError("privileged_payload_mode_refused")
            if stat.S_ISLNK(info.st_mode):
                # Framework and Python aliases may point only within this input.
                if not path.resolve(strict=True).is_relative_to(root):
                    raise ValueError("unsafe_native_payload_symlink")
                continue
            if stat.S_ISREG(info.st_mode):
                yield path
            elif not stat.S_ISDIR(info.st_mode):
                raise ValueError("unsafe_native_payload_file_type")


def wheel_entries(archive):
    entries = archive.infolist()
    if len(entries) > 20_000 or sum(entry.file_size for entry in entries) > MAX_WHEEL:
        raise ValueError("native_wheel_size_limit")
    seen = set()
    for entry in entries:
        name = entry.filename.rstrip("/")
        parts = name.split("/")
        key = unicodedata.normalize("NFC", name).casefold()
        mode = stat.S_IFMT(entry.external_attr >> 16)
        if (
            not name
            or "\\" in name
            or "\0" in entry.orig_filename
            or any(part in {"", ".", ".."} for part in parts)
            or key in seen
            or entry.flag_bits & 1
            or (entry.external_attr >> 16) & 0o6000
            or mode not in {0, stat.S_IFREG, stat.S_IFDIR}
        ):
            raise ValueError("unsafe_native_wheel_entry")
        seen.add(key)
        if any(Path(part).suffix.lower() in BUNDLES for part in parts[:-1]):
            raise ValueError("native_wheel_bundle_requires_preparation")
        if not entry.is_dir():
            yield entry


def audit_payload(roots, wheels, architecture, command, *, development):
    if architecture not in {"arm64", "x86_64"}:
        raise ValueError("unsupported_payload_architecture")
    native = executables = 0
    bundles = set()

    def inspect(path):
        nonlocal native, executables
        kind = binary_type(path)
        if kind is not None:
            native += 1
            executables += kind == 2
            if not development:
                verify_code(path, kind, architecture, command)
        return kind

    for root in roots:
        root = canonical_root(root)
        for path in tree_files(root):
            if inspect(path) is not None:
                for parent in path.parents:
                    if not parent.is_relative_to(root):
                        break
                    if parent.suffix.lower() in BUNDLES:
                        bundles.add(parent)
                    if parent == root:
                        break
    # Never extract archive paths into a filesystem tree. Selected native files
    # get generated names; wheel traversal/symlink/collision checks apply to all
    # entries, including non-native files the installer would later unpack.
    with tempfile.TemporaryDirectory(prefix="account-access-native-audit-") as temporary:
        for wheel in wheels:
            with zipfile.ZipFile(wheel) as archive:
                for index, entry in enumerate(wheel_entries(archive)):
                    with archive.open(entry) as incoming:
                        if incoming.read(4) not in MAGIC:
                            continue
                    if entry.file_size > MAX_BINARY:
                        raise ValueError("native_payload_too_large")
                    path = Path(temporary) / ("native-" + str(index))
                    with archive.open(entry) as incoming, path.open("wb") as target:
                        shutil.copyfileobj(incoming, target)
                    inspect(path)
                    path.unlink()
    if not development:
        for bundle in sorted(bundles, key=lambda path: len(path.parts), reverse=True):
            command(
                [
                    "/usr/bin/codesign",
                    "--verify",
                    "--deep",
                    "--strict",
                    "--all-architectures",
                    str(bundle),
                ]
            )
    return {
        "native_files": native,
        "executables": executables,
        "bundles": len(bundles),
        "wheels": len(wheels),
        "publisher_signatures_verified": not development,
        "notarization_verified": False,
    }
