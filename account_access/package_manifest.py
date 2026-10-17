"""Bind a package's public payload for subsequent unfinished-install recovery.

This only inventories the assembler's private copies. It neither installs code
nor authorizes replacing an existing installation or deleting account data.
"""

import hashlib
import json
import os
from pathlib import Path
import stat
import unicodedata

MAX_ENTRIES = 100_000
MAX_FILE_BYTES = 1024 * 1024 * 1024
MAX_TOTAL_BYTES = 8 * MAX_FILE_BYTES
MAX_MANIFEST_BYTES = 16 * 1024 * 1024
SUPPORT = Path("Library/Application Support/Account Access")
OWNER_APP = Path("Applications/Account Access.app")


def canonical_root(root):
    root = Path(root).absolute()
    if root.is_symlink():
        raise ValueError("unsafe_install_manifest_root")
    return root.resolve(strict=True)


def _name(path, root):
    value = path.relative_to(root).as_posix()
    if (
        len(value.encode("utf-8")) > 4096
        or "\\" in value
        or ":" in value
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
        or any(part in {"", ".", ".."} for part in path.relative_to(root).parts)
    ):
        raise ValueError("unsafe_install_manifest_name")
    return value


def _stamp(info):
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def _alias(path, root):
    target = os.readlink(path)
    current, pending, links = path.parent, list(Path(target).parts), 0
    if os.path.isabs(target) or len(target.encode("utf-8")) > 4096:
        raise ValueError("unsafe_install_manifest_alias")
    while pending:
        part = pending.pop(0)
        if part == ".":
            continue
        if part == "..":
            if current == root:
                raise ValueError("unsafe_install_manifest_alias")
            current = current.parent
            continue
        candidate = current / part
        if candidate.is_symlink():
            links += 1
            value = os.readlink(candidate)
            if os.path.isabs(value) or links > 40:
                raise ValueError("unsafe_install_manifest_alias")
            pending = list(Path(value).parts) + pending
        else:
            info = candidate.lstat()  # Missing and cyclic aliases cannot be shipped.
            if pending and not stat.S_ISDIR(info.st_mode):
                raise ValueError("unsafe_install_manifest_alias")
            current = candidate
    if any(ord(character) < 32 or ord(character) == 127 for character in target):
        raise ValueError("unsafe_install_manifest_alias")
    return target


def _file(path, expected):
    if expected.st_nlink != 1 or expected.st_size > MAX_FILE_BYTES:
        raise ValueError("unsafe_install_manifest_file")
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as stream:
        before = os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode) or _stamp(before) != _stamp(expected):
            raise ValueError("install_manifest_payload_changed")
        checksum = hashlib.sha256()
        remaining = before.st_size
        while remaining:
            block = stream.read(min(1024 * 1024, remaining))
            if not block:
                raise ValueError("install_manifest_payload_changed")
            checksum.update(block)
            remaining -= len(block)
        if stream.read(1):
            raise ValueError("install_manifest_payload_changed")
        if _stamp(os.fstat(stream.fileno())) != _stamp(before):
            raise ValueError("install_manifest_payload_changed")
    return {
        "kind": "file",
        "size": before.st_size,
        "sha256": checksum.hexdigest(),
        "mode": stat.S_IMODE(before.st_mode),
    }


def inventory(root):
    root = canonical_root(root)
    if not root.is_dir():
        raise ValueError("install_manifest_directory_required")
    rows, names, total = {}, set(), 0
    # Do not descend into aliases. They are recorded as aliases and may resolve
    # only inside this exact payload root, including their intermediate links.
    pending = [root]
    while pending:
        path = pending.pop()
        name = "" if path == root else _name(path, root)
        folded = unicodedata.normalize("NFC", name).casefold()
        if folded in names or len(rows) >= MAX_ENTRIES:
            raise ValueError("install_manifest_collision_or_limit")
        names.add(folded)
        info = path.lstat()
        if (info.st_uid != os.getuid() or info.st_mode & 0o6000
                or not stat.S_ISLNK(info.st_mode) and info.st_mode & 0o022):
            raise ValueError("unsafe_install_manifest_object")
        if stat.S_ISLNK(info.st_mode):
            try:
                target = _alias(path, root)
            except (OSError, RuntimeError):
                raise ValueError("unsafe_install_manifest_alias") from None
            rows[name] = {"kind": "symlink", "target": target}
        elif stat.S_ISDIR(info.st_mode):
            rows[name] = {"kind": "directory", "mode": stat.S_IMODE(info.st_mode)}
            pending.extend(sorted(path.iterdir(), reverse=True))
        elif stat.S_ISREG(info.st_mode):
            total += info.st_size
            if total > MAX_TOTAL_BYTES:
                raise ValueError("install_manifest_payload_limit")
            rows[name] = _file(path, info)
        else:
            raise ValueError("unsafe_install_manifest_object")
    return dict(sorted(rows.items()))


def build(root, version, architecture):
    if version != "0.8.0" or architecture not in {"arm64", "x86_64"}:
        raise ValueError("unsupported_install_manifest_package")
    root = canonical_root(root)
    info = root.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o6022:
        raise ValueError("unsafe_install_manifest_root")
    for relative in [SUPPORT, OWNER_APP]:
        current = root
        for part in relative.parts:
            current /= part
            info = current.lstat()
            if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid():
                raise ValueError("unsafe_install_manifest_root")
    value = {
        "managed_by": "account-access-install-payload-v1",
        "schema": 1,
        "package_identifier": "com.fainir.accountaccess.system",
        "version": version,
        "architecture": architecture,
        "roots": {
            "/" + str(SUPPORT): inventory(root / SUPPORT),
            "/" + str(OWNER_APP): inventory(root / OWNER_APP),
        },
    }
    encoded = (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()
    if len(encoded) > MAX_MANIFEST_BYTES:
        raise ValueError("install_manifest_size_limit")
    return encoded
