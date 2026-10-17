"""Non-destructive, descriptor-based recovery of a verified public image.

The native package coordinator supplies a verified source and already-protected
directory handles. This module grants no elevation, account access, deletion or
upgrade permission. The consumer entrypoint accepts no destination overrides.
"""

from contextlib import contextmanager
import ctypes
import errno
import fcntl
import hashlib
import json
import os
import re
import stat
import sys
import unicodedata

from .package_manifest import MAX_ENTRIES, MAX_FILE_BYTES, MAX_MANIFEST_BYTES, MAX_TOTAL_BYTES

SUPPORT = "/Library/Application Support/Account Access"
APPLICATION = "/Applications/Account Access.app"
ROOTS = {SUPPORT: "support", APPLICATION: "application"}
EXTRAS = {"broker", "home", "vault", "run", "control", "owner.json", "install-verification.json"}
DIRECTORY = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
REGULAR = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC


class ImageConflict(Exception):
    """Only fixed reasons may leave the local installer."""


def _integer(value, maximum):
    if type(value) is not int or not 0 <= value <= maximum:
        raise ImageConflict("invalid_image_inventory")
    return value


def _parts(value):
    if (
        type(value) is not str
        or len(value.encode()) > 4096
        or "\\" in value
        or ":" in value
        or any(ord(c) < 32 or ord(c) == 127 for c in value)
    ):
        raise ImageConflict("invalid_image_inventory")
    parts = value.split("/") if value else []
    if len(parts) > 128 or any(p in {"", ".", ".."} for p in parts):
        raise ImageConflict("invalid_image_inventory")
    return parts


class ImageManifest:
    def __init__(self, encoded, expected_digest):
        if (
            type(encoded) is not bytes
            or not 0 < len(encoded) <= MAX_MANIFEST_BYTES
            or type(expected_digest) is not str
            or re.fullmatch(r"[a-f0-9]{64}", expected_digest) is None
            or hashlib.sha256(encoded).hexdigest() != expected_digest
        ):
            raise ImageConflict("invalid_image_inventory")

        def unique(pairs):
            value = {}
            for key, item in pairs:
                if key in value:
                    raise ImageConflict("invalid_image_inventory")
                value[key] = item
            return value

        try:
            value = json.loads(encoded, object_pairs_hook=unique)
            if (
                type(value) is not dict
                or set(value)
                != {
                    "managed_by",
                    "schema",
                    "package_identifier",
                    "version",
                    "architecture",
                    "roots",
                }
                or value["managed_by"] != "account-access-install-payload-v1"
                or type(value["schema"]) is not int
                or value["schema"] != 1
                or value["package_identifier"] != "com.fainir.accountaccess.system"
                or value["version"] != "0.8.0"
                or value["architecture"] != "arm64"
                or type(value["roots"]) is not dict
                or set(value["roots"]) != set(ROOTS)
            ):
                raise ImageConflict("invalid_image_inventory")
            count = total = work = 0
            self.children = {}
            for root, nodes in value["roots"].items():
                if type(nodes) is not dict or nodes.get("", {}).get("kind") != "directory":
                    raise ImageConflict("invalid_image_inventory")
                folded, children = set(), {}
                for name, node in nodes.items():
                    count += 1
                    if count > MAX_ENTRIES or type(node) is not dict:
                        raise ImageConflict("invalid_image_inventory")
                    parts = _parts(name)
                    key = unicodedata.normalize("NFC", name).casefold()
                    if key in folded:
                        raise ImageConflict("invalid_image_inventory")
                    folded.add(key)
                    if parts:
                        parent = "/".join(parts[:-1])
                        if nodes.get(parent, {}).get("kind") != "directory":
                            raise ImageConflict("invalid_image_inventory")
                        children.setdefault(parent, set()).add(parts[-1])
                    kind = node.get("kind")
                    keys = {
                        "directory": {"kind", "mode"},
                        "file": {"kind", "mode", "size", "sha256"},
                        "symlink": {"kind", "target"},
                    }
                    if kind not in keys or set(node) != keys[kind]:
                        raise ImageConflict("invalid_image_inventory")
                    if kind != "symlink":
                        mode = _integer(node["mode"], 0o777)
                        if mode & 0o022:
                            raise ImageConflict("invalid_image_inventory")
                        if kind == "file":
                            total += _integer(node["size"], MAX_FILE_BYTES)
                            if (
                                total > MAX_TOTAL_BYTES
                                or type(node["sha256"]) is not str
                                or re.fullmatch(r"[a-f0-9]{64}", node["sha256"]) is None
                            ):
                                raise ImageConflict("invalid_image_inventory")
                    else:

                        def target_parts(target):
                            if (
                                type(target) is not str
                                or not target
                                or target.startswith("/")
                                or len(target.encode()) > 4096
                                or "\\" in target
                                or ":" in target
                                or any(ord(c) < 32 or ord(c) == 127 for c in target)
                            ):
                                raise ImageConflict("invalid_image_inventory")
                            result = target.split("/")
                            if len(result) > 128:
                                raise ImageConflict("invalid_image_inventory")
                            return result

                        current, pending, cursor, links = (
                            parts[:-1],
                            target_parts(node["target"]),
                            0,
                            0,
                        )
                        while cursor < len(pending):
                            work += 1
                            if work > 1_000_000:
                                raise ImageConflict("invalid_image_inventory")
                            part = pending[cursor]
                            cursor += 1
                            if part in {"", "."}:
                                continue
                            if part == "..":
                                if not current:
                                    raise ImageConflict("invalid_image_inventory")
                                current.pop()
                                continue
                            entry = nodes.get("/".join([*current, part]))
                            if type(entry) is not dict:
                                raise ImageConflict("invalid_image_inventory")
                            if entry.get("kind") == "symlink":
                                links += 1
                                if links > 40:
                                    raise ImageConflict("invalid_image_inventory")
                                pending = target_parts(entry.get("target")) + pending[cursor:]
                                cursor = 0
                            else:
                                current.append(part)
                                if cursor < len(pending) and entry.get("kind") != "directory":
                                    raise ImageConflict("invalid_image_inventory")
                self.children[root] = children
        except (ValueError, TypeError, KeyError, AttributeError, RecursionError):
            raise ImageConflict("invalid_image_inventory") from None
        self.trees, self.digest = value["roots"], expected_digest
        if set(self.children[SUPPORT].get("", set())) & EXTRAS:
            raise ImageConflict("invalid_image_inventory")


def _stamp(info):
    return tuple(
        getattr(info, name)
        for name in [
            "st_dev",
            "st_ino",
            "st_uid",
            "st_gid",
            "st_mode",
            "st_size",
            "st_nlink",
            "st_mtime_ns",
            "st_ctime_ns",
        ]
    )


def _acl(fd):
    if sys.platform != "darwin":
        return
    libc = ctypes.CDLL(None, use_errno=True)
    libc.acl_get_fd.argtypes = [ctypes.c_int]
    libc.acl_get_fd.restype = ctypes.c_void_p
    libc.acl_get_entry.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.POINTER(ctypes.c_void_p)]
    libc.acl_get_entry.restype = ctypes.c_int
    libc.acl_get_tag_type.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_int)]
    libc.acl_get_tag_type.restype = ctypes.c_int
    libc.acl_free.argtypes = [ctypes.c_void_p]
    ctypes.set_errno(0)
    acl = libc.acl_get_fd(fd)
    if not acl:
        if ctypes.get_errno() != errno.ENOENT:
            raise ImageConflict("unsafe_image_object")
        return
    try:
        position = 0
        for _ in range(170):
            entry, tag = ctypes.c_void_p(), ctypes.c_int()
            ctypes.set_errno(0)
            if libc.acl_get_entry(acl, position, ctypes.byref(entry)) != 0:
                if ctypes.get_errno() == errno.EINVAL:
                    return
                raise ImageConflict("unsafe_image_object")
            if (
                not entry.value
                or libc.acl_get_tag_type(entry, ctypes.byref(tag)) != 0
                or tag.value != 2
            ):
                raise ImageConflict("unsafe_image_object")
            position = 1
        raise ImageConflict("unsafe_image_object")
    finally:
        libc.acl_free(acl)


def _check(fd, uid, directory, mode=None, shared=False, links=(1,)):
    info = os.fstat(fd)
    if (
        info.st_uid != uid
        or stat.S_IFMT(info.st_mode) != (stat.S_IFDIR if directory else stat.S_IFREG)
        or info.st_mode & 0o6000
        or info.st_mode & (0o002 if shared else 0o022)
        or not directory
        and info.st_nlink not in links
        or mode is not None
        and stat.S_IMODE(info.st_mode) != mode
    ):
        raise ImageConflict("unsafe_image_object")
    _acl(fd)
    return info


@contextmanager
def _directory(parent, name, uid):
    fd = os.open(name, DIRECTORY, dir_fd=parent)
    try:
        _check(fd, uid, True)
        yield fd
    finally:
        os.close(fd)


def _identity(info):
    return [info.st_dev, info.st_ino]


def _names(fd):
    # An independent directory description prevents repeated inspections from
    # sharing a directory position with another descriptor or Python version.
    independent = os.open(".", DIRECTORY, dir_fd=fd)
    try:
        result = set(os.listdir(independent))
        if len(result) > MAX_ENTRIES:
            raise ImageConflict("unlisted_image_object")
        return result
    finally:
        os.close(independent)


def _same_record(left, right):
    return json.dumps(left, sort_keys=True, separators=(",", ":")) == json.dumps(
        right, sort_keys=True, separators=(",", ":")
    )


def _rename_exclusive(source, name, destination, target):
    libc = ctypes.CDLL(None, use_errno=True)
    function = libc.renameatx_np if sys.platform == "darwin" else libc.renameat2
    function.argtypes = [
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_uint,
    ]
    function.restype = ctypes.c_int
    if (
        function(
            source,
            os.fsencode(name),
            destination,
            os.fsencode(target),
            4 if sys.platform == "darwin" else 1,
        )
        != 0
    ):
        raise OSError(ctypes.get_errno(), "exclusive_image_publication_failed")


class ImageRecovery:
    """Internal engine. Handles are owned by the caller; only the lease is ours.

    Production must pass UID0 and fixed protected parents after native source
    verification. Tests pass ordinary-user synthetic directories. checkpoint
    is internal fault injection; no CLI/environment switch enables it.
    """

    def __init__(
        self, source, journal, targets, manifest, owner_uid, *, object_uid, checkpoint=None
    ):
        if (
            type(object_uid) is not int
            or object_uid < 0
            or type(owner_uid) is not int
            or owner_uid <= 0
        ):
            raise ImageConflict("invalid_install_context")
        if (
            set(source) != set(ROOTS)
            or set(targets) != set(ROOTS)
            or not isinstance(manifest, ImageManifest)
        ):
            raise ImageConflict("invalid_install_context")
        if any(name != root.rsplit("/", 1)[1] for root, (_, name) in targets.items()):
            raise ImageConflict("invalid_install_context")
        self.source, self.journal, self.targets, self.manifest = source, journal, targets, manifest
        self.uid, self.owner = object_uid, owner_uid
        self.checkpoint = checkpoint or (lambda event: None)
        self.lease = None
        self.verified = False
        self.was_complete = False

    def __enter__(self):
        _check(self.journal, self.uid, True, 0o700)
        self.lease = os.open(
            "lock",
            os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK,
            0o600,
            dir_fd=self.journal,
        )
        try:
            _check(self.lease, self.uid, False, 0o600)
            fcntl.flock(self.lease, fcntl.LOCK_EX | fcntl.LOCK_NB)
            if _identity(os.fstat(self.lease)) != _identity(
                os.stat("lock", dir_fd=self.journal, follow_symlinks=False)
            ):
                raise ImageConflict("install_lock_changed")
            allowed = {
                "lock",
                "intent.json",
                "ready.json",
                "published.json",
                "complete.json",
                "support",
                "application",
                "temporary",
                ".pending-verification.json",
            }
            allowed |= {
                ".pending-" + name
                for name in ["intent.json", "ready.json", "published.json", "complete.json"]
            }
            if _names(self.journal) - allowed:
                raise ImageConflict("unknown_install_state")
            return self
        except BaseException:
            os.close(self.lease)
            self.lease = None
            raise

    def __exit__(self, *args):
        if self.lease is not None:
            os.close(self.lease)
            self.lease = None

    def _exists(self, parent, name):
        try:
            return os.stat(name, dir_fd=parent, follow_symlinks=False)
        except FileNotFoundError:
            return None

    def _read_record(self, name):
        if not self._exists(self.journal, name):
            return None
        fd = os.open(name, REGULAR, dir_fd=self.journal)
        try:
            info = os.fstat(fd)
            pending = self._exists(self.journal, ".pending-" + name)
            paired = info.st_nlink == 2 and pending and _identity(info) == _identity(pending)
            before = _check(fd, self.uid, False, 0o600, links=(1, 2) if paired else (1,))
            if not 0 < before.st_size <= 8192:
                raise ImageConflict("unsafe_install_record")
            encoded = os.read(fd, 8193)
            if len(encoded) != before.st_size or _stamp(before) != _stamp(
                _check(fd, self.uid, False, 0o600, links=(1, 2) if paired else (1,))
            ):
                raise ImageConflict("unsafe_install_record")
            value = json.loads(encoded)
            if (
                type(value) is not dict
                or json.dumps(value, sort_keys=True, separators=(",", ":")).encode() != encoded
            ):
                raise ImageConflict("unsafe_install_record")
            return value
        finally:
            os.close(fd)

    def _record(self, name, value):
        expected = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
        if len(expected) > 8192:
            raise ImageConflict("unsafe_install_record")
        previous = self._read_record(name)
        if previous is not None:
            if not _same_record(previous, value):
                raise ImageConflict("install_record_conflict")
            pending = self._exists(self.journal, ".pending-" + name)
            if pending is not None:
                final = os.stat(name, dir_fd=self.journal, follow_symlinks=False)
                if final.st_nlink != 2 or _identity(final) != _identity(pending):
                    raise ImageConflict("install_record_conflict")
                # Remove only our exact second name after its full content and
                # authority have matched. Conflicting records remain intact.
                os.unlink(".pending-" + name, dir_fd=self.journal)
                os.fsync(self.journal)
            return
        temporary = ".pending-" + name
        fd = os.open(
            temporary,
            os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
            0o600,
            dir_fd=self.journal,
        )
        try:
            info = _check(fd, self.uid, False, 0o600)
            if (
                info.st_size > len(expected)
                or os.read(fd, len(expected) + 1) != expected[: info.st_size]
            ):
                raise ImageConflict("install_record_conflict")
            self.checkpoint("record-open:" + name)
            remaining = memoryview(expected)[info.st_size :]
            while remaining:
                written = os.write(fd, remaining)
                if written <= 0:
                    raise ImageConflict("install_write_failed")
                remaining = remaining[written:]
                self.checkpoint("record-write:" + name)
            os.fsync(fd)
            self.checkpoint("record-synced:" + name)
            os.link(
                temporary,
                name,
                src_dir_fd=self.journal,
                dst_dir_fd=self.journal,
                follow_symlinks=False,
            )
            os.fsync(self.journal)
            self.checkpoint("record-linked:" + name)
            os.unlink(temporary, dir_fd=self.journal)
            os.fsync(self.journal)
            self.checkpoint("record-published:" + name)
        finally:
            os.close(fd)

    def _mkdir(self, parent, name, initial=0o700):
        try:
            os.mkdir(name, initial, dir_fd=parent)
            self.checkpoint("directory-created:" + name)
            os.fsync(parent)
        except FileExistsError:
            pass
        return _directory(parent, name, self.uid)

    def _file_matches(self, fd, node):
        before = _check(fd, self.uid, False, node["mode"])
        if before.st_size != node["size"]:
            raise ImageConflict("image_bytes_conflict")
        digest = hashlib.sha256()
        length = 0
        while block := os.read(fd, 1024 * 1024):
            length += len(block)
            if length > node["size"]:
                raise ImageConflict("image_bytes_conflict")
            digest.update(block)
        if (
            _stamp(before) != _stamp(_check(fd, self.uid, False, node["mode"]))
            or digest.hexdigest() != node["sha256"]
        ):
            raise ImageConflict("image_bytes_conflict")

    def _copy_file(self, root, relative, source, parent, name, temporary, node):
        if self._exists(parent, name):
            fd = os.open(name, REGULAR, dir_fd=parent)
            try:
                self._file_matches(fd, node)
            finally:
                os.close(fd)
            return
        key = hashlib.sha256((root + "/" + relative).encode()).hexdigest()
        src = os.open(name, REGULAR, dir_fd=source)
        dst = None
        try:
            source_info = _check(src, self.uid, False, node["mode"])
            if source_info.st_size != node["size"]:
                raise ImageConflict("source_image_changed")
            pending = self._exists(temporary, key)
            if pending is not None and not pending.st_mode & stat.S_IWUSR:
                # A crash after final chmod can leave a completed read-only
                # temporary. Verify it without reopening it for writing.
                dst = os.open(key, REGULAR, dir_fd=temporary)
                self._file_matches(dst, node)
                self._file_matches(src, node)
                _rename_exclusive(temporary, key, parent, name)
                os.fsync(parent)
                os.fsync(temporary)
                self.checkpoint("file-published:" + relative)
                return
            dst = os.open(
                key,
                os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK,
                0o600,
                dir_fd=temporary,
            )
            info = _check(dst, self.uid, False)
            if (
                info.st_size > node["size"]
                or stat.S_IMODE(info.st_mode) not in {0o600, node["mode"]}
                or stat.S_IMODE(info.st_mode) != 0o600
                and info.st_size != node["size"]
            ):
                raise ImageConflict("image_bytes_conflict")
            self.checkpoint("file-open:" + relative)
            digest, length = hashlib.sha256(), 0
            while block := os.read(src, 1024 * 1024):
                digest.update(block)
                existing = min(len(block), max(0, info.st_size - length))
                if existing and os.read(dst, existing) != block[:existing]:
                    raise ImageConflict("image_bytes_conflict")
                remaining = memoryview(block)[existing:]
                while remaining:
                    written = os.write(dst, remaining)
                    if written <= 0:
                        raise ImageConflict("install_write_failed")
                    remaining = remaining[written:]
                    self.checkpoint("file-write:" + relative)
                length += len(block)
            if (
                length != node["size"]
                or digest.hexdigest() != node["sha256"]
                or _stamp(source_info) != _stamp(_check(src, self.uid, False, node["mode"]))
            ):
                raise ImageConflict("source_image_changed")
            os.fsync(dst)
            os.fchmod(dst, node["mode"])
            os.fsync(dst)
            self.checkpoint("file-synced:" + relative)
            _rename_exclusive(temporary, key, parent, name)
            os.fsync(parent)
            os.fsync(temporary)
            self.checkpoint("file-published:" + relative)
        finally:
            os.close(src)
            if dst is not None:
                os.close(dst)

    def _tree(
        self, root, source, destination, temporary, relative="", *, copy=False, allow_extras=False
    ):
        nodes, children = self.manifest.trees[root], self.manifest.children[root]
        node = nodes[relative]
        before = _check(destination, self.uid, True)
        allowed_modes = {node["mode"], 0o700} if copy else {node["mode"]}
        if stat.S_IMODE(before.st_mode) not in allowed_modes:
            raise ImageConflict("image_mode_conflict")
        expected = children.get(relative, set())
        actual = _names(destination)
        extra = EXTRAS if allow_extras and root == SUPPORT and not relative else set()
        if actual - expected - extra or not copy and expected - actual:
            raise ImageConflict("unlisted_image_object")
        for name in sorted(expected):
            path = relative + "/" + name if relative else name
            entry = nodes[path]
            if entry["kind"] == "directory":
                with (
                    self._mkdir(destination, name)
                    if copy
                    else _directory(destination, name, self.uid) as target
                ):
                    with _directory(source, name, self.uid) as original:
                        self._tree(root, original, target, temporary, path, copy=copy)
            elif entry["kind"] == "file":
                if copy:
                    self._copy_file(root, path, source, destination, name, temporary, entry)
                else:
                    fd = os.open(name, REGULAR, dir_fd=destination)
                    try:
                        self._file_matches(fd, entry)
                    finally:
                        os.close(fd)
            else:
                if copy and not self._exists(destination, name):
                    os.symlink(entry["target"], name, dir_fd=destination)
                    os.fsync(destination)
                    self.checkpoint("alias-published:" + path)
                info = os.stat(name, dir_fd=destination, follow_symlinks=False)
                if (
                    not stat.S_ISLNK(info.st_mode)
                    or info.st_uid != self.uid
                    or os.readlink(name, dir_fd=destination) != entry["target"]
                ):
                    raise ImageConflict("image_alias_conflict")
            observed = os.stat(name, dir_fd=destination, follow_symlinks=False)
            if entry["kind"] != "symlink" and observed.st_uid != self.uid:
                raise ImageConflict("unsafe_image_object")
        if copy:
            if stat.S_IMODE(before.st_mode) != node["mode"]:
                os.fchmod(destination, node["mode"])
            os.fsync(destination)
            self.checkpoint("directory-synced:" + relative)
        elif _stamp(before) != _stamp(_check(destination, self.uid, True, node["mode"])):
            raise ImageConflict("image_namespace_changed")

    def materialize(self):
        if self.lease is None:
            raise ImageConflict("install_lock_required")
        self.verified = False
        self.was_complete = False
        # Recheck the immutable public input before recording an intent. This
        # supplements the native source attestation; it never opens account data.
        for root in ROOTS:
            self._tree(root, self.source[root], self.source[root], None)
        intent = {
            "managed_by": "account-access-public-image-install-v1",
            "schema": 1,
            "manifest_sha256": self.manifest.digest,
            "owner_uid": self.owner,
        }
        existing = self._read_record("intent.json")
        if existing is None:
            if _names(self.journal) - {"lock", ".pending-intent.json"}:
                raise ImageConflict("unknown_install_state")
            if any(self._exists(parent, name) for parent, name in self.targets.values()):
                raise ImageConflict("existing_installation_requires_repair")
        self._record("intent.json", intent)
        ready, published = self._read_record("ready.json"), self._read_record("published.json")
        complete = self._read_record("complete.json")
        if (
            ready is None
            and self._exists(self.journal, ".pending-published.json")
            or published is None
            and any(
                self._exists(self.journal, name)
                for name in [".pending-complete.json", ".pending-verification.json"]
            )
        ):
            raise ImageConflict("invalid_install_phase")
        if (
            published is not None
            and (ready is None or not _same_record(published, ready))
            or complete is not None
            and (published is None or not _same_record(complete, self._completion()))
        ):
            raise ImageConflict("invalid_install_phase")
        if ready is None:
            if any(self._exists(parent, name) for parent, name in self.targets.values()):
                raise ImageConflict("existing_installation_requires_repair")
            with self._mkdir(self.journal, "temporary") as temporary:
                _check(temporary, self.uid, True, 0o700)
                expected_keys = {
                    hashlib.sha256((root + "/" + name).encode()).hexdigest()
                    for root, nodes in self.manifest.trees.items()
                    for name, node in nodes.items()
                    if node["kind"] == "file"
                }
                if _names(temporary) - expected_keys:
                    raise ImageConflict("unknown_install_state")
                roots = {}
                for root, stage in ROOTS.items():
                    _check(self.source[root], self.uid, True)
                    parent, _ = self.targets[root]
                    _check(parent, self.uid, True, shared=root == APPLICATION)
                    with self._mkdir(self.journal, stage) as destination:
                        if os.fstat(destination).st_dev != os.fstat(parent).st_dev:
                            raise ImageConflict("installation_volume_mismatch")
                        self._tree(root, self.source[root], destination, temporary, copy=True)
                        self._tree(root, self.source[root], destination, temporary)
                        roots[root] = _identity(os.fstat(destination))
                if _names(temporary):
                    raise ImageConflict("unknown_install_state")
            self._record("ready.json", {"manifest_sha256": self.manifest.digest, "roots": roots})
            ready = self._read_record("ready.json")
        if (
            type(ready) is not dict
            or set(ready) != {"manifest_sha256", "roots"}
            or ready["manifest_sha256"] != self.manifest.digest
            or type(ready["roots"]) is not dict
            or set(ready["roots"]) != set(ROOTS)
            or any(
                type(item) is not list
                or len(item) != 2
                or any(type(v) is not int or v < 0 for v in item)
                for item in ready["roots"].values()
            )
        ):
            raise ImageConflict("unsafe_install_record")
        self._record("ready.json", ready)
        for root, stage in ROOTS.items():
            parent, name = self.targets[root]
            _check(parent, self.uid, True, shared=root == APPLICATION)
            staged, installed = self._exists(self.journal, stage), self._exists(parent, name)
            if bool(staged) == bool(installed):
                raise ImageConflict("image_namespace_changed")
            info = staged or installed
            if _identity(info) != ready["roots"][root]:
                raise ImageConflict("image_namespace_changed")
            with _directory(
                self.journal if staged else parent, stage if staged else name, self.uid
            ) as image:
                self._tree(root, self.source[root], image, None, allow_extras=published is not None)
            if staged:
                _rename_exclusive(self.journal, stage, parent, name)
                os.fsync(parent)
                os.fsync(self.journal)
                self.checkpoint("root-published:" + stage)
            if (
                _identity(os.stat(name, dir_fd=parent, follow_symlinks=False))
                != ready["roots"][root]
            ):
                raise ImageConflict("image_namespace_changed")
        self._record("published.json", ready)
        if complete is not None:
            self._record("complete.json", self._completion())
        self.verified = True
        self.was_complete = complete is not None
        self.proof = {
            "schema": 1,
            "status": "VERIFIED",
            "manifest_sha256": self.manifest.digest,
            **{
                key: sum(
                    node["kind"] == kind
                    for tree in self.manifest.trees.values()
                    for node in tree.values()
                )
                for key, kind in [
                    ("files", "file"),
                    ("directories", "directory"),
                    ("aliases", "symlink"),
                ]
            },
        }
        return self.proof.copy()

    def publish_verification(self, proof):
        if self.lease is None or not self.verified or not _same_record(proof, self.proof):
            raise ImageConflict("invalid_install_phase")
        expected = json.dumps(proof, sort_keys=True, separators=(",", ":")).encode()
        parent, name = self.targets[SUPPORT]
        ready = self._read_record("ready.json")
        with _directory(parent, name, self.uid) as destination:
            if _identity(os.fstat(destination)) != ready["roots"][SUPPORT]:
                raise ImageConflict("image_namespace_changed")
            node = {
                "kind": "file",
                "mode": 0o644,
                "size": len(expected),
                "sha256": hashlib.sha256(expected).hexdigest(),
            }
            if self._exists(destination, "install-verification.json"):
                fd = os.open("install-verification.json", REGULAR, dir_fd=destination)
                try:
                    self._file_matches(fd, node)
                finally:
                    os.close(fd)
                return
            temporary = ".pending-verification.json"
            fd = os.open(
                temporary,
                os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK,
                0o600,
                dir_fd=self.journal,
            )
            try:
                info = _check(fd, self.uid, False)
                if (
                    stat.S_IMODE(info.st_mode) not in {0o600, 0o644}
                    or info.st_size > len(expected)
                    or os.read(fd, len(expected) + 1) != expected[: info.st_size]
                ):
                    raise ImageConflict("install_record_conflict")
                remaining = memoryview(expected)[info.st_size :]
                while remaining:
                    written = os.write(fd, remaining)
                    if written <= 0:
                        raise ImageConflict("install_write_failed")
                    remaining = remaining[written:]
                    self.checkpoint("receipt-write")
                os.fsync(fd)
                os.fchmod(fd, 0o644)
                os.fsync(fd)
                self.checkpoint("receipt-synced")
                _rename_exclusive(self.journal, temporary, destination, "install-verification.json")
                os.fsync(destination)
                os.fsync(self.journal)
                self.checkpoint("receipt-published")
            finally:
                os.close(fd)

    def _completion(self):
        return {
            "manifest_sha256": self.manifest.digest,
            "owner_uid": self.owner,
            "status": "REGISTERED",
        }

    def mark_complete(self):
        if self.lease is None or not self.verified or self._read_record("published.json") is None:
            raise ImageConflict("invalid_install_phase")
        self._record("complete.json", self._completion())
