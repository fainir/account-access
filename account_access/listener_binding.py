"""Public, native-validated listener identities for the macOS worker handoff.

The native supervisor validates canonical socket nodes before dropping identity.
The worker cannot traverse the private owner socket directory, so it checks the
forwarded node binding's policy digest and rechecks the actual inherited FD and
its bound address. This metadata contains no bootstrap key material.
"""

from dataclasses import dataclass
import hashlib
import hmac
import struct


_HEADER = struct.Struct(">8sHBBI")
_RECORD = struct.Struct(">BBHqQqQ32s32s")
METADATA_SIZE = _HEADER.size + 2 * _RECORD.size


class ListenerBindingError(ValueError):
    """The public listener handoff does not match its fixed contract."""


@dataclass(frozen=True)
class ListenerBinding:
    role: int
    source: int
    fd_device: int
    fd_inode: int
    path_device: int
    path_inode: int
    canonical_digest: bytes
    bound_name_digest: bytes


def parse_listener_bindings(value):
    """Decode exactly the v2 public prefix, never its 64-byte secret suffix."""
    try:
        if (not isinstance(value, str) or len(value) != METADATA_SIZE * 2
                or any(character not in "0123456789abcdef" for character in value)):
            raise ListenerBindingError()
        raw = bytes.fromhex(value)
        if _HEADER.unpack_from(raw) != (b"AALSN002", 2, 2, 0, 280):
            raise ListenerBindingError()
        records = []
        for index in range(2):
            role, source, reserved, *fields = _RECORD.unpack_from(raw, _HEADER.size + index * _RECORD.size)
            if role != index + 1 or source not in (0, 1) or reserved != 0:
                raise ListenerBindingError()
            record = ListenerBinding(role, source, *fields)
            if (not record.fd_inode or not record.path_inode
                    or (source == 0 and record.canonical_digest != record.bound_name_digest)):
                raise ListenerBindingError()
            records.append(record)
        first, second = records
        if ((first.fd_device, first.fd_inode) == (second.fd_device, second.fd_inode)
                or (first.path_device, first.path_inode) == (second.path_device, second.path_inode)
                or first.canonical_digest == second.canonical_digest
                or first.bound_name_digest == second.bound_name_digest):
            raise ListenerBindingError()
        return tuple(records)
    except (ValueError, TypeError, struct.error):
        raise ListenerBindingError("invalid_worker_listener_bindings") from None


def validate_listener_binding(binding, *, role, canonical_path, descriptor, bound_name, platform):
    """Recheck each FD, role, policy path and bind name after native identity drop."""
    try:
        if (type(binding) is not ListenerBinding or type(role) is not int or role not in (1, 2) or binding.role != role
                or binding.source not in (0, 1) or (binding.source == 1 and platform != "darwin")
                or not isinstance(canonical_path, str) or not canonical_path.startswith("/")
                or "\0" in canonical_path or not isinstance(bound_name, str)
                or not bound_name.startswith("/") or "\0" in bound_name
                or (descriptor.st_dev, descriptor.st_ino) != (binding.fd_device, binding.fd_inode)):
            raise ListenerBindingError()
        canonical = hashlib.sha256(canonical_path.encode("utf-8")).digest()
        bound = hashlib.sha256(bound_name.encode("utf-8")).digest()
        if (not hmac.compare_digest(canonical, binding.canonical_digest)
                or not hmac.compare_digest(bound, binding.bound_name_digest)
                or (binding.source == 0 and bound_name != canonical_path)):
            raise ListenerBindingError()
    except (ValueError, TypeError, AttributeError, UnicodeError):
        raise ListenerBindingError("invalid_worker_listener_bindings") from None
