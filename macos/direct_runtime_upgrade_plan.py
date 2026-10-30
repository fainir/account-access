"""One-machine, exact-predecessor delta plan for the installed Mac recovery.

This planner has no installation, filesystem, service, signing or credential
authority. It only accepts the public image currently installed on the owner
Mac and the qualified build-119 image. The native controller independently
checks both complete manifests and every changed file before it moves anything.
"""

from __future__ import annotations

from macos import full_image_update as image


BEFORE = "568c79ca3b45ffc357bc5af2b420d481e729630b0120dc6d0058c1a396ad21b1"
AFTER = "630e77605faac2dfdace9faaa5da55e671335c6b18e62114d7f0224a8574f24c"
TARGET_SOURCE = "d5f7c074a4cc1df48b743bf109cf6d99986a2ca5"
ORIGINAL_RECEIPT_MANIFEST = image.ORIGINAL_MANIFEST
MARKER = "account-access-exact-installed-runtime-delta-v1"
SUPPORT = image.SUPPORT
APPLICATION = image.APPLICATION
DIRECT_TREES = (
    "runtime/lib/python3.12/site-packages/account_access",
    "runtime/lib/python3.12/site-packages/account_access-0.8.0.dist-info",
    "runtime/lib/python3.12/site-packages/authlib-1.8.0.dist-info",
    "runtime/lib/python3.12/site-packages/authlib-1.9.1.dist-info",
    "runtime/lib/python3.12/site-packages/authlib/oauth2/drafts",
)
FIXED_FILES = (
    "package-identity.json",
    "package-requirements.txt",
    "runtime-image.json",
    "runtime-preparation.json",
    "runtime-ca-refresh.json",
    "broker-repair-identity.json",
)
PUBLIC_ROOTS = ("owner.app", "python", "runtime", "browsers", "wheels", "bin")


class Refused(ValueError):
    """A direct migration input failed its closed contract."""


def require(value: bool) -> None:
    if not value:
        raise Refused("direct_runtime_upgrade_refused")


def node(value):
    if value is None:
        return None
    if value["kind"] == "file":
        return {"kind": "file", "mode": value["mode"], "size": value["size"], "sha256": value["sha256"]}
    if value["kind"] == "directory":
        return {"kind": "directory", "mode": value["mode"]}
    return {"kind": "symlink", "target": value["target"]}


def _rows(manifest, root):
    return manifest["roots"][root]


def _below(path, prefix):
    return path == prefix or path.startswith(prefix + "/")


def _path_ok(path):
    if type(path) is not str or not path or path.startswith("/") or "\\" in path:
        return False
    parts = path.split("/")
    return all(part not in ("", ".", "..") for part in parts)


def _units(before, after):
    """Cover exact changed nodes with disjoint small trees and file renames."""
    old, new = _rows(before, SUPPORT), _rows(after, SUPPORT)
    changed = sorted(path for path in old.keys() | new.keys() if old.get(path) != new.get(path))
    units, covered = [], set()

    for path in DIRECT_TREES:
        old_rows = {name: value for name, value in old.items() if _below(name, path)}
        new_rows = {name: value for name, value in new.items() if _below(name, path)}
        owned = [name for name in changed if _below(name, path)]
        if not owned:
            continue
        if path in {image.PACKAGE, image.DIST_INFO}:
            require(bool(old_rows) and bool(new_rows))
        else:
            require(bool(old_rows) != bool(new_rows))
        for rows in (old_rows, new_rows):
            if rows:
                require(rows.get(path) == {"kind": "directory", "mode": 0o755})
        units.append({"kind": "public_tree", "path": path,
            "before": old_rows or None, "after": new_rows or None, "changed": owned})
        covered.update(owned)

    for path in FIXED_FILES:
        left, right = old.get(path), new.get(path)
        if left == right:
            continue
        require(left is None or left["kind"] == "file")
        require(right is None or right["kind"] == "file")
        require(left is not None or right is not None)
        mode = (left or right)["mode"]
        require(mode in (0o644, 0o755) and (left is None or left["mode"] == mode)
                and (right is None or right["mode"] == mode))
        units.append({"kind": "fixed_file", "path": path, "before": node(left), "after": node(right),
                      "changed": [path]})
        covered.add(path)

    for path in changed:
        if path in covered or any(_below(path, tree) for tree in DIRECT_TREES):
            continue
        left, right = old.get(path), new.get(path)
        require(_path_ok(path) and any(_below(path, root) for root in PUBLIC_ROOTS))
        require(left is None or left["kind"] == "file")
        require(right is None or right["kind"] == "file")
        require(left is not None or right is not None)
        mode = (left or right)["mode"]
        require(mode in (0o644, 0o755) and (left is None or left["mode"] == mode)
                and (right is None or right["mode"] == mode))
        units.append({"kind": "direct_file", "path": path, "mode": mode,
                      "before": node(left), "after": node(right), "changed": [path]})
        covered.add(path)

    require(changed and sorted(covered) == changed and len(covered) == len(set(covered)))
    require(len(units) <= 240)
    return changed, units


def derive(*, before_manifest: bytes, after_manifest: bytes, old_identity: bytes,
           new_identity: bytes, source_files: dict[str, str]) -> bytes:
    require(type(before_manifest) is bytes and image.digest(before_manifest) == BEFORE)
    require(type(after_manifest) is bytes and image.digest(after_manifest) == AFTER)
    before, after = image._manifest(before_manifest), image._manifest(after_manifest)
    old, new = _rows(before, SUPPORT), _rows(after, SUPPORT)
    require(before["roots"][APPLICATION] == after["roots"][APPLICATION]
            and old[""] == new[""] == {"kind": "directory", "mode": 0o755})
    old_peers, new_peers = image._identity(old_identity, old), image._identity(new_identity, new)
    require(old_peers["owner"] != new_peers["owner"])
    require(all(type(k) is str and image._hex(v) for k, v in source_files.items()))
    expected_sources = {
        name[len(image.SITE):]: row["sha256"]
        for name, row in new.items()
        if image._below(name, image.PACKAGE) and name.endswith(".py") and row["kind"] == "file"
    }
    require(expected_sources and set(source_files) == set(expected_sources)
            and all(source_files[name] == digest for name, digest in expected_sources.items()))
    changed, units = _units(before, after)
    target_bytes = 0
    for path in changed:
        row = new.get(path)
        if row and row["kind"] == "file":
            target_bytes += row["size"]
    value = {
        "schema": 1,
        "managed_by": MARKER,
        "before_manifest_sha256": BEFORE,
        "after_manifest_sha256": AFTER,
        "original_install_receipt_manifest_sha256": ORIGINAL_RECEIPT_MANIFEST,
        "target_source": TARGET_SOURCE,
        "target_source_files": source_files,
        "old_peers": old_peers,
        "new_peers": new_peers,
        "project_wheel_sha256": new[image.PROJECT_WHEEL]["sha256"],
        "changed": changed,
        "units": units,
        "delta_payload_bytes": target_bytes,
        "exact_installed_predecessor_required": True,
        "original_receipt_required": True,
        "native_signatures_required": True,
        "private_store_unchanged": True,
        "support_and_alias_inodes_preserved": True,
        "rollback_and_retry_required": True,
        "production_ready": False,
    }
    return image.encoded(value)


def parse(raw: bytes, *, expected_sha256: str, **inputs):
    require(type(raw) is bytes and image._hex(expected_sha256)
            and image.digest(raw) == expected_sha256 and raw == derive(**inputs))
    return image._json(raw, image.MAX_PLAN_BYTES)
