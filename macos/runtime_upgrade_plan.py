"""Data-only plan for the repaired public image to runtime92.

This module cannot read an installation, grant root authority, control services
or perform an update. The successor controller must independently qualify the
completed repair and verify signed payloads before using these fixed units.
"""
from macos import full_image_update as image

BEFORE = "5a732de4623ba50aefa6d31c54e7b1eae660b2921341f95042c5675d922d808b"
AFTER = "03fb35eb2787ebd67079dd1cbe4dda125f430964540bdd2f2e9c81eda602fd7a"
REPAIR_PLAN = "3741aae23c6c23c9da33ae233d0657800454514042d59cba951e7bbf7d1d8ec1"
REPAIR_SOURCE = "c4cf1b0918c1a51cbd4a38880364fcb71fa5980e"
TARGET_SOURCE = "7051ef225ff2f35d67576d0ddbbc3e0b107e00bf"
TREES = ("owner.app", "python", "runtime", "browsers", "wheels", "bin")
FILES = ("package-identity.json", "package-requirements.txt", "runtime-image.json",
         "runtime-preparation.json", "runtime-ca-refresh.json", "broker-repair-identity.json")
UNCHANGED = ("storage.py", "models.py", "worker_enroll.py")
NATIVE = ("bin/AccountAccess-broker", "bin/AccountAccess-bootstrap", "bin/AccountAccess-installerverify")
MARKER = "account-access-repaired-runtime-upgrade-plan-v1"


def require(value):
    if not value:
        raise image.Refused("runtime_upgrade_plan_refused")


def derive(*, before_manifest, after_manifest, old_identity, new_identity, source_files):
    require(type(before_manifest) is bytes and type(after_manifest) is bytes
            and image.digest(before_manifest) == BEFORE and image.digest(after_manifest) == AFTER)
    before, after = image._manifest(before_manifest), image._manifest(after_manifest)
    old, new = before["roots"][image.SUPPORT], after["roots"][image.SUPPORT]
    require(before["roots"][image.APPLICATION] == after["roots"][image.APPLICATION]
            and old[""] == new[""] == {"kind": "directory", "mode": 0o755})
    old_peers, new_peers = image._identity(old_identity, old), image._identity(new_identity, new)
    require(old_peers["owner"] != new_peers["owner"])
    native_nodes = {"bin", *NATIVE}
    require({name for name in old if image._below(name, "bin")} == native_nodes
            and {name for name in new if image._below(name, "bin")} == native_nodes
            and old.get("bin") == new.get("bin") == {"kind": "directory", "mode": 0o755})
    for path in NATIVE:
        require(old.get(path, {}).get("kind") == new.get(path, {}).get("kind") == "file"
                and old[path].get("mode") == new[path].get("mode") == 0o755)
    require(type(source_files) is dict and 1 <= len(source_files) <= 1000
            and all(type(k) is str and image._hex(v) for k, v in source_files.items()))
    runtime_sources = {name[len(image.SITE):]: node["sha256"] for name, node in new.items()
        if image._below(name, image.PACKAGE) and name.endswith(".py") and node["kind"] == "file"}
    require(runtime_sources and set(source_files) == set(runtime_sources) | {"macos/AccountAccess.swift"}
            and {k: v for k, v in source_files.items() if k.startswith("account_access/")} == runtime_sources)
    for name in UNCHANGED:
        path = image.PACKAGE + "/" + name
        require(old.get(path) == new.get(path) and new.get(path, {}).get("kind") == "file")
    require(image.PACKAGE + "/agent_setup.py" in new
            and old[image.PACKAGE + "/agent_setup.py"] != new[image.PACKAGE + "/agent_setup.py"]
            and image._hex(source_files.get("macos/AccountAccess.swift")))
    require(new[image.PROJECT_WHEEL] == new[image.BUNDLE_WHEEL])
    changed = sorted(n for n in old.keys() | new.keys() if old.get(n) != new.get(n))
    covered, units = [], []
    for path in TREES:
        require(old.get(path) == new.get(path) == {"kind": "directory", "mode": 0o755})
        owned = [n for n in changed if image._below(n, path)]
        if not owned:
            continue
        sides = [{n: node for n, node in rows.items() if image._below(n, path)} for rows in (old, new)]
        # Files move only through these public top-level directories. The
        # support root, application alias and private sibling branches stay put.
        units.append({"kind": "public_tree", "path": path, "before": sides[0], "after": sides[1],
                      "before_inventory_sha256": image.digest(image.encoded(sides[0])),
                      "after_inventory_sha256": image.digest(image.encoded(sides[1])), "changed": owned})
        covered.extend(owned)
    for path in FILES:
        a, b = old.get(path), new.get(path)
        require(a is not None and a.get("kind") == "file" and a.get("mode") == 0o644)
        if path == "broker-repair-identity.json":
            require(b is None)
        else:
            require(b is not None and b.get("kind") == "file" and b.get("mode") == 0o644)
        if a != b:
            units.append({"kind": "public_file", "path": path, "before": a, "after": b, "changed": [path]})
            covered.append(path)
    require(changed and sorted(covered) == changed and len(covered) == len(set(covered)))
    return image.encoded({"schema": 1, "managed_by": MARKER, "before_manifest_sha256": BEFORE,
        "after_manifest_sha256": AFTER, "predecessor_repair_plan_sha256": REPAIR_PLAN,
        "predecessor_repair_source": REPAIR_SOURCE, "target_source": TARGET_SOURCE,
        "target_source_files": source_files, "old_peers": old_peers, "new_peers": new_peers,
        "project_wheel_sha256": new[image.PROJECT_WHEEL]["sha256"], "units": units, "changed": changed,
        "storage_model_and_enrollment_source_unchanged": True, "native_peer_identity_fixed": True,
        "native_payload_and_signatures_must_be_pinned": True,
        "completed_repair_proof_required": True, "native_payload_and_signature_checks_required": True,
        "support_and_alias_inodes_must_be_preserved": True, "production_ready": False})


def parse(raw, *, expected_sha256, **inputs):
    require(type(raw) is bytes and image._hex(expected_sha256) and len(raw) <= image.MAX_PLAN_BYTES
            and image.digest(raw) == expected_sha256)
    require(raw == derive(**inputs))
    return image._json(raw, image.MAX_PLAN_BYTES)
