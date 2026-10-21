"""Deterministic build76 component-image derivation; never execute package code.

The original GUI/wheels are provenance, not newly built artifacts. Only this
closed native/worker ABI group and its derived public metadata may differ.
"""

import base64
import copy
import csv
import hashlib
import io
import json
import re

BASE_SOURCE = "fbd2a733b60acde68e82fe796cb7abd971d5d625"
BASE_MANIFEST_SHA256 = "5618053e6f8ed0a8720a9d2f7dde317425cecda6a970abd90c499fbfe27b43a8"
BASE_RECORD_SHA256 = "d77327ac0cff756e7c805a9c692360c8b3121b7fdc4f1ba9562f72a923540381"
BASE_RUNTIME_IMAGE_SHA256 = "1b0b37a103712ad8e110dcecb3e54a8ab21be302ad680ceda85259924af93ca7"
BASE_IDENTITY_SHA256 = "4bd0ef5cf76e51cd38cb09f969da5d33b018bf764890c225ee1d361935dfe1e0"
BASE_WHEEL_SHA256 = "aef341475b5b43657fe6554738431261a3635416964c8670738ebce5896dcbca"
SUPPORT = "/Library/Application Support/Account Access"
SITE = "runtime/lib/python3.12/site-packages/"
PYTHON_FILES = frozenset("account_access/" + name for name in (
    "worker_host.py", "worker_bootstrap.py", "listener_binding.py"))
ABI_FILES = frozenset({"bin/AccountAccess-broker", "bin/AccountAccess-bootstrap",
                       *(SITE + name for name in PYTHON_FILES)})
RECORD = SITE + "account_access-0.8.0.dist-info/RECORD"
DERIVED_FILES = frozenset({RECORD, "runtime-image.json", "package-identity.json", "component-identity.json"})
ALL_FILES = ABI_FILES | DERIVED_FILES


def digest(value):
    return hashlib.sha256(value).hexdigest()


def encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def _pinned(raw, expected):
    if digest(raw) != expected:
        raise ValueError("component_base_pin_changed")
    return json.loads(raw)


def reject_stale_caches(rows):
    """-B prevents writes, not cache reads; forbid both legacy cache forms."""
    for path in rows:
        for name in PYTHON_FILES:
            stem = name.removesuffix(".py")
            if (path == SITE + stem + ".pyc"
                    or path.startswith(SITE + stem.rsplit("/", 1)[0] + "/__pycache__/" + stem.rsplit("/", 1)[1] + ".")
                    and path.endswith(".pyc")):
                raise ValueError("component_stale_bytecode_present")


def derive_record(raw, replacements):
    if digest(raw) != BASE_RECORD_SHA256:
        raise ValueError("component_base_record_changed")
    rows = list(csv.reader(io.StringIO(raw.decode("utf-8"), newline="")))
    if any(len(row) != 3 for row in rows) or len({row[0] for row in rows}) != len(rows):
        raise ValueError("component_record_shape_changed")
    by_path = {row[0]: row for row in rows}
    for name in ("account_access/worker_host.py", "account_access/worker_bootstrap.py"):
        if name not in by_path:
            raise ValueError("component_record_shape_changed")
    if "account_access/listener_binding.py" in by_path:
        raise ValueError("component_record_shape_changed")
    for name in sorted(PYTHON_FILES):
        data = replacements[SITE + name]
        checksum = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode()
        by_path[name] = [name, "sha256=" + checksum, str(len(data))]
    self_name = "account_access-0.8.0.dist-info/RECORD"
    if by_path.get(self_name) != [self_name, "", ""]:
        raise ValueError("component_record_shape_changed")
    stream = io.StringIO(newline="")
    csv.writer(stream, lineterminator="\n").writerows(by_path[key] for key in sorted(by_path))
    return stream.getvalue().encode()


def _native_identities(old, signatures):
    result = copy.deepcopy(old)
    if set(signatures) != {"broker", "bootstrap"}:
        raise ValueError("component_native_peer_set_changed")
    for kind, identity in signatures.items():
        expected = "com.fainir.accountaccess." + kind
        if (set(identity) != {"team", "identifier", "hashes"}
                or identity["identifier"] != expected
                or identity["team"] != old["signatures"]["owner"]["team"]
                or re.fullmatch(r"[A-Z0-9]{10}", identity["team"]) is None
                or not 1 <= len(identity["hashes"]) <= 2
                or identity["hashes"] != sorted(set(identity["hashes"]))
                or any(re.fullmatch(r"[a-f0-9]{40}", value) is None for value in identity["hashes"])):
            raise ValueError("component_native_peer_identity_changed")
        result["signatures"][kind] = copy.deepcopy(identity)
    return result


def derive(manifest_raw, record_raw, runtime_raw, identity_raw, replacements, *, source_commit,
           source_files, signatures):
    """Return exact changed public bytes + full manifest; no disk/runtime use."""
    manifest = _pinned(manifest_raw, BASE_MANIFEST_SHA256)
    runtime = _pinned(runtime_raw, BASE_RUNTIME_IMAGE_SHA256)
    identity = _pinned(identity_raw, BASE_IDENTITY_SHA256)
    if (not re.fullmatch(r"[a-f0-9]{40}", source_commit) or not source_files
            or any(not re.fullmatch(r"[a-f0-9]{64}", value) for value in source_files.values())
            or set(replacements) != ABI_FILES
            or any(not isinstance(data, bytes) or not 0 < len(data) <= 16 * 1024 * 1024
                   for data in replacements.values())):
        raise ValueError("component_source_or_abi_group_changed")
    if any(source_files.get(name) != digest(replacements[SITE + name]) for name in PYTHON_FILES):
        raise ValueError("component_python_source_binding_changed")
    if (manifest["version"] != "0.8.0" or manifest["architecture"] != "arm64"
            or runtime["bytecode_compiled"] is not False
            or runtime["wheel_installation_executes_package_code"] is not False):
        raise ValueError("component_base_shape_changed")
    rows = manifest["roots"][SUPPORT]
    reject_stale_caches(rows)
    if rows.get("component-identity.json") is not None or rows.get(SITE + "account_access/listener_binding.py") is not None:
        raise ValueError("component_already_present")
    for path in ABI_FILES - {SITE + "account_access/listener_binding.py"}:
        if rows[path]["kind"] != "file":
            raise ValueError("component_base_shape_changed")
    if rows["owner.app/Contents/Resources/account_access.whl"]["sha256"] != BASE_WHEEL_SHA256:
        raise ValueError("component_gui_base_changed")
    changed = dict(replacements)
    changed[RECORD] = derive_record(record_raw, replacements)
    changed["package-identity.json"] = encoded(_native_identities(identity, signatures))
    overlay = [{"path": path, "before_sha256": rows.get(path, {}).get("sha256"),
                "sha256": digest(data), "bytes": len(data),
                "mode": 0o755 if path.startswith("bin/") else 0o644}
               for path, data in sorted(changed.items())]
    component = {"schema": 1, "managed_by": "account-access-component-image-v1",
                 "base_source_commit": BASE_SOURCE, "base_manifest_sha256": BASE_MANIFEST_SHA256,
                 "base_gui_and_project_wheel_sha256": BASE_WHEEL_SHA256,
                 "component_source_commit": source_commit, "component_source_files": source_files,
                 "worker_bootstrap_abi": "AALSN002", "owner_api_unchanged": True,
                 "private_schema_unchanged": True, "overlays": overlay}
    changed["component-identity.json"] = encoded(component)
    for path, data in changed.items():
        rows[path] = {"kind": "file", "mode": 0o755 if path.startswith("bin/") else 0o644,
                      "sha256": digest(data), "size": len(data)}
    runtime_rows = {path.removeprefix("runtime/") if path != "runtime" else "": node
                    for path, node in rows.items() if path == "runtime" or path.startswith("runtime/")}
    changed["runtime-image.json"] = encoded({
        "schema": 2, "transform": "account-access-component-runtime-image-v1",
        "base": {"manifest_sha256": BASE_MANIFEST_SHA256,
                 "runtime_image_sha256": BASE_RUNTIME_IMAGE_SHA256, "runtime_image": runtime,
                 "project_wheel_sha256": BASE_WHEEL_SHA256},
        "component_source_commit": source_commit,
        "component_identity_sha256": digest(changed["component-identity.json"]),
        "runtime_manifest_sha256": digest(json.dumps(runtime_rows, sort_keys=True, separators=(",", ":")).encode()),
        "bytecode_compiled": False, "wheel_installation_executes_package_code": False,
    })
    rows["runtime-image.json"] = {"kind": "file", "mode": 0o644,
                                  "sha256": digest(changed["runtime-image.json"]),
                                  "size": len(changed["runtime-image.json"])}
    assert set(changed) == ALL_FILES
    return changed, encoded(manifest)
