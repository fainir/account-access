"""Small synthetic component derivations; no owner data, native code or install."""

import copy
import csv
import io
import json

import pytest

from macos import component_update as component


@pytest.fixture
def base(monkeypatch):
    replacements = {name: ("NEW:" + name).encode() for name in component.ABI_FILES}
    rows = {"": {"kind": "directory", "mode": 0o755},
            "runtime": {"kind": "directory", "mode": 0o755},
            "owner.app/Contents/Resources/account_access.whl":
                {"kind": "file", "mode": 0o644, "sha256": component.BASE_WHEEL_SHA256, "size": 20}}
    for path in component.ABI_FILES - {component.SITE + "account_access/listener_binding.py"}:
        rows[path] = {"kind": "file", "mode": 0o755 if path.startswith("bin/") else 0o644,
                      "sha256": component.digest(("OLD:" + path).encode()), "size": 20}
    record = ("account_access/worker_host.py,sha256=old,20\n"
              "account_access/worker_bootstrap.py,sha256=old,20\n"
              "account_access/untouched.py,sha256=preserve,123\n"
              "account_access-0.8.0.dist-info/RECORD,,\n").encode()
    runtime = component.encoded({"schema": 1, "bytecode_compiled": False,
                                 "wheel_installation_executes_package_code": False,
                                 "runtime_sha256": "historical-only"})
    identity = component.encoded({"schema": 1, "managed_by": "account-access-package-identity-v1",
                                  "signatures": {key: {"identifier": "com.fainir.accountaccess" + suffix,
                                                       "team": "WBULD6N4NQ", "hashes": [letter * 40]}
                                                 for key, suffix, letter in (
                                                     ("owner", "", "a"), ("broker", ".broker", "b"),
                                                     ("bootstrap", ".bootstrap", "c"))}})
    manifest = component.encoded({"version": "0.8.0", "architecture": "arm64",
                                   "roots": {component.SUPPORT: rows}})
    for constant, raw in (("BASE_MANIFEST_SHA256", manifest), ("BASE_RECORD_SHA256", record),
                          ("BASE_RUNTIME_IMAGE_SHA256", runtime), ("BASE_IDENTITY_SHA256", identity)):
        monkeypatch.setattr(component, constant, component.digest(raw))
    signatures = {key: {"identifier": "com.fainir.accountaccess." + key,
                        "team": "WBULD6N4NQ", "hashes": [letter * 40]}
                  for key, letter in (("broker", "d"), ("bootstrap", "e"))}
    return {"args": [manifest, record, runtime, identity, replacements],
            "kwargs": {"source_commit": "f" * 40,
                       "source_files": {name: component.digest(replacements[component.SITE + name]) for name in component.PYTHON_FILES},
                       "signatures": signatures}}


def test_composite_provenance_and_record_are_exact_and_deterministic(base):
    args, kwargs = base["args"], base["kwargs"]
    before = copy.deepcopy(args)
    changed, new_manifest = component.derive(*args, **kwargs)
    assert component.derive(*args, **kwargs) == (changed, new_manifest)
    assert args == before
    assert set(changed) == component.ALL_FILES
    old_rows = json.loads(args[0])["roots"][component.SUPPORT]
    new_rows = json.loads(new_manifest)["roots"][component.SUPPORT]
    for name, row in old_rows.items():
        if name not in component.ALL_FILES:
            assert new_rows[name] == row
    identity = json.loads(changed["package-identity.json"])
    assert identity["signatures"]["owner"] == json.loads(args[3])["signatures"]["owner"]
    assert identity["signatures"]["broker"] == kwargs["signatures"]["broker"]
    records = {row[0]: row[1:] for row in csv.reader(io.StringIO(changed[component.RECORD].decode()))}
    assert records["account_access/untouched.py"] == ["sha256=preserve", "123"]
    assert records["account_access-0.8.0.dist-info/RECORD"] == ["", ""]
    for name in component.PYTHON_FILES:
        assert records[name][0].startswith("sha256=") and records[name][1] == str(len(args[4][component.SITE + name]))
    runtime = json.loads(changed["runtime-image.json"])
    assert runtime["schema"] == 2 and "runtime_sha256" not in runtime
    assert runtime["base"]["runtime_image"]["runtime_sha256"] == "historical-only"
    assert runtime["base"]["project_wheel_sha256"] == component.BASE_WHEEL_SHA256
    assert runtime["component_source_commit"] == "f" * 40
    component_identity = json.loads(changed["component-identity.json"])
    assert component_identity["base_source_commit"] == component.BASE_SOURCE
    assert component_identity["worker_bootstrap_abi"] == "AALSN002"
    assert component_identity["private_schema_unchanged"] is True


@pytest.mark.parametrize("change", ["missing_abi", "extra_path", "bad_source", "base_bytes", "other_team",
                                  "missing_python_source", "mismatched_python_source"])
def test_partial_foreign_or_unpinned_derivations_are_refused(base, change):
    args, kwargs = copy.deepcopy(base["args"]), copy.deepcopy(base["kwargs"])
    if change == "missing_abi":
        args[4].pop("bin/AccountAccess-bootstrap")
    elif change == "extra_path":
        args[4]["owner.app/Contents/MacOS/AccountAccess"] = b"foreign GUI"
    elif change == "bad_source":
        kwargs["source_commit"] = "moving-branch"
    elif change == "base_bytes":
        args[0] += b" "
    elif change == "other_team":
        kwargs["signatures"]["broker"]["team"] = "OTHERTEAM1"
    elif change == "missing_python_source":
        kwargs["source_files"].pop("account_access/worker_host.py")
    else:
        kwargs["source_files"]["account_access/worker_host.py"] = "0" * 64
    with pytest.raises(ValueError, match="component_"):
        component.derive(*args, **kwargs)


@pytest.mark.parametrize("cache", ["account_access/worker_host.pyc",
                                  "account_access/__pycache__/worker_bootstrap.cpython-312.pyc",
                                  "account_access/__pycache__/listener_binding.cpython-312.opt-1.pyc"])
def test_changed_module_bytecode_is_a_hard_refusal(base, monkeypatch, cache):
    args = list(base["args"])
    manifest = json.loads(args[0])
    manifest["roots"][component.SUPPORT][component.SITE + cache] = {"kind": "file"}
    args[0] = component.encoded(manifest)
    monkeypatch.setattr(component, "BASE_MANIFEST_SHA256", component.digest(args[0]))
    with pytest.raises(ValueError, match="component_stale_bytecode_present"):
        component.derive(*args, **base["kwargs"])


def test_duplicate_or_noncanonical_record_does_not_get_silently_repaired(base, monkeypatch):
    args = list(base["args"])
    args[1] += b"account_access/untouched.py,sha256=ambiguous,1\n"
    monkeypatch.setattr(component, "BASE_RECORD_SHA256", component.digest(args[1]))
    with pytest.raises(ValueError, match="component_record_shape_changed"):
        component.derive(*args, **base["kwargs"])
