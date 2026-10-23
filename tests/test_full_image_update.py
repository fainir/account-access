"""Synthetic inventory contracts only: no native code/signature/payload claim."""

import copy
import importlib.util
import json
from pathlib import Path

import pytest

SPEC = importlib.util.spec_from_file_location("full_image_update", Path(__file__).resolve().parents[1] / "macos/full_image_update.py")
plan = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(plan)


def file_node(raw=b"synthetic", *, sha=None, mode=0o644):
    return {"kind": "file", "mode": mode, "size": len(raw), "sha256": sha or plan.digest(raw)}


def put(rows, name, node):
    parts = name.split("/")
    for count in range(1, len(parts)):
        rows.setdefault("/".join(parts[:count]), {"kind": "directory", "mode": 0o755})
    rows[name] = node


def image(rows):
    return {"schema": 1, "managed_by": "account-access-install-payload-v1",
            "package_identifier": "com.fainir.accountaccess.system", "version": "0.8.0", "architecture": "arm64",
            "roots": {plan.SUPPORT: rows, plan.APPLICATION: {
                "": {"kind": "symlink", "target": "../Library/Application Support/Account Access/owner.app"}}}}


def identity(owner):
    return plan.encoded({"schema": 1, "managed_by": "account-access-package-identity-v1", "signatures": {
        kind: {"team": plan.TEAM, "identifier": "com.fainir.accountaccess" + ("" if kind == "owner" else "." + kind),
               "hashes": [char * 40]} for kind, char in (("owner", owner), ("broker", "c"), ("bootstrap", "d"))}})


@pytest.fixture
def inputs():
    rows = {"": {"kind": "directory", "mode": 0o755}}
    for path in plan.TREES:
        put(rows, path, {"kind": "directory", "mode": 0o755})
    for path in ("bin/AccountAccess-broker", "bin/AccountAccess-bootstrap", "runtime/bin/python3.12"):
        put(rows, path, file_node(mode=0o755))
    for path in (*plan.FILES, plan.BUNDLE_WHEEL, "owner.app/Contents/MacOS/AccountAccess",
                 plan.DIST_INFO + "/RECORD", plan.PROVIDER + "/runtime-manifest.json"):
        put(rows, path, file_node())
    for name in plan.UNCHANGED_FORMAT:
        put(rows, plan.PACKAGE + "/" + name, file_node(name.encode()))
    put(rows, plan.PACKAGE + "/bitwarden_source.py", file_node(sha=plan.WORKER_SOURCE))
    put(rows, plan.PROVIDER + "/build/bw.js", file_node(sha=plan.PROVIDER_PINS["official_entrypoint_sha256"]))
    put(rows, plan.PROVIDER + "/package.json", file_node())
    put(rows, plan.PROVIDER + "/node_modules/node-forge/unused.js", file_node())
    old_identity, new_identity = identity("a"), identity("b")
    rows["package-identity.json"] = file_node(old_identity)
    before = image(rows)
    after = copy.deepcopy(before)
    new = after["roots"][plan.SUPPORT]
    for name in list(new):
        if plan._below(name, plan.PROVIDER + "/node_modules/node-forge"):
            del new[name]
    new["package-identity.json"] = file_node(new_identity)
    new["owner.app/Contents/MacOS/AccountAccess"] = file_node(b"new-owner", mode=0o755)
    new[plan.PROJECT_WHEEL] = new[plan.BUNDLE_WHEEL] = file_node(b"new-wheel")
    new[plan.PROVIDER + "/build/bw.js"] = file_node(sha=plan.PROVIDER_PINS["entrypoint_sha256"])
    new[plan.PROVIDER + "/package.json"] = file_node(sha=plan.DERIVED_METADATA)
    put(new, plan.PROVIDER + "/dependency-overrides.json", file_node(sha=plan.PROVIDER_PINS["dependency_overrides_sha256"]))
    provider = {**plan.PROVIDER_PINS, "source_bundle_sha256": "e" * 64, "source_materials": 1}
    provider_raw = plan.encoded(provider)
    new[plan.PROVIDER + "/runtime-manifest.json"] = file_node(provider_raw)
    sources = {name: "f" * 64 for name in plan.REQUIRED_SOURCES}
    sources.update({"account_access/" + name: new[plan.PACKAGE + "/" + name]["sha256"]
                    for name in plan.UNCHANGED_FORMAT})
    sources.update({"macos/bitwarden_derivation.py": plan.PROVIDER_PINS["derivation_source_sha256"],
                    "macos/bitwarden-overrides.lock.json": plan.PROVIDER_PINS["dependency_overrides_sha256"],
                    "account_access/bitwarden_source.py": plan.WORKER_SOURCE})
    provenance = {"component_source_commit": "a" * 40, "target_source_commit": "b" * 40,
                  "original_manifest_sha256": plan.ORIGINAL_MANIFEST, "component_plan_sha256": "c" * 64,
                  "component_head_sha256": "d" * 64, "base_manifest_sha256": "", "target_manifest_sha256": "",
                  "target_source_files": sources, "designated_requirements": {
                      kind: {"before": "synthetic-requirement-" + kind, "after": "synthetic-requirement-" + kind}
                      for kind in ("owner", "broker", "bootstrap")},
                  "provider_manifest_sha256": plan.digest(provider_raw), "provider_source_bundle_sha256": "e" * 64}
    return {"before": before, "after": after, "old_identity": old_identity, "new_identity": new_identity,
            "provenance": provenance, "provider_manifest": provider_raw}


def arguments(value):
    before, after = plan.encoded(value["before"]), plan.encoded(value["after"])
    provenance = copy.deepcopy(value["provenance"])
    provenance.update(base_manifest_sha256=plan.digest(before), target_manifest_sha256=plan.digest(after))
    return {"before_manifest": before, "after_manifest": after, "old_identity": value["old_identity"],
            "new_identity": value["new_identity"], "provenance": provenance,
            "provider_manifest": value["provider_manifest"]}


def test_complete_before_after_unit_coverage_and_canonical_roundtrip(inputs):
    args = arguments(inputs)
    raw = plan.derive(**args)
    result = plan.parse(raw, expected_plan_sha256=plan.digest(raw), **args)
    assert result["production_ready"] is False
    assert result["private_format_source_unchanged"] is True
    assert "private_schema_unchanged" not in result
    assert result["native_signature_and_payload_verification_required"] is True
    assert sorted(name for unit in result["units"] for name in unit["changed"]) == result["changed"]
    owner = next(unit for unit in result["units"] if unit["path"] == "owner.app")
    assert "owner.app/Contents/Resources/account_access.whl" in owner["before"]
    provider = next(unit for unit in result["units"] if unit["path"] == plan.PROVIDER)
    assert plan.PROVIDER + "/node_modules/node-forge/unused.js" in provider["before"]
    assert plan.PROVIDER + "/node_modules/node-forge/unused.js" not in provider["after"]


@pytest.mark.parametrize("path", ["runtime/bin/python3.12", "browsers/chromium/new", "runtime/lib/other.py",
                                  "bin/AccountAccess-broker", "bin/AccountAccess-bootstrap", "unknown.txt",
                                  "runtime/lib/python3.12/site-packages/pip/__init__.py",
                                  "runtime/lib/python3.12/ensurepip/_bundled/pip-25.0.1-py3-none-any.whl"])
def test_outside_unit_interpreter_browser_dependency_native_and_unknown_changes_refused(inputs, path):
    put(inputs["after"]["roots"][plan.SUPPORT], path, file_node(b"changed", mode=0o755))
    with pytest.raises(plan.Refused):
        plan.derive(**arguments(inputs))


@pytest.mark.parametrize("path", sorted(plan.PRIVATE))
def test_even_unchanged_private_opaque_branches_are_not_planner_input(inputs, path):
    for image_value in (inputs["before"], inputs["after"]):
        put(image_value["roots"][plan.SUPPORT], path, {"kind": "directory", "mode": 0o700})
    with pytest.raises(plan.Refused):
        plan.derive(**arguments(inputs))


@pytest.mark.parametrize("name", plan.UNCHANGED_FORMAT)
def test_initial_feature_cannot_silently_migrate_private_format(inputs, name):
    node = file_node(b"format-change")
    inputs["after"]["roots"][plan.SUPPORT][plan.PACKAGE + "/" + name] = node
    inputs["provenance"]["target_source_files"]["account_access/" + name] = node["sha256"]
    with pytest.raises(plan.Refused):
        plan.derive(**arguments(inputs))


def configuration_extension(inputs):
    path = plan.PACKAGE + "/models.py"
    inputs["before"]["roots"][plan.SUPPORT][path] = dict(plan.CONFIGURATION_MODEL_BEFORE)
    inputs["after"]["roots"][plan.SUPPORT][path] = dict(plan.CONFIGURATION_MODEL_AFTER)
    inputs["provenance"]["target_source_files"]["account_access/models.py"] = plan.CONFIGURATION_MODEL_AFTER["sha256"]
    return inputs


def test_configuration_upgrade_profile_matches_reviewed_model_source():
    raw = (Path(__file__).parents[1] / "account_access/models.py").read_bytes()
    assert plan.CONFIGURATION_MODEL_AFTER == file_node(raw)


def test_explicit_configuration_extension_does_not_claim_unchanged_source(inputs):
    args = arguments(configuration_extension(inputs))
    raw = plan.derive(**args)
    value = plan.parse(raw, expected_plan_sha256=plan.digest(raw), **args)
    assert value["configuration_model_upgrade"] == "identity-contact-session-status-v1"
    assert value["private_format_source_unchanged"] is False
    assert plan.PACKAGE + "/models.py" in value["changed"]


@pytest.mark.parametrize("fault", ["old-hash", "new-hash", "old-size", "new-size", "old-mode", "new-mode",
                                  "source-pin", "storage.py", "worker_enroll.py", "agent_setup.py", "reverse"])
def test_configuration_extension_cannot_authorize_other_source_or_metadata(inputs, fault):
    configuration_extension(inputs)
    path = plan.PACKAGE + "/models.py"
    old = inputs["before"]["roots"][plan.SUPPORT]
    new = inputs["after"]["roots"][plan.SUPPORT]
    if fault == "source-pin":
        inputs["provenance"]["target_source_files"]["account_access/models.py"] = "0" * 64
    elif fault.endswith(".py"):
        new[plan.PACKAGE + "/" + fault] = file_node(b"unrelated private-format change")
        inputs["provenance"]["target_source_files"]["account_access/" + fault] = new[plan.PACKAGE + "/" + fault]["sha256"]
    elif fault == "reverse":
        old[path], new[path] = new[path], old[path]
        inputs["provenance"]["target_source_files"]["account_access/models.py"] = new[path]["sha256"]
    else:
        side, field = fault.split("-")
        node = (old if side == "old" else new)[path]
        node[{"hash": "sha256", "size": "size", "mode": "mode"}[field]] = "0" * 64 if field == "hash" else 1
    with pytest.raises(plan.Refused):
        plan.derive(**arguments(inputs))


@pytest.mark.parametrize("fault", ["missing-profile", "unknown-profile", "claims-unchanged", "extra-permission"])
def test_resealed_configuration_plan_cannot_change_compatibility_authority(inputs, fault):
    args = arguments(configuration_extension(inputs))
    value = json.loads(plan.derive(**args))
    if fault == "missing-profile":
        value.pop("configuration_model_upgrade")
    elif fault == "unknown-profile":
        value["configuration_model_upgrade"] = "arbitrary-model-migration"
    elif fault == "claims-unchanged":
        value["private_format_source_unchanged"] = True
    else:
        value["private_data_migration_allowed"] = True
    raw = plan.encoded(value)
    with pytest.raises(plan.Refused):
        plan.parse(raw, expected_plan_sha256=plan.digest(raw), **args)


@pytest.mark.parametrize("name,bad", [("cli_derivation", "upstream-patched"), ("schema", True),
                                    ("native_addons", 0), ("entrypoint_sha256", "0" * 64),
                                    ("dependency_overrides_sha256", "0" * 64),
                                    ("omitted_runtime_dependencies", {}), ("source_bundle_sha256", "0" * 64),
                                    ("upstream_patched", True), ("source_materials", True)])
def test_caller_booleans_and_forged_derivation_metadata_do_not_authorize_provider(inputs, name, bad):
    provider = json.loads(inputs["provider_manifest"])
    provider[name] = bad
    inputs["provider_manifest"] = plan.encoded(provider)
    inputs["provenance"]["provider_manifest_sha256"] = plan.digest(inputs["provider_manifest"])
    inputs["after"]["roots"][plan.SUPPORT][plan.PROVIDER + "/runtime-manifest.json"] = file_node(inputs["provider_manifest"])
    with pytest.raises(plan.Refused):
        plan.derive(**arguments(inputs))


def test_forge_presence_is_rejected_even_with_valid_derivation_pins(inputs):
    put(inputs["after"]["roots"][plan.SUPPORT], plan.PROVIDER + "/node_modules/node-forge/x.js", file_node())
    with pytest.raises(plan.Refused):
        plan.derive(**arguments(inputs))


def test_every_target_project_module_needs_a_source_binding(inputs):
    put(inputs["after"]["roots"][plan.SUPPORT], plan.PACKAGE + "/unbound.py", file_node())
    with pytest.raises(plan.Refused):
        plan.derive(**arguments(inputs))


@pytest.mark.parametrize("node", [{"kind": "directory", "mode": 0o755},
                                  {"kind": "symlink", "target": "storage.py"}])
def test_module_suffix_cannot_hide_a_nonregular_unbound_source(inputs, node):
    put(inputs["after"]["roots"][plan.SUPPORT], plan.PACKAGE + "/unbound.py", node)
    with pytest.raises(plan.Refused):
        plan.derive(**arguments(inputs))


def test_private_case_variation_cannot_be_present_even_unchanged(inputs):
    for value in (inputs["before"], inputs["after"]):
        put(value["roots"][plan.SUPPORT], "Broker/opaque", file_node())
    with pytest.raises(plan.Refused):
        plan.derive(**arguments(inputs))


@pytest.mark.parametrize("fault", ["identity-size", "provider-mode", "provider-ledger"])
def test_declared_resource_bytes_and_provider_ledger_cannot_be_substituted(inputs, fault):
    rows = inputs["after"]["roots"][plan.SUPPORT]
    if fault == "identity-size":
        rows["package-identity.json"]["size"] += 1
    elif fault == "provider-mode":
        rows[plan.PROVIDER + "/runtime-manifest.json"]["mode"] = 0o600
    else:
        rows[plan.PROVIDER + "/dependency-overrides.json"]["sha256"] = "0" * 64
    with pytest.raises(plan.Refused):
        plan.derive(**arguments(inputs))


@pytest.mark.parametrize("mutation", ["missing-unit", "extra-unit", "duplicate-change", "false-scope", "unknown-key"])
def test_resealed_plan_cannot_enlarge_or_shrink_complete_coverage(inputs, mutation):
    args = arguments(inputs)
    value = json.loads(plan.derive(**args))
    if mutation == "missing-unit":
        value["units"].pop()
    elif mutation == "extra-unit":
        value["units"].append(copy.deepcopy(value["units"][0]))
    elif mutation == "duplicate-change":
        value["changed"].append(value["changed"][0])
    elif mutation == "false-scope":
        value["native_signature_and_payload_verification_required"] = False
    else:
        value["optional"] = True
    raw = plan.encoded(value)
    with pytest.raises(plan.Refused):
        plan.parse(raw, expected_plan_sha256=plan.digest(raw), **args)


@pytest.mark.parametrize("fault", ["fixture-team", "new-broker", "changed-dr", "source-path", "source-bool", "stale-wheel"])
def test_signature_source_and_archive_pins_are_concrete(inputs, fault):
    peers = json.loads(inputs["new_identity"])
    if fault == "fixture-team":
        peers["signatures"]["owner"]["team"] = "fixture"
    elif fault == "new-broker":
        peers["signatures"]["broker"]["hashes"] = ["e" * 40]
    elif fault == "changed-dr":
        inputs["provenance"]["designated_requirements"]["owner"]["after"] = "other"
    elif fault == "source-path":
        inputs["provenance"]["target_source_files"]["../escape"] = "0" * 64
    elif fault == "source-bool":
        inputs["provenance"]["target_source_files"]["macos/AccountAccess.swift"] = True
    else:
        inputs["after"]["roots"][plan.SUPPORT][plan.BUNDLE_WHEEL] = file_node(b"stale")
    inputs["new_identity"] = plan.encoded(peers)
    inputs["after"]["roots"][plan.SUPPORT]["package-identity.json"] = file_node(inputs["new_identity"])
    with pytest.raises(plan.Refused):
        plan.derive(**arguments(inputs))


@pytest.mark.parametrize("fault", ["bool-mode", "alias-escape", "case-collision", "private-prefix-confusion"])
def test_existing_strict_manifest_semantics_are_reused(inputs, fault):
    rows = inputs["after"]["roots"][plan.SUPPORT]
    if fault == "bool-mode":
        rows[plan.PACKAGE]["mode"] = True
    elif fault == "alias-escape":
        put(rows, "owner.app/escape", {"kind": "symlink", "target": "../../../../outside"})
    elif fault == "case-collision":
        put(rows, "OWNER.APP", {"kind": "directory", "mode": 0o755})
    else:
        put(rows, "broker-nearly/x", file_node())
    with pytest.raises(plan.Refused):
        plan.derive(**arguments(inputs))


def test_duplicate_json_stale_hash_and_noncanonical_plan_refused(inputs):
    args = arguments(inputs)
    raw = plan.derive(**args)
    for altered, pin in ((raw, "0" * 64), (raw.replace(b'{"', b'{"schema":1,"', 1), None),
                         (json.dumps(json.loads(raw), indent=2).encode(), None)):
        with pytest.raises(plan.Refused):
            plan.parse(altered, expected_plan_sha256=pin or plan.digest(altered), **args)


@pytest.mark.parametrize("field,bad", [("before_manifest", []), ("after_manifest", {}),
                                    ("old_identity", None), ("new_identity", b"[]"),
                                    ("provenance", []), ("provider_manifest", [b"no"])])
def test_malformed_outer_values_have_one_closed_refusal(inputs, field, bad):
    args = arguments(inputs)
    args[field] = bad
    with pytest.raises(plan.Refused, match="^full_image_plan_refused$"):
        plan.derive(**args)


@pytest.mark.parametrize("fault", ["manifest-node-kind-list", "source-values-dict", "requirement-list", "invalid-surrogate"])
def test_malformed_nested_values_never_leak_type_or_encoding_errors(inputs, fault):
    if fault == "manifest-node-kind-list":
        inputs["after"]["roots"][plan.SUPPORT][plan.PACKAGE]["kind"] = []
    elif fault == "source-values-dict":
        inputs["provenance"]["target_source_files"]["macos/AccountAccess.swift"] = {"unexpected": []}
    elif fault == "requirement-list":
        inputs["provenance"]["designated_requirements"]["owner"] = []
    else:
        inputs["provenance"]["designated_requirements"]["owner"] = {"before": "\ud800", "after": "\ud800"}
    with pytest.raises(plan.Refused, match="^full_image_plan_refused$"):
        plan.derive(**arguments(inputs))


def test_derivation_and_parse_perform_no_filesystem_or_process_work(inputs, monkeypatch):
    import builtins
    import os
    import subprocess
    args = arguments(inputs)
    def refused(*unused, **ignored):
        pytest.fail("pure planning must not inspect host state")
    monkeypatch.setattr(builtins, "open", refused)
    monkeypatch.setattr(os, "stat", refused)
    monkeypatch.setattr(subprocess, "run", refused)
    raw = plan.derive(**args)
    assert plan.parse(raw, expected_plan_sha256=plan.digest(raw), **args)["production_ready"] is False
