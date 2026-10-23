"""Closed CA-v2 planning with synthetic inventories, never payload/native trust.

Synthetic tests explicitly replace the two complete-cohort digest constants so
the independent structural refusal checks can run on small fictional images.
The production planner has no caller flag for selecting another cohort.
"""

import copy
import json

import pytest

from test_full_image_update import arguments, configuration_extension, file_node, inputs, plan, put  # noqa: F401

SOURCE_PROFILE = {
    "lib/python3.12/site-packages/pip/__init__.py": "04aa76ceab0f4341e292daae35637f2f8718b183313cc2fb588d1304cb9c0443",
    "lib/python3.12/site-packages/pip/_vendor/vendor.txt": "3df0c9601bfa2e0dca23cc574a4f900a4d7fdad060ab203fab8354350ed93320",
    "lib/python3.12/site-packages/pip/_vendor/certifi/__init__.py": "f96d51ff2f1609a4a44f5b5d8eec47ff34c1658d581fac5081d3759db05a8ce1",
    "lib/python3.12/site-packages/pip/_vendor/certifi/cacert.pem": "bbc7e9c01d7551bb8a159b5dedd989b8ee3ce105aff522b68eb1b01bf854cab0",
    "lib/python3.12/ensurepip/__init__.py": "90f6c76cd9ef7ed6daa198bb9ef771139683487f1b061211be7aa511831b2028",
    "lib/python3.12/ensurepip/_bundled/pip-25.0.1-py3-none-any.whl": "c46efd13b6aa8279f33f2864459c8ce587ea6a1a59ee20de055868d8f7688f7f",
}
OFFICIAL_WHEEL = "fd7f4dfa8190e014013b9f08f3e973f4e4c26ffd179a204895533a7254813a70"
CA_SHA = "50f79f98dac192b20dbf73f35c56f0b0c557ab267ff5199d1117cc1180b70785"


@pytest.fixture
def ca_inputs(inputs):  # noqa: F811
    value = copy.deepcopy(inputs)
    old, new = (value[side]["roots"][plan.SUPPORT] for side in ("before", "after"))
    for rows in (old, new):
        for path, node in list(rows.items()):
            if plan._below(path, plan.PROVIDER):
                put(rows, plan.PYTHON_PROVIDER + path.removeprefix(plan.PROVIDER), copy.deepcopy(node))
    receipt = {"schema": 1, "transform": "account-access-frozen-python312-packaging-ca-refresh-v1",
        "source_python_sha256": "a" * 64, "refreshed_python_sha256": "b" * 64,
        "official_pip_wheel_sha256": OFFICIAL_WHEEL, "pip_version": "26.2.2", "certifi_version": "2026.10.19",
        "ca_sha256": CA_SHA, "ca_certificates": 120,
        "removed_root_certificate_sha256": ["86a1ecba089c4a8d3bbe2734c612ba341d813e043cf9e8a862cd5c57a36bbe6b",
            "d7a7a0fb5d7e2731d771e9484ebcdef71d5f0c3e0a2948782bc83ee0ea699ef4"],
        "source_profile_sha256": SOURCE_PROFILE, "ensurepip_initializer_sha256": "c" * 64,
        "both_active_and_seed_refreshed": True, "package_code_executed": False,
        "system_or_embedded_native_trust_stores_audited": False}
    for prefix in ("python", "runtime"):
        for path, pin in SOURCE_PROFILE.items():
            put(old, prefix + "/" + path, file_node(sha=pin))
            if "/_bundled/" not in path:
                after_pin = CA_SHA if path.endswith("/cacert.pem") else (
                    receipt["ensurepip_initializer_sha256"] if path.endswith("ensurepip/__init__.py") else plan.digest(b"refreshed-" + path.encode()))
                put(new, prefix + "/" + path, file_node(sha=after_pin))
        put(new, prefix + "/lib/python3.12/ensurepip/_bundled/pip-26.2.2-py3-none-any.whl", file_node(sha=OFFICIAL_WHEEL))
        put(old, prefix + "/lib/python3.12/site-packages/pip-26.2.1.dist-info/METADATA", file_node(b"old-pip"))
        put(new, prefix + "/lib/python3.12/site-packages/pip-26.2.2.dist-info/METADATA", file_node(b"new-pip"))
        for executable in ("pip", "pip3", "pip3.12"):
            put(old, prefix + "/bin/" + executable, file_node(b"old-wrapper", mode=0o755))
            if executable != "pip3.12":
                put(new, prefix + "/bin/" + executable, file_node(b"new-wrapper", mode=0o755))
    for rows, content in ((old, b"old-data"), (new, b"new-data")):
        put(rows, plan.PACKAGE + "/data.txt", file_node(content))
    new[plan.DIST_INFO + "/RECORD"] = file_node(b"new-record")
    new["runtime-image.json"] = file_node(b"new-image-descriptor")
    new["package-requirements.txt"] = file_node(b"new-project-wheel-pin")
    del new["component-identity.json"]
    value["ca_receipt"] = plan.encoded(receipt)
    new["runtime-ca-refresh.json"] = file_node(value["ca_receipt"])
    return value


def ca_arguments(value):
    return {**arguments(value), "ca_receipt": value["ca_receipt"]}


def reviewed_synthetic_cohort(monkeypatch, value):
    args = ca_arguments(value)
    monkeypatch.setattr(plan, "CA_BASE_MANIFEST", plan.digest(args["before_manifest"]))
    monkeypatch.setattr(plan, "CA_TARGET_MANIFEST", plan.digest(args["after_manifest"]))
    return args


def test_ca_v2_has_exact_closed_unit_order_and_explicit_absent_sides(ca_inputs, monkeypatch):
    args = reviewed_synthetic_cohort(monkeypatch, ca_inputs)
    raw = plan.derive(**args)
    result = plan.parse(raw, expected_plan_sha256=plan.digest(raw), **args)
    assert result["schema"] == 1 and result["managed_by"] == plan.CA_MARKER
    assert result["standalone_provider_matches_active"] is True
    assert result["native_optional_tree_moves_and_loader_review_required"] is True
    assert result["production_ready"] is False
    trees = [unit for unit in result["units"] if unit["kind"] == "public_tree"]
    files = [unit for unit in result["units"] if unit["kind"] == "public_file"]
    assert [unit["path"] for unit in trees] == list(plan.CA_UNIT_TREES)
    assert len(trees) == 13 and len(files) == 12
    assert {unit["path"] for unit in files} == plan.CA_FILES
    assert sorted(name for unit in result["units"] for name in unit["changed"]) == result["changed"]
    for unit in trees:
        sides = plan.OPTIONAL_TREE_SIDES.get(unit["path"], (True, True))
        for key, present in zip(("before", "after"), sides):
            assert key in unit and bool(unit[key]) is present
            assert unit[key + "_inventory_sha256"] == plan.digest(plan.encoded(unit[key]))
            if not present:
                assert unit[key] is None
    assert result["closed_CA_profile"]["official_wheel_sha256"] == OFFICIAL_WHEEL


def test_ca_cohort_cannot_be_selected_by_caller_or_silently_downgraded(ca_inputs):
    args = ca_arguments(ca_inputs)
    with pytest.raises(plan.Refused):
        plan.derive(**args)
    args.pop("ca_receipt")
    with pytest.raises(plan.Refused):
        plan.derive(**args)


def test_reviewed_configuration_cohort_requires_complete_manifest_and_model_pins(ca_inputs, monkeypatch):
    configuration_extension(ca_inputs)
    args = ca_arguments(ca_inputs)
    monkeypatch.setattr(plan, "CA_BASE_MANIFEST", plan.digest(args["before_manifest"]))
    monkeypatch.setattr(plan, "CA_CONFIGURATION_TARGET_MANIFEST", plan.digest(args["after_manifest"]))
    raw = plan.derive(**args)
    assert plan.parse(raw, expected_plan_sha256=plan.digest(raw), **args)["configuration_model_upgrade"] == plan.CONFIGURATION_MODEL_UPGRADE
    # Changing a file cannot select another target, even with fresh provenance.
    ca_inputs["after"]["roots"][plan.SUPPORT][plan.PACKAGE + "/data.txt"] = file_node(b"different-build")
    with pytest.raises(plan.Refused):
        plan.derive(**ca_arguments(ca_inputs))


@pytest.mark.parametrize("side", ["before", "after"])
def test_wrong_complete_manifest_pin_refuses(ca_inputs, monkeypatch, side):
    args = reviewed_synthetic_cohort(monkeypatch, ca_inputs)
    monkeypatch.setattr(plan, "CA_BASE_MANIFEST" if side == "before" else "CA_TARGET_MANIFEST", "0" * 64)
    with pytest.raises(plan.Refused):
        plan.derive(**args)


@pytest.mark.parametrize("prefix", ["python", "runtime"])
@pytest.mark.parametrize("change", ["stale-ca", "stale-seed", "stale-source-profile", "retained-old-info", "missing-new-info",
                                    "wrong-old-polarity", "retained-pip312", "missing-tree", "unbound-native", "broad-package"])
def test_each_prefix_requires_exact_reviewed_ca_transition(ca_inputs, monkeypatch, prefix, change):
    old, new = (ca_inputs[side]["roots"][plan.SUPPORT] for side in ("before", "after"))
    if change == "stale-ca":
        new[prefix + "/lib/python3.12/site-packages/pip/_vendor/certifi/cacert.pem"] = file_node(b"stale-ca")
    elif change == "stale-seed":
        new[prefix + "/lib/python3.12/ensurepip/_bundled/pip-26.2.2-py3-none-any.whl"] = file_node(b"stale-wheel")
    elif change == "stale-source-profile":
        old[prefix + "/lib/python3.12/site-packages/pip/__init__.py"] = file_node(b"unrecognized-source")
    elif change == "retained-old-info":
        path = prefix + "/lib/python3.12/site-packages/pip-26.2.1.dist-info"
        put(new, path, old[path])
    elif change == "missing-new-info":
        path = prefix + "/lib/python3.12/site-packages/pip-26.2.2.dist-info"
        for name in [name for name in new if plan._below(name, path)]:
            del new[name]
    elif change == "wrong-old-polarity":
        put(old, prefix + "/lib/python3.12/site-packages/pip-26.2.2.dist-info", {"kind": "directory", "mode": 0o755})
    elif change == "retained-pip312":
        put(new, prefix + "/bin/pip3.12", file_node(mode=0o755))
    elif change == "missing-tree":
        path = prefix + "/lib/python3.12/ensurepip"
        for name in [name for name in new if plan._below(name, path)]:
            del new[name]
    elif change == "unbound-native":
        put(new, prefix + "/bin/python3.12", file_node(b"new-native", mode=0o755))
    else:
        put(new, prefix + "/lib/python3.12/site-packages/another_package/module.py", file_node(b"unknown-dependency"))
    with pytest.raises(plan.Refused):
        plan.derive(**reviewed_synthetic_cohort(monkeypatch, ca_inputs))


@pytest.mark.parametrize("change", ["missing", "different-bytes", "forge-only-standalone", "mode"])
def test_standalone_provider_must_equal_active_full_inventory(ca_inputs, monkeypatch, change):
    rows = ca_inputs["after"]["roots"][plan.SUPPORT]
    if change == "missing":
        for name in [name for name in rows if plan._below(name, plan.PYTHON_PROVIDER)]:
            del rows[name]
    elif change == "different-bytes":
        rows[plan.PYTHON_PROVIDER + "/build/bw.js"] = file_node(b"unreviewed-provider")
    elif change == "mode":
        rows[plan.PYTHON_PROVIDER]["mode"] = 0o700
    else:
        put(rows, plan.PYTHON_PROVIDER + "/node_modules/node-forge/extra.js", file_node())
    with pytest.raises(plan.Refused):
        plan.derive(**reviewed_synthetic_cohort(monkeypatch, ca_inputs))


@pytest.mark.parametrize("field,bad", [("schema", True), ("transform", "other"), ("source_python_sha256", "unbound"),
    ("official_pip_wheel_sha256", "0" * 64), ("pip_version", "26.2.1"), ("certifi_version", "2026.7.22"),
    ("ca_sha256", "0" * 64), ("ca_certificates", True), ("ca_certificates", 501),
    ("removed_root_certificate_sha256", []), ("source_profile_sha256", {}),
    ("ensurepip_initializer_sha256", "0" * 64), ("both_active_and_seed_refreshed", 1),
    ("package_code_executed", True), ("system_or_embedded_native_trust_stores_audited", True), ("extra", True)])
def test_fixed_receipt_profile_cannot_be_replaced_by_caller_claims(ca_inputs, monkeypatch, field, bad):
    receipt = json.loads(ca_inputs["ca_receipt"])
    receipt[field] = bad
    ca_inputs["ca_receipt"] = plan.encoded(receipt)
    ca_inputs["after"]["roots"][plan.SUPPORT]["runtime-ca-refresh.json"] = file_node(ca_inputs["ca_receipt"])
    with pytest.raises(plan.Refused):
        plan.derive(**reviewed_synthetic_cohort(monkeypatch, ca_inputs))


@pytest.mark.parametrize("change", ["receipt-size", "duplicate-json", "missing", "metadata-mode"])
def test_ca_receipt_bytes_must_match_complete_image_node(ca_inputs, monkeypatch, change):
    rows = ca_inputs["after"]["roots"][plan.SUPPORT]
    if change == "receipt-size":
        rows["runtime-ca-refresh.json"]["size"] += 1
    elif change == "metadata-mode":
        rows["runtime-ca-refresh.json"]["mode"] = 0o600
    elif change == "missing":
        del rows["runtime-ca-refresh.json"]
    else:
        ca_inputs["ca_receipt"] = ca_inputs["ca_receipt"].replace(b'{"', b'{"schema":1,"', 1)
        rows["runtime-ca-refresh.json"] = file_node(ca_inputs["ca_receipt"])
    with pytest.raises(plan.Refused):
        plan.derive(**reviewed_synthetic_cohort(monkeypatch, ca_inputs))


@pytest.mark.parametrize("change", ["omit-side", "empty-side", "both-absent", "wrong-polarity", "unbound-unit", "downgrade"])
def test_resealed_optional_plan_cannot_omit_or_reverse_manifest_authority(ca_inputs, monkeypatch, change):
    args = reviewed_synthetic_cohort(monkeypatch, ca_inputs)
    value = json.loads(plan.derive(**args))
    unit = next(unit for unit in value["units"] if unit["path"].endswith("pip-26.2.2.dist-info"))
    if change == "omit-side":
        unit.pop("before")
    elif change == "empty-side":
        unit["before"] = {}
    elif change == "both-absent":
        unit["after"] = None
    elif change == "wrong-polarity":
        unit["before"], unit["after"] = unit["after"], unit["before"]
    elif change == "unbound-unit":
        unit["path"] = "runtime/lib/python3.12/site-packages"
    else:
        value["managed_by"] = plan.MARKER
    raw = plan.encoded(value)
    with pytest.raises(plan.Refused):
        plan.parse(raw, expected_plan_sha256=plan.digest(raw), **args)


@pytest.mark.parametrize("value", [None, {}, [], b"[]", b"{}", b"null", b"", True])
def test_malformed_or_missing_ca_receipt_has_closed_failure(ca_inputs, monkeypatch, value):
    args = reviewed_synthetic_cohort(monkeypatch, ca_inputs)
    args["ca_receipt"] = value
    with pytest.raises(plan.Refused, match="^full_image_plan_refused$"):
        plan.derive(**args)


def test_expanded_plan_and_roundtrip_are_data_only(ca_inputs, monkeypatch):
    import builtins
    import os
    import subprocess
    args = reviewed_synthetic_cohort(monkeypatch, ca_inputs)

    def refused(*unused, **ignored):
        pytest.fail("pure planning must not inspect host state or execute a payload")

    monkeypatch.setattr(builtins, "open", refused)
    monkeypatch.setattr(os, "stat", refused)
    monkeypatch.setattr(subprocess, "run", refused)
    raw = plan.derive(**args)
    assert plan.parse(raw, expected_plan_sha256=plan.digest(raw), **args)["production_ready"] is False
