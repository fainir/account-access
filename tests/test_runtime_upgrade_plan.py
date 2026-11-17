"""Public inventory qualification only; no update or account authority."""
from copy import deepcopy

import pytest

from macos import runtime_upgrade_plan as plan
from test_full_image_update import file_node, identity, image, put


@pytest.fixture
def fixture(monkeypatch):
    old = {"": {"kind": "directory", "mode": 0o755}}
    for path in plan.TREES:
        put(old, path, {"kind": "directory", "mode": 0o755})
        if path != "bin":
            put(old, path + "/fixture", file_node())
    for path in plan.FILES:
        put(old, path, file_node())
    for path in plan.NATIVE:
        put(old, path, file_node(mode=0o755))
    put(old, "owner.app/Contents/MacOS/AccountAccess", file_node(mode=0o755))
    for name in (*plan.UNCHANGED, "agent_setup.py"):
        put(old, plan.image.PACKAGE + "/" + name, file_node())
    for path in (plan.image.PROJECT_WHEEL, plan.image.BUNDLE_WHEEL):
        put(old, path, file_node())
    old_identity, new_identity = identity("a"), identity("b", broker="e", bootstrap="f")
    old["package-identity.json"] = file_node(old_identity)
    new = deepcopy(old)
    new["package-identity.json"] = file_node(new_identity)
    for path in plan.TREES:
        if path == "bin":
            for executable in plan.NATIVE:
                new[executable] = file_node(("rotated " + executable).encode(), mode=0o755)
        else:
            new[path + "/fixture"] = file_node(b"changed")
    new[plan.image.PACKAGE + "/agent_setup.py"] = file_node(b"connection fix")
    new[plan.image.PROJECT_WHEEL] = new[plan.image.BUNDLE_WHEEL] = file_node(b"new wheel")
    del new["broker-repair-identity.json"]
    def arguments():
        before, after = plan.image.encoded(image(old)), plan.image.encoded(image(new))
        monkeypatch.setattr(plan, "BEFORE", plan.image.digest(before))
        monkeypatch.setattr(plan, "AFTER", plan.image.digest(after))
        sources = {"account_access/" + n: new[plan.image.PACKAGE + "/" + n]["sha256"]
                   for n in (*plan.UNCHANGED, "agent_setup.py")}
        sources["macos/AccountAccess.swift"] = "f" * 64
        return dict(before_manifest=before, after_manifest=after, old_identity=old_identity,
                    new_identity=new_identity, source_files=sources)
    return old, new, arguments


def test_complete_public_units_cover_changes_once(fixture):
    _, _, args = fixture
    inputs = args()
    raw = plan.derive(**inputs)
    result = plan.parse(raw, expected_sha256=plan.image.digest(raw), **inputs)
    assert result["production_ready"] is False
    assert result["completed_repair_proof_required"] is True
    covered = [p for u in result["units"] for p in u["changed"]]
    assert sorted(covered) == result["changed"] and len(set(covered)) == len(covered)
    assert {u["path"] for u in result["units"] if u["kind"] == "public_tree"} == set(plan.TREES)
    bin_unit = next(u for u in result["units"] if u["path"] == "bin")
    expected_nodes = {"bin", *plan.NATIVE}
    assert set(bin_unit["before"]) == set(bin_unit["after"]) == expected_nodes
    assert bin_unit["before"]["bin"] == bin_unit["after"]["bin"] == {"kind": "directory", "mode": 0o755}
    for path in plan.NATIVE:
        assert bin_unit["before"][path]["kind"] == bin_unit["after"][path]["kind"] == "file"
        assert bin_unit["before"][path]["mode"] == bin_unit["after"][path]["mode"] == 0o755
        assert bin_unit["before"][path]["sha256"] != bin_unit["after"][path]["sha256"]
    assert result["old_peers"]["broker"] != result["new_peers"]["broker"]
    assert result["old_peers"]["bootstrap"] != result["new_peers"]["bootstrap"]
    assert next(u for u in result["units"] if u["path"] == "broker-repair-identity.json")["after"] is None


@pytest.mark.parametrize("path", ["bin/foreign", *(plan.image.PACKAGE + "/" + n for n in plan.UNCHANGED),
                                  "unknown-public-file", "owner.json", "vault/private", "broker/install.json"])
def test_native_store_or_uncovered_changes_refused(fixture, path):
    _, new, args = fixture
    put(new, path, file_node(b"foreign"))
    with pytest.raises(plan.image.Refused):
        plan.derive(**args())


@pytest.mark.parametrize("fault", ["alias", "root", "missing_tree", "wrong_tree_mode", "wrong_bin_mode",
                                 "missing_native_executable", "nonexecutable_native", "repair_identity_retained",
                                 "wheel_mismatch", "setup_unchanged", "missing_source", "foreign_source", "wrong_source"])
def test_publication_and_source_substitutions_refused(fixture, fault):
    old, new, args = fixture
    if fault == "root":
        new[""]["mode"] = 0o700
    elif fault == "missing_tree":
        del new["browsers"]
    elif fault == "wrong_tree_mode":
        new["browsers"]["mode"] = 0o700
    elif fault == "wrong_bin_mode":
        new["bin"]["mode"] = 0o700
    elif fault == "missing_native_executable":
        del new[plan.NATIVE[0]]
    elif fault == "nonexecutable_native":
        new[plan.NATIVE[1]]["mode"] = 0o644
    elif fault == "repair_identity_retained":
        new["broker-repair-identity.json"] = old["broker-repair-identity.json"]
    elif fault == "wheel_mismatch":
        new[plan.image.BUNDLE_WHEEL] = file_node(b"other")
    elif fault == "setup_unchanged":
        new[plan.image.PACKAGE + "/agent_setup.py"] = old[plan.image.PACKAGE + "/agent_setup.py"]
    inputs = args()
    if fault == "alias":
        value = plan.image._json(inputs["after_manifest"], plan.image.MAX_MANIFEST_BYTES)
        value["roots"][plan.image.APPLICATION][""]["target"] = "/tmp/foreign"
        inputs["after_manifest"] = plan.image.encoded(value)
    elif fault == "missing_source":
        del inputs["source_files"]["account_access/agent_setup.py"]
    elif fault == "foreign_source":
        inputs["source_files"]["../foreign.py"] = "f" * 64
    elif fault == "wrong_source":
        inputs["source_files"]["account_access/agent_setup.py"] = "0" * 64
    with pytest.raises(plan.image.Refused):
        plan.derive(**inputs)


def test_plan_cannot_change_units_or_pin(fixture):
    _, _, args = fixture
    inputs = args()
    raw = plan.derive(**inputs)
    value = plan.image._json(raw, plan.image.MAX_PLAN_BYTES)
    value["units"][0]["path"] = "vault"
    changed = plan.image.encoded(value)
    with pytest.raises(plan.image.Refused):
        plan.parse(changed, expected_sha256=plan.image.digest(changed), **inputs)
    with pytest.raises(plan.image.Refused):
        plan.parse(raw, expected_sha256="0" * 64, **inputs)
