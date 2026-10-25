"""Synthetic proposal contracts, with no installed reads or update authority."""

from copy import deepcopy

import pytest

from macos import owner_upgrade_plan as plan
from test_full_image_update import file_node, identity, image, put


@pytest.fixture
def fixture(monkeypatch):
    old = {"": {"kind": "directory", "mode": 0o755}}
    for path in (
        "owner.app/Contents/Info.plist",
        "owner.app/Contents/MacOS/AccountAccess",
        "runtime/fixture",
        "python/fixture",
        "wheels/fixture",
        "bin/AccountAccess-broker",
    ):
        put(old, path, file_node(mode=0o755 if path.endswith("/AccountAccess") else 0o644))
    before_identity, after_identity = identity("a"), identity("b")
    old["package-identity.json"] = file_node(before_identity)
    new = deepcopy(old)
    new["owner.app/Contents/Info.plist"] = file_node(b"new plist")
    new["owner.app/Contents/MacOS/AccountAccess"] = file_node(b"new executable", mode=0o755)
    new["package-identity.json"] = file_node(after_identity)
    sources = {name: "f" * 64 for name in plan.NATIVE_SOURCES}
    monkeypatch.setattr(plan, "SOURCE_FILES", sources)

    def arguments():
        before, after = plan.image.encoded(image(old)), plan.image.encoded(image(new))
        monkeypatch.setattr(plan, "BEFORE", plan.image.digest(before))
        monkeypatch.setattr(plan, "AFTER", plan.image.digest(after))
        return dict(
            before_manifest=before,
            after_manifest=after,
            old_identity=before_identity,
            new_identity=after_identity,
            source_files=dict(sources),
        )

    return old, new, arguments


def test_only_owner_tree_and_identity_are_proposed(fixture):
    _, _, args = fixture
    inputs = args()
    raw = plan.derive(**inputs)
    result = plan.parse(raw, expected_sha256=plan.image.digest(raw), **inputs)
    assert result["changed"] == sorted(plan.CHANGED)
    assert [(u["kind"], u["path"]) for u in result["units"]] == [
        ("public_tree", "owner.app"),
        ("public_file", "package-identity.json"),
    ]
    assert result["completed_runtime_proof_required"] is True
    assert result["native_signature_checks_required"] is True
    assert result["installation_authority"] is result["production_ready"] is False


@pytest.mark.parametrize(
    "path",
    [
        "runtime/fixture",
        "python/fixture",
        "wheels/fixture",
        "bin/AccountAccess-broker",
        "owner.app/Contents/Resources/new",
        "vault/private",
        "owner.json",
        "broker/install.json",
    ],
)
def test_runtime_private_and_extra_app_changes_refused(fixture, path):
    _, new, args = fixture
    put(new, path, file_node(b"foreign"))
    with pytest.raises(plan.image.Refused):
        plan.derive(**args())


@pytest.mark.parametrize(
    "fault",
    [
        "missing",
        "unchanged",
        "binary_mode",
        "plist_mode",
        "root_mode",
        "app_mode",
        "source_missing",
        "source_changed",
        "source_extra",
        "identity_changed",
        "manifest_changed",
        "alias_changed",
    ],
)
def test_changed_metadata_and_bindings_refused(fixture, fault):
    old, new, args = fixture
    binary = "owner.app/Contents/MacOS/AccountAccess"
    if fault == "missing":
        del new[binary]
    elif fault == "unchanged":
        new[binary] = old[binary]
    elif fault == "binary_mode":
        new[binary]["mode"] = 0o700
    elif fault == "plist_mode":
        new["owner.app/Contents/Info.plist"]["mode"] = 0o600
    elif fault == "root_mode":
        new[""]["mode"] = 0o700
    elif fault == "app_mode":
        new["owner.app"]["mode"] = 0o700
    inputs = args()
    if fault == "source_missing":
        inputs["source_files"].pop("macos/ManagedAgentSetup.swift")
    elif fault == "source_changed":
        inputs["source_files"]["macos/ManagedAgentSetup.swift"] = "0" * 64
    elif fault == "source_extra":
        inputs["source_files"]["unrelated.swift"] = "f" * 64
    elif fault == "identity_changed":
        inputs["new_identity"] = identity("e")
    elif fault == "manifest_changed":
        inputs["after_manifest"] += b" "
    elif fault == "alias_changed":
        manifest = plan.image._json(inputs["after_manifest"], plan.image.MAX_MANIFEST_BYTES)
        manifest["roots"][plan.image.APPLICATION][""]["target"] = "/tmp/foreign"
        inputs["after_manifest"] = plan.image.encoded(manifest)
        # Pin the hostile fixture to exercise alias validation, not just hashing.
        plan.AFTER = plan.image.digest(inputs["after_manifest"])
    with pytest.raises(plan.image.Refused):
        plan.derive(**inputs)


def test_changed_plan_authority_or_hash_refused(fixture):
    _, _, args = fixture
    inputs = args()
    raw = plan.derive(**inputs)
    altered = plan.image._json(raw, plan.image.MAX_PLAN_BYTES)
    altered["installation_authority"] = True
    forged = plan.image.encoded(altered)
    with pytest.raises(plan.image.Refused):
        plan.parse(forged, expected_sha256=plan.image.digest(forged), **inputs)
    with pytest.raises(plan.image.Refused):
        plan.parse(raw, expected_sha256="0" * 64, **inputs)


@pytest.mark.parametrize("peer", ["broker", "bootstrap", "owner"])
def test_only_the_owner_signature_can_rotate(fixture, peer, monkeypatch):
    _, new, args = fixture
    inputs = args()
    value = plan.image._json(inputs["new_identity"], 8192)
    value["signatures"][peer]["hashes"] = [("a" if peer == "owner" else "e") * 40]
    changed = plan.image.encoded(value)
    new["package-identity.json"] = file_node(changed)
    inputs = args()
    inputs["new_identity"] = changed
    with pytest.raises(plan.image.Refused):
        plan.derive(**inputs)
