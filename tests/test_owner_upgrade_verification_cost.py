from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "macos/source-fragments/OwnerUpgradeInstalledAdapter.swift.inc"


def test_owner_upgrade_revalidates_captured_history_without_rebuilding_full_proof():
    source = SOURCE.read_text()
    body = source[source.index("static func runOwnerUpgrade("):]

    # The initial proof qualifies the predecessor. A fresh install then proves
    # the prepared owner projection once; recovery already did so while loading
    # its existing intent. Transition boundaries must keep using that projected
    # proof instead of rescanning the entire predecessor image at every step.
    assert body.count("completedRuntimeUpgradeLocked(") == 3
    assert "try proof.revalidateHistory()" in body
    assert "let projected = try ownerProjection(source: source, intent: intent, files: files, routes: routes)" in body
    assert "if preliminary != nil { activeProof = proof }" in body
    assert "expectedEvidenceSHA256: proof.sha256, projection: projected" in body

    verify_unchanged = body.split("let verifyUnchanged = {", 1)[1].split(
        "let verifyPublic = {", 1
    )[0]
    assert "try activeProof.revalidateHistory()" in verify_unchanged

    verify_public = body.split("let verifyPublic = {", 1)[1].split(
        "let storage = try FullImageMixedStorage", 1
    )[0]
    assert "try fullLayout(source: source" in verify_public
    assert "try FullImagePublicView.verify(source: source, states: states" in verify_public
    assert "try ownerUpgradeSignatures(source, root:" in verify_public

    storage = body.split("let storage = try FullImageMixedStorage", 1)[1].split(
        "reference.storage = storage", 1
    )[0]
    assert "verifyOld: verifyPublic" in storage
    assert "verifyRecoverable: verifyPublic" in storage
    assert "verifyNew: verifyPublic" in storage
    assert "completedRuntimeUpgradeLocked(" not in storage
