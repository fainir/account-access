"""No network or upstream execution is needed to check the reviewed inventory."""

import hashlib
from pathlib import Path
import re

import pytest

from macos import bitwarden_notices as notices


FIXTURE = Path(__file__).parent / "fixtures" / "bitwarden" / "block-modes-0.9.1.crate"
MATERIAL = "cargo/block-modes-0.9.1.crate"
ORIGIN = {"url": "https://static.crates.io/crates/block-modes/block-modes-0.9.1.crate"}


@pytest.fixture(autouse=True)
def clear_catalog_cache():
    notices._catalog.cache_clear()
    yield
    notices._catalog.cache_clear()


def test_all_reviewed_notices_have_exact_archive_and_primary_document_bindings():
    catalog = notices._catalog()
    assert len(catalog["components"]) == 116
    assert len(catalog["documents"]) == 31
    methods = set()
    for material, row in catalog["components"].items():
        assert material.startswith(("npm/", "cargo/"))
        assert re.fullmatch(r"[0-9a-f]{64}", row["archive_sha256"])
        assert row["metadata"]["license"] == row["declared_license"]
        assert (row["metadata"]["name"], row["metadata"]["version"]) == (row["name"], row["version"])
        assert row["documents"] or row["evidence"]
        methods.add(row["method"])
        for evidence in row["evidence"]:
            assert hashlib.sha256(evidence["text"].encode()).hexdigest() == evidence["sha256"]
        for identifier in row["documents"]:
            document = catalog["documents"][identifier]
            assert re.match(r"https://raw\.githubusercontent\.com/[^/]+/[^/]+/[0-9a-f]{40}/", document["source_url"])
            assert hashlib.sha256(document["text"].encode()).hexdigest() == document["sha256"]
    assert methods == {
        "upstream-license-file", "upstream-license-declaration",
        "upstream-license-file-and-declaration", "archive-license-section",
    }


def test_published_empty_crate_retains_declaration_without_inventing_copyright():
    text = notices.supplemental_notice(MATERIAL, ORIGIN, FIXTURE)
    assert '"name": "block-modes"' in text
    assert '"authors": ["RustCrypto Developers"]' in text
    assert '"license": "MIT OR Apache-2.0"' in text
    assert "Selected license: Apache-2.0" in text
    assert "TERMS AND CONDITIONS FOR USE, REPRODUCTION, AND DISTRIBUTION" in text
    assert "upstream-license-declaration" in text
    assert "Copyright (c) RustCrypto Developers" not in text
    assert "Copyright 2026 Account Access" not in text


def test_unreviewed_archive_cannot_gain_a_license_from_a_known_package_name(tmp_path):
    changed = tmp_path / "changed.crate"
    changed.write_bytes(FIXTURE.read_bytes() + b"changed")
    with pytest.raises(ValueError, match="^bitwarden_supplemental_notice_source_changed$"):
        notices.supplemental_notice(MATERIAL, ORIGIN, changed)


def test_changed_download_origin_cannot_reuse_a_reviewed_notice():
    with pytest.raises(ValueError, match="^bitwarden_supplemental_notice_source_changed$"):
        notices.supplemental_notice(MATERIAL, {"url": "https://example.org/block-modes.crate"}, FIXTURE)


def test_unknown_material_stays_missing_and_its_path_is_not_opened(tmp_path):
    assert notices.supplemental_notice("cargo/unreviewed-9.0.0.crate", ORIGIN, tmp_path / "absent") == ""


def test_catalog_edits_require_an_explicit_reviewed_digest_update(tmp_path, monkeypatch):
    changed = tmp_path / "changed.json"
    changed.write_bytes(notices.CATALOG.read_bytes() + b" ")
    monkeypatch.setattr(notices, "CATALOG", changed)
    with pytest.raises(ValueError, match="^bitwarden_supplemental_notices_changed$"):
        notices.supplemental_notice(MATERIAL, ORIGIN, FIXTURE)


def test_combined_license_dependencies_retain_all_required_licenses():
    components = notices._catalog()["components"]
    protobuf = next(row for row in components.values() if row["name"] == "@bufbuild/protobuf")
    assert protobuf["selected_license"] == "Apache-2.0 AND BSD-3-Clause"
    assert any("Copyright 2008 Google" in row["text"] and "Redistribution and use" in row["text"]
               for row in protobuf["evidence"])
    assert any("Copyright 2021-2026 Buf Technologies" in row["text"] for row in protobuf["evidence"])
    documents = notices._catalog()["documents"]
    for row in components.values():
        if row["name"].startswith("@swc/core-") and "MIT" in row["declared_license"]:
            assert row["selected_license"] == "Apache-2.0 AND MIT"
            assert any(documents[key]["role"] == "upstream-license-file" for key in row["documents"])
            assert any("/text/MIT.txt" in documents[key]["source_url"] for key in row["documents"])
