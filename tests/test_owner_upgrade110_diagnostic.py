from __future__ import annotations

import importlib.util
from pathlib import Path
import subprocess

import pytest


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "build_owner_upgrade110_diagnostic",
    ROOT / "scripts/build_owner_upgrade110_diagnostic.py",
)
assert SPEC is not None and SPEC.loader is not None
BUILDER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BUILDER)


def test_rebind_wrapper_changes_only_the_pinned_helper_digest() -> None:
    old = "a" * 64
    new = "b" * 64
    wrapper = (
        b"#!/bin/sh\n"
        b'AC_COMPONENT_HELPER="$AC_COMPONENT_SCRIPTS/AccountAccess-ownerupgrade"\n'
        b"[ \"$(/usr/bin/shasum -a 256 \\\"$AC_COMPONENT_HELPER\\\")\" = '"
        + old.encode()
        + b"' ] || exit 1\n"
        b"exec \"$AC_COMPONENT_HELPER\"\n"
    )

    updated = BUILDER.rebind_wrapper(wrapper, old, new)

    assert old.encode() not in updated
    assert updated.count(new.encode()) == 1
    assert updated.startswith(b"#!/bin/sh\n")


def test_rebind_wrapper_refuses_a_mismatched_or_ambiguous_guard() -> None:
    old = "a" * 64
    new = "b" * 64
    with pytest.raises(BUILDER.BuildRefused, match="base_wrapper_binding_invalid"):
        BUILDER.rebind_wrapper(b"#!/bin/sh\n", old, new)
    ambiguous = b" = '" + old.encode() + b"' ] || exit 1\n" * 2
    with pytest.raises(BUILDER.BuildRefused, match="base_wrapper_binding_invalid"):
        BUILDER.rebind_wrapper(ambiguous, old, new)


def test_package_info_update_requires_the_expected_base_identity_and_timeout() -> None:
    valid = (
        b'<pkg-info identifier="com.fainir.accountaccess.ownerupgrade110" install-location="/">'
        b'<postinstall file="./postinstall" timeout="600"/>'
    )

    updated = BUILDER.update_package_info(valid)
    assert b'timeout="1800"' in updated
    assert b'identifier="com.fainir.accountaccess.ownerupgrade110"' in updated
    assert b'ownerupgrade109' not in updated
    with pytest.raises(BUILDER.BuildRefused, match="generated_package_info_mismatch"):
        BUILDER.update_package_info(valid.replace(b"ownerupgrade110", b"ownerupgrade108"))
    with pytest.raises(BUILDER.BuildRefused, match="generated_package_info_mismatch"):
        BUILDER.update_package_info(valid.replace(b'timeout="600"', b'timeout="300"'))


def test_candidate_is_bound_to_the_previously_refused_package() -> None:
    assert BUILDER.BASE_PACKAGE_SHA256 == "0528d4a545c14c92c58a8ebe03660e8d75efd7d38b67db92ccc913a5249ce2a0"
    assert BUILDER.PACKAGE_ID == "com.fainir.accountaccess.ownerupgrade110"


def test_process_output_includes_gatekeeper_stderr() -> None:
    result = subprocess.CompletedProcess(["spctl"], 0, b"", b"accepted\nsource=Notarized Developer ID\n")

    assert BUILDER.process_output(result) == "accepted\nsource=Notarized Developer ID"


def test_flat_package_listing_requires_archived_scripts_component() -> None:
    BUILDER.validate_flat_package_listing(b"PackageInfo\nScripts\n")

    with pytest.raises(BUILDER.BuildRefused, match="package_scripts_archive_not_flat"):
        BUILDER.validate_flat_package_listing(b"PackageInfo\nScripts\nScripts/postinstall\n")
