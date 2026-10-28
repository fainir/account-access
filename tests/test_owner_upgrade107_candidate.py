from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "build_owner_upgrade107_candidate",
    ROOT / "scripts/build_owner_upgrade107_candidate.py",
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
        b'<pkg-info identifier="com.fainir.accountaccess.ownerupgrade106">'
        b'<postinstall timeout="1800"/>'
    )

    assert b'identifier="com.fainir.accountaccess.ownerupgrade107"' in BUILDER.update_package_info(valid)
    with pytest.raises(BUILDER.BuildRefused, match="base_package_identity_mismatch"):
        BUILDER.update_package_info(valid.replace(b"ownerupgrade106", b"ownerupgrade105"))
    with pytest.raises(BUILDER.BuildRefused, match="base_package_identity_mismatch"):
        BUILDER.update_package_info(valid.replace(b'timeout="1800"', b'timeout="600"'))
