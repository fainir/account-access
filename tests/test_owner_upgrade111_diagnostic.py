from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "build_owner_upgrade111_diagnostic",
    ROOT / "scripts/build_owner_upgrade111_diagnostic.py",
)
assert SPEC is not None and SPEC.loader is not None
BUILDER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BUILDER)


def test_candidate_is_bound_to_reviewed_inputs_and_new_package_identity() -> None:
    assert BUILDER.BASE_PACKAGE_SHA256 == "0528d4a545c14c92c58a8ebe03660e8d75efd7d38b67db92ccc913a5249ce2a0"
    assert BUILDER.PACKAGE95_SHA256 == "0c7a83b47d405bd9b02686aceb938877c5cd2f36112cb0b8369069c643453371"
    assert BUILDER.INVENTORY95_SHA256 == "9072d9bce2fd9c1b6118e657c77cab3f32e5c44689f4bb230132f07bbbb0e1e1"
    assert BUILDER.PACKAGE_ID == "com.fainir.accountaccess.ownerupgrade111"


def test_package_info_binds_build111_identity_and_extends_postinstall_timeout() -> None:
    package_info = (
        b'<pkg-info identifier="com.fainir.accountaccess.ownerupgrade111" install-location="/">'
        b'<postinstall file="./postinstall" timeout="600"/>'
    )

    updated = BUILDER.update_package_info(package_info)

    assert b'identifier="com.fainir.accountaccess.ownerupgrade111"' in updated
    assert b'timeout="1800"' in updated
    for mismatch in (
        package_info.replace(b"ownerupgrade111", b"ownerupgrade110"),
        package_info.replace(b'timeout="600"', b'timeout="300"'),
    ):
        with pytest.raises(BUILDER.BuildRefused, match="generated_package_info_mismatch"):
            BUILDER.update_package_info(mismatch)


def test_builder_pins_its_own_source_for_reproducible_builds() -> None:
    source = (ROOT / "scripts/build_owner_upgrade111_diagnostic.py").read_text()
    assert '"scripts/build_owner_upgrade111_diagnostic.py"' in source
    assert "scripts/build_owner_upgrade110_diagnostic.py" not in source
