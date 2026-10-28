"""Pinned release-input checks for the build-104 successor recipe."""

import importlib.util
from pathlib import Path

SPEC = importlib.util.spec_from_file_location(
    "owner104_builder",
    Path(__file__).resolve().parents[1] / "scripts/build_owner_upgrade104_review.py",
)
builder = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(builder)


def test_build_104_recipe_is_bound_to_its_exact_predecessor_and_successor():
    assert builder.PACKAGE95 == "0c7a83b47d405bd9b02686aceb938877c5cd2f36112cb0b8369069c643453371"
    assert builder.INVENTORY95 == "9072d9bce2fd9c1b6118e657c77cab3f32e5c44689f4bb230132f07bbbb0e1e1"
    assert builder.PINS95 == "c63ff71959f969edf95fe11b02672ea195a0d2b5cb607c7f2afa67e2a7a1a49a"
    assert builder.PLAN == "1647952c58111b78557dee209b5201b43ffab63fb8a689ce73a258a8794d2dd3"
    assert builder.BEFORE == "03fb35eb2787ebd67079dd1cbe4dda125f430964540bdd2f2e9c81eda602fd7a"
    assert builder.AFTER == "c1b6f40aeafc5243dd2b16a9c4f14448245e389fa45dabcfae4c4f7b913d4afc"
    assert builder.TARGET == "9c375d1655f8fb27aa4389b11f546193e05b05f5"
    assert builder.IDENTIFIER == "com.fainir.accountaccess.ownerupgrade104"


def test_build_104_recipe_hashes_its_own_committed_source():
    source = (Path(__file__).resolve().parents[1] / "scripts/build_owner_upgrade104_review.py").read_text()
    assert 'git("show", args.source + ":scripts/build_owner_upgrade104_review.py")' in source
    assert "scripts/build_owner_upgrade_review.py" not in source
