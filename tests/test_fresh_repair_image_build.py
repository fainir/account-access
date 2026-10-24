"""Inert build images only; no installer, signing or installed paths are used."""
import hashlib
import json
from pathlib import Path
import runpy
import shutil

import pytest

from account_access.package_manifest import build as manifest
from macos.system_package import preassembled_inventory
from test_system_package_preassembled import fixture_image

ROOT = Path(__file__).resolve().parents[1]


def controller():
    return runpy.run_path(str(ROOT / "scripts/build_fresh_repair_image_review.py"))


def fixture(tmp_path, monkeypatch):
    module = controller()
    args, _, repin = fixture_image(tmp_path, monkeypatch)
    before = repin()
    scripts = tmp_path / "resources"
    source = scripts / "CompletedImage/TargetImage"
    source.parent.mkdir(parents=True)
    shutil.copytree(args.preassembled_image, source, symlinks=True)
    desired = tmp_path / "expected"
    shutil.copytree(source, desired, symlinks=True)
    for relative, name in module["REPLACEMENTS"].items():
        raw = ("fictional replacement " + name).encode()
        (scripts / name).write_bytes(raw)
        path = desired / module["BASE"] / relative
        path.write_bytes(raw)
        path.chmod(0o755 if relative.startswith("bin/") else 0o644)
    after = manifest(desired, "0.8.0", "arm64")
    (scripts / "BaseManifest.json").write_bytes(before)
    (scripts / "TargetManifest.json").write_bytes(after)
    # Only synthetic unit fixtures substitute pins; the CLI offers no override.
    for name, raw in (("BEFORE", before), ("AFTER", after)):
        monkeypatch.setitem(module["materialize"].__globals__, name, hashlib.sha256(raw).hexdigest())
    return module, scripts, tmp_path / "target", before, after


def test_materializes_exact_successor_and_preserves_predecessor(tmp_path, monkeypatch):
    module, scripts, target, before, after = fixture(tmp_path, monkeypatch)
    assert module["materialize"](scripts, target, preassembled_inventory) == after
    assert manifest(target, "0.8.0", "arm64") == after
    assert manifest(scripts / "CompletedImage/TargetImage", "0.8.0", "arm64") == before


@pytest.mark.parametrize("fault", ["source", "replacement", "manifest", "link", "hardlink", "existing", "inside-source"])
def test_refuses_drift_and_unsafe_destinations(tmp_path, monkeypatch, fault):
    module, scripts, target, before, _ = fixture(tmp_path, monkeypatch)
    replacement = scripts / "AccountAccess-broker"
    if fault == "source":
        (scripts / "CompletedImage/TargetImage" / module["BASE"] / "bin/AccountAccess-broker").write_bytes(b"drift")
    elif fault == "replacement":
        replacement.write_bytes(b"drift")
    elif fault == "manifest":
        (scripts / "TargetManifest.json").write_text("{}")
    elif fault == "link":
        original = scripts / "original"
        replacement.rename(original)
        replacement.symlink_to(original.name)
    elif fault == "hardlink":
        (scripts / "alias").hardlink_to(replacement)
    elif fault == "existing":
        target.mkdir()
        (target / "keep").write_text("preserved")
    else:
        target = scripts / "forbidden-output"
    with pytest.raises((ValueError, OSError)):
        module["materialize"](scripts, target, preassembled_inventory)
    if fault == "existing":
        assert (target / "keep").read_text() == "preserved"
    else:
        assert not target.exists()
    if fault != "source":
        assert manifest(scripts / "CompletedImage/TargetImage", "0.8.0", "arm64") == before


def test_rechecks_source_after_copy(tmp_path, monkeypatch):
    module, scripts, target, _, _ = fixture(tmp_path, monkeypatch)
    copy = shutil.copytree

    def mutate(source, output, *args, **kwargs):
        result = copy(source, output, *args, **kwargs)
        if Path(source) == scripts / "CompletedImage/TargetImage":
            (source / module["BASE"] / "bin/AccountAccess-broker").write_bytes(b"late drift")
        return result

    monkeypatch.setattr(shutil, "copytree", mutate)
    with pytest.raises(ValueError):
        module["materialize"](scripts, target, preassembled_inventory)


@pytest.mark.parametrize("fault", ["root", "personal-host", "repository", "revision", "linux", "intel"])
def test_build_context_refuses_before_any_inputs(tmp_path, monkeypatch, fault):
    module = controller()
    monkeypatch.setattr(module["os"], "getuid", lambda: 0 if fault == "root" else 501)
    monkeypatch.setattr(module["os"], "geteuid", module["os"].getuid)
    monkeypatch.setattr(module["sys"], "platform", "linux" if fault == "linux" else "darwin")
    monkeypatch.setattr(module["platform"], "machine", lambda: "x86_64" if fault == "intel" else "arm64")
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    monkeypatch.setenv("RUNNER_ENVIRONMENT", "self-hosted" if fault == "personal-host" else "github-hosted")
    monkeypatch.setenv("GITHUB_REPOSITORY", "elsewhere/repo" if fault == "repository" else module["REPOSITORY"])
    monkeypatch.setenv("GITHUB_SHA", "bad" if fault == "revision" else "a" * 40)
    with pytest.raises(ValueError, match="fresh_repair_image_build_refused"):
        module["build"](None, None, None)


def test_frozen_request_and_each_identity_pin():
    module = controller()
    request = json.loads((ROOT / module["REQUEST"]).read_bytes())
    module["validate_request"](request)
    for key, changed in (("schema", True), ("production_ready", 0)):
        with pytest.raises(ValueError, match="fresh_repair_image_build_refused"):
            module["validate_request"]({**request, key: changed})
    for key, value in request.items():
        changed = not value if isinstance(value, bool) else "changed"
        with pytest.raises(ValueError, match="fresh_repair_image_build_refused"):
            module["validate_request"]({**request, key: changed})
