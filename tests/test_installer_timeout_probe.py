import importlib.util
from pathlib import Path
import stat
from types import SimpleNamespace
import xml.etree.ElementTree as ET

import pytest


ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("timeout_probe", ROOT / "scripts/mac_installer_timeout_probe.py")
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)


def envelope(case="short"):
    return (f'<pkg-info identifier="{probe.PREFIX}{case}" auth="root" version="1">'
            '<payload numberOfFiles="0" installKBytes="0"/>'
            '<scripts><postinstall file="./postinstall"/></scripts></pkg-info>').encode()


@pytest.mark.parametrize("case", ["short", "long"])
def test_only_generated_deadline_changes(case):
    original = ET.fromstring(envelope(case))
    changed = ET.fromstring(probe.with_deadline(envelope(case), case))
    assert changed.find("scripts/postinstall").attrib.pop("timeout") == str(probe.CASES[case][0])
    assert ET.tostring(changed) == ET.tostring(original)
    assert probe.script(case) == f"#!/bin/sh\nset -eu\n/bin/sleep {probe.CASES[case][1]}\nexit 0\n".encode()


def test_generated_macos26_default_timeout_and_empty_bundle_metadata():
    raw = envelope().replace(b'<scripts>', b'<bundle-version/><upgrade-bundle/><update-bundle/>'
        b'<atomic-update-bundle/><strict-identifier/><relocate/><scripts>').replace(
            b'file="./postinstall"', b'file="./postinstall" timeout="600"')
    changed = ET.fromstring(probe.with_deadline(raw, "short"))
    assert changed.find("scripts/postinstall").get("timeout") == "15"
    for invalid in (raw.replace(b'<bundle-version/>', b'<bundle-version><bundle/></bundle-version>'),
                    raw.replace(b'<relocate/>', b'<relocate search="true"/>')):
        with pytest.raises(ValueError):
            probe.with_deadline(invalid, "short")


@pytest.mark.parametrize("before,after", [
    (b'numberOfFiles="0"', b'numberOfFiles="1"'),
    (b'auth="root"', b'auth="none"'),
    (b'file="./postinstall"', b'file="./postinstall" timeout="1"'),
    (b'file="./postinstall"', b'file="/other"'),
    (b'</scripts>', b'<preinstall file="./preinstall"/></scripts>'),
    (b'</pkg-info>', b'<bundle id="unexpected"/></pkg-info>'),
    (b'<pkg-info', b'<!DOCTYPE pkg-info><pkg-info'),
])
def test_nonfixture_packages_refused(before, after):
    with pytest.raises(ValueError):
        probe.with_deadline(envelope().replace(before, after), "short")


def test_early_failures_and_ignored_deadlines_cannot_pass():
    assert probe.accepted("short", 1, 15.2)
    assert not probe.accepted("short", 1, 2)
    assert not probe.accepted("short", 0, 25)
    assert not probe.accepted("long", 0, 600)
    assert not probe.accepted("long", 1, 610)
    assert probe.accepted("long", 0, 611)


def test_owner_context_refuses_before_paths(monkeypatch):
    monkeypatch.setattr(probe.os, "getuid", lambda: 501)
    monkeypatch.setattr(Path, "read_bytes", lambda *_: pytest.fail("read before guard"))
    with pytest.raises(ValueError):
        probe.run(Path("/not-a-repository"))


def test_unknown_cases_refused():
    with pytest.raises(ValueError):
        probe.with_deadline(envelope(), "arbitrary")
    with pytest.raises(ValueError):
        probe.script("arbitrary")


@pytest.mark.parametrize("missing", ["GITHUB_ACTIONS", "RUNNER_ENVIRONMENT", "GITHUB_REPOSITORY", "RUNNER_ARCH"])
def test_root_alone_cannot_authorize_probe(monkeypatch, missing):
    monkeypatch.setattr(probe.sys, "platform", "darwin")
    monkeypatch.setattr(probe.platform, "machine", lambda: "arm64")
    monkeypatch.setattr(probe.os, "getuid", lambda: 0)
    monkeypatch.setattr(probe.os, "geteuid", lambda: 0)
    for name, value in {"GITHUB_ACTIONS": "true", "CI": "true", "RUNNER_ENVIRONMENT": "github-hosted",
                        "RUNNER_OS": "macOS", "RUNNER_ARCH": "ARM64", "GITHUB_REPOSITORY": "fainir/account-access",
                        "GITHUB_RUN_ID": "1", "GITHUB_RUN_ATTEMPT": "1", "GITHUB_SHA": "a" * 40}.items():
        monkeypatch.setenv(name, value)
    monkeypatch.delenv(missing)
    monkeypatch.setattr(Path, "read_bytes", lambda *_: pytest.fail("read before host guard"))
    with pytest.raises(ValueError):
        probe.run(Path("/not-a-repository"))


def test_expanded_script_directory_preserves_exact_program(tmp_path):
    def metadata(info, mode, directory=True):
        assert (stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode))
        assert stat.S_IMODE(info.st_mode) == mode
    h = SimpleNamespace(protected_metadata=metadata, read_file=lambda p, **_: p.read_bytes())
    tmp_path.chmod(0o755)
    leaf = tmp_path / "postinstall"
    leaf.write_bytes(probe.script("short"))
    leaf.chmod(0o755)
    probe.verify_scripts(h, tmp_path, "short")
    leaf.write_bytes(b"#!/bin/sh\nexit 0\n")
    with pytest.raises(ValueError):
        probe.verify_scripts(h, tmp_path, "short")
    leaf.write_bytes(probe.script("short"))
    sidecar = tmp_path / "._postinstall"
    sidecar.write_bytes(bytes.fromhex("0005160700020000"))
    sidecar.chmod(0o644)
    assert set(probe.verify_scripts(h, tmp_path, "short")) == {"postinstall", "._postinstall"}
    sidecar.write_bytes(b"not metadata")
    with pytest.raises(ValueError):
        probe.verify_scripts(h, tmp_path, "short")
    sidecar.unlink()
    (tmp_path / "unexpected").touch()
    with pytest.raises(ValueError):
        probe.verify_scripts(h, tmp_path, "short")
