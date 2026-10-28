"""Synthetic owner homes only; never read real Codex profiles or credentials."""

import json
import os
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from account_access.errors import AccessError
from account_access.install import install_detected
from account_access.integration import START, resolve_codex_home


@pytest.fixture
def owner_home(tmp_path, monkeypatch):
    home = tmp_path / "owner"
    home.mkdir(mode=0o700)
    monkeypatch.delenv("CODEX_HOME", raising=False)
    return home


def test_default_namespace_and_missing_custom_tail_do_not_create_files(owner_home):
    assert resolve_codex_home(owner_home) == owner_home / ".codex"
    assert resolve_codex_home(owner_home, "~/Library/Codex Work") == owner_home / "Library/Codex Work"
    assert list(owner_home.iterdir()) == []


def test_existing_namespace_is_checked_without_reading_config_or_auth(owner_home, monkeypatch):
    directory = owner_home / "Library/Codex Work"
    directory.mkdir(parents=True, mode=0o700)
    for name in ["config.toml", "auth.json"]:
        (directory / name).write_bytes(b"fictional private data, never read")

    def forbidden(*_args, **_kwargs):
        raise AssertionError("Namespace discovery must only read directory metadata")

    monkeypatch.setattr(Path, "read_bytes", forbidden)
    monkeypatch.setattr(Path, "read_text", forbidden)
    monkeypatch.setenv("CODEX_HOME", str(directory))
    assert resolve_codex_home(owner_home) == directory


@pytest.mark.parametrize("value", ["", ".codex", "/", "/unrelated/codex", "~other/codex",
                                    "~/../outside", "~/one/./codex", "~/bad\nname", "~/bad\x7fname",
                                    "~/" + "x" * 4096, "~/bad\ud800name", 42])
def test_invalid_namespace_is_fixed_error_and_does_not_create_files(owner_home, value):
    with pytest.raises(AccessError, match="codex_home_needs_review"):
        resolve_codex_home(owner_home, value)
    assert list(owner_home.iterdir()) == []


def test_owner_home_itself_and_prefix_sibling_are_not_codex_namespaces(owner_home):
    for value in [str(owner_home), str(owner_home) + "/", str(owner_home) + "-sibling/.codex"]:
        with pytest.raises(AccessError, match="codex_home_needs_review"):
            resolve_codex_home(owner_home, value)


@pytest.mark.parametrize("kind", ["alias", "dangling", "file", "writable", "special-mode", "foreign"])
def test_unsafe_existing_component_is_refused(owner_home, tmp_path, monkeypatch, kind):
    component = owner_home / "profile"
    if kind in {"alias", "dangling"}:
        target = tmp_path / "elsewhere"
        if kind == "alias":
            target.mkdir(mode=0o700)
        component.symlink_to(target, target_is_directory=True)
    elif kind == "file":
        component.write_text("unrelated")
    else:
        component.mkdir(mode=0o700)
        if kind == "writable":
            component.chmod(0o770)
        if kind == "special-mode":
            component.chmod(0o1700)
        if kind == "foreign":
            inode = component.stat().st_ino
            original = os.fstat

            def foreign(fd):
                info = original(fd)
                if info.st_ino == inode:
                    return SimpleNamespace(st_uid=os.getuid() + 1, st_mode=info.st_mode)
                return info

            monkeypatch.setattr(os, "fstat", foreign)
    with pytest.raises(AccessError, match="codex_home_needs_review"):
        resolve_codex_home(owner_home, component / "new-profile")
    assert not (component / "new-profile").exists()


def test_namespace_swap_is_refused_and_all_open_descriptors_are_closed(owner_home, monkeypatch):
    directory = owner_home / "codex"
    directory.mkdir(mode=0o700)
    original_open, original_stat = os.open, os.stat
    descriptors = []

    def opened(*args, **kwargs):
        descriptor = original_open(*args, **kwargs)
        descriptors.append(descriptor)
        return descriptor

    def swapped(path, *args, **kwargs):
        if Path(path) == directory and kwargs.get("follow_symlinks") is False:
            directory.rename(owner_home / "original")
            directory.symlink_to(owner_home / "original", target_is_directory=True)
        return original_stat(path, *args, **kwargs)

    monkeypatch.setattr(os, "open", opened)
    monkeypatch.setattr(os, "stat", swapped)
    with pytest.raises(AccessError, match="codex_home_needs_review"):
        resolve_codex_home(owner_home, directory)
    assert len(descriptors) == 2
    for descriptor in descriptors:
        with pytest.raises(OSError):
            os.fstat(descriptor)


def test_ordinary_install_uses_custom_namespace_and_preserves_other_profile_files(env, owner_home, monkeypatch):
    _, broker, _ = env
    namespace = owner_home / "profiles/Codex Work"
    namespace.mkdir(parents=True, mode=0o700)
    originals = {"config.toml": b"sandbox_mode = 'read-only'\n", "auth.json": b"synthetic-placeholder",
                 "AGENTS.override.md": b"My override stays.\n", "rules/personal.rules": b"unrelated rule\n"}
    for name, data in originals.items():
        path = namespace / name
        path.parent.mkdir(exist_ok=True, mode=0o700)
        path.write_bytes(data)
    default = owner_home / ".codex"
    default.mkdir(mode=0o700)
    (default / "AGENTS.md").write_text("Inactive profile remains unchanged\n")
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: owner_home))
    monkeypatch.setenv("CODEX_HOME", str(namespace))
    monkeypatch.setattr("account_access.install.shutil.which", lambda _name: None)
    result = install_detected(broker.store)
    instructions = result["automatic_sessions"]["codex"]["instruction_files"]
    assert instructions == [str(namespace / "AGENTS.md"), str(namespace / "AGENTS.override.md")]
    assert START in (namespace / "AGENTS.md").read_text()
    assert (namespace / "AGENTS.override.md").read_bytes().startswith(originals["AGENTS.override.md"])
    for name in ["config.toml", "auth.json", "rules/personal.rules"]:
        assert (namespace / name).read_bytes() == originals[name]
    assert (default / "AGENTS.md").read_text() == "Inactive profile remains unchanged\n"
    assert (namespace / "rules/account-access.rules").is_file()


def test_ordinary_install_refuses_invalid_namespace_before_issuing_client(env, owner_home, monkeypatch):
    _, broker, _ = env
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: owner_home))
    monkeypatch.setenv("CODEX_HOME", str(owner_home.parent / "unrelated"))
    with pytest.raises(AccessError, match="codex_home_needs_review"):
        install_detected(broker.store)
    assert not (broker.store.root / "clients/generic").exists()
    assert not (owner_home / ".agents").exists()


def test_protected_install_and_status_bind_current_namespace_without_reading_profiles(owner_home, monkeypatch):
    from account_access.agent_setup import RELATIVE, install, status

    namespace = owner_home / "profiles/Codex Work"
    namespace.mkdir(parents=True, mode=0o700)
    default = owner_home / ".codex"
    default.mkdir(mode=0o700)
    (default / "AGENTS.md").write_text("Default profile stays unchanged\n")
    originals = {"config.toml": b"sandbox_mode='read-only'\n", "auth.json": b"fictional-no-auth"}
    for name, content in originals.items():
        (namespace / name).write_bytes(content)
    original_read_bytes = Path.read_bytes

    def no_profile_read(path):
        assert path.name not in originals, "Integration must not read existing profile config or auth"
        return original_read_bytes(path)

    monkeypatch.setattr(Path, "read_bytes", no_profile_read)
    monkeypatch.setattr("account_access.client.Client.request", lambda *_args, **_kwargs: {"accounts": []})
    monkeypatch.setenv("CODEX_HOME", str(namespace))
    kwargs = {"python": sys.executable, "socket": owner_home / "fictional.sock"}
    result = install(owner_home, ["codex"], **kwargs)
    assert result["automatic_sessions"]["codex"]["instruction_files"] == [str(namespace / "AGENTS.md")]
    assert status(owner_home, ["codex"], **kwargs)["status"] == "INSTALLED"
    receipt = json.loads((owner_home / RELATIVE / "installed.json").read_text())
    assert receipt["codex_home"] == str(namespace)
    assert (default / "AGENTS.md").read_text() == "Default profile stays unchanged\n"
    for name, content in originals.items():
        assert original_read_bytes(namespace / name) == content
    second = owner_home / "profiles/Other Codex"
    second.mkdir(mode=0o700)
    monkeypatch.setenv("CODEX_HOME", str(second))
    assert status(owner_home, ["codex"], **kwargs) == {"status": "NOT_INSTALLED"}
    assert not (second / "AGENTS.md").exists()


def test_protected_preflight_rejects_unsafe_custom_home_before_capability_writes(owner_home, monkeypatch):
    from account_access.agent_setup import RELATIVE, prepare

    namespace = owner_home / "profiles"
    namespace.symlink_to(owner_home.parent, target_is_directory=True)
    monkeypatch.setenv("CODEX_HOME", str(namespace / "codex"))
    with pytest.raises(AccessError, match="codex_home_needs_review"):
        prepare(owner_home, ["codex"])
    assert not (owner_home / RELATIVE).exists()
