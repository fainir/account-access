import os
from pathlib import Path
import subprocess
import fcntl
import hashlib
import shutil
import sys
import zipfile
import json

import pytest

from account_access.runtime_bootstrap import INSTALLATION_MARKER, MARKER, active_runtime_launcher, install, installation_snapshot, write_installation, write_launcher


@pytest.fixture
def setup(tmp_path, monkeypatch):
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: home))
    runtime = tmp_path / "runtime's folder"
    launcher = runtime / "bin/account-access"
    launcher.parent.mkdir(parents=True)
    runtime.chmod(0o700)
    old = "#!/bin/sh\n" + MARKER + "\n# previous runtime\n"
    launcher.write_text(old)
    launcher.chmod(0o700)
    wheel = tmp_path / "account_access-0.8.0-py3-none-any.whl"
    wheel.write_bytes(b"fictional package")
    requirements = tmp_path / "requirements.txt"
    requirements.write_text("example==1.0 --hash=sha256:" + "0" * 64 + "\n")
    return runtime, launcher, old, wheel, requirements


@pytest.mark.parametrize("version", ["13.7.8", "12.0", "", "unknown"])
def test_direct_bootstrap_rejects_unsupported_mac_without_touching_runtime(tmp_path, monkeypatch, version):
    monkeypatch.setattr("account_access.runtime_bootstrap.sys.platform", "darwin")
    monkeypatch.setattr("account_access.runtime_bootstrap.platform.mac_ver", lambda: (version, (), ""))
    runtime = tmp_path / "runtime"
    def no_execution(*args, **kwargs):
        raise AssertionError("Unsupported OS must stop before any installer commands")
    with pytest.raises(RuntimeError, match="requires macOS 14"):
        install("uv", tmp_path / "unused.whl", runtime, tmp_path / "unused.txt", run=no_execution)
    assert not runtime.exists()


@pytest.mark.parametrize("architecture", ["x86_64", "i386", "unknown", ""])
def test_direct_bootstrap_rejects_unsupported_mac_architecture_before_runtime_changes(tmp_path, monkeypatch, architecture):
    monkeypatch.setattr("account_access.runtime_bootstrap.sys.platform", "darwin")
    monkeypatch.setattr("account_access.runtime_bootstrap.platform.mac_ver", lambda: ("14.0", (), ""))
    monkeypatch.setattr("account_access.runtime_bootstrap.platform.machine", lambda: architecture)
    runtime = tmp_path / "runtime"
    def no_execution(*args, **kwargs):
        raise AssertionError("Unsupported architecture must stop before any installer commands")
    with pytest.raises(RuntimeError, match="requires an Apple silicon"):
        install("uv", tmp_path / "unused.whl", runtime, tmp_path / "unused.txt", run=no_execution)
    assert not runtime.exists()


@pytest.mark.parametrize("failure", [None, "packages", "browser", "health", "start"])
def test_prepare_then_switch_and_rollback_failed_runtime(setup, failure, monkeypatch):
    runtime, launcher, old, wheel, requirements = setup
    calls = []
    start_failed = False
    monkeypatch.setenv("UV_NO_VERIFY_HASHES", "1")
    monkeypatch.setenv("PYTHONPATH", "/untrusted")
    def run(command, *, check, env):
        nonlocal start_failed
        assert check and "PYTHONPATH" not in env and "UV_NO_VERIFY_HASHES" not in env
        calls.append(command)
        if command[1] == "venv":
            folder = Path(command[-1]) / "bin"
            folder.mkdir()
            (folder / "python").touch()
        if command[1:3] == ["pip", "sync"]:
            assert {"--require-hashes", "--no-build", "--strict", "--no-config"} <= set(command)
            text = Path(command[-1]).read_text()
            assert requirements.read_text() in text and wheel.as_uri() in text and "--hash=sha256:" in text
        fail = ((failure == "packages" and command[1:3] == ["pip", "sync"])
                or (failure == "browser" and "playwright" in command)
                or (failure == "health" and "-c" in command))
        if command[0] == str(launcher):
            if command[-1] == "stop" and not start_failed:
                assert launcher.read_text() == old
            if "start" in command and failure == "start" and not start_failed:
                assert "previous runtime" not in launcher.read_text()
                start_failed = True
                fail = True
        if fail:
            raise subprocess.CalledProcessError(1, command)
    if failure:
        with pytest.raises(subprocess.CalledProcessError):
            install("uv", wheel, runtime, requirements, data_dir="private data", no_open=True, run=run)
        assert launcher.read_text() == old
        assert not (runtime / "installed-wheel.json").exists()
        assert list((runtime / "environments").iterdir()) == []
        if failure == "start":
            assert calls[-1] == [str(launcher), "--root", "private data", "start", "--no-open"]
        else:
            assert not any(command[0] == str(launcher) for command in calls)
    else:
        install("uv", wheel, runtime, requirements, data_dir="private data", no_open=True, run=run)
        assert len(list((runtime / "environments").iterdir())) == 1
        assert launcher.read_text().startswith("#!/bin/sh\n" + MARKER)
        assert "-I -m account_access.cli" in launcher.read_text()
        assert os.stat(launcher).st_mode & 0o077 == 0
        assert calls[-2:] == [[str(launcher), "--root", "private data", "stop"],
                              [str(launcher), "--root", "private data", "start", "--no-open"]]
        assert (Path.home() / "Applications/Account Access.command").is_file()
        record = json.loads(installation_snapshot(runtime / "installed-wheel.json"))
        assert record == {"managed_by": INSTALLATION_MARKER, "schema": 2,
                          "wheel_sha256": hashlib.sha256(wheel.read_bytes()).hexdigest(),
                          "runtime": str(next((runtime / "environments").iterdir()) / "bin/python"),
                          "launcher_sha256": hashlib.sha256(launcher.read_bytes()).hexdigest()}


def test_unowned_runtime_launcher_is_not_replaced(setup):
    runtime, launcher, _, wheel, requirements = setup
    launcher.write_text("another application")
    with pytest.raises(RuntimeError, match="Another application"):
        install("uv", wheel, runtime, requirements)
    assert launcher.read_text() == "another application"


@pytest.mark.parametrize("damage", ["unknown", "public", "symlink", "hardlink"])
def test_untrusted_payload_record_cannot_change_existing_installation(setup, damage):
    runtime, launcher, old, wheel, requirements = setup
    path = runtime / "installed-wheel.json"
    content = json.dumps({"managed_by": INSTALLATION_MARKER, "schema": 1, "wheel_sha256": "a" * 64}).encode()
    write_installation(path, content if damage != "unknown" else b"unrelated existing file")
    outside = runtime.parent / "outside-record"
    if damage == "public":
        path.chmod(0o644)
    elif damage in {"symlink", "hardlink"}:
        path.replace(outside)
        if damage == "symlink":
            path.symlink_to(outside)
        else:
            os.link(outside, path)
    commands = []
    with pytest.raises(RuntimeError, match="payload record"):
        install("uv", wheel, runtime, requirements, run=lambda *a, **k: commands.append(a))
    assert not commands and launcher.read_text() == old
    if outside.exists():
        assert outside.read_bytes() == content


def test_failed_repair_keeps_previous_payload_digest_and_launcher(setup):
    runtime, launcher, old, wheel, requirements = setup
    record = runtime / "installed-wheel.json"
    content = json.dumps({"managed_by": INSTALLATION_MARKER, "schema": 1, "wheel_sha256": "a" * 64}).encode()
    write_installation(record, content)
    def run(command, **_kwargs):
        if command[1] == "venv":
            folder = Path(command[-1]) / "bin"
            folder.mkdir()
            (folder / "python").touch()
        if "start" in command:
            raise subprocess.CalledProcessError(1, command)
    with pytest.raises(subprocess.CalledProcessError):
        install("uv", wheel, runtime, requirements, data_dir="fixture data", no_open=True, run=run)
    assert launcher.read_text() == old and record.read_bytes() == content


@pytest.mark.parametrize("damage", ["outside", "traversal", "relative", "bad-launcher-digest", "extra"])
def test_unbound_version_two_record_stops_before_any_installation_change(setup, damage):
    runtime, launcher, old, wheel, requirements = setup
    record = {"managed_by": INSTALLATION_MARKER, "schema": 2,
              "wheel_sha256": "a" * 64, "launcher_sha256": "b" * 64,
              "runtime": str(runtime / "environments/previous/bin/python")}
    if damage == "outside":
        record["runtime"] = "/usr/bin/python3"
    elif damage == "traversal":
        record["runtime"] = str(runtime / "environments/previous/bin/../bin/python")
    elif damage == "relative":
        record["runtime"] = "environments/previous/bin/python"
    elif damage == "bad-launcher-digest":
        record["launcher_sha256"] = "invalid"
    else:
        record["unexpected"] = True
    path = runtime / "installed-wheel.json"
    write_installation(path, json.dumps(record).encode())
    commands = []
    with pytest.raises(RuntimeError, match="payload record"):
        install("uv", wheel, runtime, requirements, run=lambda *a, **k: commands.append(a))
    assert not commands and launcher.read_text() == old
    assert json.loads(path.read_text()) == record


def test_failed_repair_preserves_an_activated_version_two_record(setup):
    runtime, launcher, old, wheel, requirements = setup
    content = json.dumps({"managed_by": INSTALLATION_MARKER, "schema": 2,
        "wheel_sha256": "a" * 64, "launcher_sha256": hashlib.sha256(old.encode()).hexdigest(),
        "runtime": str(runtime / "environments/previous/bin/python")}).encode()
    record = runtime / "installed-wheel.json"
    write_installation(record, content)
    def run(command, **_kwargs):
        if command[1] == "venv":
            folder = Path(command[-1]) / "bin"
            folder.mkdir()
            (folder / "python").touch()
        if "start" in command:
            raise subprocess.CalledProcessError(1, command)
    with pytest.raises(subprocess.CalledProcessError):
        install("uv", wheel, runtime, requirements, data_dir="fixture data", no_open=True, run=run)
    assert launcher.read_text() == old and record.read_bytes() == content


@pytest.mark.parametrize("damage", [None, "readable-bin", "legacy", "launcher", "wrong-runtime", "public-directory", "missing"])
def test_older_managed_client_selects_only_the_activated_launcher(setup, damage):
    runtime, launcher, _, _, _ = setup
    runtime.chmod(0o700)
    launcher.parent.chmod(0o700)
    environments = runtime / "environments"
    environments.mkdir(mode=0o700)
    interpreters = []
    for name in ["previous", "activated"]:
        folder = environments / ("account-access-" + name)
        folder.mkdir(mode=0o700)
        (folder / "bin").mkdir(mode=0o755)
        executable = folder / "bin/python"
        executable.write_text("#!/bin/sh\nexit 0\n")
        executable.chmod(0o700)
        interpreters.append(executable)
    previous, activated = interpreters
    write_launcher(launcher, [str(activated), "-I", "-m", "account_access.cli"], MARKER)
    value = {"managed_by": INSTALLATION_MARKER, "schema": 2, "wheel_sha256": "a" * 64,
             "runtime": str(activated), "launcher_sha256": hashlib.sha256(launcher.read_bytes()).hexdigest()}
    if damage == "legacy":
        value = {key: value[key] for key in ["managed_by", "schema", "wheel_sha256"]}
        value["schema"] = 1
    elif damage == "launcher":
        write_launcher(launcher, [str(previous), "-I", "-m", "account_access.cli"], MARKER)
    elif damage == "wrong-runtime":
        value["runtime"] = str(previous)
    elif damage == "public-directory":
        activated.parent.parent.chmod(0o755)
    if damage != "missing":
        write_installation(runtime / "installed-wheel.json", json.dumps(value).encode())
    if damage == "readable-bin":
        launcher.parent.chmod(0o755)
    if damage not in {None, "readable-bin"}:
        with pytest.raises(RuntimeError, match="installation repair"):
            active_runtime_launcher(str(previous))
    else:
        assert active_runtime_launcher(str(previous)) == launcher


def test_standalone_interpreter_does_not_claim_managed_runtime_authority():
    assert active_runtime_launcher("/opt/developer-venv/bin/python") is None


@pytest.mark.parametrize("damage", ["public-root", "writable-root", "writable-bin", "public-environments",
                                    "public-launcher", "linked-launcher", "pipe-launcher", "pipe-lock"])
def test_unsafe_existing_installation_never_executes_a_launcher(setup, damage):
    runtime, launcher, old, wheel, requirements = setup
    outside = runtime.parent / "outside-launcher"
    if damage == "public-root":
        runtime.chmod(0o755)
    elif damage == "writable-root":
        runtime.chmod(0o777)
    elif damage == "writable-bin":
        launcher.parent.chmod(0o777)
    elif damage == "public-environments":
        directory = runtime / "environments"
        directory.mkdir(mode=0o755)
        directory.chmod(0o755)  # An earlier CLI check may have set umask 077.
        assert directory.stat().st_mode & 0o777 == 0o755
    elif damage == "public-launcher":
        launcher.chmod(0o744)
    elif damage == "linked-launcher":
        os.link(launcher, outside)
    elif damage == "pipe-launcher":
        launcher.unlink()
        os.mkfifo(launcher, 0o600)
    else:
        os.mkfifo(runtime / ".install.lock", 0o600)
    commands = []
    with pytest.raises(RuntimeError, match="private"):
        install("uv", wheel, runtime, requirements, run=lambda *a, **k: commands.append(a))
    assert not commands
    if damage != "pipe-launcher":
        assert launcher.read_text() == old
    if outside.exists():
        assert outside.read_text() == old


def test_failed_start_and_stop_retains_the_possibly_running_environment(setup):
    runtime, launcher, old, wheel, requirements = setup
    commands = []
    start_attempted = False
    def run(command, **_kwargs):
        nonlocal start_attempted
        commands.append(command)
        if command[1] == "venv":
            folder = Path(command[-1]) / "bin"
            folder.mkdir()
            (folder / "python").touch()
        if "start" in command:
            assert not start_attempted, "The previous service must not start before the replacement stops"
            start_attempted = True
            raise subprocess.CalledProcessError(1, command)
        if command[-1] == "stop" and start_attempted:
            raise subprocess.CalledProcessError(1, command)
    with pytest.raises(subprocess.CalledProcessError):
        install("uv", wheel, runtime, requirements, data_dir="fixture data", no_open=True, run=run)
    assert launcher.read_text() == old
    environments = list((runtime / "environments").iterdir())
    assert len(environments) == 1 and (environments[0] / "bin/python").is_file()
    assert commands[-1][-1] == "stop"
    assert not (runtime / "installed-wheel.json").exists()


@pytest.mark.parametrize("existing_desktop", [False, True])
def test_failed_payload_publication_restores_the_desktop_launcher(setup, monkeypatch, existing_desktop):
    runtime, launcher, old, wheel, requirements = setup
    from account_access.runtime_bootstrap import DESKTOP_MARKER
    desktop = Path.home() / "Applications/Account Access.command"
    previous_desktop = "#!/bin/sh\n" + DESKTOP_MARKER + "\n# previous data directory\n"
    if existing_desktop:
        desktop.parent.mkdir(parents=True)
        desktop.write_text(previous_desktop)
        desktop.chmod(0o700)
    def run(command, **_kwargs):
        if command[1] == "venv":
            folder = Path(command[-1]) / "bin"
            folder.mkdir()
            (folder / "python").touch()
    def fail_record(*_args):
        assert desktop.exists() and desktop.read_text() != previous_desktop
        raise OSError("fixture disk publication failure")
    monkeypatch.setattr("account_access.runtime_bootstrap.write_installation", fail_record)
    with pytest.raises(OSError, match="publication"):
        install("uv", wheel, runtime, requirements, data_dir="new fixture data", no_open=True, run=run)
    assert launcher.read_text() == old
    assert desktop.read_text() == previous_desktop if existing_desktop else not desktop.exists()
    assert list((runtime / "environments").iterdir()) == []


def test_only_the_owned_legacy_uv_link_can_be_migrated(setup):
    runtime, launcher, _, _, _ = setup
    from account_access.runtime_bootstrap import launcher_snapshot
    launcher.unlink()
    launcher.symlink_to("../tools/account-access/bin/account-access")
    assert launcher_snapshot(launcher, runtime)[0] == "symlink"
    launcher.unlink()
    launcher.symlink_to("/another/application")
    with pytest.raises(RuntimeError, match="Another application"):
        launcher_snapshot(launcher, runtime)


def test_concurrent_repair_stops_before_changing_installed_files(setup):
    runtime, launcher, old, wheel, requirements = setup
    descriptor = os.open(runtime / ".install.lock", os.O_CREAT | os.O_RDWR, 0o600)
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        with pytest.raises(RuntimeError, match="Another Account Access installation"):
            install("uv", wheel, runtime, requirements)
        assert launcher.read_text() == old
        assert not (runtime / "environments").exists()
    finally:
        os.close(descriptor)


@pytest.mark.parametrize("modified", [False, True])
def test_real_offline_installer_accepts_pinned_wheel_and_rejects_modified_artifact(tmp_path, modified):
    uv = shutil.which("uv")
    if not uv:
        pytest.skip("uv is needed for the offline installer contract")
    wheel = tmp_path / "example_fixture-1.0-py3-none-any.whl"
    with zipfile.ZipFile(wheel, "w") as archive:
        archive.writestr("example_fixture.py", "value = 42\n")
        archive.writestr("example_fixture-1.0.dist-info/METADATA", "Metadata-Version: 2.3\nName: example-fixture\nVersion: 1.0\n")
        archive.writestr("example_fixture-1.0.dist-info/WHEEL", "Wheel-Version: 1.0\nGenerator: test\nRoot-Is-Purelib: true\nTag: py3-none-any\n")
        archive.writestr("example_fixture-1.0.dist-info/RECORD", "")
    digest = hashlib.sha256(wheel.read_bytes()).hexdigest()
    if modified:
        with zipfile.ZipFile(wheel, "a") as archive:
            archive.writestr("unapproved.py", "value = 0\n")
    requirements = tmp_path / "locked.txt"
    requirements.write_text(wheel.as_uri() + " --hash=sha256:" + digest + "\n")
    environment = tmp_path / "env"
    subprocess.run([uv, "venv", "--no-config", "--python", sys.executable, str(environment)],
                   check=True, capture_output=True, timeout=15)
    python = environment / "bin/python"
    result = subprocess.run([uv, "pip", "sync", "--no-config", "--no-index", "--no-cache",
                             "--require-hashes", "--no-build", "--strict", "--python", str(python), str(requirements)],
                            capture_output=True, text=True, timeout=15)
    if modified:
        assert result.returncode != 0 and "Hash mismatch" in result.stderr
    else:
        assert result.returncode == 0, result.stderr
        subprocess.run([str(python), "-I", "-c", "import example_fixture; assert example_fixture.value == 42"],
                       check=True, capture_output=True, timeout=15)
