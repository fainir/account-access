import os
from pathlib import Path
import subprocess
import fcntl
import hashlib
import shutil
import sys
import zipfile

import pytest

from account_access.runtime_bootstrap import MARKER, install


@pytest.fixture
def setup(tmp_path, monkeypatch):
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: home))
    runtime = tmp_path / "runtime's folder"
    launcher = runtime / "bin/account-access"
    launcher.parent.mkdir(parents=True)
    old = "#!/bin/sh\n" + MARKER + "\n# previous runtime\n"
    launcher.write_text(old)
    launcher.chmod(0o700)
    wheel = tmp_path / "account_access-0.8.0-py3-none-any.whl"
    wheel.write_bytes(b"fictional package")
    requirements = tmp_path / "requirements.txt"
    requirements.write_text("example==1.0 --hash=sha256:" + "0" * 64 + "\n")
    return runtime, launcher, old, wheel, requirements


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


def test_unowned_runtime_launcher_is_not_replaced(setup):
    runtime, launcher, _, wheel, requirements = setup
    launcher.write_text("another application")
    with pytest.raises(RuntimeError, match="Another application"):
        install("uv", wheel, runtime, requirements)
    assert launcher.read_text() == "another application"


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
