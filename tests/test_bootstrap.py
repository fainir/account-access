import os
import subprocess
import hashlib
from pathlib import Path

import pytest


@pytest.mark.parametrize("manifest_matches", [False, True])
def test_installer_refuses_modified_download_before_installing(tmp_path, manifest_matches):
    tools = tmp_path / "bin"
    tools.mkdir()
    marker = tmp_path / "uv-was-called"
    uv = tools / "uv"
    uv.write_text('#!/bin/sh\ntouch "' + str(marker) + '"\nexit 0\n')
    uv.chmod(0o700)
    curl = tools / "curl"
    curl.write_text("""#!/bin/sh
dest=""
url=""
while [ "$#" -gt 0 ]; do
  case "$1" in -o) shift; dest="$1";; https://*) url="$1";; esac
  shift
done
case "$url" in
  */SHA256SUMS) printf '%s  account_access-0.8.0-py3-none-any.whl\\n' "$TEST_MANIFEST_SHA" > "$dest";;
  *) printf 'modified package' > "$dest";;
esac
""")
    curl.chmod(0o700)
    result = subprocess.run(["sh", str(Path(__file__).resolve().parents[1] / "install.sh")],
                            env={**os.environ, "PATH": str(tools) + ":/usr/bin:/bin",
                                 "ACCOUNT_ACCESS_INSTALL_DIR": str(tmp_path / "runtime"),
                                 "TEST_MANIFEST_SHA": hashlib.sha256(b"modified package").hexdigest() if manifest_matches else "0" * 64,
                                 "ACCOUNT_ACCESS_EXPECTED_WHEEL_SHA256": "f" * 64 if manifest_matches else ""},
                            text=True, capture_output=True, timeout=15)
    assert result.returncode != 0
    assert "Download verification failed" in result.stdout
    assert not marker.exists()


@pytest.mark.parametrize("pin", ["", "f" * 64])
def test_bundled_package_requires_matching_signed_pin(tmp_path, pin):
    tools = tmp_path / "bin"
    tools.mkdir()
    marker = tmp_path / "executed"
    for name in ["uv", "curl"]:
        executable = tools / name
        executable.write_text('#!/bin/sh\ntouch "' + str(marker) + '"\nexit 1\n')
        executable.chmod(0o700)
    wheel = tmp_path / "account_access.whl"
    wheel.write_bytes(b"changed package")
    result = subprocess.run(["sh", str(Path(__file__).resolve().parents[1] / "install.sh")],
                            env={**os.environ, "PATH": str(tools) + ":/usr/bin:/bin",
                                 "ACCOUNT_ACCESS_INSTALL_DIR": str(tmp_path / "runtime"),
                                 "ACCOUNT_ACCESS_BUNDLED_WHEEL": str(wheel),
                                 "ACCOUNT_ACCESS_EXPECTED_WHEEL_SHA256": pin},
                            text=True, capture_output=True, timeout=15)
    assert result.returncode != 0
    assert "verification failed" in result.stdout
    assert not marker.exists()


@pytest.mark.parametrize("cached_uv", [False, True])
def test_successful_repair_restarts_service_even_when_version_is_unchanged(tmp_path, cached_uv):
    tools = tmp_path / "bin"
    tools.mkdir()
    uv = tools / "uv"
    uv.write_text('''#!/bin/sh
mkdir -p "$UV_TOOL_DIR/account-access/bin" "$UV_TOOL_BIN_DIR"
cp "$TEST_FAKE_PYTHON" "$UV_TOOL_DIR/account-access/bin/python"
cp "$TEST_FAKE_APP" "$UV_TOOL_BIN_DIR/account-access"
''')
    uv.chmod(0o700)
    if cached_uv:
        cache = tmp_path / "runtime/uv"
        cache.mkdir(parents=True)
        uv.rename(cache / "uv")
    fake_python = tmp_path / "fake-python"
    # Keep the installer smoke test from writing a real launcher or installing
    # browsers. The service's stop/start entrypoints are the behavior under test.
    fake_python.write_text("#!/bin/sh\nexit 0\n")
    fake_python.chmod(0o700)
    fake_app = tmp_path / "fake-app"
    fake_app.write_text('#!/bin/sh\nprintf \'%s\\n\' "$*" >> "$TEST_RESTART_LOG"\n')
    fake_app.chmod(0o700)
    curl = tools / "curl"
    curl.write_text("#!/bin/sh\nexit 99\n")
    curl.chmod(0o700)
    wheel = tmp_path / "account_access.whl"
    wheel.write_bytes(b"checksum-pinned-test-package")
    log = tmp_path / "restart.log"
    root = tmp_path / "owner data"
    result = subprocess.run(["sh", str(Path(__file__).resolve().parents[1] / "install.sh")],
                            env={**os.environ, "PATH": str(tools) + ":/usr/bin:/bin",
                                 "ACCOUNT_ACCESS_INSTALL_DIR": str(tmp_path / "runtime"),
                                 "ACCOUNT_ACCESS_DATA_DIR": str(root), "ACCOUNT_ACCESS_NO_OPEN": "1",
                                 "ACCOUNT_ACCESS_BUNDLED_WHEEL": str(wheel),
                                 "ACCOUNT_ACCESS_EXPECTED_WHEEL_SHA256": hashlib.sha256(wheel.read_bytes()).hexdigest(),
                                 "TEST_FAKE_PYTHON": str(fake_python), "TEST_FAKE_APP": str(fake_app),
                                 "TEST_RESTART_LOG": str(log)},
                            text=True, capture_output=True, timeout=15)
    assert result.returncode == 0, result.stdout + result.stderr
    assert log.read_text().splitlines() == ["--root " + str(root) + " stop", "--root " + str(root) + " start --no-open"]
