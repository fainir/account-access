import os
import subprocess
import hashlib
import json
import sys
import zipfile
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
@pytest.mark.parametrize("mac_version", [None, "14.0", "26.1"])
def test_verified_bootstrap_runs_without_finder_path_dependencies(tmp_path, cached_uv, mac_version):
    tools = tmp_path / "bin"
    tools.mkdir()
    if mac_version:
        for name, value in [("uname", "Darwin"), ("sw_vers", mac_version)]:
            path = tools / name
            path.write_text("#!/bin/sh\nif [ \"${1:-}\" = -m ]; then printf '%s\\n' arm64; "
                            "else printf '%s\\n' '" + value + "'; fi\n")
            path.chmod(0o700)
    uv = tools / "uv"
    uv.write_text('''#!/bin/sh
case "$1 $2" in
  "python install") exit 0;;
  "python find") printf '%s\\n' "$TEST_BOOTSTRAP_PYTHON";;
  *) exit 99;;
esac
''')
    uv.chmod(0o700)
    if cached_uv:
        cache = tmp_path / "runtime/uv"
        cache.mkdir(parents=True)
        uv.rename(cache / "uv")
    curl = tools / "curl"
    curl.write_text("#!/bin/sh\nexit 99\n")
    curl.chmod(0o700)
    wheel = tmp_path / "account_access.whl"
    with zipfile.ZipFile(wheel, "w") as archive:
        archive.writestr("account_access/runtime_bootstrap.py", '''import json, os, sys
from pathlib import Path
Path(os.environ["TEST_BOOTSTRAP_LOG"]).write_text(json.dumps(sys.argv[1:]))
''')
        archive.writestr("account_access/runtime-requirements.txt", "# fixture\n")
    log = tmp_path / "bootstrap.json"
    root = tmp_path / "owner's data"
    result = subprocess.run(["sh", str(Path(__file__).resolve().parents[1] / "install.sh")],
                            env={**os.environ, "PATH": str(tools) + ":/usr/bin:/bin",
                                 "ACCOUNT_ACCESS_INSTALL_DIR": str(tmp_path / "runtime"),
                                 "ACCOUNT_ACCESS_DATA_DIR": str(root), "ACCOUNT_ACCESS_NO_OPEN": "1",
                                 "ACCOUNT_ACCESS_BUNDLED_WHEEL": str(wheel),
                                 "ACCOUNT_ACCESS_EXPECTED_WHEEL_SHA256": hashlib.sha256(wheel.read_bytes()).hexdigest(),
                                 "TEST_BOOTSTRAP_PYTHON": sys.executable,
                                 "TEST_BOOTSTRAP_LOG": str(log)},
                            text=True, capture_output=True, timeout=15)
    assert result.returncode == 0, result.stdout + result.stderr
    args = json.loads(log.read_text())
    assert args[0] == str(tmp_path / "runtime/uv/uv" if cached_uv else uv)
    assert args[2] == str(tmp_path / "runtime")
    assert args[4:] == [str(root), "1"]


@pytest.mark.parametrize("version", ["13.7.8", "12.0", "", "unknown", "9999.0"])
def test_unsupported_mac_stops_before_downloads_or_runtime_changes(tmp_path, version):
    tools = tmp_path / "bin"
    tools.mkdir()
    marker = tmp_path / "downloads-or-execution"
    for name, script in {
        "uname": "printf '%s\\n' Darwin",
        "sw_vers": 'printf "%s\\n" "$TEST_MAC_VERSION"',
        "uv": 'touch "$TEST_INSTALL_MARKER"; exit 99',
        "curl": 'touch "$TEST_INSTALL_MARKER"; exit 99',
    }.items():
        path = tools / name
        path.write_text("#!/bin/sh\n" + script + "\n")
        path.chmod(0o700)
    runtime = tmp_path / "runtime"
    result = subprocess.run(["sh", str(Path(__file__).resolve().parents[1] / "install.sh")],
                            env={**os.environ, "PATH": str(tools) + ":/usr/bin:/bin",
                                 "ACCOUNT_ACCESS_INSTALL_DIR": str(runtime), "TEST_MAC_VERSION": version,
                                 "TEST_INSTALL_MARKER": str(marker)},
                            text=True, capture_output=True, timeout=15)
    assert result.returncode == 1 and "requires macOS 14" in result.stdout
    assert not runtime.exists() and not marker.exists()


@pytest.mark.parametrize("architecture", ["x86_64", "i386", "unknown", ""])
def test_unsupported_mac_architecture_stops_before_downloads_or_runtime_changes(tmp_path, architecture):
    tools = tmp_path / "bin"
    tools.mkdir()
    marker = tmp_path / "downloads-or-execution"
    scripts = {
        "uname": 'if [ "${1:-}" = -m ]; then printf "%s\\n" "$TEST_MAC_ARCH"; else printf "%s\\n" Darwin; fi',
        "sw_vers": "printf '%s\\n' 14.0",
        "uv": 'touch "$TEST_INSTALL_MARKER"; exit 99',
        "curl": 'touch "$TEST_INSTALL_MARKER"; exit 99',
    }
    for name, script in scripts.items():
        path = tools / name
        path.write_text("#!/bin/sh\n" + script + "\n")
        path.chmod(0o700)
    runtime = tmp_path / "runtime"
    result = subprocess.run(["sh", str(Path(__file__).resolve().parents[1] / "install.sh")],
                            env={**os.environ, "PATH": str(tools) + ":/usr/bin:/bin",
                                 "ACCOUNT_ACCESS_INSTALL_DIR": str(runtime), "TEST_MAC_ARCH": architecture,
                                 "TEST_INSTALL_MARKER": str(marker)},
                            text=True, capture_output=True, timeout=15)
    assert result.returncode == 1 and "requires an Apple silicon" in result.stdout
    assert not runtime.exists() and not marker.exists()
