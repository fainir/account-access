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
  */SHA256SUMS) printf '%s  account_access-0.7.1-py3-none-any.whl\\n' "$TEST_MANIFEST_SHA" > "$dest";;
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
