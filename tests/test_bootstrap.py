import os
import subprocess
from pathlib import Path


def test_installer_refuses_modified_download_before_installing(tmp_path):
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
  */SHA256SUMS) printf '%064d  account_access-0.4.1-py3-none-any.whl\\n' 0 > "$dest";;
  *) printf 'modified package' > "$dest";;
esac
""")
    curl.chmod(0o700)
    result = subprocess.run(["sh", str(Path(__file__).resolve().parents[1] / "install.sh")],
                            env={**os.environ, "PATH": str(tools) + ":/usr/bin:/bin",
                                 "ACCOUNT_ACCESS_INSTALL_DIR": str(tmp_path / "runtime")},
                            text=True, capture_output=True, timeout=15)
    assert result.returncode != 0
    assert "Download verification failed" in result.stdout
    assert not marker.exists()
