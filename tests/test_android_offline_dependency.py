"""The QR dependency must build offline and fail closed before Java on bad bytes."""

import os
from pathlib import Path
import shutil
import subprocess

import pytest

ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize('case', ['valid-offline', 'changed-jar', 'linked-jar'])
def test_android_dependency_uses_only_pinned_local_bytes(tmp_path, case):
    repo = tmp_path / 'repo'
    vendor = repo / 'android/vendor'
    vendor.mkdir(parents=True)
    shutil.copyfile(ROOT / 'android/build.sh', repo / 'android/build.sh')
    jar = vendor / 'zxing-core-3.5.3.jar'
    if case == 'linked-jar':
        jar.symlink_to(ROOT / 'android/vendor/zxing-core-3.5.3.jar')
    elif case == 'changed-jar':
        jar.write_bytes(b'invalid dependency must not reach Java')
    else:
        shutil.copyfile(ROOT / 'android/vendor/zxing-core-3.5.3.jar', jar)
    java = tmp_path / 'jdk'
    (java / 'bin').mkdir(parents=True)
    compiler = java / 'bin/javac'
    compiler.write_text('#!/bin/sh\necho VERIFIED_DEPENDENCY_REACHED_JAVA\nexit 77\n')
    compiler.chmod(0o700)
    fake = tmp_path / 'no-network'
    fake.mkdir()
    curl = fake / 'curl'
    curl.write_text('#!/bin/sh\necho NETWORK_WAS_USED\nexit 99\n')
    curl.chmod(0o700)
    result = subprocess.run(['/bin/sh', str(repo / 'android/build.sh')], capture_output=True,
        text=True, timeout=20, env={**os.environ, 'PATH': str(fake) + os.pathsep + os.environ['PATH'],
            'ACCOUNT_ACCESS_JAVA_HOME': str(java), 'ACCOUNT_ACCESS_ANDROID_OUTPUT': str(tmp_path / 'build')})
    assert 'NETWORK_WAS_USED' not in result.stdout + result.stderr
    if case == 'valid-offline':
        assert result.returncode == 77 and 'VERIFIED_DEPENDENCY_REACHED_JAVA' in result.stdout
        assert (tmp_path / 'build/zxing-core-3.5.3.jar').read_bytes() == jar.read_bytes()
    else:
        assert result.returncode != 0 and 'VERIFIED_DEPENDENCY_REACHED_JAVA' not in result.stdout
        assert not (tmp_path / 'build/zxing-core-3.5.3.jar').exists()
