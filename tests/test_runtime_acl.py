"""Use ordinary temporary files; never change protected Mac paths or ACLs."""

import subprocess
import sys

import pytest

from account_access.worker_bootstrap import BootstrapError, reject_grant_acl


@pytest.mark.skipif(sys.platform != 'darwin', reason='Darwin extended ACLs')
def test_runtime_acl_rejects_allow_entries_even_when_posix_mode_stays_safe(tmp_path):
    file = tmp_path / 'inert-runtime-fixture'
    file.write_bytes(b'fictional')
    file.chmod(0o600)
    reject_grant_acl(file)
    subprocess.run(['/bin/chmod', '+a', 'everyone allow write', str(file)], check=True)
    assert file.stat().st_mode & 0o022 == 0
    with pytest.raises(BootstrapError, match='untrusted_worker_runtime'):
        reject_grant_acl(file)
    subprocess.run(['/bin/chmod', '-N', str(file)], check=True)
    reject_grant_acl(file)


@pytest.mark.skipif(sys.platform != 'darwin', reason='Darwin extended ACLs')
def test_runtime_acl_allows_restrictive_deny_entries(tmp_path):
    file = tmp_path / 'inert-runtime-fixture'
    file.write_bytes(b'fictional')
    subprocess.run(['/bin/chmod', '+a', 'everyone deny delete', str(file)], check=True)
    try:
        reject_grant_acl(file)
    finally:
        subprocess.run(['/bin/chmod', '-N', str(file)], check=True)
