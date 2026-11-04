"""A signed image alone cannot qualify the installed-browser repair."""
from copy import deepcopy
from pathlib import Path
import subprocess
import sys

import pytest

from scripts import build_direct_runtime_upgrade_candidate as candidate
from scripts import build_owner_routes_update_image as owner_image
from scripts.build_jit_update_image import JIT, JIT_ROLES


@pytest.mark.parametrize('release', ['125', '126', '127'])
@pytest.mark.parametrize('module', ['scripts.build_owner_routes_update_image',
                                  'scripts.build_direct_runtime_upgrade_candidate'])
def test_release_cli_accepts_profile_before_requesting_image_inputs(release, module):
    result = subprocess.run([sys.executable, '-m', module,
                             '--release', release], cwd=Path(__file__).resolve().parents[1],
                            capture_output=True, text=True, timeout=10)
    assert result.returncode == 2
    assert 'the following arguments are required' in result.stderr
    assert 'invalid choice' not in result.stderr


def test_harel_image_profile_requires_the_installed_127_predecessor():
    assert owner_image.RELEASES['128'] == (
        127, 128, '82b953e0698ee73468c2cff8aa546c5b94368fbf1fe24036e2623d039fee2f06')
    result = subprocess.run(
        [sys.executable, '-m', 'scripts.build_owner_routes_update_image', '--release', '128'],
        cwd=Path(__file__).resolve().parents[1], capture_output=True, text=True, timeout=10)
    assert result.returncode == 2
    assert 'the following arguments are required' in result.stderr
    assert 'invalid choice' not in result.stderr


@pytest.mark.parametrize('statuses,ready,calls', [
    (['READY'], True, 1),
    (['UNAVAILABLE', 'READY'], True, 2),
    (['UNAVAILABLE', 'UNAVAILABLE'], False, 2),
])
def test_publisher_browser_probe_requires_real_readiness_and_bounds_retries(monkeypatch, capsys, statuses, ready, calls):
    from account_access import browser_health

    checked = []

    class Health:
        def check(self):
            checked.append(statuses[len(checked)])

        def view(self):
            return {'status': checked[-1]}

    monkeypatch.setattr(browser_health, 'BrowserHealth', Health)
    if ready:
        exec(owner_image.OFFLINE_BROWSER_PROBE, {})
        assert capsys.readouterr().out.strip() == 'SIGNED_OFFLINE_BROWSER_READY'
    else:
        with pytest.raises(AssertionError):
            exec(owner_image.OFFLINE_BROWSER_PROBE, {})
        assert not capsys.readouterr().out
    assert len(checked) == calls


def jit_report():
    release = candidate.RELEASE121
    return {'status': 'TARGET_IMAGE_QUALIFIED', 'owner_app_build': 121, 'source_image_build': 120,
            'builder_commit': release.image_builder, 'target_source_commit': release.target_source,
            'base_manifest_sha256': release.image_base, 'manifest_sha256': release.after,
            'project_wheel_sha256': 'a' * 64, 'publisher_sandboxed_browser_execution': True,
            'native_audit': {'publisher_signatures_verified': True}, 'installed_paths_changed': False,
            'account_data_used': False, 'jit_roles': sorted(JIT_ROLES), 'entitlements': dict(JIT)}


def test_successor_requires_signed_sandboxed_browser_execution_and_exact_jit_roles():
    report = jit_report()
    candidate.verify_target_qualification(report, candidate.RELEASE121, {'project_wheel_sha256': 'a' * 64})
    assert candidate.RELEASE121.before == candidate.RELEASE120.after


@pytest.mark.parametrize('change', ['not-executed', 'signature-only', 'other-predecessor',
                                  'other-target', 'other-source', 'extra-entitlement', 'extra-role',
                                  'installed-mutated', 'private-data-used'])
def test_signatures_or_unqualified_runtime_exceptions_cannot_pass(change):
    report = deepcopy(jit_report())
    if change == 'not-executed':
        report['publisher_sandboxed_browser_execution'] = False
    elif change == 'signature-only':
        report.pop('publisher_sandboxed_browser_execution')
    elif change == 'other-predecessor':
        report['base_manifest_sha256'] = candidate.RELEASE120.before
    elif change == 'other-target':
        report['manifest_sha256'] = candidate.RELEASE120.after
    elif change == 'other-source':
        report['target_source_commit'] = candidate.RELEASE120.target_source
    elif change == 'extra-entitlement':
        report['entitlements']['com.apple.security.cs.disable-library-validation'] = True
    elif change == 'extra-role':
        report['jit_roles'].append('python/bin/python3.12')
    elif change == 'installed-mutated':
        report['installed_paths_changed'] = True
    else:
        report['account_data_used'] = True
    with pytest.raises(ValueError, match='target_image_qualification_mismatch'):
        candidate.verify_target_qualification(report, candidate.RELEASE121, {'project_wheel_sha256': 'a' * 64})
