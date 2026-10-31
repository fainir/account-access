"""A signed image alone cannot qualify the installed-browser repair."""
from copy import deepcopy

import pytest

from scripts import build_direct_runtime_upgrade_candidate as candidate
from scripts.build_jit_update_image import JIT, JIT_ROLES


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
