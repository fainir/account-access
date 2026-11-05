"""A signed image alone cannot qualify the installed-browser repair."""
from copy import deepcopy
import io
import json
from pathlib import Path
import subprocess
import sys
import zipfile

import pytest

from scripts import build_direct_runtime_upgrade_candidate as candidate
from scripts import build_owner_routes_update_image as owner_image
from scripts.build_jit_update_image import JIT, JIT_ROLES


@pytest.mark.parametrize('release', ['125', '126', '127', '128'])
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


def harel_report():
    release = candidate.RELEASE128
    return {'status': 'TARGET_IMAGE_QUALIFIED', 'owner_app_build': 128, 'source_image_build': 127,
            'builder_commit': release.image_builder, 'target_source_commit': release.target_source,
            'owner_source_commit': release.target_source, 'native_source_commit': release.target_source,
            'base_manifest_sha256': release.before, 'manifest_sha256': release.after,
            'project_wheel_sha256': 'a' * 64, 'native_dependency_bytes_unchanged': True,
            'publisher_sandboxed_browser_execution': True,
            'native_audit': {'publisher_signatures_verified': True}, 'jit_roles': sorted(JIT_ROLES),
            'installed_paths_changed': False, 'account_data_used': False}


def test_harel_updater_qualification_is_bound_to_the_qualified_127_successor():
    from macos.system_package import PREASSEMBLED_BUILD128_MANIFEST_SHA256
    release = candidate.RELEASE128
    assert release.before == release.image_base == candidate.RELEASE127.after
    assert release.after == PREASSEMBLED_BUILD128_MANIFEST_SHA256
    assert release.target_source == '605a0495345742194a8e82397da25ac9b6bc3e37'
    assert release.image_builder == '605a0495345742194a8e82397da25ac9b6bc3e37'
    assert release.base_identity == 'd5d21bd2f1aaa7e7ed9d83d0a937036998b7f3d285bc2386cddba9fd19818268'
    assert release.component_id == 'com.fainir.accountaccess.harelemail128'
    assert release.package_stem == 'Account-Access-Harel-Email-128'
    candidate.verify_target_qualification(harel_report(), release, {'project_wheel_sha256': 'a' * 64})


@pytest.mark.parametrize('field,value', [
    ('owner_app_build', 127), ('source_image_build', 126),
    ('builder_commit', candidate.RELEASE127.image_builder),
    ('target_source_commit', candidate.RELEASE127.target_source),
    ('owner_source_commit', candidate.RELEASE127.target_source),
    ('native_source_commit', candidate.RELEASE127.target_source),
    ('base_manifest_sha256', candidate.RELEASE126.after),
    ('manifest_sha256', candidate.RELEASE127.after), ('project_wheel_sha256', 'b' * 64),
    ('native_dependency_bytes_unchanged', 1), ('publisher_sandboxed_browser_execution', 1),
    ('native_audit', {'publisher_signatures_verified': False}), ('jit_roles', []),
    ('installed_paths_changed', True), ('account_data_used', True),
])
def test_harel_qualification_rejects_mixed_pins_and_signature_only_proof(field, value):
    report = harel_report()
    report[field] = value
    with pytest.raises(ValueError, match='target_image_qualification_mismatch'):
        candidate.verify_target_qualification(report, candidate.RELEASE128, {'project_wheel_sha256': 'a' * 64})


def test_harel_historical_compiler_artifact_admission_still_requires_exact_source(monkeypatch, tmp_path):
    # No Actions or network: exercise the retained artifact reader with local
    # synthetic responses. Real local qualification omits --compiled-run.
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, 'w') as archive:
        archive.writestr('AccountAccess-runtimeupgrade', b'synthetic compiled helper')
    raw = stream.getvalue()
    metadata = {'head_sha': 'a' * 40, 'status': 'completed', 'conclusion': 'success',
                'path': '.github/workflows/mac-release-native-review.yml',
                'repository': {'full_name': candidate.REPOSITORY}}
    asset = {'id': 7, 'name': 'release-compiled-updater-128', 'expired': False,
             'size_in_bytes': len(raw), 'digest': 'sha256:' + candidate.digest(raw)}

    def checked(argv, **kwargs):
        if argv[-1].endswith('/zip'):
            return raw
        return json.dumps({'artifacts': [asset]} if argv[-1].endswith('/artifacts') else metadata).encode()

    monkeypatch.setattr(candidate, 'checked', checked)
    destination = tmp_path / 'fixture-helper'
    candidate.reviewed_ci_helper(1, 'a' * 40, destination, artifact_name='release-compiled-updater-128')
    assert destination.read_bytes() == b'synthetic compiled helper'
    with pytest.raises(ValueError, match='compiled_helper_run_not_qualified'):
        candidate.reviewed_ci_helper(1, 'b' * 40, tmp_path / 'must-not-exist',
                                    artifact_name='release-compiled-updater-128')
    assert not (tmp_path / 'must-not-exist').exists()


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
