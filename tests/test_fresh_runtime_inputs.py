"""Frozen new-runtime assets and hosted-only acceptance; no installation/network."""
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import runpy

import pytest

ROOT = Path(__file__).resolve().parents[1]


def modules():
    return (runpy.run_path(str(ROOT / 'scripts/download_fresh_runtime_inputs.py')),
            runpy.run_path(str(ROOT / 'scripts/mac_fresh_image_installer_probe.py')))


def test_runtime_profile_keeps_historical_counts_separate():
    download, probe = modules()
    assert probe['cohort_pins'](89) == (download['MANIFEST'], download['SOURCE'], download['CONTRACT'])
    assert probe['cohort_counts'](89) == {'files': 25167, 'directories': 2297, 'aliases': 21}
    for cohort in (80, 84):
        assert probe['cohort_counts'](cohort) == {'files': 25165, 'directories': 2297, 'aliases': 21}
    for cohort in (True, '89', 89.0, 88, None):
        with pytest.raises(ValueError):
            probe['cohort_counts'](cohort)


def fixture(monkeypatch):
    download, probe = modules()
    value = {'schema': 1, 'status': 'FROZEN_REVIEWED_ASSETS', 'repository': download['REPOSITORY'],
        'target_source': download['SOURCE'], 'packaging_source': download['SOURCE'],
        'target_manifest_sha256': download['MANIFEST'], 'installer_verifier_sha256': download['VERIFIER'],
        'assets': {}}
    for index, name in enumerate(sorted(download['FILES']), 1):
        value['assets'][name] = {'id': index, 'bytes': 100 + index, 'sha256': str(index) * 64,
            'release': {'id': 100, 'tag': 'fictional', 'source': download['SOURCE']}}
    raw = json.dumps(value, sort_keys=True, separators=(',', ':')).encode() + b'\n'
    monkeypatch.setitem(download['validate'].__globals__, 'CONTRACT_SHA256', hashlib.sha256(raw).hexdigest())
    return download, probe, value


def test_all_asset_identities_and_release_metadata_are_pinned(monkeypatch):
    download, _, value = fixture(monkeypatch)
    assert download['validate'](value) == value
    for name, row in value['assets'].items():
        for key in row:
            candidate = deepcopy(value)
            candidate['assets'][name][key] = 'foreign'
            with pytest.raises(ValueError):
                download['validate'](candidate)
        for key in row['release']:
            candidate = deepcopy(value)
            candidate['assets'][name]['release'][key] = 'foreign'
            with pytest.raises(ValueError):
                download['validate'](candidate)
    for key in value:
        with pytest.raises(ValueError):
            download['validate']({**value, key: 'foreign'})


@pytest.mark.parametrize('pin', [None, '', True, '0' * 64, 'g' * 64])
def test_unreviewed_contract_cannot_download(monkeypatch, pin):
    download, _, value = fixture(monkeypatch)
    monkeypatch.setitem(download['validate'].__globals__, 'CONTRACT_SHA256', pin)
    with pytest.raises(ValueError):
        download['validate'](value)


def test_new_runtime_review_cannot_substitute_an_old_image(monkeypatch):
    download, probe, value = fixture(monkeypatch)
    review = {'schema': 1, 'status': 'BUILT_NOT_INSTALLED_NOT_INSTALL_QUALIFIED',
        'package_sha256': value['assets']['fresh.pkg']['sha256'],
        'package_bytes': value['assets']['fresh.pkg']['bytes'],
        'target_manifest_sha256': download['MANIFEST'], 'target_source': download['SOURCE'],
        'packaging_source': download['SOURCE'], 'installer_verifier_sha256': download['VERIFIER'],
        'expanded_inventory_sha256': value['assets']['fresh-expanded-inventory.json']['sha256'],
        'actual_Installer_qualified': False, 'production_ready': False}
    assert probe['validate_review'](review, value, 89) == review
    for cohort in (80, 84):
        with pytest.raises(ValueError):
            probe['validate_review'](review, value, cohort)
    for key in review:
        with pytest.raises(ValueError):
            probe['validate_review']({**review, key: 'foreign'}, value, 89)


def test_download_context_refuses_before_path_access(monkeypatch, tmp_path):
    download, _ = modules()
    monkeypatch.delenv('GITHUB_ACTIONS', raising=False)
    monkeypatch.setattr(download['os'], 'getuid', lambda: 501)
    monkeypatch.setattr(download['os'], 'geteuid', lambda: 501)
    monkeypatch.setattr('sys.argv', ['download', '--output', str(tmp_path / 'unused'), '--contract', 'unused'])
    monkeypatch.setattr(Path, 'read_bytes', lambda *_: pytest.fail('Unexpected path access'))
    with pytest.raises(ValueError):
        download['main']()


def test_workflow_tests_a_fresh_host_without_transferring_tokens():
    import yaml
    value = yaml.safe_load((ROOT / '.github/workflows/mac-fresh-image89-installer-review.yml').read_text())
    trigger = value.get('on', value.get(True))
    assert trigger == {'push': {'branches': ['codex/full-image-update'],
                               'paths': ['artifacts/fresh-image89-installer-inputs.json']}}
    job = value['jobs']['actual-installer']
    assert job['permissions'] == {'contents': 'read'}
    assert 'GH_TOKEN' not in json.dumps(job)
    assert '--cohort 89' in json.dumps(job)
    assert all(step.get('with', {}).get('persist-credentials') is False
               for step in job['steps'] if 'checkout@' in step.get('uses', ''))


def test_committed_runtime_contract_is_frozen():
    download, _ = modules()
    value = json.loads((ROOT / download['CONTRACT']).read_bytes())
    assert download['validate'](value) == value


def test_runtime92_contract_cannot_be_used_as_runtime89():
    download, probe = modules()
    source, manifest, contract, _ = download['profile'](92)
    value = json.loads((ROOT / contract).read_bytes())
    assert download['validate'](value, 92) == value
    assert probe['cohort_pins'](92) == (manifest, source, contract)
    assert probe['cohort_counts'](92) == {'files': 25167, 'directories': 2297, 'aliases': 21}
    with pytest.raises(ValueError):
        download['validate'](value, 89)
    old = json.loads((ROOT / download['CONTRACT']).read_bytes())
    with pytest.raises(ValueError):
        download['validate'](old, 92)
    for name in value['assets']:
        changed = deepcopy(value)
        changed['assets'][name]['sha256'] = '0' * 64
        with pytest.raises(ValueError):
            download['validate'](changed, 92)


def test_runtime92_workflow_uses_only_the_new_frozen_contract():
    import yaml
    value = yaml.safe_load((ROOT / '.github/workflows/mac-fresh-image92-installer-review.yml').read_text())
    trigger = value.get('on', value.get(True))
    assert trigger['push']['paths'] == ['artifacts/fresh-image92-installer-inputs.json']
    job = value['jobs']['actual-installer']
    assert job['permissions'] == {'contents': 'read'}
    assert 'GH_TOKEN' not in json.dumps(job)
    assert '--cohort 92' in json.dumps(job)
