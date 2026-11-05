"""The production permission repair is confined to the two pinned V8 roles."""
from copy import deepcopy

import pytest

from scripts.build_jit_update_image import JIT, JIT_ROLES, NODE, install_driver_files, publisher_jit_plan


def test_wheel_record_metadata_cannot_make_the_prepared_runtime_writable(tmp_path):
    from account_access.package_manifest import inventory
    unpacked = tmp_path / 'wheel'
    runtime = tmp_path / 'runtime'
    for name, mode in [(NODE, 0o755), ('playwright-1.63.0.dist-info/RECORD', 0o644)]:
        source = unpacked / name
        destination = runtime / 'lib/python3.12/site-packages' / name
        source.parent.mkdir(parents=True, exist_ok=True)
        destination.parent.mkdir(parents=True, exist_ok=True)
        source.write_bytes(b'new prepared bytes')
        source.chmod(0o664)
        destination.write_bytes(b'old bytes')
        destination.chmod(mode)
    install_driver_files(unpacked, runtime)
    result = inventory(runtime)
    assert result['lib/python3.12/site-packages/playwright-1.63.0.dist-info/RECORD']['mode'] == 0o644
    assert result['lib/python3.12/site-packages/' + NODE]['mode'] == 0o755
    assert (runtime / 'lib/python3.12/site-packages/' / NODE).read_bytes() == b'new prepared bytes'


def preparation():
    return {'schema': 1, 'publisher_team': 'WBULD6N4NQ', 'development': False,
            'source_trees': {'python': 'a' * 64, 'browsers': 'b' * 64},
            'native_files': [
                *[{'kind': 2, 'path': name, 'original_sha256': str(index) * 64}
                  for index, name in enumerate(sorted(JIT_ROLES), 1)],
                {'kind': 2, 'path': 'python/bin/python3.12', 'original_sha256': '3' * 64},
                {'kind': 2, 'path': 'browsers/ffmpeg-1011/ffmpeg-mac', 'original_sha256': '4' * 64},
                {'kind': 6, 'path': 'browsers/chrome/libEGL.dylib', 'original_sha256': '5' * 64}]}


def test_only_reviewed_v8_roles_get_jit_without_other_runtime_exceptions():
    receipt = preparation()
    before = deepcopy(receipt)
    plan = publisher_jit_plan(receipt)
    assert receipt == before
    assert {p for row in plan['executables'].values() if row['entitlements'] for p in row['paths']} == JIT_ROLES
    assert all(row['entitlements'] in ({}, JIT) for row in plan['executables'].values())
    assert len(plan['executables']) == 4
    assert plan['executables']['3' * 64]['entitlements'] == {}
    assert plan['executables']['4' * 64]['entitlements'] == {}


@pytest.mark.parametrize('change', ['ad-hoc', 'wrong-team', 'missing-node', 'wrong-role-type',
                                  'duplicate-path', 'shared-with-unrelated-role'])
def test_unqualified_or_ambiguous_native_role_is_refused(change):
    receipt = preparation()
    if change == 'ad-hoc':
        receipt['development'] = True
    elif change == 'wrong-team':
        receipt['publisher_team'] = 'UNKNOWN'
    elif change == 'missing-node':
        receipt['native_files'].pop(1)
    elif change == 'wrong-role-type':
        receipt['native_files'][0]['kind'] = 6
    elif change == 'duplicate-path':
        receipt['native_files'].append(dict(receipt['native_files'][0]))
    else:
        receipt['native_files'].append({'kind': 2, 'path': 'python/bin/unrelated',
                                       'original_sha256': '1' * 64})
    with pytest.raises(ValueError):
        publisher_jit_plan(receipt)
