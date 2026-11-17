import base64
import csv
import hashlib
import io
import zipfile

import pytest

from scripts import build_owner_routes_update_image as successor
from scripts.build_security_update_image import replace_joserfc, sha


def setup(tmp_path, *, native=False, distribution='joserfc', package='joserfc',
          before='1.7.5', after='1.7.7'):
    runtime = tmp_path / 'runtime'
    site = runtime / 'lib/python3.12/site-packages'
    (site / package).mkdir(parents=True)
    (site / package / '__init__.py').write_text('old')
    (site / f'{distribution}-{before}.dist-info').mkdir()
    (site / 'unrelated.txt').write_text('preserve')
    wheel = tmp_path / f'{distribution}-{after}-py3-none-any.whl'
    info = f'{distribution}-{after}.dist-info'
    entries = {f'{package}/__init__.py': b'patched',
               f'{info}/WHEEL': b'Wheel-Version: 1.0\nRoot-Is-Purelib: true\nTag: py3-none-any\n',
               f'{info}/METADATA': f'Metadata-Version: 2.1\nName: {distribution}\nVersion: {after}\n'.encode()}
    if native:
        entries[f'{package}/unreviewed.so'] = b'not-pure-python'
    record = io.StringIO()
    writer = csv.writer(record, lineterminator='\n')
    for name, value in entries.items():
        pin = base64.urlsafe_b64encode(hashlib.sha256(value).digest()).rstrip(b'=').decode()
        writer.writerow([name, 'sha256=' + pin, str(len(value))])
    writer.writerow([f'{info}/RECORD', '', ''])
    entries[f'{info}/RECORD'] = record.getvalue().encode()
    with zipfile.ZipFile(wheel, 'w') as archive:
        for name, value in entries.items():
            archive.writestr(name, value)
    return runtime, site, wheel


def test_dependency_replacement_preserves_unrelated_files(tmp_path):
    runtime, site, wheel = setup(tmp_path)
    replace_joserfc(runtime, wheel, sha(wheel))
    assert (site / 'joserfc/__init__.py').read_text() == 'patched'
    assert not (site / 'joserfc-1.7.5.dist-info').exists()
    assert (site / 'joserfc-1.7.7.dist-info/RECORD').is_file()
    assert (site / 'unrelated.txt').read_text() == 'preserve'


@pytest.mark.parametrize('fault', ['hash', 'native'])
def test_invalid_dependency_does_not_remove_predecessor(tmp_path, fault):
    runtime, site, wheel = setup(tmp_path, native=fault == 'native')
    with pytest.raises(ValueError, match='jose_wheel_'):
        replace_joserfc(runtime, wheel, '0' * 64 if fault == 'hash' else sha(wheel))
    assert (site / 'joserfc/__init__.py').read_text() == 'old'
    assert (site / 'joserfc-1.7.5.dist-info').is_dir()


@pytest.mark.parametrize('stale_lock', [False, True])
def test_opentelemetry_image_requires_matching_project_lock(tmp_path, monkeypatch, stale_lock):
    _, site, wheel = setup(tmp_path, distribution='opentelemetry_api', package='opentelemetry',
                           before='1.45.1', after='1.45.2')
    wheels = tmp_path / 'wheels'
    wheels.mkdir()
    old_wheel = wheels / 'opentelemetry_api-1.45.1-py3-none-any.whl'
    old_wheel.write_bytes(b'old wheel')
    old_digest, new_digest = sha(old_wheel), sha(wheel)
    monkeypatch.setattr(successor, 'OTEL_PREDECESSOR', old_digest)
    monkeypatch.setattr(successor, 'OTEL_PATCHED', new_digest)
    old_pin = f'opentelemetry-api==1.45.1 --hash=sha256:{old_digest}\n'.encode()
    new_pin = f'opentelemetry-api==1.45.2 --hash=sha256:{new_digest}\n'.encode()
    project = tmp_path / 'account_access-0.8.0-py3-none-any.whl'
    with zipfile.ZipFile(project, 'w') as archive:
        archive.writestr('account_access/runtime-requirements.txt', old_pin if stale_lock else new_pin)
    prep = {'wheels': [{'filename': old_wheel.name,
                        'original_sha256': old_digest, 'prepared_sha256': old_digest}]}
    image = {'wheels': [{'name': 'opentelemetry-api', 'version': '1.45.1', 'sha256': old_digest}]}
    if stale_lock:
        with pytest.raises(ValueError, match='opentelemetry_project_requirement_invalid'):
            successor.patch_opentelemetry(tmp_path, wheel, project, new_pin, old_pin, prep, image)
        assert old_wheel.is_file() and (site / 'opentelemetry/__init__.py').read_text() == 'old'
        return
    assert successor.patch_opentelemetry(tmp_path, wheel, project, new_pin, old_pin, prep, image) == new_pin
    assert not old_wheel.exists() and sha(wheels / wheel.name) == new_digest
    assert (site / 'opentelemetry/__init__.py').read_text() == 'patched'
    assert not (site / 'opentelemetry_api-1.45.1.dist-info').exists()
    assert (site / 'unrelated.txt').read_text() == 'preserve'
    assert prep['wheels'][0]['prepared_sha256'] == new_digest
    assert prep['original_requirements_sha256'] == hashlib.sha256(new_pin).hexdigest()
    assert image['wheels'][0] == {'name': 'opentelemetry-api', 'version': '1.45.2',
                                 'sha256': new_digest}
