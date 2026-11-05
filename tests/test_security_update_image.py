import base64
import csv
import hashlib
import io
import zipfile

import pytest

from scripts.build_security_update_image import replace_joserfc, sha


def setup(tmp_path, *, native=False):
    runtime = tmp_path / 'runtime'
    site = runtime / 'lib/python3.12/site-packages'
    (site / 'joserfc').mkdir(parents=True)
    (site / 'joserfc/__init__.py').write_text('old')
    (site / 'joserfc-1.7.5.dist-info').mkdir()
    (site / 'unrelated.txt').write_text('preserve')
    wheel = tmp_path / 'joserfc-1.7.7-py3-none-any.whl'
    entries = {'joserfc/__init__.py': b'patched',
               'joserfc-1.7.7.dist-info/WHEEL': b'Wheel-Version: 1.0\nRoot-Is-Purelib: true\nTag: py3-none-any\n',
               'joserfc-1.7.7.dist-info/METADATA': b'Metadata-Version: 2.1\nName: joserfc\nVersion: 1.7.7\n'}
    if native:
        entries['joserfc/unreviewed.so'] = b'not-pure-python'
    record = io.StringIO()
    writer = csv.writer(record, lineterminator='\n')
    for name, value in entries.items():
        pin = base64.urlsafe_b64encode(hashlib.sha256(value).digest()).rstrip(b'=').decode()
        writer.writerow([name, 'sha256=' + pin, str(len(value))])
    writer.writerow(['joserfc-1.7.7.dist-info/RECORD', '', ''])
    entries['joserfc-1.7.7.dist-info/RECORD'] = record.getvalue().encode()
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
