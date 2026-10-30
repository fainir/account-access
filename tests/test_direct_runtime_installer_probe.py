"""Safety boundaries of the root-only disposable Installer acceptance probe."""
import io
from types import SimpleNamespace
import tarfile

import pytest

from scripts import mac_direct_runtime_installer_probe as probe


def archive(extra=None):
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode='w') as target:
        for name in ['PublicImage', 'PublicImage/Library', 'PublicImage/Library/Application Support',
                     'PublicImage/Applications', 'PublicImage/Library/Application Support/Account Access']:
            item = tarfile.TarInfo(name)
            item.type = tarfile.DIRTYPE
            target.addfile(item)
        item = tarfile.TarInfo('BaseManifest.json')
        target.addfile(item, io.BytesIO())
        item = tarfile.TarInfo('PublicImage/Applications/Account Access.app')
        item.type = tarfile.SYMTYPE
        item.linkname = '../Library/Application Support/Account Access/owner.app'
        target.addfile(item)
        if extra:
            extra(target)
    stream.seek(0)
    return tarfile.open(fileobj=stream)


MANIFEST = {'roots': {str(probe.BASE): {'': {'kind': 'directory', 'mode': 0o755}},
                     str(probe.APP): {'': {'kind': 'symlink',
                                          'target': '../Library/Application Support/Account Access/owner.app'}}}}


def test_exact_public_archive_has_only_manifest_paths():
    with archive() as source:
        assert len(probe.archive_members(source, MANIFEST)) == 7


@pytest.mark.parametrize('name', ['../escape', '/absolute', 'PublicImage/vault/password',
                                  'BaseManifest.json'])
def test_unlisted_or_duplicate_archive_entries_are_refused(name):
    def extra(target):
        target.addfile(tarfile.TarInfo(name), io.BytesIO())
    with archive(extra) as source, pytest.raises(ValueError, match='membership_invalid'):
        probe.archive_members(source, MANIFEST)


def test_archive_hardlink_cannot_replace_the_manifest():
    with archive() as source:
        source.getmember('BaseManifest.json').type = tarfile.LNKTYPE
        with pytest.raises(ValueError, match='parent_invalid'):
            probe.archive_members(source, MANIFEST)


@pytest.mark.parametrize('mode', ['upgrade', 'fresh'])
def test_probe_refuses_an_ordinary_owner_context_before_inputs(tmp_path, mode):
    args = SimpleNamespace(inputs=tmp_path / 'missing', output=tmp_path / 'output', mode=mode)
    with pytest.raises(ValueError, match='component_installer_acceptance_failed'):
        probe.run(args)
    assert not args.output.exists()


def test_only_synthetic_evidence_is_made_readable_for_artifact_upload(tmp_path):
    tmp_path.chmod(0o700)
    log = tmp_path / 'install.log'
    log.write_text('synthetic')
    log.chmod(0o600)
    retained = tmp_path / 'baseline'
    retained.mkdir(mode=0o700)
    probe.publish_report(tmp_path, {'status': 'PASSED', 'personal_accounts_used': 0})
    assert tmp_path.stat().st_mode & 0o777 == 0o755
    assert log.stat().st_mode & 0o777 == 0o644
    assert (tmp_path / 'report.json').stat().st_mode & 0o777 == 0o644
    assert retained.stat().st_mode & 0o777 == 0o700
