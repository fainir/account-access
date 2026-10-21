"""Flat-installer protocol fixtures; no Apple acceptance or real signing."""
import json
import os
from pathlib import Path
import subprocess
import struct
import sys

import pytest

from macos.notarize import PackageNotarization, ReleaseError, sha256
from test_notarization import AppleTools, JOB, PROFILE, TEAM

TICKET_DATA = b's8chfictional-notary-ticket'
TICKET = (struct.pack('<4sHHI4s', b't8lr', 1, 1, 0, b'\0' * 4) + TICKET_DATA
          + struct.pack('<4sHHI4s', b't8lr', 1, 2, len(TICKET_DATA), b'\0' * 4))


class PackageTools(AppleTools):
    def __init__(self):
        super().__init__()
        self.installer_status = 'signed by a developer certificate issued by Apple for distribution'
        self.installer_purpose = 'Developer ID Installer'
        self.installer_fingerprint = 'AB ' * 32
        self.installer_signature_code = 0
        self.mutate_on_staple = False
        self.overlarge_ticket = False

    def __call__(self, argv, timeout=60):
        if argv[0] not in {'pkgutil', 'spctl'} and argv[:2] not in [
                ['xcrun', 'stapler'], ['xcrun', 'notarytool']]:
            return super().__call__(argv, timeout)
        self.calls.append(argv)
        text, error, code = '', '', 0
        if argv[0] == 'pkgutil':
            code = self.installer_signature_code
            text = ('Package "fixture.pkg":\n'
                    f'  Status: {self.installer_status}\n'
                    + ('  Signed with a trusted timestamp on: 2026-10-19 00:00:00 +0000\n' if self.timestamp else '')
                    + f'  Certificate Chain:\n  1. {self.installer_purpose}: Fictional Publisher ({self.signature_team})\n'
                    + f'    SHA256 Fingerprint:\n      {self.installer_fingerprint}\n'
                    + '    ------------------------------------------------------------------------\n'
                    + '  2. Developer ID Certification Authority\n')
        elif argv[0] == 'spctl':
            if self.policy_fails:
                code, error = 3, 'fictional-private-policy-error'
        elif argv[:3] == ['xcrun', 'notarytool', 'submit']:
            self.uploads += 1
            self.submitted_sha = sha256(argv[3])
            self.submitted_name = Path(argv[3]).name
            if self.upload_timeout:
                raise ReleaseError('tool_unavailable_or_timed_out', 'RETRYABLE')
            text = json.dumps({'id': JOB})
        elif argv[:3] == ['xcrun', 'notarytool', 'info']:
            text = json.dumps({'id': JOB, 'status': self.apple_status, 'name': self.submitted_name,
                               **self.info_override})
        elif argv[:3] == ['xcrun', 'notarytool', 'log']:
            text = json.dumps({'logFormatVersion': 1, 'jobId': JOB, 'status': self.apple_status,
                               'statusCode': 0 if self.apple_status == 'Accepted' else 4000,
                               'archiveFilename': self.submitted_name, 'sha256': self.submitted_sha,
                               **self.log_override})
        elif argv[:3] == ['xcrun', 'stapler', 'validate']:
            code = 0 if Path(argv[-1]).read_bytes().endswith(TICKET) else 1
        elif argv[:3] == ['xcrun', 'stapler', 'staple']:
            self.staples += 1
            path = Path(argv[-1])
            content = path.read_bytes()
            if self.mutate_on_staple:
                content = b'xar!changed signed contents'
            path.write_bytes(content + (b'x' * (PackageNotarization.max_ticket + 1)
                                       if self.overlarge_ticket else b'') + TICKET)
            if self.staple_error_after_ticket:
                self.staple_error_after_ticket = False
                code = 69
        return subprocess.CompletedProcess(argv, code, text, error)


@pytest.fixture
def package_release(tmp_path):
    source = tmp_path / 'input/Account-Access-arm64.pkg'
    source.parent.mkdir()
    source.write_bytes(b'xar!fictional signed flat package and complete runtime')
    source.chmod(0o644)
    tools = PackageTools()
    task = PackageNotarization(tmp_path / 'release', tools)
    task.prepare(source, TEAM)
    return task, tools, source


def accepted(package_release):
    task, tools, _ = package_release
    task.submit(PROFILE)
    tools.apple_status = 'Accepted'
    return task, tools


def test_flat_package_preparation_is_local_copy_only_and_pins_installer_identity(package_release):
    task, tools, source = package_release
    state = task.load()
    assert state['package'] == {'team': TEAM, 'certificate_sha256': 'ab' * 32,
                               'trusted_timestamp': '2026-10-19 00:00:00 +0000'}
    assert task.archive.name == 'submission.pkg'
    assert task.archive.read_bytes() == source.read_bytes()
    assert task.archive.stat().st_mode & 0o077 == 0
    assert source.stat().st_mode & 0o777 == 0o644
    assert tools.uploads == tools.staples == 0
    assert all(call[:2] == ['pkgutil', '--check-signature'] for call in tools.calls)
    assert task.prepare(source, TEAM)['status'] == 'CACHED_STATE'
    source.write_bytes(b'xar!changed original; prepared bytes are independent')
    task.submit(PROFILE)
    assert tools.submitted_sha == state['archive_sha256']
    assert tools.uploads == 1


@pytest.mark.parametrize('damage', ['unsigned', 'team', 'purpose', 'untrusted', 'timestamp', 'fingerprint',
                                    'header', 'directory', 'symlink', 'hardlink', 'writable', 'oversize'])
def test_unsigned_or_untrusted_input_never_reaches_upload(package_release, tmp_path, damage):
    _, tools, source = package_release
    if damage == 'unsigned':
        tools.installer_signature_code = 1
    elif damage == 'team':
        tools.signature_team = 'OTHER12345'
    elif damage == 'purpose':
        tools.installer_purpose = '3rd Party Mac Developer Installer'
    elif damage == 'untrusted':
        tools.installer_status = 'signed by an untrusted certificate'
    elif damage == 'timestamp':
        tools.timestamp = False
    elif damage == 'fingerprint':
        tools.installer_fingerprint = 'AB ' * 31
    elif damage == 'header':
        source.write_bytes(b'not a flat package')
    elif damage == 'directory':
        source.unlink()
        source.mkdir()
    elif damage == 'symlink':
        link = source.with_name('alias.pkg')
        link.symlink_to(source)
        source = link
    elif damage == 'hardlink':
        os.link(source, source.with_name('hardlink.pkg'))
    elif damage == 'writable':
        source.chmod(0o666)
    else:
        with source.open('r+b') as stream:
            stream.truncate(PackageNotarization.max_package + 1)
    fresh = PackageNotarization(tmp_path / 'fresh', tools)
    with pytest.raises(ReleaseError):
        fresh.prepare(source, TEAM)
    assert not fresh.archive.exists()
    assert tools.uploads == tools.staples == 0


@pytest.mark.parametrize('status', ['signed by a certificate trusted by macOS',
                                    'signed by a certificate trusted by Mac OS X'])
def test_alternate_apple_trusted_signature_output_is_supported(package_release, tmp_path, status):
    _, tools, source = package_release
    tools.installer_status = status
    assert PackageNotarization(tmp_path / 'fresh', tools).prepare(source, TEAM)['status'] == 'PREPARED'


def test_changed_submitted_package_is_refused_before_apple(package_release):
    task, tools, _ = package_release
    task.archive.write_bytes(b'xar!changed submitted content')
    with pytest.raises(ReleaseError, match='submitted_archive_changed'):
        task.submit(PROFILE)
    assert tools.uploads == 0


def test_pending_package_is_checked_without_duplicate_submission(package_release):
    task, tools, _ = package_release
    assert task.submit(PROFILE)['status'] == 'SUBMITTED'
    resumed = PackageNotarization(task.root, tools)
    assert resumed.submit(PROFILE)['apple_status'] == 'In Progress'
    assert resumed.finalize(PROFILE)['apple_status'] == 'In Progress'
    assert tools.uploads == 1 and tools.staples == 0 and not task.output.exists()


def test_package_upload_timeout_requires_adoption_and_never_reuploads(package_release):
    task, tools, _ = package_release
    tools.upload_timeout = True
    with pytest.raises(ReleaseError, match='submission_outcome_uncertain'):
        task.submit(PROFILE)
    with pytest.raises(ReleaseError, match='submission_outcome_uncertain'):
        PackageNotarization(task.root, tools).submit(PROFILE)
    tools.apple_status = 'Accepted'
    assert task.check(PROFILE, adopt=JOB)['status'] == 'ACCEPTED'
    assert task.finalize(PROFILE)['status'] == 'READY_FOR_RELEASE_REVIEW'
    assert tools.uploads == 1


@pytest.mark.parametrize('field,value', [('sha256', '0' * 64), ('archiveFilename', 'submission.zip'),
                                        ('jobId', '22222222-2222-4222-8222-222222222222')])
def test_package_accepted_log_must_bind_exact_archive_before_stapling(package_release, field, value):
    task, tools = accepted(package_release)
    tools.log_override[field] = value
    with pytest.raises(ReleaseError, match='apple_log_does_not_match_archive'):
        task.finalize(PROFILE)
    assert tools.staples == 0 and not task.output.exists()


def test_package_receipt_recovers_interruption_without_duplicate_upload(package_release, monkeypatch):
    task, tools, _ = package_release
    save = task.save

    def interrupted(state):
        if state['phase'] == 'SUBMITTED':
            raise OSError('fictional state interruption')
        save(state)

    monkeypatch.setattr(task, 'save', interrupted)
    with pytest.raises(OSError):
        task.submit(PROFILE)
    resumed = PackageNotarization(task.root, tools)
    assert resumed.submit(PROFILE)['submission_id'] == JOB
    assert tools.uploads == 1


@pytest.mark.parametrize('damage', ['symlink', 'hardlink', 'changed-sha', 'invalid-id'])
def test_package_untrusted_receipt_cannot_adopt_or_start_another_upload(package_release, tmp_path, damage):
    task, tools, _ = package_release
    tools.upload_timeout = True
    with pytest.raises(ReleaseError):
        task.submit(PROFILE)
    receipt = task.root / 'upload-receipt.json'
    document = {'archive_sha256': task.load()['archive_sha256'], 'submission_id': JOB}
    if damage == 'changed-sha':
        document['archive_sha256'] = '0' * 64
    elif damage == 'invalid-id':
        document['submission_id'] = 'not a job'
    elsewhere = tmp_path / 'unrelated-private-receipt'
    elsewhere.write_text(json.dumps(document))
    elsewhere.chmod(0o600)
    if damage == 'symlink':
        receipt.symlink_to(elsewhere)
    elif damage == 'hardlink':
        os.link(elsewhere, receipt)
    else:
        receipt.write_text(json.dumps(document))
        receipt.chmod(0o600)
    with pytest.raises(ReleaseError):
        PackageNotarization(task.root, tools).submit(PROFILE)
    assert tools.uploads == 1
    assert elsewhere.read_text() == json.dumps(document)


def test_stapling_and_install_policy_only_check_separate_copy_and_resume(package_release):
    task, tools, source = package_release
    original = source.read_bytes()
    task, tools = accepted(package_release)
    tools.staple_error_after_ticket = True
    with pytest.raises(ReleaseError, match='ticket_check_failed'):
        task.finalize(PROFILE)
    resumed = PackageNotarization(task.root, tools)
    result = resumed.finalize(PROFILE)
    assert result['status'] == 'READY_FOR_RELEASE_REVIEW'
    assert source.read_bytes() == task.archive.read_bytes() == original
    assert task.output.read_bytes() == original + TICKET
    assert result['sha256'] == sha256(task.output) != result['archive_sha256']
    assert tools.uploads == tools.staples == 1
    assert ['spctl', '--assess', '--type', 'install', '--ignore-cache', '--no-cache',
            str(task.root / 'release.tmp.pkg')] in tools.calls
    assert resumed.finalize(PROFILE)['sha256'] == result['sha256']
    assert ['spctl', '--assess', '--type', 'install', '--ignore-cache', '--no-cache', str(task.output)] in tools.calls
    assert tools.uploads == tools.staples == 1
    assert not any(call[0] in {'installer', 'security', 'xattr', 'syspolicy_check'} for call in tools.calls)


@pytest.mark.parametrize('damage', ['changed-content', 'oversized-ticket', 'policy', 'temporary-symlink',
                                    'temporary-content', 'final-symlink'])
def test_changed_or_unassessed_package_never_becomes_release(package_release, tmp_path, damage):
    task, tools = accepted(package_release)
    outside = tmp_path / 'unrelated.pkg'
    outside.write_bytes(b'xar!unrelated')
    if damage == 'changed-content':
        tools.mutate_on_staple = True
    elif damage == 'oversized-ticket':
        tools.overlarge_ticket = True
    elif damage == 'policy':
        tools.policy_fails = True
    elif damage == 'temporary-symlink':
        (task.root / 'release.tmp.pkg').symlink_to(outside)
    elif damage == 'temporary-content':
        temporary = task.root / 'release.tmp.pkg'
        temporary.write_bytes(b'xar!changed temporary')
        temporary.chmod(0o600)
    else:
        task.output.symlink_to(outside)
    with pytest.raises(ReleaseError):
        task.finalize(PROFILE)
    assert task.load()['phase'] != 'READY_FOR_RELEASE_REVIEW'
    assert not task.output.exists() or task.output.is_symlink()
    assert outside.read_bytes() == b'xar!unrelated'
    if damage in {'temporary-symlink', 'temporary-content', 'final-symlink'}:
        assert tools.staples == 0


def test_changed_final_package_cannot_reuse_a_ready_receipt(package_release):
    task, tools = accepted(package_release)
    task.finalize(PROFILE)
    task.output.write_bytes(b'xar!different output' + TICKET)
    with pytest.raises(ReleaseError, match='release_archive_already_exists'):
        task.finalize(PROFILE)
    assert tools.uploads == 1


def test_package_cli_detects_private_mode_and_status_never_uses_credentials(package_release, monkeypatch, capsys):
    import macos.notarize as module
    task, tools, _ = package_release
    monkeypatch.setattr(module, 'PackageNotarization', lambda root: task)
    # Keep factory mode detection while preserving this fixture's fake tools.
    module.PackageNotarization.kind = task.kind
    monkeypatch.setattr(sys, 'platform', 'darwin')
    monkeypatch.setattr(sys, 'argv', ['notarize.py', 'status', '--workdir', str(task.root)])
    before = len(tools.calls)
    assert module.main() == 0
    result = json.loads(capsys.readouterr().out)
    assert result['status'] == 'CACHED_STATE' and result['package']['team'] == TEAM
    assert len(tools.calls) == before


def test_package_finalization_recovers_saved_hash_before_rename(package_release, monkeypatch):
    task, tools = accepted(package_release)
    save = task.save

    def interrupted(state):
        save(state)
        if state['phase'] == 'PACKAGED':
            raise OSError('fictional interruption before publication')

    monkeypatch.setattr(task, 'save', interrupted)
    with pytest.raises(OSError):
        task.finalize(PROFILE)
    state = task.load()
    assert state['phase'] == 'PACKAGED' and not task.output.exists()
    resumed = PackageNotarization(task.root, tools)
    assert resumed.finalize(PROFILE)['sha256'] == state['output_sha256']
    assert tools.uploads == tools.staples == 1


def test_package_copy_must_match_source_even_when_a_copy_operation_changes_bytes(package_release, tmp_path, monkeypatch):
    import macos.notarize as module
    _, tools, source = package_release
    original = source.read_bytes()
    real_copy = module.shutil.copyfile

    def changed(source, target):
        real_copy(source, target)
        Path(target).write_bytes(b'xar!changed copy')

    monkeypatch.setattr(module.shutil, 'copyfile', changed)
    task = PackageNotarization(tmp_path / 'other', tools)
    with pytest.raises(ReleaseError, match='package_changed_during_copy'):
        task.prepare(source, TEAM)
    assert source.read_bytes() == original and tools.uploads == 0


@pytest.mark.parametrize('field,value', [('archive_bytes', True), ('archive_sha256', 'not a digest'),
                                        ('kind', 'app'), ('package', [])])
def test_malformed_package_state_stops_before_tools(package_release, field, value):
    task, tools, _ = package_release
    state = task.load()
    state[field] = value
    task.state_path.write_text(json.dumps(state))
    before = len(tools.calls)
    with pytest.raises(ReleaseError, match='invalid_release_state'):
        task.submit(PROFILE)
    assert len(tools.calls) == before


def test_package_install_policy_failure_is_redacted_and_cannot_be_bypassed(package_release, monkeypatch, capsys):
    import macos.notarize as module
    task, tools = accepted(package_release)
    tools.policy_fails = True
    monkeypatch.setattr(module, 'PackageNotarization', lambda root: task)
    module.PackageNotarization.kind = task.kind
    monkeypatch.setattr(sys, 'platform', 'darwin')
    monkeypatch.setattr(sys, 'argv', ['notarize.py', 'finalize', '--workdir', str(task.root), '--profile', PROFILE])
    assert module.main() == 1
    output = json.loads(capsys.readouterr().out)
    assert output == {'status': 'RETRYABLE', 'reason': 'distribution_check_failed'}
    assert 'fictional-private' not in json.dumps(output)
    assert not task.output.exists()
    assert not any(call[0] in {'installer', 'security', 'xattr'} for call in tools.calls)


def test_package_tools_use_fixed_paths_and_known_output_locale(monkeypatch):
    import macos.notarize as module
    calls = []

    def execute(argv, **kwargs):
        calls.append((argv, kwargs))
        return subprocess.CompletedProcess(argv, 0, '', '')

    monkeypatch.setattr(module.subprocess, 'run', execute)
    module.run_tool(['pkgutil', '--check-signature', 'fixture.pkg'])
    module.run_tool(['spctl', '--assess', '--type', 'install', '--ignore-cache', '--no-cache', 'fixture.pkg'])
    assert calls[0][0][0] == '/usr/sbin/pkgutil'
    assert calls[1][0][0] == '/usr/sbin/spctl'
    assert all(options['env']['LC_ALL'] == 'C' and options['env']['LANG'] == 'C'
               and options['stdin'] == subprocess.DEVNULL and not options.get('shell') for _, options in calls)


@pytest.mark.parametrize('damage', ['padding', 'truncated', 'magic', 'version', 'type', 'length', 'reserved',
                                    'terminator', 'missing-terminator'])
def test_native_ticket_acceptance_cannot_allow_unframed_or_padded_appendix(package_release, damage):
    task, tools = accepted(package_release)
    original = task.archive.read_bytes()
    suffix = TICKET
    if damage == 'padding':
        suffix = b'fictional-unrelated-padding' + suffix
    elif damage == 'truncated':
        suffix = suffix[:-1]
    elif damage == 'missing-terminator':
        suffix = suffix[16:]
    elif damage == 'terminator':
        suffix = struct.pack('<4sHHI4s', b't8lr', 1, 1, 1, b'\0' * 4) + suffix[16:]
    else:
        frame = list(struct.unpack('<4sHHI4s', suffix[-16:]))
        index, value = {'magic': (0, b'fail'), 'version': (1, 2), 'type': (2, 1),
                        'length': (3, len(TICKET_DATA) + 1), 'reserved': (4, b'x\0\0\0')}[damage]
        frame[index] = value
        suffix = suffix[:-16] + struct.pack('<4sHHI4s', *frame)
    temporary = task.root / 'release.tmp.pkg'
    temporary.write_bytes(original + suffix)
    temporary.chmod(0o600)
    with pytest.raises(ReleaseError, match='stapled_package_framing_invalid'):
        task.finalize(PROFILE)
    assert tools.staples == 0
    assert not any(call[0] == 'spctl' for call in tools.calls)
    assert not task.output.exists()
