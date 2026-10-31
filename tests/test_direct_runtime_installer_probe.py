"""Safety boundaries of the root-only disposable Installer acceptance probe."""
import io
from types import SimpleNamespace
import tarfile

import pytest

from scripts import mac_direct_runtime_installer_probe as probe


def test_browser_crash_summary_keeps_only_the_exact_fixture_child():
    import json
    body = {'pid': 123, 'procName': 'chrome-headless-shell', 'exception': {'signal': 'SIGTRAP'},
            'asi': {'chromium': ['FATAL: fixture bootstrap failure']}, 'faultingThread': 0,
            'threads': [{'frames': [{'symbol': 'FixtureCrash', 'imageOffset': 1234}]}],
            'machineIdentifier': 'never included'}
    raw = json.dumps({'header': True}) + '\n' + json.dumps(body)
    value = probe.browser_crash_summary(raw, 123)
    assert value['symbols'] == ['FixtureCrash']
    assert 'machineIdentifier' not in value and 'threads' not in value
    assert probe.browser_crash_summary(raw, 456) is None
    assert probe.browser_crash_summary('not a crash report', 123) is None


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
@pytest.mark.parametrize('release', ['120', '121'])
def test_probe_refuses_an_ordinary_owner_context_before_inputs(tmp_path, mode, release):
    args = SimpleNamespace(inputs=tmp_path / 'missing', output=tmp_path / 'output', mode=mode, release=release)
    with pytest.raises(ValueError, match='component_installer_acceptance_failed'):
        probe.run(args)
    assert not args.output.exists()


def test_worker_health_fixture_never_seeds_a_client_on_an_owner_mac():
    calls = []
    with pytest.raises(ValueError, match='component_installer_acceptance_failed'):
        probe.worker_browser_health(lambda *args: calls.append(args), 'offline')
    assert calls == []


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


def service_output(state='running', pid='123'):
    return (f'system/{probe.LABEL} = {{\n\tstate = {state}\n\tpid = {pid}\n'
            '\tendpoint = {\n\t\tstate = active\n\t}\n}\n').encode()


@pytest.mark.parametrize('state,pid', [('spawn scheduled', '123'), ('exited', '123'),
                                     ('running', '0'), ('running', '-1'), ('active', '123')])
def test_registered_crashed_or_pidless_service_cannot_pass(state, pid):
    with pytest.raises(ValueError, match='protected_service_not_running'):
        probe.running_service_pid(service_output(state, pid))


def test_nested_running_endpoint_cannot_hide_a_crashed_daemon():
    raw = b'job = {\n\tstate = exited\n\t\tstate = running\n\t\tpid = 123\n}\n'
    with pytest.raises(ValueError, match='protected_service_not_running'):
        probe.running_service_pid(raw)


def test_service_must_keep_same_running_pid_across_health_checks(monkeypatch):
    monkeypatch.setattr(probe.time, 'sleep', lambda _: None)
    responses = iter([service_output(), service_output(pid='124')])
    with pytest.raises(ValueError, match='protected_service_restarted_during_check'):
        probe.verify_live_service(lambda *_: SimpleNamespace(stdout=next(responses)), 'health')


def test_stable_running_daemon_passes_three_health_checks(monkeypatch):
    monkeypatch.setattr(probe.time, 'sleep', lambda _: None)
    calls = []

    def command(label, arguments):
        calls.append((label, arguments))
        return SimpleNamespace(stdout=service_output())

    probe.verify_live_service(command, 'health')
    assert len(calls) == 3
    assert all(arguments == ['/bin/launchctl', 'print', 'system/' + probe.LABEL]
               for _, arguments in calls)


def test_normal_launch_transition_is_bounded_and_can_become_ready(monkeypatch):
    monkeypatch.setattr(probe.time, 'sleep', lambda _: None)
    responses = iter([service_output('spawn scheduled'), service_output('xpcproxy'),
                      service_output(), service_output(), service_output()])
    probe.verify_live_service(lambda *_: SimpleNamespace(stdout=next(responses)), 'health')
    assert next(responses, None) is None


def test_permanently_crashing_loaded_job_fails_after_bounded_startup(monkeypatch):
    monkeypatch.setattr(probe.time, 'sleep', lambda _: None)
    calls = []

    def command(*_):
        calls.append(None)
        return SimpleNamespace(stdout=service_output('spawn scheduled'))

    with pytest.raises(ValueError, match='protected_service_not_running'):
        probe.verify_live_service(command, 'health')
    assert len(calls) == 30
