"""Publisher creation needs explicit approval, native custody and no secret output."""

import os
import json
from types import SimpleNamespace

import pytest

from scripts import android_keychain_publisher as managed


def request(tmp_path, *, approved=True):
    parent = tmp_path / 'publisher'
    parent.mkdir(mode=0o700)
    return SimpleNamespace(directory=parent / 'first', output=tmp_path / 'candidate',
        publisher_name='Isolated publisher fixture', version_code=2, version_name='0.8.0',
        approve_first_identity=approved)


def setup_fixtures(tmp_path, monkeypatch):
    java = tmp_path / 'java'
    (java / 'bin').mkdir(parents=True)
    tool = java / 'bin/keytool'
    tool.write_text('fixture only')
    tool.chmod(0o700)
    monkeypatch.setattr(managed, 'JAVA', java)
    monkeypatch.setattr(managed.sys, 'stdin', SimpleNamespace(isatty=lambda: True))


class MemoryKeychain:
    def __init__(self):
        self.items = {}

    def add(self, service, password):
        assert service not in self.items
        self.items[service] = password

    def read(self, service):
        return self.items[service]


@pytest.mark.parametrize('approved,tty', [(False, True), (True, False)])
def test_no_identity_or_keychain_access_without_explicit_approval_and_tty(tmp_path, monkeypatch,
                                                                       approved, tty):
    args = request(tmp_path, approved=approved)
    setup_fixtures(tmp_path, monkeypatch)
    monkeypatch.setattr(managed.sys, 'stdin', SimpleNamespace(isatty=lambda: tty))
    monkeypatch.setattr(managed, 'MacKeychain', lambda: pytest.fail('credential access before approval'))
    with pytest.raises(ValueError):
        managed.create_and_sign(args)
    assert not args.directory.exists() and not args.output.exists()


@pytest.mark.parametrize('which', ['identity', 'output'])
def test_existing_identity_or_output_is_preserved_before_keychain_access(tmp_path, monkeypatch, which):
    args = request(tmp_path)
    setup_fixtures(tmp_path, monkeypatch)
    target = args.directory if which == 'identity' else args.output
    target.mkdir()
    (target / 'keep').write_text('owner data')
    monkeypatch.setattr(managed, 'MacKeychain', lambda: pytest.fail('credential access before refusal'))
    with pytest.raises(ValueError):
        managed.create_and_sign(args)
    assert (target / 'keep').read_text() == 'owner data'


def test_generated_password_stays_in_child_memory_and_keychain_not_args_or_files(tmp_path, monkeypatch,
                                                                             capsys):
    args = request(tmp_path)
    setup_fixtures(tmp_path, monkeypatch)
    keychain = MemoryKeychain()
    secret = 'isolated-fixture-password-never-output'
    monkeypatch.setattr(managed.secrets, 'token_urlsafe', lambda _: secret)
    commands, environments = [], []

    def command(argv, environment):
        assert secret not in str(argv)
        assert environment['AC_ANDROID_PUBLISHER_PASSWORD'] == secret
        commands.append(argv)
        environments.append(environment)
        if '-genkeypair' in argv:
            key = args.directory / 'phone.p12'
            key.write_bytes(b'isolated fixture, not a real key')
            key.chmod(0o600)
        else:
            (args.directory / 'phone-certificate.der').write_bytes(b'public fixture certificate')

    def signer(options, read_password):
        assert read_password('local only') == secret
        assert options.keystore == args.directory / 'phone.p12'
        report = dict(status='SIGNED_CANDIDATE', version_code=2, version_name='0.8.0',
                      certificate_sha256='a' * 64, apk_sha256='b' * 64, signing_key_created=False)
        options.output.mkdir(mode=0o700)
        (options.output / 'release-review.json').write_text(json.dumps(report))
        return report

    result = managed.create_and_sign(args, keychain=keychain, command=command, signer=signer)
    assert len(commands) == 2 and len(keychain.items) == 1
    assert result['status'] == 'SIGNED_CANDIDATE' and secret not in str(result)
    assert result['signing_key_created'] is True
    assert json.loads((args.output / 'release-review.json').read_text())['password_custody'] == 'native-macos-keychain'
    assert all(not environment for environment in environments)  # Secret child env cleared.
    assert all(secret.encode() not in p.read_bytes() for p in args.directory.iterdir())
    assert secret not in capsys.readouterr().out


def test_failed_keychain_storage_never_generates_a_key_or_falls_back(tmp_path, monkeypatch):
    args = request(tmp_path)
    setup_fixtures(tmp_path, monkeypatch)
    keychain = MemoryKeychain()
    keychain.add = lambda *_: (_ for _ in ()).throw(RuntimeError('fixture denied'))
    with pytest.raises(RuntimeError):
        managed.create_and_sign(args, keychain=keychain,
            command=lambda *_: pytest.fail('keytool after failed custody'))
    assert not (args.directory / 'phone.p12').exists()
    assert (args.directory / 'keychain-service.txt').is_file()  # Retained for safe diagnosis.


def test_keychain_readback_must_match_before_key_generation(tmp_path, monkeypatch):
    args = request(tmp_path)
    setup_fixtures(tmp_path, monkeypatch)
    keychain = MemoryKeychain()
    keychain.read = lambda _: 'unexpected-value'
    with pytest.raises(ValueError):
        managed.create_and_sign(args, keychain=keychain,
            command=lambda *_: pytest.fail('keytool before verified custody'))
    assert not (args.directory / 'phone.p12').exists()


def test_cli_never_prints_a_secret_from_a_child_or_keychain_exception(tmp_path, monkeypatch, capsys):
    args = request(tmp_path)
    marker = 'isolated-secret-must-not-be-printed'
    monkeypatch.setattr(managed, 'create_and_sign',
                        lambda _: (_ for _ in ()).throw(RuntimeError(marker)))
    assert managed.main(['--directory', str(args.directory), '--output', str(args.output),
        '--publisher-name', args.publisher_name, '--version-code', '2', '--version-name', '0.8.0',
        '--approve-first-identity']) == 78
    assert marker not in capsys.readouterr().out


def test_native_add_is_exclusive_and_has_no_delete_or_update_path():
    calls = []
    api = SimpleNamespace(create_query=lambda **kwargs: kwargs, k_=lambda key: key,
        SecItemAdd=lambda query, result: calls.append(query) or 0,
        Error=SimpleNamespace(raise_for_status=lambda status: None))
    keychain = object.__new__(managed.MacKeychain)
    keychain.api = api
    keychain.add('isolated-service', 'isolated-secret')
    assert calls == [dict(kSecClass='kSecClassGenericPassword', kSecAttrService='isolated-service',
                         kSecAttrAccount='phone', kSecValueData='isolated-secret')]


@pytest.mark.skipif(os.name == 'nt', reason='Mac publisher filesystem contract')
def test_preparation_does_not_create_an_identity_or_credential(tmp_path, monkeypatch, capsys):
    args = request(tmp_path, approved=False)
    setup_fixtures(tmp_path, monkeypatch)
    monkeypatch.setattr(managed, 'MacKeychain', lambda: pytest.fail('preparation accessed Keychain'))
    assert managed.main(['--directory', str(args.directory), '--output', str(args.output),
        '--publisher-name', args.publisher_name, '--version-code', '2', '--version-name', '0.8.0']) == 0
    assert 'PREPARED' in capsys.readouterr().out
    assert not args.directory.exists() and not args.output.exists()
