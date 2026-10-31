"""The publisher handoff must refuse unattended identity creation and replacement."""

import hashlib
import os
import subprocess
from types import SimpleNamespace

import pytest

from scripts import android_publisher_setup as setup


def fixture(tmp_path):
    parent = tmp_path / 'publisher'
    parent.mkdir(mode=0o700)
    tool = tmp_path / 'keytool'
    tool.write_text('fixture only')
    tool.chmod(0o700)
    return parent / 'first-release', tool


@pytest.mark.parametrize('confirmation', ['', 'yes', 'CREATE', 'CREATE AND SIGN\n'])
def test_no_identity_or_command_before_exact_owner_confirmation(tmp_path, confirmation):
    destination, tool = fixture(tmp_path)
    with pytest.raises(ValueError):
        setup.create_identity(destination, 'Publisher', 'phone', keytool=tool,
            owner_confirmation=confirmation, command=lambda _: pytest.fail('keytool ran'))
    assert not destination.exists()


@pytest.mark.parametrize('case', ['existing', 'symlink', 'public-parent', 'invalid-name'])
def test_identity_cannot_replace_or_escape_private_storage(tmp_path, case):
    destination, tool = fixture(tmp_path)
    publisher = 'Publisher'
    if case == 'existing':
        destination.mkdir()
        (destination / 'retained').write_text('existing owner data')
    elif case == 'symlink':
        destination.symlink_to(destination.parent, target_is_directory=True)
    elif case == 'public-parent':
        destination.parent.chmod(0o755)
    else:
        publisher = 'Publisher,OU=injected'
    with pytest.raises(ValueError):
        setup.create_identity(destination, publisher, 'phone', keytool=tool,
            owner_confirmation='CREATE AND SIGN', command=lambda _: pytest.fail('keytool ran'))
    if case == 'existing':
        assert (destination / 'retained').read_text() == 'existing owner data'


def test_new_key_uses_terminal_password_prompt_and_records_only_public_certificate(tmp_path):
    destination, tool = fixture(tmp_path)
    public = b'isolated public certificate fixture'
    calls = []

    def command(args):
        calls.append(args)
        if args[0] == '-genkeypair':
            key = destination / 'phone.p12'
            key.write_bytes(b'isolated fixture, not a usable private key')
            key.chmod(0o600)
        else:
            (destination / 'phone-certificate.der').write_bytes(public)

    key, pin = setup.create_identity(destination, 'Publisher', 'phone', keytool=tool,
                                    owner_confirmation='CREATE AND SIGN', command=command)
    assert key == destination / 'phone.p12'
    assert pin == hashlib.sha256(public).hexdigest()
    assert (destination / 'certificate-sha256.txt').read_text() == pin + '\n'
    assert '-storepass' not in str(calls) and '-keypass' not in str(calls)
    with pytest.raises(ValueError):
        setup.create_identity(destination, 'Publisher', 'phone', keytool=tool,
            owner_confirmation='CREATE AND SIGN', command=lambda _: pytest.fail('replacement ran'))


def test_partial_keytool_failure_preserves_new_identity_without_falling_back(tmp_path):
    destination, tool = fixture(tmp_path)

    def failure(args):
        (destination / 'phone.p12').write_bytes(b'partially created owner file')
        raise ValueError('fixture failure')

    with pytest.raises(ValueError):
        setup.create_identity(destination, 'Publisher', 'phone', keytool=tool,
                              owner_confirmation='CREATE AND SIGN', command=failure)
    assert (destination / 'phone.p12').read_bytes() == b'partially created owner file'


def test_noninteractive_setup_cannot_create_directories_or_ask_for_passwords(tmp_path, monkeypatch):
    destination, tool = fixture(tmp_path)
    monkeypatch.setattr(setup.sys, 'stdin', SimpleNamespace(isatty=lambda: False))
    monkeypatch.setattr('builtins.input', lambda _: pytest.fail('unattended prompt'))
    assert setup.main(['--publisher-name', 'Publisher', '--publisher-directory', str(destination),
                       '--output', str(tmp_path / 'output'), '--version-code', '2',
                       '--version-name', '0.8.0']) == 78
    assert not destination.exists()


def test_invalid_release_is_refused_before_any_identity_prompt(tmp_path, monkeypatch):
    destination, tool = fixture(tmp_path)
    terminal = SimpleNamespace(isatty=lambda: True, write=lambda _: None, flush=lambda: None)
    monkeypatch.setattr(setup.sys, 'stdin', terminal)
    monkeypatch.setattr(setup.sys, 'stdout', terminal)
    monkeypatch.setattr('builtins.input', lambda _: pytest.fail('invalid release asked owner'))
    assert setup.main(['--publisher-name', 'Publisher', '--publisher-directory', str(destination),
                       '--output', str(tmp_path / 'output'), '--version-code', '1',
                       '--version-name', '0.8.0-preview']) == 78
    assert not destination.exists()


def test_existing_identity_requires_private_key_and_independent_pin(tmp_path):
    destination, tool = fixture(tmp_path)
    key = destination.parent / 'existing.p12'
    key.write_bytes(b'owner fixture')
    key.chmod(0o600)
    assert setup.existing_identity(key, 'phone', 'a' * 64) == (key, 'a' * 64)
    for pin in ['bad', 'a' * 64 + '\n']:
        with pytest.raises(ValueError):
            setup.existing_identity(key, 'phone', pin)
    key.chmod(0o644)
    with pytest.raises(ValueError):
        setup.existing_identity(key, 'phone', 'a' * 64)


@pytest.mark.skipif(not (setup.JAVA / 'bin/keytool').is_file(), reason='local JDK fixture')
def test_real_keytool_fixture_exports_the_same_public_certificate(tmp_path):
    destination, _ = fixture(tmp_path)
    tool = setup.JAVA / 'bin/keytool'
    environment = {'PATH': '/usr/bin:/bin', 'AC_ISOLATED_KEY_PASSWORD': 'disposable-fixture-password'}

    def command(args):
        subprocess.run([str(tool), *map(str, args), '-storepass:env', 'AC_ISOLATED_KEY_PASSWORD'],
                       env=environment, input=b'', capture_output=True, check=True, timeout=60)

    before = os.umask(0o077)
    try:
        key, pin = setup.create_identity(destination, 'Isolated signing fixture', 'fixture',
            keytool=tool, owner_confirmation='CREATE AND SIGN', command=command)
    finally:
        os.umask(before)
    exported = subprocess.check_output([str(tool), '-exportcert', '-keystore', str(key),
        '-alias', 'fixture', '-storepass:env', 'AC_ISOLATED_KEY_PASSWORD'], env=environment,
        stdin=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30)
    assert hashlib.sha256(exported).hexdigest() == pin
    assert key.stat().st_mode & 0o777 == 0o600
    assert b'disposable-fixture-password' not in (destination / 'certificate-sha256.txt').read_bytes()
