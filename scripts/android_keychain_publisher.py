"""Create one explicitly approved first Android publisher identity using Mac Keychain."""

import argparse
import hmac
import json
import os
from pathlib import Path
import re
import secrets
import subprocess
import sys
from types import SimpleNamespace

from .android_publisher_setup import JAVA, create_identity, private_directory
from .build_android_release import ROOT, build, release_manifest, require

PREFIX = 'Account Access Android Publisher '
ACCOUNT = 'phone'


class MacKeychain:
    """Native exclusive item creation; never update/delete an existing credential."""

    def __init__(self):
        require(sys.platform == 'darwin')
        from keyring.backends.macOS import api
        self.api = api

    def add(self, service, password):
        api = self.api
        query = api.create_query(kSecClass=api.k_('kSecClassGenericPassword'),
            kSecAttrService=service, kSecAttrAccount=ACCOUNT, kSecValueData=password)
        api.Error.raise_for_status(api.SecItemAdd(query, None))

    def read(self, service):
        return self.api.find_generic_password(None, service, ACCOUNT)


def preflight(args):
    require(args.directory.is_absolute() and args.directory.resolve() == args.directory
            and not args.directory.is_relative_to(ROOT) and not os.path.lexists(args.directory)
            and args.output.is_absolute() and args.output.resolve() == args.output
            and args.output.parent.is_dir() and not os.path.lexists(args.output))
    private_directory(args.directory.parent)
    release_manifest((ROOT / 'android/app/AndroidManifest.xml').read_bytes(), args.version_code,
                     args.version_name)
    require(re.fullmatch(r'[\w .-]{1,100}', args.publisher_name)
            and (JAVA / 'bin/keytool').is_file())


def create_and_sign(args, *, keychain=None, command=None, signer=build):
    # A missing approval cannot touch Keychain, create a directory or invoke a signer.
    require(args.approve_first_identity is True and sys.stdin.isatty()
            and os.getuid() == os.geteuid() != 0)
    preflight(args)
    keychain = keychain if keychain is not None else MacKeychain()
    password = secrets.token_urlsafe(48)
    service = PREFIX + secrets.token_hex(16)
    environment = {k: v for k, v in os.environ.items()
                   if k in {'HOME', 'PATH', 'LANG', 'LC_ALL', 'TMPDIR'}}
    environment['AC_ANDROID_PUBLISHER_PASSWORD'] = password
    saved = False

    def invoke(values):
        nonlocal saved
        if not saved:
            # create_identity has already reserved the new private directory exclusively.
            with (args.directory / 'keychain-service.txt').open('x') as reference:
                reference.write(service + '\n')  # Functional reference, never a password.
            keychain.add(service, password)
            recovered = keychain.read(service)
            require(isinstance(recovered, str) and hmac.compare_digest(recovered, password))
            saved = True
        argv = [str(JAVA / 'bin/keytool'), *map(str, values),
                '-storepass:env', 'AC_ANDROID_PUBLISHER_PASSWORD']
        if command is None:
            result = subprocess.run(argv, env=environment, stdin=subprocess.DEVNULL,
                                    capture_output=True, timeout=90, check=False)
            require(result.returncode == 0)
        else:
            command(argv, environment)

    try:
        key, pin = create_identity(args.directory, args.publisher_name, ACCOUNT,
            keytool=JAVA / 'bin/keytool', owner_confirmation='CREATE AND SIGN', command=invoke)
        report = signer(SimpleNamespace(keystore=key, alias=ACCOUNT, certificate_sha256=pin,
            version_code=args.version_code, version_name=args.version_name, output=args.output,
            previous_apk=None, initial_release=True, separate_key_password=False),
            read_password=lambda _: password)
        review = args.output / 'release-review.json'
        require(review.is_file() and not review.is_symlink()
                and json.loads(review.read_text()) == report)
        report.update(signing_key_created=True, password_custody='native-macos-keychain')
        review.write_text(json.dumps(report, indent=2) + '\n')
        return {k: report[k] for k in ('status', 'version_code', 'version_name',
                                      'certificate_sha256', 'apk_sha256', 'signing_key_created',
                                      'password_custody')}
    finally:
        environment.clear()
        password = ''


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--directory', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--publisher-name', required=True)
    parser.add_argument('--version-code', type=int, required=True)
    parser.add_argument('--version-name', required=True)
    parser.add_argument('--approve-first-identity', action='store_true')
    args = parser.parse_args(argv)
    try:
        if not args.approve_first_identity:
            preflight(args)
            print('PREPARED PLAN: create one first Android publisher identity and sign one local APK candidate.')
            print('Password destination: native Mac Keychain; private key remains on this Mac.')
            print('Owner approval required. No identity, Keychain item or APK has been created.')
            return 0
        print(json.dumps(create_and_sign(args)))
        return 0
    except (Exception, KeyboardInterrupt):
        print('REFUSED: publisher setup did not finish. Existing identities were not replaced.')
        print('Keep any new identity directory and its Keychain reference for review.')
        return 78


if __name__ == '__main__':
    os.umask(0o077)
    raise SystemExit(main())
