"""Owner-present Android publishing setup. Keys and passwords stay on this Mac."""

import argparse
import hashlib
import os
from pathlib import Path
import re
import subprocess
import sys
from types import SimpleNamespace

from .build_android_release import ROOT, build, private_keystore, release_manifest, require

JAVA = Path('/opt/homebrew/opt/openjdk@17/libexec/openjdk.jdk/Contents/Home')


def private_directory(directory):
    require(directory.is_absolute() and directory.resolve() == directory
            and not directory.is_relative_to(ROOT))
    info = directory.stat()
    require(directory.is_dir() and info.st_uid == os.getuid() and not info.st_mode & 0o077)


def create_identity(directory, publisher, alias, *, keytool, owner_confirmation, command=None):
    """Never overwrite/reuse a key. keytool itself owns the hidden password prompt."""
    require(owner_confirmation == 'CREATE AND SIGN'
            and re.fullmatch(r'[\w .-]{1,100}', publisher)
            and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,79}', alias))
    require(directory.is_absolute() and directory.resolve() == directory
            and not directory.is_relative_to(ROOT) and not os.path.lexists(directory))
    private_directory(directory.parent)
    require(keytool.is_absolute() and keytool.is_file() and os.access(keytool, os.X_OK))
    directory.mkdir(mode=0o700)  # Exclusive: partial/previous attempts need owner review.
    key, public = directory / 'phone.p12', directory / 'phone-certificate.der'
    environment = {k: v for k, v in os.environ.items() if k in {'HOME', 'PATH', 'LANG', 'LC_ALL', 'TERM'}}

    def invoke(values):
        if command is not None:
            return command(values)
        result = subprocess.run([str(keytool), *map(str, values)], env=environment,
                                stdin=sys.stdin, stdout=sys.stdout, stderr=sys.stderr,
                                timeout=900, check=False)
        require(result.returncode == 0)

    # No password argument, environment variable, pipe, transcript or log file.
    invoke(['-genkeypair', '-keystore', key, '-storetype', 'PKCS12', '-alias', alias,
            '-keyalg', 'RSA', '-keysize', '3072', '-validity', '10000', '-dname', 'CN=' + publisher])
    private_keystore(key)
    invoke(['-exportcert', '-keystore', key, '-alias', alias, '-file', public])
    require(public.is_file() and not public.is_symlink() and 1 <= public.stat().st_size <= 65536)
    pin = hashlib.sha256(public.read_bytes()).hexdigest()
    # Public certificate is independently recorded before the APK signing step.
    with (directory / 'certificate-sha256.txt').open('x') as output:
        output.write(pin + '\n')
    return key, pin


def existing_identity(key, alias, pin):
    require(re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,79}', alias)
            and re.fullmatch(r'[a-f0-9]{64}', pin))
    private_keystore(key)
    return key, pin


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--publisher-name', required=True)
    parser.add_argument('--publisher-directory', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--version-code', type=int, required=True)
    parser.add_argument('--version-name', required=True)
    args = parser.parse_args(argv)
    try:
        require(sys.stdin.isatty() and sys.stdout.isatty() and os.getuid() == os.geteuid() != 0)
        require(args.output.is_absolute() and args.output.parent.is_dir()
                and args.output.resolve() == args.output and not os.path.lexists(args.output))
        release_manifest((ROOT / 'android/app/AndroidManifest.xml').read_bytes(),
                         args.version_code, args.version_name)
        print('Account Access Phone - publisher signing setup\n')
        print('One local APK candidate. No upload, installation, purchase or account creation.')
        print('Keep signing passwords in this Terminal, never in chat.')
        print('1 - Use an existing Account Access Phone publisher key')
        print('2 - First Android release: create a new publisher key and sign this candidate')
        print('Q - Cancel')
        choice = input('Choose 1, 2 or Q: ').strip().lower()
        if choice == 'q':
            return 0
        require(choice in {'1', '2'})
        alias = input('Key alias [phone]: ').strip() or 'phone'
        separate = False
        previous = None
        if choice == '2':
            print('Only continue if this app has never had a production Android signing key.')
            print('New private key directory: ' + str(args.publisher_directory))
            confirmation = input('Create this first identity and sign one APK? Type CREATE AND SIGN: ')
            require(confirmation == 'CREATE AND SIGN')
            parent = args.publisher_directory.parent
            if not parent.exists():
                require(parent.parent.is_dir() and parent.resolve() == parent)
                parent.mkdir(mode=0o700)
            key, pin = create_identity(args.publisher_directory, args.publisher_name, alias,
                                      keytool=JAVA / 'bin/keytool', owner_confirmation=confirmation)
            print('Public certificate fingerprint saved beside your keystore. Keep both for updates.')
        else:
            key = Path(input('Existing publisher keystore path: ').strip()).expanduser().absolute()
            pin = input('Independently recorded certificate SHA-256: ').strip().lower()
            key, pin = existing_identity(key, alias, pin)
            prior = input('Previous publisher-signed APK path (blank only for a first release): ').strip()
            previous = Path(prior).expanduser().absolute() if prior else None
            separate = input('Separate key password? [y/N]: ').strip().lower() == 'y'
            require(input('Sign one local APK with this identity? Type SIGN: ') == 'SIGN')
        report = build(SimpleNamespace(keystore=key, alias=alias, certificate_sha256=pin,
            version_code=args.version_code, version_name=args.version_name, output=args.output,
            previous_apk=previous, initial_release=previous is None, separate_key_password=separate))
        print('\nSIGNED CANDIDATE: ' + str(args.output / 'Account-Access-Phone.apk'))
        print('Certificate SHA-256: ' + report['certificate_sha256'])
        print('Physical pairing and SMS acceptance are still required. Nothing was installed or uploaded.')
        return 0
    except (Exception, KeyboardInterrupt):
        print('\nSetup stopped. No installation or upload was performed. Existing keys are unchanged.')
        print('A newly created key or partial build is kept for review; do not replace it by retrying creation.')
        return 78


if __name__ == '__main__':
    os.umask(0o077)
    raise SystemExit(main())
