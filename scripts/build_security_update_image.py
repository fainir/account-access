"""Prepare build 120 from the qualified public build-119 image, without installation.

Only the JOSE pure-Python wheel, project wheel, owner-bundle metadata and their
derived receipts change. Native runtime binaries retain their publisher signatures.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import plistlib
import shutil
import subprocess
import sys
import tempfile
import zipfile

from installer import install
from installer.sources import WheelFile

from account_access.package_manifest import build as manifest, inventory_digest
from account_access.system_provision import signature
from macos.payload_audit import audit_payload, wheel_entries
from macos.runtime_image import Destination
from macos.runtime_prepare import tree_digest
from scripts.build_direct_runtime_target_image import replace_project_wheel

BASE_SHA256 = '630e77605faac2dfdace9faaa5da55e671335c6b18e62114d7f0224a8574f24c'
SUPPORT = Path('Library/Application Support/Account Access')


def sha(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def require(value, reason):
    if not value:
        raise ValueError(reason)


def replace_joserfc(runtime, wheel, expected_sha256):
    require(sha(wheel) == expected_sha256, 'jose_wheel_digest_mismatch')
    require(wheel.name == 'joserfc-1.7.7-py3-none-any.whl', 'jose_wheel_identity_mismatch')
    with zipfile.ZipFile(wheel) as archive:
        entries = list(wheel_entries(archive))
        require(entries and all(item.filename.startswith(('joserfc/', 'joserfc-1.7.7.dist-info/'))
                and not item.filename.endswith(('.so', '.dylib', '.bundle', '.pyc')) for item in entries),
                'jose_wheel_contents_refused')
    site = runtime / 'lib/python3.12/site-packages'
    old = [site / 'joserfc', site / 'joserfc-1.7.5.dist-info']
    require(all(p.is_dir() and not p.is_symlink() for p in old), 'old_jose_layout_invalid')
    for directory in old:
        require(all(not p.is_symlink() for p in directory.rglob('*')), 'old_jose_link_refused')
    with tempfile.TemporaryDirectory(prefix='jose-wheel-', dir=runtime.parent) as temporary:
        staged = Path(temporary) / 'runtime'
        (staged / 'lib/python3.12/site-packages').mkdir(parents=True)
        (staged / 'bin').mkdir()
        with WheelFile.open(wheel) as source:
            source.validate_record(validate_contents=True)
            install(source, Destination(staged, 'account-access'),
                    additional_metadata={'INSTALLER': b'account-access-static-runtime-image 1\n'})
        require(not list((staged / 'bin').iterdir()), 'jose_wheel_scripts_refused')
        staged_site = staged / 'lib/python3.12/site-packages'
        require({p.name for p in staged_site.iterdir()} == {'joserfc', 'joserfc-1.7.7.dist-info'},
                'jose_staged_layout_invalid')
        for directory in old:
            shutil.rmtree(directory)
        for directory in staged_site.iterdir():
            shutil.copytree(directory, site / directory.name)


def build(args):
    require(sys.platform == 'darwin' and os.getuid() == os.geteuid() != 0, 'ordinary_mac_required')
    repository = Path(__file__).resolve().parents[1]
    require(subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=repository).decode().strip() == args.source,
            'source_revision_mismatch')
    require(not subprocess.check_output(['git', 'status', '--porcelain'], cwd=repository).strip(),
            'source_tree_not_clean')
    raw = args.base_manifest.read_bytes()
    require(hashlib.sha256(raw).hexdigest() == BASE_SHA256, 'base_manifest_mismatch')
    require(manifest(args.image, '0.8.0', 'arm64') == raw, 'base_image_mismatch')
    payload = args.image / SUPPORT
    jose_sha, project_sha = sha(args.jose_wheel), sha(args.project_wheel)
    replace_joserfc(payload / 'runtime', args.jose_wheel, args.jose_sha256)
    wheelhouse = payload / 'wheels'
    (wheelhouse / 'joserfc-1.7.5-py3-none-any.whl').unlink()
    shutil.copy2(args.jose_wheel, wheelhouse / args.jose_wheel.name)
    replace_project_wheel(payload / 'runtime', args.project_wheel, wheelhouse)

    app = payload / 'owner.app'
    shutil.copy2(args.project_wheel, app / 'Contents/Resources/account_access.whl')
    info_path = app / 'Contents/Info.plist'
    info = plistlib.loads(info_path.read_bytes())
    require(info['CFBundleVersion'] == '119', 'base_owner_build_mismatch')
    info.update(CFBundleVersion='120', AccountAccessWheelSHA256=project_sha)
    info_path.write_bytes(plistlib.dumps(info))
    def command(argv):
        result = subprocess.run(list(map(str, argv)), capture_output=True, check=True, timeout=180)
        return result
    command(['/usr/bin/codesign', '--force', '--options', 'runtime', '--timestamp',
             '--preserve-metadata=identifier,entitlements,requirements', '--sign',
             'E42D109853911EC536C2A07B769D4FC5B7B96BB9', app])
    command(['/usr/bin/codesign', '--verify', '--deep', '--strict', '--all-architectures', app])
    identity_path = payload / 'package-identity.json'
    identity = json.loads(identity_path.read_bytes())
    identity['signatures']['owner'] = signature(app, 'com.fainir.accountaccess')
    identity_path.write_text(json.dumps(identity, sort_keys=True) + '\n')

    # Derive the prepared graph from the new source lock while retaining every
    # existing native-wheel transformation. No package code is executed.
    prep_path = payload / 'runtime-preparation.json'
    prep = json.loads(prep_path.read_bytes())
    jose = [row for row in prep['wheels'] if row['filename'].startswith('joserfc-')]
    require(len(jose) == 1, 'jose_preparation_receipt_invalid')
    jose[0].update(filename=args.jose_wheel.name, original_sha256=jose_sha, prepared_sha256=jose_sha)
    prep['wheels'].sort(key=lambda row: row['filename'])
    prep['project_wheel']['sha256'] = project_sha
    raw_requirements = args.runtime_requirements.read_bytes()
    prep['original_requirements_sha256'] = hashlib.sha256(raw_requirements).hexdigest()
    requirements = []
    from packaging.utils import parse_wheel_filename
    for wheel in sorted(wheelhouse.glob('*.whl')):
        name, version, _, _ = parse_wheel_filename(wheel.name)
        requirements.append(f'{name}=={version} --hash=sha256:{sha(wheel)}')
    prepared = ('\n'.join(requirements) + '\n').encode()
    (payload / 'package-requirements.txt').write_bytes(prepared)
    prep['prepared_requirements_sha256'] = hashlib.sha256(prepared).hexdigest()
    prep_path.write_text(json.dumps(prep, sort_keys=True, indent=2) + '\n')

    image_path = payload / 'runtime-image.json'
    image = json.loads(image_path.read_bytes())
    for row in image['wheels']:
        if row['name'] == 'joserfc':
            row.update(version='1.7.7', sha256=jose_sha)
        elif row['name'] == 'account-access':
            row['sha256'] = project_sha
    image['requirements_sha256'] = hashlib.sha256(prepared).hexdigest()
    image['runtime_sha256'] = tree_digest(payload / 'runtime')
    image['runtime_manifest_sha256'] = inventory_digest(payload / 'runtime')
    image_path.write_text(json.dumps(image, sort_keys=True, indent=2) + '\n')
    result = manifest(args.image, '0.8.0', 'arm64')
    args.manifest_output.write_bytes(result)
    audit = audit_payload([app, payload / 'python', payload / 'runtime', payload / 'browsers', payload / 'bin'],
                          sorted(wheelhouse.glob('*.whl')), 'arm64', command, development=False)
    # The verifier inspection takes the manifest on stdin, never an installed root.
    inspected = subprocess.run([str(payload / 'bin/AccountAccess-installerverify'), '--inspect-manifest'],
                               input=result, capture_output=True, check=True, timeout=120)
    require(json.loads(inspected.stdout)['manifest_sha256'] == hashlib.sha256(result).hexdigest(),
            'native_manifest_inspection_failed')
    report = {'schema': 1, 'status': 'TARGET_IMAGE_QUALIFIED', 'source_image_build': 119,
              'source_manifest_sha256': BASE_SHA256, 'source_image_unchanged': True,
              'owner_app_build': 120, 'target_manifest_sha256': hashlib.sha256(result).hexdigest(),
              'project_wheel_sha256': project_sha, 'joserfc_version': '1.7.7',
              'joserfc_wheel_sha256': jose_sha, 'builder_commit': args.source,
              'target_source_commit': args.source, 'native_payload_audit': audit,
              'native_manifest_preflight': True, 'installed': False, 'installer_executed': False,
              'production_ready': False}
    args.report.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report), flush=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ['image', 'base-manifest', 'jose-wheel', 'project-wheel', 'runtime-requirements',
                 'manifest-output', 'report']:
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--jose-sha256', required=True)
    parser.add_argument('--source', required=True)
    build(parser.parse_args())
