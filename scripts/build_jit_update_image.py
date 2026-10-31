"""Prepare the exact build-120 to build-121 publisher-signed public image.

Only private build copies are changed. No installer, account store or installed
runtime is modified. JIT is granted only to the two reviewed V8 executables;
library validation, executable page protection and debugging stay unchanged.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import plistlib
import shutil
import stat
import subprocess
import sys
import tempfile

from installer.sources import WheelFile

from account_access.package_manifest import build as manifest, inventory_digest
from account_access.system_provision import signature
from macos.payload_audit import audit_payload
from macos.runtime_prepare import repack_wheel, tree_digest, unpack_wheel
from scripts.build_direct_runtime_target_image import replace_project_wheel

BASE_SHA256 = '6ab5f90fa72dfed84c295d5df4741d3cb9aaf6a0fa89ed155b4cb76400570874'
SUPPORT = Path('Library/Application Support/Account Access')
PLAYWRIGHT = 'playwright-1.63.0-py3-none-macosx_11_0_arm64.whl'
NODE = 'playwright/driver/node'
CHROME = 'browsers/chromium_headless_shell-1243/chrome-headless-shell-mac-arm64/chrome-headless-shell'
JIT_ROLES = frozenset({'wheels/' + PLAYWRIGHT + '/' + NODE, CHROME})
JIT = {'com.apple.security.cs.allow-jit': True}
IDENTITY = 'E42D109853911EC536C2A07B769D4FC5B7B96BB9'


def require(value, reason):
    if not value:
        raise ValueError(reason)


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()


def sha(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def publisher_jit_plan(receipt):
    require(receipt['schema'] == 1 and receipt['publisher_team'] == 'WBULD6N4NQ'
            and receipt['development'] is False, 'publisher_preparation_required')
    rows = receipt['native_files']
    require(len({row['path'] for row in rows}) == len(rows), 'duplicate_native_role')
    require({row['path'] for row in rows if row['kind'] == 2 and row['path'] in JIT_ROLES} == JIT_ROLES,
            'required_jit_roles_missing')
    plan = {'schema': 1, 'python_sha256': receipt['source_trees']['python'],
            'browsers_sha256': receipt['source_trees']['browsers'], 'executables': {}}
    for row in rows:
        if row['kind'] != 2:
            continue
        value = plan['executables'].setdefault(row['original_sha256'], {'paths': [], 'entitlements': {}})
        value['paths'].append(row['path'])
        if row['path'] in JIT_ROLES:
            value['entitlements'] = dict(JIT)
    for value in plan['executables'].values():
        value['paths'].sort()
        require(not value['entitlements'] or set(value['paths']) <= JIT_ROLES,
                'jit_role_alias_refused')
    return plan


def install_driver_files(unpacked, runtime):
    # A wheel's RECORD can be group-writable upstream. The verified image
    # already has the required public modes; copying bytes retains those modes
    # instead of importing archive metadata into the prepared runtime.
    for name in (NODE, 'playwright-1.63.0.dist-info/RECORD'):
        shutil.copyfile(unpacked / name, runtime / 'lib/python3.12/site-packages' / name)


def build(args):
    require(sys.platform == 'darwin' and os.getuid() == os.geteuid() != 0, 'ordinary_mac_required')
    repository = Path(__file__).resolve().parents[1]
    image_root = args.image.absolute()
    require(image_root.resolve(strict=True) == image_root
            and image_root.is_relative_to(repository / 'dist')
            and image_root.stat().st_uid == os.getuid()
            and image_root.parent.stat().st_uid == os.getuid()
            and stat.S_IMODE(image_root.parent.stat().st_mode) == 0o700,
            'private_repository_build_copy_required')
    args.image = image_root
    builder_commit = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=repository).decode().strip()
    require(subprocess.run(['git', 'diff', '--quiet', args.source, builder_commit, '--', 'account_access', 'macos'],
                           cwd=repository).returncode == 0, 'target_program_source_changed')
    require(not subprocess.check_output(['git', 'status', '--porcelain'], cwd=repository).strip(),
            'source_tree_not_clean')
    require(args.owner_source == args.source, 'owner_binary_source_mismatch')
    require(hashlib.sha256(manifest(args.image, '0.8.0', 'arm64')).hexdigest() == BASE_SHA256,
            'exact_build120_image_required')
    payload = args.image / SUPPORT
    prep_path = payload / 'runtime-preparation.json'
    prep = json.loads(prep_path.read_bytes())
    plan = publisher_jit_plan(prep)
    native = {row['path']: row for row in prep['native_files']}
    wheel = payload / 'wheels' / PLAYWRIGHT
    wheel_row = next(row for row in prep['wheels'] if row['filename'] == PLAYWRIGHT)
    require(sha(wheel) == wheel_row['prepared_sha256'], 'prepared_driver_wheel_changed')
    old_wheel_sha = sha(wheel)
    commands = []

    def command(argv, timeout=180, **kwargs):
        r = subprocess.run(list(map(str, argv)), capture_output=True, timeout=timeout, **kwargs)
        require(r.returncode == 0, 'image_command_failed:' + Path(str(argv[0])).name)
        commands.append(Path(str(argv[0])).name)
        return r

    with tempfile.TemporaryDirectory(prefix='jit-image-', dir=args.image.parent) as temporary:
        scratch = Path(temporary)
        entitlements = scratch / 'jit.plist'
        entitlements.write_bytes(plistlib.dumps(JIT))

        def sign_jit(binary):
            command(['/usr/bin/codesign', '--force', '--options', 'runtime', '--timestamp',
                     '--preserve-metadata=identifier,requirements', '--entitlements', entitlements,
                     '--sign', IDENTITY, binary])
            command(['/usr/bin/codesign', '--verify', '--strict', '--all-architectures', binary])
            result = command(['/usr/bin/codesign', '-d', '--entitlements', ':-', binary])
            require(plistlib.loads(result.stdout) == JIT, 'unexpected_signed_entitlements')

        unpacked = scratch / 'wheel'
        unpacked.mkdir()
        entries = unpack_wheel(wheel, unpacked)
        node = unpacked / NODE
        installed_node = payload / 'runtime/lib/python3.12/site-packages' / NODE
        require(sha(node) == sha(installed_node) == native['wheels/' + PLAYWRIGHT + '/' + NODE]['prepared_sha256'],
                'driver_wheel_runtime_disagree')
        sign_jit(node)
        repack_wheel(wheel, unpacked, entries)
        with WheelFile.open(wheel) as source:
            source.validate_record(validate_contents=True)
        install_driver_files(unpacked, payload / 'runtime')
        native['wheels/' + PLAYWRIGHT + '/' + NODE]['prepared_sha256'] = sha(node)
        chrome = payload / CHROME
        require(sha(chrome) == native[CHROME]['prepared_sha256'], 'browser_preparation_changed')
        sign_jit(chrome)
        native[CHROME]['prepared_sha256'] = sha(chrome)

    wheel_row['prepared_sha256'] = sha(wheel)
    requirements = payload / 'package-requirements.txt'
    raw = requirements.read_bytes()
    require(raw.count(old_wheel_sha.encode()) == 1, 'prepared_driver_pin_ambiguous')
    requirements.write_bytes(raw.replace(old_wheel_sha.encode(), sha(wheel).encode()))
    replace_project_wheel(payload / 'runtime', args.project_wheel, payload / 'wheels')
    project_sha = sha(args.project_wheel)
    old_project_sha = prep['project_wheel']['sha256']
    raw = requirements.read_bytes()
    require(raw.count(old_project_sha.encode()) == 1, 'project_pin_ambiguous')
    requirements.write_bytes(raw.replace(old_project_sha.encode(), project_sha.encode()))
    prep['project_wheel']['sha256'] = project_sha
    prep['prepared_requirements_sha256'] = sha(requirements)
    prep['prepared_trees'] = {name: tree_digest(payload / name) for name in ('python', 'browsers')}
    prep['signing_plan_sha256'] = hashlib.sha256(encoded(plan)).hexdigest()
    prep_path.write_text(json.dumps(prep, sort_keys=True, indent=2) + '\n')

    app = payload / 'owner.app'
    require(plistlib.loads((args.owner_app / 'Contents/Info.plist').read_bytes())['CFBundleVersion'] == '121',
            'owner_build121_required')
    shutil.rmtree(app)  # Only this verified, invocation-owned public build copy.
    shutil.copytree(args.owner_app, app, symlinks=True)
    info = plistlib.loads((app / 'Contents/Info.plist').read_bytes())
    require(info['AccountAccessWheelSHA256'] == project_sha
            and info.get('AccountAccessSystemInstallationRequired') is True, 'owner_wheel_binding_mismatch')
    command(['/usr/bin/codesign', '--force', '--options', 'runtime', '--timestamp', '--identifier',
             'com.fainir.accountaccess.background', '--sign', IDENTITY, app / 'Contents/MacOS/AccountAccessBackground'])
    command(['/usr/bin/codesign', '--force', '--options', 'runtime', '--timestamp', '--sign', IDENTITY, app])
    command(['/usr/bin/codesign', '--verify', '--deep', '--strict', '--all-architectures', app])
    identity_path = payload / 'package-identity.json'
    identity = json.loads(identity_path.read_bytes())
    identity['signatures']['owner'] = signature(app, 'com.fainir.accountaccess')
    identity_path.write_text(json.dumps(identity, sort_keys=True) + '\n')
    image_path = payload / 'runtime-image.json'
    image = json.loads(image_path.read_bytes())
    for row in image['wheels']:
        if row['name'] == 'playwright':
            row['sha256'] = sha(wheel)
        elif row['name'] == 'account-access':
            row['sha256'] = project_sha
    image['requirements_sha256'] = sha(requirements)
    image['runtime_sha256'] = tree_digest(payload / 'runtime')
    image['runtime_manifest_sha256'] = inventory_digest(payload / 'runtime')
    image_path.write_text(json.dumps(image, sort_keys=True, indent=2) + '\n')
    raw_manifest = manifest(args.image, '0.8.0', 'arm64')
    args.manifest_output.write_bytes(raw_manifest)
    audit = audit_payload([app, payload / 'python', payload / 'runtime', payload / 'browsers', payload / 'bin'],
                          sorted((payload / 'wheels').glob('*.whl')), 'arm64', command, development=False)
    probe = '''from playwright.sync_api import sync_playwright
with sync_playwright() as pw:
    b = pw.chromium.launch(headless=True, chromium_sandbox=True)
    c = b.new_context(offline=True)
    p = c.new_page()
    p.set_content('<title>Account Access runtime check</title><script>window.runtimeAnswer=6*7</script>')
    assert p.title() == 'Account Access runtime check' and p.evaluate('window.runtimeAnswer') == 42
    b.close()
print('PUBLISHER_SANDBOXED_BROWSER_READY')
'''
    with tempfile.TemporaryDirectory(prefix='jit-probe-') as home:
        result = command([payload / 'runtime/bin/python', '-I', '-B', '-c', probe],
                         env={'PATH': '/usr/bin:/bin:/usr/sbin:/sbin', 'HOME': home,
                              'LANG': 'en_US.UTF-8', 'PLAYWRIGHT_BROWSERS_PATH': str((payload / 'browsers').resolve())})
    require(result.stdout.strip() == b'PUBLISHER_SANDBOXED_BROWSER_READY', 'signed_browser_probe_failed')
    report = {'status': 'TARGET_IMAGE_QUALIFIED', 'owner_app_build': 121, 'source_image_build': 120,
              'base_manifest_sha256': BASE_SHA256, 'manifest_sha256': hashlib.sha256(raw_manifest).hexdigest(),
              'builder_commit': builder_commit, 'target_source_commit': args.source,
              'jit_roles': sorted(JIT_ROLES), 'entitlements': JIT,
              'publisher_sandboxed_browser_execution': True, 'native_audit': audit,
              'project_wheel_sha256': project_sha, 'installed_paths_changed': False, 'account_data_used': False}
    args.report.write_text(json.dumps(report, sort_keys=True, indent=2) + '\n')
    print(json.dumps({key: report[key] for key in ['status', 'manifest_sha256', 'publisher_sandboxed_browser_execution']}))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image', type=Path, required=True)
    parser.add_argument('--source', required=True)
    parser.add_argument('--owner-source', required=True)
    parser.add_argument('--owner-app', type=Path, required=True)
    parser.add_argument('--project-wheel', type=Path, required=True)
    parser.add_argument('--manifest-output', type=Path, required=True)
    parser.add_argument('--report', type=Path, required=True)
    build(parser.parse_args())
