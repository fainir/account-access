"""Prepare a matching owner/broker successor from one exact public predecessor.

No installed paths or account data are accessed. Existing JIT/native dependency
bytes stay fixed. Builds 129 and 130 both replace the exact reviewed pure-Python
OpenTelemetry wheel from build 128. Build 130 also carries the broker startup
fix. Publisher signing and payload/browser verification occur here.
"""

import argparse
from copy import deepcopy
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
import zipfile

from account_access.package_manifest import build as manifest, inventory_digest
from account_access.system_provision import signature
from macos.payload_audit import audit_payload
from macos.runtime_image import select, verify_origins
from macos.runtime_prepare import tree_digest
from scripts.build_direct_runtime_target_image import replace_project_wheel
from scripts.build_jit_update_image import CHROME, IDENTITY, JIT_ROLES, NODE, PLAYWRIGHT, SUPPORT, require, sha
from scripts.build_security_update_image import replace_pure_python_dependency

BASE_SHA256 = '0eb9a5bfab615f23f9d3d6e98f7895f7bf46e6196ef8a1e5e07115906f4d443c'
RELEASES = {'122': (121, 122, BASE_SHA256),
            '123': (122, 123, 'b6537a7617db5a53540adca82023fdbf50ef45e9ca9e9dd1ae46dd682639832d'),
            '124': (123, 124, '5f3390496afaa436c64e3629cc125cbb4017e9deec8f70e4f5eb06c16e790930'),
            '125': (124, 125, '37cadaf59502657983f6cdb4a3bec0a755eb5e0dd041b625151ee51608ab2d8f'),
            '126': (125, 126, '8abffd8078832752aa13c59e58834b0a9b669656758dab47d4418ae663c41bcd'),
            '127': (126, 127, '0e1c1f3a2b05f3eb5f9acd32b7a55bea28d775411519d41be0401b43d852d20f'),
            '128': (127, 128, '82b953e0698ee73468c2cff8aa546c5b94368fbf1fe24036e2623d039fee2f06'),
            '129': (128, 129, '7b1eccdab5c75cf80963ee005ecb5dca66e64041acc9f50aa65aa3dc2b8131ba'),
            '130': (128, 130, '7b1eccdab5c75cf80963ee005ecb5dca66e64041acc9f50aa65aa3dc2b8131ba')}
OPENTELEMETRY_RELEASES = {'129', '130'}

OTEL_BEFORE = '1.45.1'
OTEL_AFTER = '1.45.2'
OTEL_PREDECESSOR = 'b31553efa588ae44bc306f863c785c5333a9ecc091248c6ee68b4b6c87fdedfb'
OTEL_PATCHED = '2cbd737377e710ee740d261c94e93fa0f08e6d037c18f17513cc0a2d94479a34'

OFFLINE_BROWSER_PROBE = """from account_access.browser_health import BrowserHealth
h = BrowserHealth()
for _ in range(2):
    h.check()
    if h.view() == {'status': 'READY'}:
        break
assert h.view() == {'status': 'READY'}
print('SIGNED_OFFLINE_BROWSER_READY')
"""


def patch_opentelemetry(payload, wheel, project_wheel, source_lock, requirements, preparation, image):
    """Apply the pinned security update to an already verified private image."""
    old_name = f'opentelemetry_api-{OTEL_BEFORE}-py3-none-any.whl'
    new_name = f'opentelemetry_api-{OTEL_AFTER}-py3-none-any.whl'
    wheelhouse = payload / 'wheels'
    old_wheel = wheelhouse / old_name
    require(old_wheel.is_file() and not old_wheel.is_symlink()
            and sha(old_wheel) == OTEL_PREDECESSOR
            and not os.path.lexists(wheelhouse / new_name), 'opentelemetry_predecessor_wheel_invalid')
    rows = [row for row in preparation['wheels'] if row['filename'] == old_name]
    artifacts = [row for row in image['wheels'] if row['name'] == 'opentelemetry-api']
    require(len(rows) == 1 and rows[0]['original_sha256'] == rows[0]['prepared_sha256']
            == OTEL_PREDECESSOR and len(artifacts) == 1
            and artifacts[0]['version'] == OTEL_BEFORE and artifacts[0]['sha256'] == OTEL_PREDECESSOR,
            'opentelemetry_predecessor_receipts_invalid')
    old_pin = f'opentelemetry-api=={OTEL_BEFORE} --hash=sha256:{OTEL_PREDECESSOR}\n'.encode()
    new_pin = f'opentelemetry-api=={OTEL_AFTER} --hash=sha256:{OTEL_PATCHED}\n'.encode()
    require(requirements.splitlines(keepends=True).count(old_pin) == 1,
            'opentelemetry_predecessor_requirement_invalid')
    with zipfile.ZipFile(project_wheel) as archive:
        lock_member = archive.getinfo('account_access/runtime-requirements.txt')
        require(lock_member.file_size == len(source_lock), 'opentelemetry_project_requirement_invalid')
        embedded_lock = archive.read(lock_member)
    require(embedded_lock == source_lock
            and f'opentelemetry-api=={OTEL_AFTER} '.encode() in source_lock
            and f'--hash=sha256:{OTEL_PATCHED}'.encode() in source_lock
            and OTEL_PREDECESSOR.encode() not in source_lock, 'opentelemetry_project_requirement_invalid')
    require(all(row is rows[0] or f'--hash=sha256:{row["original_sha256"]}'.encode() in source_lock
                for row in preparation['wheels']), 'opentelemetry_unrelated_lock_changed')
    require(wheel.name == new_name and wheel.is_file() and not wheel.is_symlink(),
            'opentelemetry_wheel_identity_mismatch')
    with tempfile.TemporaryDirectory(prefix='opentelemetry-input-', dir=payload.parent) as temporary:
        copied_wheel = Path(temporary) / new_name
        shutil.copy2(wheel, copied_wheel)
        replace_pure_python_dependency(payload / 'runtime', copied_wheel, expected_sha256=OTEL_PATCHED,
                                       distribution='opentelemetry_api', package='opentelemetry',
                                       before=OTEL_BEFORE, after=OTEL_AFTER, label='opentelemetry')
        shutil.copy2(copied_wheel, wheelhouse / new_name)
    old_wheel.unlink()
    rows[0].update(filename=new_name, original_sha256=OTEL_PATCHED, prepared_sha256=OTEL_PATCHED)
    preparation['original_requirements_sha256'] = hashlib.sha256(source_lock).hexdigest()
    artifacts[0].update(version=OTEL_AFTER, sha256=OTEL_PATCHED)
    return requirements.replace(old_pin, new_pin)


def build(args):
    release = getattr(args, 'release', '122')
    require(type(release) is str and release in RELEASES, 'unsupported_image_release')
    opentelemetry_wheel = getattr(args, 'opentelemetry_wheel', None)
    upgrades_opentelemetry = release in OPENTELEMETRY_RELEASES
    require(upgrades_opentelemetry == (opentelemetry_wheel is not None), 'opentelemetry_wheel_release_mismatch')
    before_build, target_build, base_sha256 = RELEASES[release]
    require(sys.platform == 'darwin' and os.getuid() == os.geteuid() != 0, 'ordinary_mac_required')
    repository = Path(__file__).resolve().parents[1]
    root = args.image.absolute()
    require(root.resolve(strict=True) == root and root.is_relative_to(repository / 'dist')
            and root.stat().st_uid == os.getuid() and root.parent.stat().st_uid == os.getuid()
            and stat.S_IMODE(root.parent.stat().st_mode) == 0o700, 'private_repository_build_copy_required')
    if upgrades_opentelemetry:
        outputs = [args.manifest_output.absolute(), args.report.absolute()]
        require(len(set(outputs)) == 2 and all(path.parent == root.parent and not os.path.lexists(path)
                                                for path in outputs), 'private_new_release_outputs_required')
    revision = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=repository).decode().strip()
    require(args.owner_source == args.native_source == args.source, 'program_source_mismatch')
    require(subprocess.run(['git', 'diff', '--quiet', args.source, revision, '--', 'account_access', 'macos'],
                           cwd=repository).returncode == 0, 'target_program_source_changed')
    require(not subprocess.check_output(['git', 'status', '--porcelain'], cwd=repository).strip(), 'source_tree_not_clean')
    require(hashlib.sha256(manifest(root, '0.8.0', 'arm64')).hexdigest() == base_sha256,
            'exact_predecessor_image_required')
    payload = root / SUPPORT
    prep_path = payload / 'runtime-preparation.json'
    prep = json.loads(prep_path.read_bytes())
    native_before = deepcopy(prep['native_files'])
    jit_before = {row['path']: row['prepared_sha256'] for row in native_before if row['path'] in JIT_ROLES}
    require(set(jit_before) == JIT_ROLES, 'qualified_jit_roles_missing')
    project_sha = sha(args.project_wheel)
    source_app = args.owner_app
    info = plistlib.loads((source_app / 'Contents/Info.plist').read_bytes())
    require(not source_app.is_symlink() and info['CFBundleVersion'] == str(target_build)
            and info['AccountAccessWheelSHA256'] == project_sha
            and info.get('AccountAccessSystemInstallationRequired') is True, 'bound_owner_successor_required')
    bundled_wheel = source_app / 'Contents/Resources/account_access.whl'
    require(bundled_wheel.is_file() and bundled_wheel.resolve() == bundled_wheel.absolute()
            and sha(bundled_wheel) == project_sha, 'bound_owner_wheel_required')
    old_project_sha = prep['project_wheel']['sha256']
    requirements = payload / 'package-requirements.txt'
    raw = requirements.read_bytes()
    require(raw.count(old_project_sha.encode()) == 1, 'project_pin_ambiguous')
    image_path = payload / 'runtime-image.json'
    image = json.loads(image_path.read_bytes())
    if opentelemetry_wheel is not None:
        lock = (repository / 'account_access/runtime-requirements.txt').read_bytes()
        raw = patch_opentelemetry(payload, opentelemetry_wheel, args.project_wheel, lock, raw, prep, image)
    replace_project_wheel(payload / 'runtime', args.project_wheel, payload / 'wheels')
    requirements.write_bytes(raw.replace(old_project_sha.encode(), project_sha.encode()))
    prep['project_wheel']['sha256'] = project_sha
    prep['prepared_requirements_sha256'] = sha(requirements)
    if opentelemetry_wheel is not None:
        wheelhouse = payload / 'wheels'
        origins = verify_origins(wheelhouse, lock, args.project_wheel.name, project_sha, prep)
        prepared_lock = b''.join(line for line in requirements.read_bytes().splitlines(keepends=True)
                                 if not line.startswith(b'account-access=='))
        select(wheelhouse, prepared_lock, args.project_wheel.name, project_sha,
               'arm64', image['python_version'], origins=origins)
    require(prep['prepared_trees'] == {name: tree_digest(payload / name) for name in ('python', 'browsers')},
            'native_dependency_tree_changed')
    prep_path.write_text(json.dumps(prep, sort_keys=True, indent=2) + '\n')
    commands = []

    def command(argv, timeout=180, **kwargs):
        result = subprocess.run(list(map(str, argv)), capture_output=True, timeout=timeout, **kwargs)
        require(result.returncode == 0, 'image_command_failed:' + Path(str(argv[0])).name)
        commands.append(Path(str(argv[0])).name)
        return result

    app = payload / 'owner.app'
    shutil.rmtree(app)  # Only this verified invocation-owned public build copy.
    shutil.copytree(source_app, app, symlinks=True)
    command(['/usr/bin/codesign', '--force', '--options', 'runtime', '--timestamp', '--identifier',
             'com.fainir.accountaccess.background', '--sign', IDENTITY, app / 'Contents/MacOS/AccountAccessBackground'])
    command(['/usr/bin/codesign', '--force', '--options', 'runtime', '--timestamp', '--sign', IDENTITY, app])
    command(['/usr/bin/codesign', '--verify', '--deep', '--strict', '--all-architectures', app])
    identity_path = payload / 'package-identity.json'
    identity = json.loads(identity_path.read_bytes())
    identity['signatures']['owner'] = signature(app, 'com.fainir.accountaccess')
    for role in ['broker', 'bootstrap', 'installerverify']:
        source = args.native / ('AccountAccess-' + role)
        target = payload / 'bin' / source.name
        require(source.is_file() and not source.is_symlink() and target.is_file()
                and not target.is_symlink(), 'native_role_input_invalid')
        shutil.copyfile(source, target)
        identifier = 'com.fainir.accountaccess.' + role
        command(['/usr/bin/codesign', '--force', '--options', 'runtime', '--timestamp', '--identifier',
                 identifier, '--sign', IDENTITY, target])
        command(['/usr/bin/codesign', '--verify', '--strict', '--all-architectures', target])
        peer = signature(target, identifier)
        if role != 'installerverify':
            identity['signatures'][role] = peer
    identity_path.write_text(json.dumps(identity, sort_keys=True) + '\n')
    for row in image['wheels']:
        if row['name'] == 'account-access':
            row['sha256'] = project_sha
    image['requirements_sha256'] = sha(requirements)
    image['runtime_sha256'] = tree_digest(payload / 'runtime')
    image['runtime_manifest_sha256'] = inventory_digest(payload / 'runtime')
    image_path.write_text(json.dumps(image, sort_keys=True, indent=2) + '\n')
    require(prep['native_files'] == native_before, 'native_dependency_preparation_changed')
    require(sha(payload / CHROME) == jit_before[CHROME]
            and sha(payload / 'runtime/lib/python3.12/site-packages' / NODE) == jit_before['wheels/' + PLAYWRIGHT + '/' + NODE],
            'qualified_jit_program_changed')
    require(all(sha(payload / 'wheels' / row['filename']) == row['prepared_sha256'] for row in prep['wheels']),
            'prepared_dependency_wheel_changed')
    audit = audit_payload([app, payload / 'python', payload / 'runtime', payload / 'browsers', payload / 'bin'],
                          sorted((payload / 'wheels').glob('*.whl')), 'arm64', command, development=False)
    with tempfile.TemporaryDirectory(prefix='owner-routes-browser-') as home:
        result = command([payload / 'runtime/bin/python', '-I', '-B', '-c', OFFLINE_BROWSER_PROBE], timeout=60,
            env={'PATH': '/usr/bin:/bin:/usr/sbin:/sbin', 'HOME': home, 'LANG': 'en_US.UTF-8',
                 'PLAYWRIGHT_BROWSERS_PATH': str((payload / 'browsers').resolve())})
    require(result.stdout.strip() == b'SIGNED_OFFLINE_BROWSER_READY', 'signed_browser_probe_failed')
    raw_manifest = manifest(root, '0.8.0', 'arm64')
    report = {'status': 'TARGET_IMAGE_QUALIFIED', 'owner_app_build': target_build, 'source_image_build': before_build,
              'base_manifest_sha256': base_sha256, 'manifest_sha256': hashlib.sha256(raw_manifest).hexdigest(),
              'builder_commit': revision, 'target_source_commit': args.source,
              'owner_source_commit': args.owner_source, 'native_source_commit': args.native_source,
              'project_wheel_sha256': project_sha, 'native_audit': audit,
              'native_dependency_bytes_unchanged': True, 'jit_roles': sorted(JIT_ROLES),
              'publisher_sandboxed_browser_execution': True,
              'installed_paths_changed': False, 'account_data_used': False}
    if opentelemetry_wheel is not None:
        report.update(opentelemetry_api_version=OTEL_AFTER, opentelemetry_wheel_sha256=OTEL_PATCHED)
    mode = 'xb' if upgrades_opentelemetry else 'wb'
    with args.manifest_output.open(mode) as output:
        output.write(raw_manifest)
    with args.report.open(mode) as output:
        output.write((json.dumps(report, sort_keys=True, indent=2) + '\n').encode())
    print(json.dumps({key: report[key] for key in ['status', 'manifest_sha256', 'publisher_sandboxed_browser_execution']}))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--release', choices=tuple(RELEASES), default='122')
    parser.add_argument('--opentelemetry-wheel', type=Path)
    for name in ['image', 'owner-app', 'native', 'project-wheel', 'manifest-output', 'report']:
        parser.add_argument('--' + name, type=Path, required=True)
    for name in ['source', 'owner-source', 'native-source']:
        parser.add_argument('--' + name, required=True)
    build(parser.parse_args())
