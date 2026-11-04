"""Prepare a matching owner/broker successor from one exact public predecessor.

No installed paths or account data are accessed. Existing JIT/native dependency
bytes stay fixed; only the reviewed project wheel, owner and native helpers are
replaced. Publisher signing and full payload/browser verification occur here.
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

from account_access.package_manifest import build as manifest, inventory_digest
from account_access.system_provision import signature
from macos.payload_audit import audit_payload
from macos.runtime_prepare import tree_digest
from scripts.build_direct_runtime_target_image import replace_project_wheel
from scripts.build_jit_update_image import CHROME, IDENTITY, JIT_ROLES, NODE, PLAYWRIGHT, SUPPORT, require, sha

BASE_SHA256 = '0eb9a5bfab615f23f9d3d6e98f7895f7bf46e6196ef8a1e5e07115906f4d443c'
RELEASES = {'122': (121, 122, BASE_SHA256),
            '123': (122, 123, 'b6537a7617db5a53540adca82023fdbf50ef45e9ca9e9dd1ae46dd682639832d'),
            '124': (123, 124, '5f3390496afaa436c64e3629cc125cbb4017e9deec8f70e4f5eb06c16e790930'),
            '125': (124, 125, '37cadaf59502657983f6cdb4a3bec0a755eb5e0dd041b625151ee51608ab2d8f'),
            '126': (125, 126, '8abffd8078832752aa13c59e58834b0a9b669656758dab47d4418ae663c41bcd'),
            '127': (126, 127, '0e1c1f3a2b05f3eb5f9acd32b7a55bea28d775411519d41be0401b43d852d20f'),
            '128': (127, 128, '82b953e0698ee73468c2cff8aa546c5b94368fbf1fe24036e2623d039fee2f06')}

OFFLINE_BROWSER_PROBE = """from account_access.browser_health import BrowserHealth
h = BrowserHealth()
for _ in range(2):
    h.check()
    if h.view() == {'status': 'READY'}:
        break
assert h.view() == {'status': 'READY'}
print('SIGNED_OFFLINE_BROWSER_READY')
"""


def build(args):
    release = getattr(args, 'release', '122')
    require(type(release) is str and release in RELEASES, 'unsupported_image_release')
    before_build, target_build, base_sha256 = RELEASES[release]
    require(sys.platform == 'darwin' and os.getuid() == os.geteuid() != 0, 'ordinary_mac_required')
    repository = Path(__file__).resolve().parents[1]
    root = args.image.absolute()
    require(root.resolve(strict=True) == root and root.is_relative_to(repository / 'dist')
            and root.stat().st_uid == os.getuid() and root.parent.stat().st_uid == os.getuid()
            and stat.S_IMODE(root.parent.stat().st_mode) == 0o700, 'private_repository_build_copy_required')
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
    old_project_sha = prep['project_wheel']['sha256']
    requirements = payload / 'package-requirements.txt'
    raw = requirements.read_bytes()
    require(raw.count(old_project_sha.encode()) == 1, 'project_pin_ambiguous')
    replace_project_wheel(payload / 'runtime', args.project_wheel, payload / 'wheels')
    requirements.write_bytes(raw.replace(old_project_sha.encode(), project_sha.encode()))
    prep['project_wheel']['sha256'] = project_sha
    prep['prepared_requirements_sha256'] = sha(requirements)
    require(prep['prepared_trees'] == {name: tree_digest(payload / name) for name in ('python', 'browsers')},
            'native_dependency_tree_changed')
    prep_path.write_text(json.dumps(prep, sort_keys=True, indent=2) + '\n')
    commands = []

    def command(argv, timeout=180, **kwargs):
        result = subprocess.run(list(map(str, argv)), capture_output=True, timeout=timeout, **kwargs)
        require(result.returncode == 0, 'image_command_failed:' + Path(str(argv[0])).name)
        commands.append(Path(str(argv[0])).name)
        return result

    source_app = args.owner_app
    info = plistlib.loads((source_app / 'Contents/Info.plist').read_bytes())
    require(not source_app.is_symlink() and info['CFBundleVersion'] == str(target_build)
            and info['AccountAccessWheelSHA256'] == project_sha
            and info.get('AccountAccessSystemInstallationRequired') is True, 'bound_owner_successor_required')
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
    image_path = payload / 'runtime-image.json'
    image = json.loads(image_path.read_bytes())
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
    args.manifest_output.write_bytes(raw_manifest)
    report = {'status': 'TARGET_IMAGE_QUALIFIED', 'owner_app_build': target_build, 'source_image_build': before_build,
              'base_manifest_sha256': base_sha256, 'manifest_sha256': hashlib.sha256(raw_manifest).hexdigest(),
              'builder_commit': revision, 'target_source_commit': args.source,
              'owner_source_commit': args.owner_source, 'native_source_commit': args.native_source,
              'project_wheel_sha256': project_sha, 'native_audit': audit,
              'native_dependency_bytes_unchanged': True, 'jit_roles': sorted(JIT_ROLES),
              'publisher_sandboxed_browser_execution': True,
              'installed_paths_changed': False, 'account_data_used': False}
    args.report.write_text(json.dumps(report, sort_keys=True, indent=2) + '\n')
    print(json.dumps({key: report[key] for key in ['status', 'manifest_sha256', 'publisher_sandboxed_browser_execution']}))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--release', choices=tuple(RELEASES), default='122')
    for name in ['image', 'owner-app', 'native', 'project-wheel', 'manifest-output', 'report']:
        parser.add_argument('--' + name, type=Path, required=True)
    for name in ['source', 'owner-source', 'native-source']:
        parser.add_argument('--' + name, required=True)
    build(parser.parse_args())
