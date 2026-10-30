"""Exact signed direct-updater acceptance on an empty hosted Mac, never an owner Mac.

The predecessor contains public program files only. This probe creates fresh
synthetic policies and a vault sentinel; it never enrolls a personal account.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import plistlib
import pwd
import runpy
import subprocess
import sys
import tarfile

ROOT = Path(__file__).resolve().parents[1]
BASE = Path('/Library/Application Support/Account Access')
APP = Path('/Applications/Account Access.app')
JOURNAL = BASE.parent / 'Account Access Installer'
BINDING = BASE.parent / 'Account Access Installation Binding'
TRANSITION = BASE.parent / 'Account Access Runtime Recovery'
JOB = Path('/Library/LaunchDaemons/com.fainir.accountaccess.broker.plist')
LABEL = 'com.fainir.accountaccess.broker'
ORIGINAL = '5618053e6f8ed0a8720a9d2f7dde317425cecda6a970abd90c499fbfe27b43a8'
BEFORE = '568c79ca3b45ffc357bc5af2b420d481e729630b0120dc6d0058c1a396ad21b1'
AFTER = '630e77605faac2dfdace9faaa5da55e671335c6b18e62114d7f0224a8574f24c'
PLAN = 'd73f29c04cce63b39abd9df657f9e2258a7cb7eb9e1c5a858bffb86be19c5e5e'


def require(value, reason):
    if not value:
        raise ValueError(reason)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()


def publish_report(output, report):
    # Only these synthetic/public logs leave the disposable root fixture.
    (output / 'report.json').write_bytes(encoded(report) + b'\n')
    for path in output.iterdir():
        if path.is_file() and not path.is_symlink() and path.suffix in {'.log', '.json'}:
            path.chmod(0o644)
    output.chmod(0o755)


def archive_members(archive, manifest):
    """Exact manifest membership, without private branches or archive links as files."""
    expected = {'PublicImage', 'PublicImage/Library', 'PublicImage/Library/Application Support',
                'PublicImage/Applications', 'BaseManifest.json'}
    nodes = {}
    for root, rows in manifest['roots'].items():
        for relative, node in rows.items():
            name = 'PublicImage' + root + ('/' + relative if relative else '')
            expected.add(name)
            nodes[name] = node
    members = archive.getmembers()
    require(len(members) == len(expected) and {m.name for m in members} == expected,
            'baseline_archive_membership_invalid')
    for member in members:
        node = nodes.get(member.name)
        if node is None:
            require(member.isfile() if member.name == 'BaseManifest.json' else member.isdir(),
                    'baseline_archive_parent_invalid')
            continue
        kind = node['kind']
        require((kind == 'directory' and member.isdir())
                or (kind == 'file' and member.isfile() and member.size == node['size'])
                or (kind == 'symlink' and member.issym() and member.linkname == node['target']),
                'baseline_archive_node_invalid')
    return members


def run(args):
    if getattr(args, 'mode', 'upgrade') == 'fresh':
        return fresh_run(args)
    # The shared guard checks root, ARM64, hosted runner, repo and run identity.
    shared = runpy.run_path(str(ROOT / 'scripts/mac_component_update_installer_probe.py'))
    shared['guard']()
    require(all(not os.path.lexists(p) for p in (BASE, APP, JOURNAL, BINDING, TRANSITION, JOB)),
            'fresh_hosted_namespaces_required')
    owner = os.stat('/dev/console').st_uid
    require(owner > 0 and pwd.getpwuid(owner).pw_name == 'runner', 'hosted_console_required')
    contract = json.loads((ROOT / 'artifacts/direct-runtime-root-recovery-inputs.json').read_bytes())
    for name in ('baseline.tar.gz', 'candidate.pkg'):
        data = args.inputs / name
        with data.open('rb') as stream:
            require(hashlib.file_digest(stream, 'sha256').hexdigest() == contract['assets'][name]['sha256']
                    and data.stat().st_size == contract['assets'][name]['bytes'], 'input_digest_mismatch')
    args.output.mkdir(mode=0o700)
    report = {'status': 'FAILED', 'checks': [], 'personal_accounts_used': 0, 'production_ready': False}

    def command(label, argv, timeout=120, expected=0):
        result = subprocess.run(list(map(str, argv)), stdin=subprocess.DEVNULL,
                                capture_output=True, timeout=timeout)
        (args.output / (label + '.log')).write_bytes((result.stdout + result.stderr)[:128 * 1024])
        require(result.returncode == expected, 'command_failed:' + label)
        return result

    def check(name, value):
        require(value, name)
        report['checks'].append(name)
        (args.output / 'report.json').write_bytes(encoded(report) + b'\n')

    def write(path, value, mode=0o600):
        path.write_bytes(encoded(value))
        path.chmod(mode)

    def image_matches(manifest):
        shared['verify_image'](manifest)

    touched = False
    try:
        with tarfile.open(args.inputs / 'baseline.tar.gz', 'r:gz') as archive:
            member = archive.getmember('BaseManifest.json')
            require(member.isfile() and member.size < 16 * 1024 * 1024, 'baseline_manifest_invalid')
            raw = archive.extractfile(member).read()
            check('pinned_predecessor_manifest', digest(raw) == BEFORE)
            manifest = json.loads(raw)
            members = archive_members(archive, manifest)
            archive.extractall(args.output / 'baseline', members=members, filter='data')
        image = args.output / 'baseline/PublicImage'
        command('stage-public-image', ['/usr/bin/ditto', image / str(BASE)[1:], BASE], 300)
        touched = True
        command('public-ownership', ['/usr/sbin/chown', '-R', 'root:wheel', BASE], 300)
        APP.symlink_to('../Library/Application Support/Account Access/owner.app')
        os.lchmod(APP, 0o755)
        image_matches(manifest)
        check('exact_signed_public_predecessor', True)
        sys.path.insert(0, str(ROOT))
        from account_access import system_provision as provision
        provision.activate(provision.Layout.installed(), owner)
        # A synthetic private inode must survive the updater untouched.
        sentinel = BASE / 'vault/data/installer-fixture-sentinel'
        sentinel.write_bytes(b'Synthetic private store; no credentials\n')
        sentinel.chmod(0o600)
        os.chown(sentinel, pwd.getpwnam('_accountaccess').pw_uid, pwd.getpwnam('_accountaccess').pw_gid)
        sentinel_state = (sentinel.stat().st_dev, sentinel.stat().st_ino, sentinel.read_bytes())
        command('live-predecessor', ['/bin/launchctl', 'print', 'system/' + LABEL])
        roots = {str(p): [p.lstat().st_dev + 1, p.lstat().st_ino] for p in (BASE, APP)}
        JOURNAL.mkdir(mode=0o700)
        records = {'intent.json': {'schema': 1, 'managed_by': 'account-access-public-image-install-v1',
                    'manifest_sha256': ORIGINAL, 'owner_uid': owner},
                   'complete.json': {'manifest_sha256': ORIGINAL, 'owner_uid': owner, 'status': 'REGISTERED'},
                   'ready.json': {'manifest_sha256': ORIGINAL, 'roots': roots},
                   'published.json': {'manifest_sha256': ORIGINAL, 'roots': roots}}
        for name, value in records.items():
            write(JOURNAL / name, value)
        data_volume = Path('/System/Volumes/Data')
        require(BASE.stat().st_dev == APP.lstat().st_dev == data_volume.stat().st_dev,
                'fixture_data_volume_mismatch')
        volume = plistlib.loads(command('volume', ['/usr/sbin/diskutil', 'info', '-plist', data_volume]).stdout)['VolumeUUID'].lower()
        policies = {'install': BASE / 'broker/install.json', 'host': BASE / 'broker/host.json',
                    'owner': BASE / 'owner.json', 'worker': BASE / 'broker/worker.json', 'service': JOB}
        prior = {'schema': 1, 'managed_by': 'account-access-installation-root-revalidation-v1',
                 'base_manifest_sha256': ORIGINAL, 'owner_uid': owner,
                 'original_receipt_sha256': {n: digest(encoded(v)) for n, v in records.items()},
                 'roots': {str(p): {'inode': p.lstat().st_ino, 'volume_uuid': volume} for p in (BASE, APP)},
                 'publisher_team': 'WBULD6N4NQ', 'publisher_identifier': 'com.fainir.accountaccess.componentupdate',
                 'authorizing_plan_sha256': 'a' * 64, 'authorizing_source_commit': 'b' * 40,
                 'policy_sha256': {n: digest(p.read_bytes()) for n, p in policies.items()}}
        BINDING.mkdir(mode=0o700)
        write(BINDING / 'revalidated-v1.json', prior)
        previous_root = BASE.with_name('Account Access Hosted Previous Root')
        BASE.rename(previous_root)
        BASE.mkdir(mode=0o755)
        for child in previous_root.iterdir():
            child.rename(BASE / child.name)
        previous_root.rmdir()
        check('same_volume_support_root_replaced', BASE.stat().st_ino != roots[str(BASE)][1])
        image_matches(manifest)
        candidate = args.inputs / 'candidate.pkg'
        command('candidate-signature', ['/usr/sbin/pkgutil', '--check-signature', candidate])
        command('candidate-gatekeeper', ['/usr/sbin/spctl', '--assess', '--type', 'install', candidate])
        command('expand-candidate', ['/usr/sbin/pkgutil', '--expand-full', candidate, args.output / 'expanded'], 300)
        target = json.loads((args.output / 'expanded/Scripts/TargetManifest.json').read_bytes())
        check('pinned_target_manifest', digest((args.output / 'expanded/Scripts/TargetManifest.json').read_bytes()) == AFTER)
        for attempt in ('install', 'reapply'):
            log_path = Path('/var/log/install.log')
            offset = log_path.stat().st_size
            try:
                command(attempt, ['/usr/sbin/installer', '-dumplog', '-verboseR', '-pkg', candidate, '-target', '/'], 2100)
            finally:
                # This VM contains only the probe's synthetic state. Preserve
                # the new daemon output so a refusal identifies its checkpoint.
                with log_path.open('rb') as stream:
                    stream.seek(offset)
                    (args.output / (attempt + '-daemon.log')).write_bytes(stream.read(128 * 1024))
            image_matches(target)
            check(attempt + '_exact_target', True)
            recovery = json.loads((BINDING / 'recovered-v2.json').read_bytes())
            check(attempt + '_recovery_bound', recovery['schema'] == 2
                  and recovery['previous_supplement_sha256'] == digest(encoded(prior))
                  and base64.b64decode(recovery['previous_supplement']) == encoded(prior)
                  and recovery['authorizing_plan_sha256'] == PLAN)
            check(attempt + '_private_inode_preserved',
                  (sentinel.stat().st_dev, sentinel.stat().st_ino, sentinel.read_bytes()) == sentinel_state)
            check(attempt + '_legacy_receipts_preserved',
                  all((JOURNAL / n).read_bytes() == encoded(v) for n, v in records.items()))
            head = json.loads((TRANSITION / 'head.json').read_bytes())
            check(attempt + '_verified_head', head['plan_sha256'] == PLAN and head['manifest_sha256'] == AFTER)
            command(attempt + '-live-service', ['/bin/launchctl', 'print', 'system/' + LABEL])
            info = plistlib.loads((BASE / 'owner.app/Contents/Info.plist').read_bytes())
            check(attempt + '_app_build119', info['CFBundleVersion'] == '119')
            if attempt == 'install':
                stable = {str(p): (p.stat().st_ino, p.read_bytes()) for p in
                          [BINDING / 'recovered-v2.json', TRANSITION / 'head.json', *policies.values()]}
            else:
                check('reapply_preserves_policies_and_head',
                      stable == {p: (Path(p).stat().st_ino, Path(p).read_bytes()) for p in stable})
        report['status'] = 'PASSED'
    except Exception as error:
        report['failure_reason'] = str(error) if isinstance(error, ValueError) else type(error).__name__
        raise
    finally:
        if touched:
            stopped = subprocess.run(['/bin/launchctl', 'bootout', 'system/' + LABEL],
                                     capture_output=True, timeout=30)
            report['created_job_stopped_or_absent'] = stopped.returncode in (0, 113)
        publish_report(args.output, report)


def fresh_run(args):
    """Exercise the public-download package, including identical-image repair."""
    shared = runpy.run_path(str(ROOT / 'scripts/mac_component_update_installer_probe.py'))
    shared['guard']()
    require(all(not os.path.lexists(p) for p in (BASE, APP, JOURNAL, BINDING, TRANSITION, JOB)),
            'fresh_hosted_namespaces_required')
    owner = os.stat('/dev/console').st_uid
    require(owner > 0 and pwd.getpwuid(owner).pw_name == 'runner', 'hosted_console_required')
    contract = json.loads((ROOT / 'artifacts/direct-runtime-root-recovery-inputs.json').read_bytes())
    package = args.inputs / 'fresh.pkg'
    with package.open('rb') as stream:
        require(hashlib.file_digest(stream, 'sha256').hexdigest() == contract['assets']['fresh.pkg']['sha256']
                and package.stat().st_size == contract['assets']['fresh.pkg']['bytes'], 'fresh_input_digest_mismatch')
    args.output.mkdir(mode=0o700)
    report = {'status': 'FAILED', 'mode': 'fresh', 'checks': [], 'personal_accounts_used': 0,
              'production_ready': False}

    def command(label, argv, timeout=120):
        result = subprocess.run(list(map(str, argv)), stdin=subprocess.DEVNULL,
                                capture_output=True, timeout=timeout)
        (args.output / (label + '.log')).write_bytes((result.stdout + result.stderr)[:128 * 1024])
        require(result.returncode == 0, 'command_failed:' + label)
        return result

    def check(name, value):
        require(value, name)
        report['checks'].append(name)
        (args.output / 'report.json').write_bytes(encoded(report) + b'\n')

    try:
        command('signature', ['/usr/sbin/pkgutil', '--check-signature', package])
        command('gatekeeper', ['/usr/sbin/spctl', '--assess', '--type', 'install', package])
        command('staple', ['/usr/bin/xcrun', 'stapler', 'validate', package])
        command('expand', ['/usr/sbin/pkgutil', '--expand-full', package, args.output / 'expanded'], 300)
        manifests = list((args.output / 'expanded').rglob('RecoveryManifest.json'))
        check('one_pinned_fresh_manifest', len(manifests) == 1 and digest(manifests[0].read_bytes()) == AFTER)
        target = json.loads(manifests[0].read_bytes())
        for attempt in ('install', 'repair'):
            log_path = Path('/var/log/install.log')
            offset = log_path.stat().st_size
            try:
                command(attempt, ['/usr/sbin/installer', '-dumplog', '-verboseR', '-pkg', package, '-target', '/'], 2100)
            finally:
                with log_path.open('rb') as stream:
                    stream.seek(offset)
                    (args.output / (attempt + '-daemon.log')).write_bytes(stream.read(128 * 1024))
            shared['verify_image'](target)
            check(attempt + '_exact_public_image', True)
            info = plistlib.loads((BASE / 'owner.app/Contents/Info.plist').read_bytes())
            check(attempt + '_owner_build119', info['CFBundleVersion'] == '119')
            command(attempt + '-live-service', ['/bin/launchctl', 'print', 'system/' + LABEL])
            # Only this just-created fixture app can exist in this empty VM.
            subprocess.run(['/usr/bin/pkill', '-u', str(owner), '-x', 'AccountAccess'],
                           capture_output=True, timeout=30)
            sentinel = BASE / 'vault/data/installer-fixture-sentinel'
            if attempt == 'install':
                sentinel.write_bytes(b'Synthetic fresh-install private store\n')
                sentinel.chmod(0o600)
                identity = pwd.getpwnam('_accountaccess')
                os.chown(sentinel, identity.pw_uid, identity.pw_gid)
                state = (sentinel.stat().st_ino, sentinel.read_bytes(), BASE.stat().st_ino)
                receipts = {p.name: p.read_bytes() for p in JOURNAL.iterdir()
                            if p.name in ('intent.json', 'ready.json', 'published.json', 'complete.json')}
            else:
                check('repair_preserves_vault_and_root',
                      (sentinel.stat().st_ino, sentinel.read_bytes(), BASE.stat().st_ino) == state)
                check('repair_preserves_receipts', all((JOURNAL / n).read_bytes() == v for n, v in receipts.items()))
        report['status'] = 'PASSED'
    except Exception as error:
        report['failure_reason'] = str(error) if isinstance(error, ValueError) else type(error).__name__
        raise
    finally:
        stopped = subprocess.run(['/bin/launchctl', 'bootout', 'system/' + LABEL],
                                 capture_output=True, timeout=30)
        report['created_job_stopped_or_absent'] = stopped.returncode in (0, 113)
        publish_report(args.output, report)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--inputs', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--mode', choices=['upgrade', 'fresh'], default='upgrade')
    run(parser.parse_args())
