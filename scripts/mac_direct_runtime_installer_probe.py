"""Exact signed direct-updater acceptance on an empty hosted Mac, never an owner Mac.

The predecessor contains public program files only. This probe creates fresh
synthetic policies and a vault sentinel; it never enrolls a personal account.
"""
from __future__ import annotations

import argparse
import base64
from dataclasses import dataclass
import hashlib
import http.client
import json
import os
from pathlib import Path
import plistlib
import pwd
import re
import runpy
import secrets
import socket
import subprocess
import sys
import tarfile
import time

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
AFTER = '6ab5f90fa72dfed84c295d5df4741d3cb9aaf6a0fa89ed155b4cb76400570874'
PLAN = '7949dee76094337190bd9efa31b7e09fc478bf62a3bbdfd44824cc9ba3f3d58b'


@dataclass(frozen=True)
class Release:
    number: str
    before: str
    after: str
    plan: str
    transition: Path
    contract: str
    recovery_plan: str


RELEASES = {
    '120': Release('120', BEFORE, AFTER, PLAN, TRANSITION,
                   'direct-runtime-root-recovery-inputs.json', PLAN),
    '121': Release('121', AFTER, '1917cff3a29b8306549287f4e6ac4fcc393dc4445f21a3ab0019c55e457b2053',
                   '59b7741173281a6f72701f91b99ada75cc53e3bb85f2f42c666fd33b021dff69',
                   BASE.parent / 'Account Access Runtime JIT Repair', 'runtime121-installer-inputs.json', PLAN),
}


def selected_release(args):
    return RELEASES[getattr(args, 'release', '120')]


BROWSER_CHECK = '''import json, os, sys
# Match WorkerBootstrap's service-home cwd and private file creation policy.
os.chdir(os.environ['HOME'])
os.umask(0o077)
from playwright.sync_api import sync_playwright
flags = sys.argv[1:]
assert flags in [[], ['--enable-logging=stderr'], ['--enable-logging=stderr', '--disable-gpu'],
                 ['--enable-logging=stderr', '--disable-gpu', '--disable-software-rasterizer']]
with sync_playwright() as pw:
    b = pw.chromium.launch(headless=True, chromium_sandbox=True, args=flags)
    c = b.new_context(offline=True)
    p = c.new_page()
    p.set_content('<title>Installed runtime check</title><script>window.runtimeAnswer=6*7</script>')
    assert p.title() == 'Installed runtime check' and p.evaluate('window.runtimeAnswer') == 42
    b.close()
print(json.dumps({'status': 'PASSED', 'sandboxed_browser': True, 'external_website_used': False}))
'''


def installed_browser_command():
    return ['/usr/bin/sudo', '-n', '-u', '_accountaccess', '/usr/bin/env', '-i',
            'PATH=/usr/bin:/bin:/usr/sbin:/sbin', 'LANG=en_US.UTF-8', 'HOME=' + str(BASE / 'home'),
            'USER=_accountaccess', 'LOGNAME=_accountaccess',
            'PLAYWRIGHT_BROWSERS_PATH=' + str(BASE / 'browsers'),
            BASE / 'runtime/bin/python', '-I', '-B', '-c', BROWSER_CHECK]


def worker_browser_health(command, label):
    # This never runs on an owner Mac. The fixture is empty, and this client
    # has no account or operation grants. Seed only its synthetic public token
    # verifier; no vault key, owner token or existing client is read.
    runpy.run_path(str(ROOT / 'scripts/mac_component_update_installer_probe.py'))['guard']()
    token = secrets.token_urlsafe(32)
    verifier = hashlib.sha256(token.encode()).hexdigest()
    seed = '''import os, sqlite3, sys
os.umask(0o077)
with sqlite3.connect(sys.argv[1]) as db:
    db.execute('INSERT INTO clients(digest,principal,revoked) VALUES (?,?,0)', (sys.argv[2], 'installer-runtime-test'))
'''
    command(label + '-synthetic-client', ['/usr/bin/sudo', '-n', '-u', '_accountaccess',
            BASE / 'runtime/bin/python', '-I', '-B', '-c', seed, BASE / 'vault/data/state.db', verifier])
    connection = http.client.HTTPConnection('localhost', timeout=10)
    channel = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        channel.settimeout(10)
        channel.connect(str(BASE / 'run/agent.sock'))
        connection.sock = channel
        connection.request('GET', '/v1/accounts', headers={'Authorization': 'Bearer ' + token})
        response = connection.getresponse()
        raw = response.read(65537)
        require(response.status == 200 and len(raw) <= 65536, 'worker_browser_health_unavailable')
        data = json.loads(raw)
        require(data.get('status') == 'OK' and data.get('accounts') == []
                and data.get('browser_runtime') == {'status': 'READY'}, 'worker_browser_health_not_ready')
    finally:
        connection.close()
        channel.close()


def browser_crash_summary(raw, pid):
    try:
        decoder = json.JSONDecoder()
        first, end = decoder.raw_decode(raw.lstrip())
        body = decoder.decode(raw.lstrip()[end:].lstrip()) if raw.lstrip()[end:].strip() else first
        if type(body) is not dict or body.get('pid') != pid:
            return None
        summary = {key: body[key] for key in ('pid', 'procName', 'exception', 'termination', 'asi') if key in body}
        index = body.get('faultingThread')
        threads = body.get('threads', [])
        if type(index) is int and isinstance(threads, list) and 0 <= index < len(threads):
            summary['symbols'] = [frame['symbol'] for frame in threads[index].get('frames', [])[:20]
                                  if isinstance(frame, dict) and isinstance(frame.get('symbol'), str)]
        return summary
    except (ValueError, TypeError, KeyError, AttributeError):
        return None


def capture_browser_failure(output, raw):
    # Never inspect an owner's crash history. This is restricted to the same
    # empty hosted fixture as Installer acceptance, with one exact child PID.
    runpy.run_path(str(ROOT / 'scripts/mac_component_update_installer_probe.py'))['guard']()
    match = re.search(rb'<launched> pid=([1-9][0-9]*)', raw)
    if not match:
        return
    pid = int(match[1])
    folders = [Path('/Library/Logs/DiagnosticReports'), BASE / 'home/Library/Logs/DiagnosticReports']
    for folder in folders:
        for path in folder.glob('*.ips'):
            if path.is_symlink() or not path.is_file() or path.stat().st_size > 2 * 1024 * 1024:
                continue
            summary = browser_crash_summary(path.read_text(), pid)
            if summary:
                (output / 'browser-crash.log').write_text(json.dumps(summary, indent=2) + '\n')
    try:
        result = subprocess.run(['/usr/bin/log', 'show', '--last', '2m', '--style', 'compact',
            '--predicate', 'processID == ' + str(pid)], capture_output=True, timeout=20)
        (output / 'browser-system.log').write_bytes((result.stdout + result.stderr)[:128 * 1024])
    except subprocess.TimeoutExpired:
        pass
    # Diagnose the same immutable installed program, with its sandbox retained.
    # These runs cannot turn the failed default acceptance check into a pass.
    variants = [('logging', ['--enable-logging=stderr']),
                ('without-gpu', ['--enable-logging=stderr', '--disable-gpu']),
                ('without-software-gpu', ['--enable-logging=stderr', '--disable-gpu', '--disable-software-rasterizer'])]
    for name, flags in variants:
        try:
            result = subprocess.run(list(map(str, installed_browser_command())) + flags,
                                    cwd=BASE / 'home', capture_output=True, timeout=45)
            raw = result.stdout + result.stderr
            code = result.returncode
        except subprocess.TimeoutExpired as exc:
            raw = (exc.stdout or b'') + (exc.stderr or b'')
            code = 'timeout'
        (output / ('browser-diagnostic-' + name + '.log')).write_bytes(
            ('exit_code=' + str(code) + '\n').encode() + raw[:128 * 1024])
    helper = output / 'browser-context-probe'
    build = subprocess.run(['/usr/bin/xcrun', 'clang', '-Wno-deprecated-declarations',
        str(ROOT / 'macos/Tests/BrowserServiceContextProbe.c'), '-framework', 'Security', '-o', str(helper)],
        capture_output=True, timeout=120)
    (output / 'browser-context-build.log').write_bytes((build.stdout + build.stderr)[:128 * 1024])
    if build.returncode != 0:
        return
    actor = pwd.getpwnam('_accountaccess')
    # Remove only sudo's identity switch; the reviewed helper performs the
    # same permanent group/gid/uid drop as WorkerBootstrap before exec.
    arguments = list(map(str, installed_browser_command()))[4:]
    contexts = [('dropper', [], 'plain'),
                ('per-user-domain', ['/bin/launchctl', 'asuser', str(actor.pw_uid)], 'plain'),
                ('private-session', [], 'session'),
                ('private-subset-before', [], 'subset-before'),
                ('private-subset-after', [], 'subset-after')]
    job = subprocess.run(['/bin/launchctl', 'print', 'system/' + LABEL], capture_output=True, timeout=15)
    try:
        broker_pid = running_service_pid(job.stdout)
        contexts.append(('broker-domain', ['/bin/launchctl', 'bsexec', str(broker_pid)], 'plain'))
    except ValueError:
        pass
    for name, prefix, mode in contexts:
        try:
            result = subprocess.run(prefix + [str(helper), mode] + arguments,
                                    cwd=BASE / 'home', capture_output=True, timeout=45)
            raw = result.stdout + result.stderr
            code = result.returncode
        except subprocess.TimeoutExpired as exc:
            raw = (exc.stdout or b'') + (exc.stderr or b'')
            code = 'timeout'
        (output / ('browser-context-' + name + '.log')).write_bytes(
            ('exit_code=' + str(code) + '\n').encode() + raw[:128 * 1024])

JOSE_CHECK = '''import importlib.metadata, json
from joserfc import jws
from joserfc.errors import ExceededSizeError
assert importlib.metadata.version('joserfc') == '1.7.7'
class NoSegmentCopies(bytes):
    def split(self, *args, **kwargs):
        raise AssertionError('oversized input copied before rejection')
try:
    jws.deserialize_compact(NoSegmentCopies(b'a' * 1000000 + b'.b.c'), None)
except ExceededSizeError:
    print(json.dumps({'status': 'PASSED', 'joserfc': '1.7.7'}))
else:
    raise AssertionError('oversized input accepted')
'''


def require(value, reason):
    if not value:
        raise ValueError(reason)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()


def running_service_pid(raw):
    """A loaded launchd job or an active nested endpoint is not a live daemon."""
    text = raw.decode('utf-8', errors='replace')
    states = re.findall(r'^\tstate = ([^\n]+)$', text, re.MULTILINE)
    pids = re.findall(r'^\tpid = ([1-9][0-9]*)$', text, re.MULTILINE)
    require(states == ['running'] and len(pids) == 1, 'protected_service_not_running')
    return int(pids[0])


def verify_live_service(command, label):
    pid = None
    samples = 0
    for attempt in range(30):
        raw = command(label, ['/bin/launchctl', 'print', 'system/' + LABEL]).stdout
        try:
            current = running_service_pid(raw)
        except ValueError:
            if pid is not None or attempt == 29:
                raise
            time.sleep(1)
            continue
        require(pid is None or current == pid, 'protected_service_restarted_during_check')
        pid = current
        samples += 1
        if samples == 3:
            return
        time.sleep(1)
    raise ValueError('protected_service_not_running')


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
    release = selected_release(args)
    if getattr(args, 'mode', 'upgrade') == 'fresh':
        return fresh_run(args)
    # The shared guard checks root, ARM64, hosted runner, repo and run identity.
    shared = runpy.run_path(str(ROOT / 'scripts/mac_component_update_installer_probe.py'))
    shared['guard']()
    require(all(not os.path.lexists(p) for p in (BASE, APP, JOURNAL, BINDING, release.transition, JOB)),
            'fresh_hosted_namespaces_required')
    owner = os.stat('/dev/console').st_uid
    require(owner > 0 and pwd.getpwuid(owner).pw_name == 'runner', 'hosted_console_required')
    contract = json.loads((ROOT / 'artifacts' / release.contract).read_bytes())
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
        if result.returncode != expected and label.endswith('publisher-sandboxed-browser'):
            capture_browser_failure(args.output, result.stderr)
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
            check('pinned_predecessor_manifest', digest(raw) == release.before)
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
        # Match the qualified owner predecessor: root:admin support root,
        # root:wheel published runtime. Do not normalize runtime descendants.
        os.chown(BASE, 0, 80)
        # A synthetic private inode must survive the updater untouched.
        sentinel = BASE / 'vault/data/installer-fixture-sentinel'
        sentinel.write_bytes(b'Synthetic private store; no credentials\n')
        sentinel.chmod(0o600)
        os.chown(sentinel, pwd.getpwnam('_accountaccess').pw_uid, pwd.getpwnam('_accountaccess').pw_gid)
        sentinel_state = (sentinel.stat().st_dev, sentinel.stat().st_ino, sentinel.read_bytes())
        verify_live_service(command, 'live-predecessor')
        roots = {str(p): [p.lstat().st_dev + 1, p.lstat().st_ino] for p in (BASE, APP)}
        JOURNAL.mkdir(mode=0o700)
        # The real installer creates this root-owned maintenance lease.
        # Synthetic receipts must reproduce it before invoking the updater.
        (JOURNAL / "lock").touch(mode=0o600, exist_ok=False)
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
        os.chown(BASE, 0, 80)
        for child in previous_root.iterdir():
            child.rename(BASE / child.name)
        previous_root.rmdir()
        check('same_volume_support_root_replaced', BASE.stat().st_ino != roots[str(BASE)][1])
        completed_objects = None
        if release.number == '121':
            # Reproduce the completed build-120 root recovery and its separate
            # published namespace. The successor must preserve both verbatim.
            recovery = {'schema': 2, 'managed_by': 'account-access-installation-root-recovery-v2',
                'base_manifest_sha256': ORIGINAL, 'owner_uid': owner,
                'original_receipt_sha256': {n: digest(encoded(v)) for n, v in records.items()},
                'previous_supplement_sha256': digest(encoded(prior)),
                'previous_supplement': base64.b64encode(encoded(prior)).decode(),
                'publisher_team': 'WBULD6N4NQ', 'publisher_identifier': 'com.fainir.accountaccess.componentupdate',
                'authorizing_plan_sha256': release.recovery_plan,
                'authorizing_source_commit': 'beda6324d836458a35045ee0d2acd579238d6929',
                'policy_sha256': {n: digest(p.read_bytes()) for n, p in policies.items()},
                'roots': {str(p): {'inode': p.lstat().st_ino, 'volume_uuid': volume} for p in (BASE, APP)}}
            write(BINDING / 'recovered-v2.json', recovery)
            earlier = RELEASES['120'].transition
            require(not os.path.lexists(earlier), 'predecessor_namespace_not_empty')
            earlier.mkdir(mode=0o700)
            completed = earlier / ('transition-' + release.recovery_plan)
            completed.mkdir(mode=0o700)
            write(earlier / 'head.json', {'schema': 1, 'managed_by': 'account-access-full-image-head-v1',
                'plan_sha256': release.recovery_plan, 'manifest_sha256': release.before,
                'before_manifest_sha256': RELEASES['120'].before,
                'source_commit': 'beda6324d836458a35045ee0d2acd579238d6929',
                'predecessor_evidence_sha256': 'c' * 64,
                'state': 'public_image_verified_gui_unverified', 'automatic_reboot_recovery': False})
            write(completed / 'completed-fixture.json', {'synthetic': True})
            completed_objects = {p: (p.stat().st_ino, p.read_bytes()) for p in
                                 [BINDING / 'recovered-v2.json', earlier / 'head.json', completed / 'completed-fixture.json']}
            check('completed_predecessor_recovery_and_namespace_seeded', True)
        image_matches(manifest)
        # Reproduce the owner's retained, unpublished earlier-plan preparation.
        # It stays opaque and must keep its original inode and bytes.
        release.transition.mkdir(mode=0o700)
        os.chown(release.transition, 0, 0)
        prior_preparation = release.transition / '.preparing-681f2b48c2b35bc1ccdb4309da636b1b88fcbeb2b2ae982b92dbf0c4198dd51e-ddff6846-ab86-4335-a2d1-16c0b0a7738b'
        prior_preparation.mkdir(mode=0o700)
        (prior_preparation / 'files').mkdir(mode=0o700)
        (prior_preparation / 'trees').mkdir(mode=0o700)
        (prior_preparation / 'trees/public').mkdir(mode=0o755)
        prior_file = prior_preparation / 'files/partial'
        prior_file.write_bytes(b'Synthetic earlier unpublished public preparation\n')
        prior_file.chmod(0o644)
        prior_state = (prior_preparation.stat().st_ino, prior_file.stat().st_ino, prior_file.read_bytes())
        check('earlier_unpublished_preparation_seeded', True)
        candidate = args.inputs / 'candidate.pkg'
        command('candidate-signature', ['/usr/sbin/pkgutil', '--check-signature', candidate])
        command('candidate-gatekeeper', ['/usr/sbin/spctl', '--assess', '--type', 'install', candidate])
        command('expand-candidate', ['/usr/sbin/pkgutil', '--expand-full', candidate, args.output / 'expanded'], 300)
        target = json.loads((args.output / 'expanded/Scripts/TargetManifest.json').read_bytes())
        check('pinned_target_manifest', digest((args.output / 'expanded/Scripts/TargetManifest.json').read_bytes()) == release.after)
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
            check(attempt + '_prior_preparation_preserved',
                  (prior_preparation.stat().st_ino, prior_file.stat().st_ino, prior_file.read_bytes()) == prior_state)
            recovery = json.loads((BINDING / 'recovered-v2.json').read_bytes())
            check(attempt + '_recovery_bound', recovery['schema'] == 2
                  and recovery['previous_supplement_sha256'] == digest(encoded(prior))
                  and base64.b64decode(recovery['previous_supplement']) == encoded(prior)
                  and recovery['authorizing_plan_sha256'] == release.recovery_plan)
            check(attempt + '_private_inode_preserved',
                  (sentinel.stat().st_dev, sentinel.stat().st_ino, sentinel.read_bytes()) == sentinel_state)
            check(attempt + '_legacy_receipts_preserved',
                  all((JOURNAL / n).read_bytes() == encoded(v) for n, v in records.items()))
            head = json.loads((release.transition / 'head.json').read_bytes())
            check(attempt + '_verified_head', head['plan_sha256'] == release.plan and head['manifest_sha256'] == release.after)
            verify_live_service(command, attempt + '-live-service')
            if release.number == '121':
                worker_browser_health(command, attempt + '-publisher-sandboxed-browser')
                check(attempt + '_publisher_sandboxed_browser', True)
                check(attempt + '_completed_predecessor_history_preserved',
                      completed_objects == {p: (p.stat().st_ino, p.read_bytes()) for p in completed_objects})
            info = plistlib.loads((BASE / 'owner.app/Contents/Info.plist').read_bytes())
            check(attempt + '_app_build' + release.number, info['CFBundleVersion'] == release.number)
            command(attempt + '-installed-jose-guard', ['/usr/bin/sudo', '-n', '-u', 'runner',
                    BASE / 'runtime/bin/python', '-I', '-B', '-c', JOSE_CHECK])
            check(attempt + '_patched_dependency_guard', True)
            if attempt == 'install':
                stable = {str(p): (p.stat().st_ino, p.read_bytes()) for p in
                          [BINDING / 'recovered-v2.json', release.transition / 'head.json', *policies.values()]}
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
    release = selected_release(args)
    shared = runpy.run_path(str(ROOT / 'scripts/mac_component_update_installer_probe.py'))
    shared['guard']()
    require(all(not os.path.lexists(p) for p in (BASE, APP, JOURNAL, BINDING, release.transition, JOB)),
            'fresh_hosted_namespaces_required')
    owner = os.stat('/dev/console').st_uid
    require(owner > 0 and pwd.getpwuid(owner).pw_name == 'runner', 'hosted_console_required')
    contract = json.loads((ROOT / 'artifacts' / release.contract).read_bytes())
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
        if result.returncode != 0 and label.endswith('publisher-sandboxed-browser'):
            capture_browser_failure(args.output, result.stderr)
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
        check('one_pinned_fresh_manifest', len(manifests) == 1 and digest(manifests[0].read_bytes()) == release.after)
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
            check(attempt + '_owner_build' + release.number, info['CFBundleVersion'] == release.number)
            command(attempt + '-installed-jose-guard', ['/usr/bin/sudo', '-n', '-u', 'runner',
                    BASE / 'runtime/bin/python', '-I', '-B', '-c', JOSE_CHECK])
            check(attempt + '_patched_dependency_guard', True)
            verify_live_service(command, attempt + '-live-service')
            if release.number == '121':
                worker_browser_health(command, attempt + '-publisher-sandboxed-browser')
                check(attempt + '_publisher_sandboxed_browser', True)
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
    parser.add_argument('--release', choices=['120', '121'], default='120')
    run(parser.parse_args())
