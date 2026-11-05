"""Retain duplicate public preview backups that occupy the native upgrade slot.

This maintenance repair never reads client credentials, enrolls a connection,
changes an active skill, or grants access. The normal app performs the upgrade.
Unknown, modified or current-version backup folders remain untouched.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import shlex
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from account_access.agent_setup import (  # noqa: E402
    LEGACY_AGENT_TEMPLATE, LEGACY_PAYLOADS, UPGRADE_SLOT,
    _directories, _rename_directory, _skill_snapshot, _sync_directory,
)


def require(value):
    if not value:
        raise ValueError('duplicate_preview_backup_not_verified')


def reviewed_preview(home, target, data):
    """Validate only the public skill templates and their path bindings."""
    binding = json.loads(data['installation.json'])
    require(type(binding) is dict and set(binding) == {'client_config', 'python'}
            and all(type(value) is str for value in binding.values())
            and data['.account-access-install'] == b'account-access-v1')
    client, python = Path(binding['client_config']), Path(binding['python'])
    principal = 'claude' if target.parent.parent.name == '.claude' else 'codex'
    require(client.parent.name in {'generic', principal})
    preview = client.parent.parent.parent
    require(client == preview / 'clients' / client.parent.name / 'client.json')
    # No legacy client file is opened, even to inspect its metadata.
    require((preview == home / 'Library/Application Support/AccountAccess'
             or (preview.parent == home / '.local/share'
                 and re.fullmatch(r'account-access(?:-[A-Za-z0-9][A-Za-z0-9_-]{0,79})?', preview.name)))
            and str(client) == binding['client_config'])
    runtime = (preview if preview.parent == home / '.local/share'
               else home / '.local/share/account-access') / 'runtime'
    require(python.parent.name == 'bin'
            and re.fullmatch(r'python(?:3(?:\.[0-9]{1,2})?)?', python.name)
            and str(python) == binding['python']
            and (python.parent.parent == runtime / 'tools/account-access'
                 or (python.parent.parent.parent == runtime / 'environments'
                     and re.fullmatch(r'account-access-[A-Za-z0-9_-]{1,80}', python.parent.parent.name))))
    skill = hashlib.sha256(data['SKILL.md']).hexdigest()
    reader = hashlib.sha256(data['scripts/access.py']).hexdigest()
    require(hashlib.sha256(data['agents/openai.yaml']).hexdigest() == LEGACY_AGENT_TEMPLATE)
    isolation = next((isolated for a, b, isolated in LEGACY_PAYLOADS if (a, b) == (skill, reader)), None)
    require(isolation is not None)
    launcher = ('#!/bin/sh\nexec ' + shlex.quote(str(python)) + (' -I ' if isolation else ' ')
                + shlex.quote(str(target / 'scripts/access.py')) + ' "$@"\n').encode()
    require(data['scripts/access'] == launcher)


def retain_duplicates(home, *, apply=False):
    home = Path(home)
    plans = []
    for host in ('.agents', '.claude'):
        target = home / host / 'skills/account-access'
        backup = target.with_name(UPGRADE_SLOT)
        if not os.path.lexists(backup):
            continue
        _directories(home, target.parent.relative_to(home))
        active_stamp, active = _skill_snapshot(target)
        backup_stamp, saved = _skill_snapshot(backup)
        require(active == saved)
        reviewed_preview(home, target, active)
        content_id = hashlib.sha256(b''.join(name.encode() + b'\0' + active[name]
                                            for name in sorted(active))).hexdigest()[:16]
        destination = home / '.local/share/account-access-retained-skills' / (host[1:] + '-' + content_id)
        require(not os.path.lexists(destination))
        plans.append((target, backup, destination, active_stamp, backup_stamp))
    if apply:
        for target, backup, destination, active_stamp, backup_stamp in plans:
            _directories(home, destination.parent.relative_to(home), create=True)
            require(_skill_snapshot(target)[0] == active_stamp
                    and _skill_snapshot(backup)[0] == backup_stamp)
            _rename_directory(backup, destination)  # Exclusive rename, never overwrite.
            _sync_directory(backup.parent)
            _sync_directory(destination.parent)
    return {'status': 'RETAINED' if apply else 'CHECKED', 'duplicate_public_backups': len(plans)}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--apply', action='store_true')
    args = parser.parse_args()
    if os.getuid() == 0 or os.getuid() != os.geteuid():
        parser.error('Run as the ordinary signed-in owner, without sudo.')
    try:
        print(json.dumps(retain_duplicates(Path(pwd.getpwuid(os.getuid()).pw_dir), apply=args.apply)))
    except Exception:
        print(json.dumps({'status': 'REFUSED', 'reason': 'duplicate_preview_backup_not_verified'}))
        sys.exit(1)
