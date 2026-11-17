"""Ordinary public fixtures for the duplicate-backup maintenance repair."""
import json
import os
from pathlib import Path
import shutil

import pytest

from account_access.agent_setup import UPGRADE_SLOT
from account_access.errors import AccessError
from scripts import retain_duplicate_preview_skills as repair
from test_agent_setup import file_bytes, home_at, legacy_skills


def duplicate_previews(tmp_path):
    home = home_at(tmp_path)
    targets, token = legacy_skills(home, root_name='account-access-video06')
    for target in targets:
        shutil.copytree(target, target.with_name(UPGRADE_SLOT))
    return home, targets, token


def test_repair_retains_both_public_backups_without_reading_any_credentials(tmp_path, monkeypatch):
    home, targets, token = duplicate_previews(tmp_path)
    before = {target: (target.stat().st_ino, file_bytes(target),
                      target.with_name(UPGRADE_SLOT).stat().st_ino) for target in targets}
    real_open = os.open

    def public_only(path, *args, **kwargs):
        if isinstance(path, (str, bytes, os.PathLike)):
            p = Path(os.fsdecode(path))
            assert p.name != 'token' and 'clients' not in p.parts and 'client-v1' not in p.parts
        return real_open(path, *args, **kwargs)

    monkeypatch.setattr(os, 'open', public_only)
    assert repair.retain_duplicates(home) == {'status': 'CHECKED', 'duplicate_public_backups': 2}
    assert not (home / '.local/share/account-access-retained-skills').exists()
    assert repair.retain_duplicates(home, apply=True) == {'status': 'RETAINED', 'duplicate_public_backups': 2}
    retained = list((home / '.local/share/account-access-retained-skills').iterdir())
    assert len(retained) == 2
    for target, (inode, files, backup_inode) in before.items():
        assert target.stat().st_ino == inode and file_bytes(target) == files
        assert not target.with_name(UPGRADE_SLOT).exists()
        saved = next(path for path in retained if path.stat().st_ino == backup_inode)
        assert file_bytes(saved) == files
    assert repair.retain_duplicates(home, apply=True)['duplicate_public_backups'] == 0
    assert token.read_text() == 'old-preview-token-must-never-be-read'


@pytest.mark.parametrize('change', ['unknown-template', 'extra-file', 'symlink', 'hardlink',
                                  'mode', 'foreign-binding', 'changed-backup'])
def test_unknown_or_changed_backup_is_preserved_and_nothing_moves(tmp_path, change):
    home, targets, _ = duplicate_previews(tmp_path)
    active = targets[1]
    backup = active.with_name(UPGRADE_SLOT)
    if change == 'unknown-template':
        for folder in (active, backup):
            (folder / 'SKILL.md').write_text('Unknown custom skill')
    elif change == 'extra-file':
        (backup / 'keep-me').write_text('Unrelated owner file')
    elif change == 'symlink':
        (backup / 'SKILL.md').unlink()
        (backup / 'SKILL.md').symlink_to(active / 'SKILL.md')
    elif change == 'hardlink':
        (backup / 'SKILL.md').unlink()
        os.link(active / 'SKILL.md', backup / 'SKILL.md')
    elif change == 'mode':
        (backup / 'SKILL.md').chmod(0o666)
    elif change == 'foreign-binding':
        for folder in (active, backup):
            binding = json.loads((folder / 'installation.json').read_text())
            binding['client_config'] = '/somewhere/clients/generic/client.json'
            (folder / 'installation.json').write_text(json.dumps(binding))
    else:
        (backup / 'scripts/access').write_text('different launcher')
    inodes = [target.with_name(UPGRADE_SLOT).lstat().st_ino for target in targets]
    with pytest.raises((ValueError, AccessError, OSError)):
        repair.retain_duplicates(home, apply=True)
    assert [target.with_name(UPGRADE_SLOT).lstat().st_ino for target in targets] == inodes
    assert not (home / '.local/share/account-access-retained-skills').exists()


def test_existing_retention_destination_is_never_overwritten(tmp_path, monkeypatch):
    home, targets, _ = duplicate_previews(tmp_path)
    repair.retain_duplicates(home, apply=True)
    retained = list((home / '.local/share/account-access-retained-skills').iterdir())
    for target in targets:
        saved = next(path for path in retained if file_bytes(path) == file_bytes(target))
        shutil.copytree(saved, target.with_name(UPGRADE_SLOT))
    before = [(path.stat().st_ino, file_bytes(path)) for path in retained]
    with pytest.raises(ValueError):
        repair.retain_duplicates(home, apply=True)
    assert [(path.stat().st_ino, file_bytes(path)) for path in retained] == before
    assert all(target.with_name(UPGRADE_SLOT).is_dir() for target in targets)


def test_changed_active_skill_after_validation_prevents_relocation(tmp_path, monkeypatch):
    home, targets, _ = duplicate_previews(tmp_path)
    original = repair._directories

    def change_before_apply(owner, relative, *, create=False):
        if create:
            (targets[0] / 'SKILL.md').write_text('Owner edited this while repair was running')
        return original(owner, relative, create=create)

    monkeypatch.setattr(repair, '_directories', change_before_apply)
    with pytest.raises(ValueError):
        repair.retain_duplicates(home, apply=True)
    assert all(target.with_name(UPGRADE_SLOT).is_dir() for target in targets)
