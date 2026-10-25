"""Disposable-Mac-CI owner-user skill setup against an actual isolated worker."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import sys
import tempfile

from account_access.agent_setup import RELATIVE, install, prepare, status
from account_access.worker_bootstrap import root_managed_path


def seed_legacy_upgrade(home, prefix, hosts, options):
    """Exchange only the exact current skills in this disposable fixture home.

    Keep the previous current trees intact; never remove or execute an old
    preview runtime. The historical client file contains no credential, and no
    old token is created. The already enrolled protected client stays in place.
    """
    from account_access import agent_setup as setup

    if home != prefix / "portable-owner-home" or hosts != ["codex", "claude"]:
        raise RuntimeError("disposable_agent_upgrade_required")
    current = status(home, hosts, **options)
    if current.get("status") != "INSTALLED":
        raise RuntimeError("fixture_current_connection_required")
    config = home / RELATIVE / "client.json"
    template = prefix / "legacy-skill-074"
    root_managed_path(template)
    root = setup._directories(home, ".local/share/account-access-review06", create=True)
    client = setup._directories(home, root.relative_to(home) / "clients/generic", create=True) / "client.json"
    from account_access.storage import private_file

    private_file(client, b'{"fixture":"credential-free-legacy-metadata"}')
    python = setup._directories(home, root.relative_to(home) / "runtime/tools/account-access/bin", create=True) / "python"
    # The historical executable and token deliberately do not exist. A passing
    # migration must use the current protected interpreter and client instead.
    if python.exists() or client.with_name("token").exists():
        raise RuntimeError("fixture_legacy_secret_or_runtime_present")
    snapshots = {}
    for target in setup._targets(home, hosts):
        before = setup._current_skill(target, target, config, options["python"])
        slot = target.parent / ".account-access-qa-current-v1"
        if os.path.lexists(slot):
            raise RuntimeError("fixture_current_backup_already_present")
        stage = Path(tempfile.mkdtemp(prefix=".account-access-qa-legacy-", dir=target.parent))
        for name in ("agents", "scripts"):
            (stage / name).mkdir(mode=0o700)
        for name in ("SKILL.md", "agents/openai.yaml", "scripts/access.py"):
            source = template / name
            root_managed_path(source)
            private_file(stage / name, source.read_bytes())
        private_file(stage / ".account-access-install", b"account-access-v1")
        private_file(stage / "installation.json", json.dumps({"client_config": str(client), "python": str(python)}).encode())
        private_file(stage / "scripts/access", ("#!/bin/sh\nexec " + shlex.quote(str(python)) + " "
            + shlex.quote(str(target / "scripts/access.py")) + ' "$@"\n').encode())
        (stage / "scripts/access").chmod(0o700)
        snapshots[target] = setup._legacy_skill(home, stage, launcher_target=target)
        setup._rename_directory(stage, target, exchange=True)
        setup._rename_directory(stage, slot)
        if not setup._same_relocated(before, setup._current_skill(slot, target, config, options["python"])):
            raise RuntimeError("fixture_current_backup_changed")
    if status(home, hosts, **options) != {"status": "MIGRATION_REQUIRED", "legacy_connections": 2}:
        raise RuntimeError("fixture_legacy_not_recognized")
    return current["client_id"], snapshots, client


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--prefix", type=Path, required=True)
    parser.add_argument("--socket", type=Path, required=True)
    parser.add_argument("phase", choices=["prepare", "install", "upgrade"])
    args = parser.parse_args(argv)
    if (
        sys.platform != "darwin"
        or os.getuid() == 0
        or os.getuid() != os.geteuid()
        or os.environ.get("GITHUB_ACTIONS") != "true"
        or args.prefix.parent != Path("/Library/PrivilegedHelperTools")
        or re.fullmatch(r"account-access-worker-qa-[A-Za-z0-9]{8}", args.prefix.name) is None
        or args.socket != args.prefix / "public/first-enrollment-agent.sock"
    ):
        raise RuntimeError("disposable_agent_setup_required")
    root_managed_path(args.prefix)
    root_managed_path(Path(__file__))
    home = args.prefix / "portable-owner-home"
    hosts = ["codex", "claude"]
    options = {"python": args.prefix / "runtime/bin/python", "socket": args.socket}
    if args.phase == "prepare":
        for name, filename in [(".codex", "AGENTS.md"), (".claude", "CLAUDE.md")]:
            directory = home / name
            directory.mkdir(mode=0o700)
            file = directory / filename
            file.write_text("Keep my existing preferences.\n")
            file.chmod(0o600)
        result = prepare(home, hosts, **options)
        assert result["status"] == "PREPARED"
        assert not (home / ".agents/skills/account-access").exists()
        print(json.dumps({"status": "PREPARED", "client_id": result["client_id"]}))
        return 0
    upgrade_checks = {}
    if args.phase == "upgrade":
        from account_access import agent_setup as setup

        preferences = {home / folder / filename: (home / folder / filename).read_bytes()
            for folder, filename in ((".codex", "AGENTS.md"), (".claude", "CLAUDE.md"))}
        previous, snapshots, client = seed_legacy_upgrade(home, args.prefix, hosts, options)
        metadata_hash = hashlib.sha256(client.read_bytes()).hexdigest()
        prepared = prepare(home, hosts, upgrade=True, **options)
        upgrade_checks["legacy_upgrade_reuses_registered_client_identity"] = prepared["client_id"] == previous
        result = install(home, hosts, upgrade=True, **options)
        upgrade_checks["legacy_upgrade_reaches_actual_worker"] = result["client_id"] == previous
        upgrade_checks["legacy_upgrade_preserves_exact_preview_backups"] = all(
            setup._same_relocated(before, setup._legacy_skill(home, target.with_name(setup.UPGRADE_SLOT), launcher_target=target))
            for target, before in snapshots.items())
        upgrade_checks["legacy_upgrade_preserves_owner_session_preferences"] = all(
            path.read_bytes() == before for path, before in preferences.items())
        upgrade_checks["legacy_upgrade_needs_no_old_token_or_runtime"] = (
            not client.with_name("token").exists()
            and not (client.parent.parent.parent / "runtime/tools/account-access/bin/python").exists()
            and hashlib.sha256(client.read_bytes()).hexdigest() == metadata_hash)
        upgrade_checks["legacy_upgrade_reapplication_is_idempotent"] = (
            install(home, hosts, upgrade=True, **options) == result)
    else:
        result = install(home, hosts, **options)
    token = (home / RELATIVE / "token").read_text()
    assert token not in json.dumps(result)
    assert status(home, hosts, **options)["client_id"] == result["client_id"]
    checks = dict(upgrade_checks)
    for name, folder in [("portable", ".agents"), ("claude", ".claude")]:
        launcher = home / folder / "skills/account-access/scripts/access"
        invoked = subprocess.run(
            [str(launcher), "accounts"],
            capture_output=True,
            timeout=15,
            env={"PATH": "/usr/bin:/bin", "HOME": str(home)},
        )
        value = json.loads(invoked.stdout)
        checks[("upgraded_" if args.phase == "upgrade" else "") + name + "_launcher_discovers_empty_approved_account_set"] = (
            invoked.returncode == 0 and value["accounts"] == []
        )
        checks[("upgraded_" if args.phase == "upgrade" else "") + name + "_launcher_omits_client_capability"] = (
            token.encode() not in invoked.stdout + invoked.stderr
        )
    for folder, filename in [(".codex", "AGENTS.md"), (".claude", "CLAUDE.md")]:
        value = (home / folder / filename).read_text()
        assert (
            value.startswith("Keep my existing preferences.")
            and value.count("<!-- account-access:automatic:start -->") == 1
        )
        assert token not in value
    checks["both_host_session_instructions_preserved"] = True
    try:
        with (args.prefix / "first-enrollment-destination/state.db").open("rb"):
            blocked = False
    except PermissionError:
        blocked = True
    checks["owner_user_client_install_has_no_broker_store_access"] = blocked
    assert all(value is True for value in checks.values())
    print(json.dumps({"status": "PASSED", "checks": checks, "client_id": result["client_id"]}))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception:
        print('{"status":"FAILED","reason":"agent_setup_fixture_failed"}')
        raise SystemExit(78) from None
