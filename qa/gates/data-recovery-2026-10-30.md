# Data recovery and account controls - 2026-10-30

- `uv run --no-sync pytest -q tests/test_vault_backup.py tests/test_security.py tests/test_account_data.py tests/test_worker_boundary.py tests/test_managed_client.py tests/test_upgrade.py`: **84 passed in 38.25s**.
- The CLI backup/restore journey uses a fresh encrypted backup, changed data, explicit restore confirmation and a hidden passphrase prompt. Backup creation uses scrypt and AES-GCM, owner-only permissions, a 128 MiB bound and no overwrite of an existing destination.
- Restore validates the authenticated archive, configuration, SQLite integrity and encrypted records before publication. Wrong passphrases, tampered files, active-service races and interrupted replacements preserve or recover the prior vault. Tests cover another local key store, identity/grant/client continuity, additive schema migration and future-schema refusal.
- Explicit single-account plaintext export and local forget/delete flows are covered by owner API tests; auth, origin, malformed-input and principal checks are included in the same run.
- The build-118 image contains the current Python project and passes native payload audit and manifest preflight ([image qualification](../direct-runtime-target-image-2026-10-30.json)). It has not been installed. The owner UI and live-vault acceptance remain on F8/F1.
- **Gate: verified for source migration, encrypted backup/restore and account export/delete controls.** Installer and live owner UI acceptance remain tracked separately.
