# Local reliability QA - 2026-10-29

## Evidence

- Command: `uv run pytest -q tests/test_worker_health.py tests/test_supervisor.py tests/test_access.py tests/test_worker_boundary.py tests/test_worker_signals.py tests/test_mailbox_health.py tests/test_gmail_reusable_mailbox.py tests/test_automatic_sessions.py`
- Result after fix: **145 passed** in 94.89 seconds.
- Race regression command: `uv run pytest -q tests/test_access.py::test_concurrent_rotating_refresh_is_singleflight tests/test_vault_backup.py tests/test_worker_health.py`
- Race regression result: **17 passed** in 21.69 seconds.

## What the source checks cover

- Worker retry backoff is bounded and provider failures remain retryable instead of turning into false owner challenges.
- Worker health hides exception details while reporting actionable local health states.
- A temporary worker failure resumes tasks; supervisor lease and process restart paths are exercised.
- Idempotency and checkpoints prevent a retry from repeating completed work.
- Mailbox refresh failure, signal handling, shutdown and automatic session behavior are exercised.
- The expanded backup/recovery work introduced a constructor race: concurrent Store instances used to fail immediately while checking the restore journal. Recovery now takes a bounded 10-second exclusive lock, serializing short startup checks while keeping stores unavailable during an active restore. The concurrent refresh test and vault recovery suite pass with this change.

## Limits

This is local source evidence. The notarized build-117 successor is qualified but remains uninstalled, so installed-service restart recovery has not been observed on the owner's Mac. Account Access is local-first v1 and does not promise a remote alerting service; health is visible to the owner locally. Build/package restart acceptance remains tied to F1 in `READINESS.md`.

Ruff, Python compilation and `git diff --check` are recorded after the ledger update.
