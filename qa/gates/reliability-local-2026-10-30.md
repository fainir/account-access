# Local reliability QA - 2026-10-30

- `uv run --no-sync pytest -q tests/test_worker_health.py tests/test_supervisor.py tests/test_access.py tests/test_worker_boundary.py tests/test_worker_signals.py tests/test_mailbox_health.py tests/test_gmail_reusable_mailbox.py tests/test_automatic_sessions.py`: **145 passed in 99.30s**.
- Covered bounded retry backoff, provider-down recovery, actionable health state without exception details, resumed tasks after temporary worker errors, supervisor lease/restart, checkpoints and idempotency, mailbox refresh recovery, signals, shutdown and automatic sessions.
- The package and native payload included in build 118 passed signature audit and manifest preflight ([image qualification](../direct-runtime-target-image-2026-10-30.json)). The image has not been installed; live launch, restart and installed-service recovery remain on F1/Ops.
- Account Access v1 is local-first; health is visible to the owner and there is no remote alerting service in scope.
- **Gate: verified for local health, retries, idempotency, provider-down behavior and supervisor recovery.** Installed restart acceptance remains separate.
