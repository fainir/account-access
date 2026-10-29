# Account Access continuation smoke - 2026-10-30

## Current source identity and SMS path

- Command: `uv run --no-sync pytest -q tests/test_identity_contact_login.py tests/test_identity_login.py`
- Result: **52 passed in 73.65 seconds**.
- Scope: local synthetic identity/contact, SMS delivery, login recovery, expiry and refusal cases. This verifies the shared login engine, not Harel or Phoenix; neither insurer's connector is qualified by these fixtures.

## Installed agent path

- The installed Account Access launcher returned service version `0.6.0`, environment `controlled-demo`, and three synthetic accounts.
- The permitted synthetic `demo-web:summary` operation returned `RETRYABLE` with reason `browser_execution_failed`.
- `/Applications/Account Access.app` reports version `0.8.0`, build `110`.
- The build-118 direct-upgrade package is open in Installer. macOS Installer recorded only the package-open event; no install plan, install result or system-package receipt exists. Therefore build 118 has not entered installation, and no update is currently running.
- The Installer UI accessibility query timed out. No UI action, authentication or package install was performed by this check.

No private credentials, mailbox messages, insurer details or verification codes were read.
