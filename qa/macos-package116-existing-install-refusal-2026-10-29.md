# Build 116 existing-install and agent check - 2026-10-29

- Opened the signed and notarized build 116 package in macOS Installer and started installation. Installer ended with PackageKit error 112 from `postinstall`; its public output was `system_install_not_completed`.
- Read only the protected install journal's public receipt fields. The installed intent/completion record is for the original image (`5618053e…`); build 116 targets a different image (`78113e53…`). The intent is dated 19 October; the current owner app remains bundle version 110.
- `ImageRecovery.materialize()` rejects an existing intent whose manifest differs (`install_record_conflict`) before it copies or publishes a new image. This package supports first install and same-image retry; it is not an update package. The failed attempt preserved the prior app, broker and journal.
- The package build report incorrectly said `fresh_install_only: false`. Source now labels both raw and preassembled system packages `fresh_install_only: true`; the installer emits the fixed public reason `existing_installation_requires_update` for this exact journal mismatch. A signed package must still be rebuilt before that diagnostic reaches users.
- Opened `/Applications/Account Access.app` by its full path. It showed **Upgrade your existing connection**. Starting that flow left the app waiting for the separate macOS dialog **Authorize Account Access setup**; no such dialog appeared in the computer-use app inventory.
- The installed agent launcher returned three permitted accounts in `controlled-demo` on service 0.6.0. Its one allowed synthetic summary read returned `RETRYABLE browser_execution_failed`; no account data, credentials, cookies or codes were returned. Per the Account Access skill, the direct read was not repeated.

Conclusion: build 116 is not qualified to update this owner Mac. The existing image remains in place. A supported successor update and the owner-approved agent connection are still required for end-to-end acceptance.

## Follow-up source QA

- `./.venv/bin/pytest -q tests/test_system_package.py tests/test_system_package_preassembled.py tests/test_install_transaction.py` -> 125 passed, 1 skipped. The skip is limited to `installer -volinfo` returning no volume candidates for the inert fixture on this Mac; static distribution/payload assertions ran.
- `./.venv/bin/ruff check account_access/install_transaction.py macos/system_package.py tests/test_install_transaction.py tests/test_system_package.py tests/test_system_package_preassembled.py` -> passed.
- `swiftc -frontend -parse` -> passed for `AccountAccess.swift`, `ManagedAgentSetup.swift` and `OwnerScreenChecks.swift`.
- Full native type-check and owner-screen executable could not run: the installed Swift compiler is 6.4.0.34.1 while the available macOS 27 SDK was built with 6.4.0.31.4, and no Xcode toolchain is installed. The system app remains at the **Upgrade your existing connection** screen; this source diagnostic fix has not been packaged or installed.
- The owner-screen regression cases now map a closed set of protected-store response reasons to fixed explanations. Unknown reasons are reduced to one generic safe message; response details, paths and client capabilities are never included.

## Extended local regression check

- `./.venv/bin/pytest -q --tb=short` in the default sandbox could not run integration fixtures because binding `127.0.0.1` raised `PermissionError: Operation not permitted`; this is an execution permission failure, not a test assertion failure.
- Retried with loopback access. The full suite was manually interrupted after 315 seconds at 650 passed and 1 skipped while a storage lock was held; it did not complete, so it is not a full-suite pass.
- Isolated `tests/test_browser_sessions.py` with loopback access -> 45 passed in 57.97s. The focused installer/package/transaction suite remains 125 passed, 1 host-specific skip; Ruff and Swift syntax parsing passed.
- Full native type-check remains unverified because the local Command Line Tools compiler and macOS SDK were built from different Swift revisions. The current Swift changes are not packaged or installed.

## Current commit CI acceptance

- [Push CI](https://github.com/fainir/account-access/actions/runs/40866251182) passed the full Python test job and native owner UI, owner gateway, and owner-upgrade source checks for commit `e23e1e4`.
- [Mac worker acceptance](https://github.com/fainir/account-access/actions/runs/40866251306) passed cross-user password, email, SMS and authenticator recovery, plus offline development-package build and smoke installation in a disposable VM.
- [Android CI](https://github.com/fainir/account-access/actions/runs/40866251198) passed the Android 11 automatic/owner-entered journey and Android 15 refusal journey. [Linux cross-user acceptance](https://github.com/fainir/account-access/actions/runs/40866251227) also passed.
- These checks validate test identities and a development package. They do not install a signed successor update on the owner's Mac, confirm his live AI connection, or qualify Harel/Phoenix and private Gmail/Lemon Squeezy sessions.
