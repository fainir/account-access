# Production acceptance

**Account Access remains a preview. Production readiness is false.**

Updated 25 October 2026. The requested outcome is installation, local Chrome
password import, email/SMS/authenticator setup, and later approved sign-ins
through the user's existing AI agent. Controlled tests cover those mechanisms;
they do not establish personal-account or physical-phone acceptance.

## Current Mac recovery

Package 91 installed successfully on the owner Mac. Its subsequent **Connect
automatically** action failed because the agent-upgrade checker did not recognize
a named preview root. Runtime 92 contains the fix and passed fresh installation
and reapplication on a disposable Mac.

Package 93, which upgrades that existing installation to runtime 92, passed its
three disposable-Mac Installer scenarios but failed on the owner Mac while
waiting for the dedicated service identity to become empty. The old public
image remains intact; the broker is currently absent and disabled. Two Apple
per-user services survived removal of that user domain.

Package **94** is built from controller `b5ea8a2`, retaining the frozen runtime 92
application payload at `7051ef2`. It permits only the two specific Apple service
identities after live code-signature, executable-path and process-identity
attestation. Unknown processes, changed observations and failed attestation
still refuse the update. The package SHA-256 is
`1086e6eac90083489c7b85578f5267eaee77bdd6b3844b1b4a4579d89c731c3e`.

- Its seven draft assets match their recorded sizes and hashes.
- Controller source CI passed 4,178 Python tests (108 skipped), dependency
  auditing and both native jobs. Separate-user Mac CI produced 28 verified
  passing reports containing 492 named checks. Local core checks (377) and
  runtime checks (68) also passed.
- Hosted live-process qualification passed for both Apple identities and
  rejected incorrect identities. The repeat dedicated-UID survival fixture
  passed; its archive and all 16 referenced log hashes were verified.
- Actual Installer run `40128222988` passed all four scenarios: installation and
  reapplication, interruption of the owner-app exchange, interruption of the
  runtime exchange, and recovery after the old package leaves its owned disabled
  transition. All 52 successor checks and six extra recovery checks passed.
  All four archives and 221 referenced log hashes were independently verified.
  Eight complete launchd observations also passed the stronger exact-job check.
  The recovery evidence confirms both intended refusals and the same Apple
  process surviving through successful recovery.
- A new read-only owner preflight matched all 25,166 old public files, 2,297
  directories and 21 links, and verified the exact package 94 hash. On 25 October,
  the owner Mac was unlocked and package 94 was opened to the Installer's Install
  button. Regenerable project build expansions were cleared to recover about
  2.48 GB; all tested installers and evidence were retained. Owner authentication,
  successful installation, service recovery and **Connect automatically** remain
  pending. The outer package is unsigned and not notarized.
  [Owner handoff](../artifacts/owner-runtime94-installer-handoff-20261025.json).

[Actual Installer acceptance](../artifacts/runtime-upgrade94-installer-acceptance-20261024.json) ·
[Owner preflight](../artifacts/owner-mac-before-runtime94-20261024.json) ·
[Package build](../artifacts/runtime-upgrade94-build-20261024.json) ·
[Controller CI](../artifacts/runtime94-controller-source-ci-20261024.json) ·
[Separate-user Mac checks](../artifacts/runtime94-source-mac-acceptance-20261024.json) ·
[Live-process evidence](../artifacts/runtime94-live-witness-20261024.json) ·
[Owner package 93 refusal](../artifacts/runtime93-owner-quiescence-refusal-20261024.json).

## Requested end-to-end acceptance

| User journey | Verified evidence | Remaining acceptance |
| --- | --- | --- |
| Install and connect the AI agent | Package 91 owner installation; runtime 92 fresh-install CI; automatic skill discovery in earlier owner testing | Package 94 recovery, successful current owner setup and agent connection, clean downloaded installation, reboot and interrupted-operation recovery |
| Import Chrome passwords | One approved personal credential imported locally through protected owner setup; controlled format, review and permission tests | Fresh private-website login using the imported credential; representative export coverage. Imports are snapshots; Chrome live sync is not implemented |
| Email verification | A real Gmail enrollment and mailbox check passed; controlled fresh-code login and sender/template checks | Actual website email delivery and completed login. Consumer Gmail OAuth also needs a publisher-configured Google application and real consent/renewal QA |
| Android SMS | Android 11 emulator completes a synthetic browser SMS login; Android 15 emulator refuses delivery without association | Physical Android 15+ installation, system-approved computer association, carrier notification delivery, reconnect and completed insurer login |
| Harel and Phoenix | Public login-page investigation; narrow identity/phone session-status machinery | Reviewed connectors for each complete flow, private local enrollment, verified sender/template and authenticated marker. Neither insurer is currently supported end to end |
| Lemon Squeezy authenticator | TOTP and supported QR/transfer-batch fixtures; official provider setup documentation reviewed | Reviewed provider login flow, local owner enrollment of the existing account and completed real TOTP login |
| Agent continuation | Installed portable CLI/skill, durable approved-operation tasks, synthetic authentication recovery, session reuse and revocation checks | Real-account task continuation, session reuse, expiry, password change, source revocation and restart without restoring revoked access |
| Consumer distribution | Developer ID signed native components; offline package and provenance checks | Developer ID Installer signing, Apple notarization/stapling, downloaded clean-Mac qualification and production Android distribution |

The installed skill starts with permitted-account discovery. It can submit
supported operations as durable tasks and resume them after owner authentication.
It does not intercept every browser tool or automatically resume an entire AI
conversation. Importing a password does not create a connector for any website.
Mandatory passkeys, biometrics, phone unlocks or administrative approvals still
require genuine owner presence.

[Insurer scope](insurer-login-acceptance.md) ·
[Provider coverage](other-service-validation.md) ·
[Agent setup](mac-agent-setup.md) ·
[Agent QA boundary](agent-qa-boundary.md) ·
[Automatic sessions](automatic-sessions.md).

## Current Android candidate

Source `df12c47` keeps unrelated apps' notifications from replacing the last
login-delivery status. Source run `40128583358` and PR run `40128591173` both passed
the Android 11 and Android 15 emulator journeys. The Android 15 test observes a
blocked login notification, posts a separate real shell notification and checks
that the blocked status and zero-delivery timestamp remain unchanged.

Both source-run APK archives and their APK hashes were independently verified.
The same source passed 4,181 Python tests (108 skipped), dependency auditing,
both native jobs and separate-user Mac CI. Its five Mac archives, 28 passing
reports and 492 named checks were verified. See
[source CI](../artifacts/android-status-source-ci-20261024.json) and
[Mac evidence](../artifacts/android-status-source-mac-ci-20261024.json).
The Android 15 development APK has SHA-256
`1f38c3ca3cbea45fe6edc879298238255ccebd43d5f2b6017d8af9934d487572`.
This is not physical Bluetooth-association or SMS-delivery acceptance.
[Android evidence](../artifacts/android-status-race-fixed-20261024.json) ·
[Phone setup](../android/README.md).

## Additional supported mechanisms and limits

Controlled coverage also includes TLS IMAP, iPhone-to-Mac Messages collection,
Google Messages Web preparation, approved 1Password/Bitwarden synchronization,
protected key custody and operation revocation. Their private enrollment,
rotation, consent and delivery requirements remain open where no corresponding
owner result is recorded. Arbitrary webmail, authenticator push approvals,
nonstandard TOTP, Google Authenticator cloud sync and native Windows support
are not implemented. The Google Messages Web pilot is limited to its reviewed
GitHub flow and does not qualify the requested insurers.

## Evidence and owner boundaries

Private GitHub testing was stopped at the owner's request. The blocked Namecheap
attempt is quarantined. Neither is a substitute for the selected acceptance
sites. Real tests should establish fresh login, session reuse, revocation and
recovery through permitted operations; they should not read unrelated policy,
medical or financial records.

Passwords, exports, cookies, QR secrets, message contents and raw private traces
stay local. Public evidence records sanitized outcomes, exact source/package
identity and test scope. Interrupted owned-helper tests do not demonstrate
physical power-loss recovery. No fictional fixture or mailbox connectivity check
closes a real login or delivery gate.

The complete [qualification history](qualification-history-20261024.md) preserves
earlier passes, failures and their original scope. Source-specific counts must
not be presented as results for a different package. See also the
[validation record](validation.md) and [security architecture](architecture.md).
