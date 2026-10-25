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
image remained intact; the broker was absent and disabled. Two Apple
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
  the owner authenticated and package 94 installed successfully. The exact broker
  job is running, but the GUI reports `worker_process_unavailable`. All 25,167
  regular files match the target. Twenty runtime/Python links have mode 0700:
  root Installer checks can read them, but the ordinary worker's public path
  validator refuses the interpreter alias. A direct interpreter version check
  succeeds, so that check alone is also insufficient. The corrected native
  observer uses target group 0 and confirms the owner app, browsers and wheels;
  Python/runtime trees remain unreadable through those links. The staging fix
  passed 433 native adapter assertions, including link permissions, unchanged
  targets, interrupted repair, retry and foreign-path refusal. The package 95
  candidate also repairs the already-completed package 94 transition and will
  require a normal restart; it does not add a separate service-restart mechanism.
  Package 95's actual Installer qualification and subsequent owner repair are
  recorded below. No private records or installed files were changed during
  these observations. The outer package is unsigned and not notarized.
  [Owner handoff](../artifacts/owner-runtime94-installer-handoff-20261025.json).
  [Installed startup failure](../artifacts/owner-runtime94-installed-startup-failure-20261025.json).

Package **95** is built from controller `cbf0606`, with the same application
image at `7051ef2`. Its SHA-256 is
`0c7a83b47d405bd9b02686aceb938877c5cd2f36112cb0b8369069c643453371`.
All seven private draft assets match their recorded hashes. Source `95e351d`
passed 4,209 Python tests (108 skipped), dependency auditing and both native
jobs; archived native source pins were independently checked. The same source
passed separate-user Mac acceptance: all five archives and 28 reports were
verified, containing 492 passing named checks. Android 11/15 emulator and Linux
separate-user workflows also passed. Actual Installer
run `40175711160` passed all five scenarios: installation/reapplication,
owner/runtime interruption, quiescence recovery and repair of the installed
package 94 image. All five archives and 300 referenced log hashes were verified.
The 80 successor checks and 12 scenario-specific recovery checks passed, along
with 20 ordinary-identity observations and 10 exact running-broker observations.
The package 94 regression refused both ordinary identities before repair,
preserved all 20 link targets and inodes during repair, and accepted both
identities after repair and reapplication. These checks do not start a real
account worker or test an operating-system restart.

Installer's actual `RestartAction` query reports `RequireRestart`. Package 95
installed successfully on the owner Mac, and the owner restarted on 25 October.
The post-restart read-only check matches all 25,167 public files, 2,297
directories and 21 aliases. All 20 repaired links pass the ordinary-user
production runtime path validator; all five native public-tree checks pass.
The app opens to **Upgrade AI connection**, replacing the earlier startup error.
The subsequent connection upgrade failed after the owner reported macOS
approval. Reopening still offered the upgrade, and one explicit retry returned
the same generic error. The installed app does not identify the failing step;
the current agent connection and real-account operations remain unverified.
The bounded Installer result observed before restart was
`ALREADY_UPDATED_GUI_UNVERIFIED` at `complete`; the same bounded reader was
unavailable after restart. No raw install logs or private account data were
exported. The repair adds no service-control command.
[Package 95 build](../artifacts/runtime-upgrade95-build-20261025.json) ·
[Actual Installer acceptance](../artifacts/runtime-upgrade95-installer-acceptance-20261025.json) ·
[Verified draft assets](../artifacts/runtime95-draft-assets-20261025.json) ·
[Current source CI](../artifacts/runtime95-source-ci-20261025.json) ·
[Current Mac worker acceptance](../artifacts/runtime95-source-mac-acceptance-20261025.json) ·
[Current live-process evidence](../artifacts/runtime95-live-witness-20261025.json) ·
[Owner preflight](../artifacts/owner-mac-before-runtime95-20261025.json) ·
[Owner installation and restart](../artifacts/owner-runtime95-post-restart-20261025.json) ·
[Connection upgrade failure](../artifacts/owner-runtime95-agent-upgrade-failure-20261025.json).

The signed diagnostic owner app 96 identifies the failing AI-connection step
using fixed messages. Package **97** failed actual Installer run `40198410301`
at the native source check: its embedded predecessor resource container had
mode `0700`, while the native resource contract requires `0755`. Its independent
payload, signature and predecessor checks had passed, but that did not establish
installability. The run was canceled and package 97 was not installed on the
owner Mac. Source CI at `a0eb4cd` passed 4,289 Python tests (111 skipped), auditing
and all three native jobs.

Package **98** corrects only that fresh resource container and package identity.
It reuses the exact signed native helper from `91d4b7b`, with packaging source
`abb48e2` and diagnostic owner app 96. Its 13,695,014-byte package has SHA-256
`d224e47e78f4a72a454010e76a5bb0d34f355f17ed9829722861b8196694aaa6`.
The independently expanded inventory matches, the helper signature and
ordinary-user refusal pass, all three private draft assets match their hashes,
and Installer reports no restart. No native guard was relaxed. Native source
checks passed 32 parser, 26 namespace, 477 tree-storage and 324 mixed-storage
checks. Six actual Installer scenarios cover installation/reapplication, three
interrupted exchanges, and predecessors recovered through alias and
service-quiescence repairs. Each also requires package 97 to refuse at the
source checkpoint without changing the installed image or history. These
package 98 scenarios did not pass: both actual installation and the owned-helper
interruption fixture refused at `journal`. The captured native result was
`owner_upgrade_unavailable`. Both verified the corrected resource directory,
the old-package source refusal and the foreign-predecessor refusal. The two
failure archives and all 82 referenced log hashes were independently verified;
the remaining run was canceled. Package 98 was not installed on the owner Mac.
The owner Mac is on package 95, and the AI connection failure remains unresolved.
Qualification source `3bb3c8f` passed 4,295 Python tests (111 skipped), dependency
auditing and all three native jobs. The actual package's owner/runtime source
records also pass the pure native parsers. Packaging source `abb48e2` passed
28 separate-user Mac reports with 492 named checks. The new Installer run's
live Apple-identity qualification and surviving-job witness passed, with all
17 referenced log hashes independently verified. These checks do not replace
actual owner-successor Installer acceptance.
[Package 97 build](../artifacts/owner-upgrade97-build-20261025.json) ·
[Package 97 refusal](../artifacts/owner-upgrade97-installer-refusal-20261025.json) ·
[Package 98 build](../artifacts/owner-upgrade98-build-20261025.json) ·
[Package 98 refusal](../artifacts/owner-upgrade98-installer-refusal-20261025.json) ·
[Compact-source checks](../artifacts/owner-upgrade97-compact-source-20261025.json) ·
[Frozen Installer inputs](../artifacts/owner-upgrade98-installer-inputs.json).

The package 99 candidate seals its local tree intent during preparation, before
publishing the global transition. Previously the successor projection opened
that still-empty local journal read-only and correctly refused. The native
ordinary-user regression now passes 21 checks: reproducing the exact empty
journal refusal, opening the prepared journal read-only before and after parent
publication, preserving its bytes/inode and refusing foreign records. The
read-only projection remains read-only. This result is a source projection;
full controller checks, a new signed helper/package and actual Installer
qualification remain pending.
[Local journal regression](../artifacts/owner99-local-journal-regression-20261025.json).

The separate-user Mac fixture now additionally exercises an already-enrolled
client upgrading both exact legacy skills against its actual isolated worker.
It preserves the previous current trees, verifies both upgraded launchers and
idempotent reapplication, and contains no historical token or executable. This
additional integration scenario awaits its new CI result; its approval remains
synthetic and does not qualify the owner Mac's connection.

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
| Install and connect the AI agent | Package 95 owner installation, normal restart, complete public-image verification and app opening to AI connection upgrade; runtime 92 fresh-install CI | Complete and verify the current agent connection and protected account operations; clean downloaded installation and interrupted-operation recovery |
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
