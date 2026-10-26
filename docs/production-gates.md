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
The installed agent launcher also returned `RETRYABLE/service_unavailable` on
three account-discovery checks; it returned no account metadata, and no login
operation or code request was made. This is the launcher's generic unavailable
result and does not identify its underlying cause.
[Launcher discovery](../artifacts/owner-agent-launcher-discovery-20261025.json).
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
the full native controller also passed 32 parser, 26 namespace, 21 preparation,
477 tree and 324 mixed-storage checks. Controller source `9b867da` passed
4,303 Python tests (111 skipped), dependency auditing and all three native jobs.
Package **99** is built from that source, with SHA-256
`b478bee55de47feb3cf0af91c1cd072a67db02a5979ba67a490ae6cd4cc87b85`.
Its signed helper, independent extracted inventory and no-restart query pass;
all three private draft assets match their hashes. Its seven-scenario actual
Installer run failed before native execution: assembly replaced the helper but
retained the previous helper digest in the shell wrapper. The strict shell hash
guard refused it, so the expected native foreign-predecessor result was absent.
The first failure archive and all 63 referenced log hashes were verified; the
remaining run was canceled. Package 99 has not been installed on the owner Mac.
The live Apple-identity qualification for run `40212316045` passed all five
checks; its ten native source pins and all 17 surviving-job witness log hashes
were verified independently. These passing observer checks do not qualify the
failed package.
Qualification source `68bed08` passed 4,326 Python tests (112 skipped), dependency
auditing and all three native jobs. This source includes the additional
publication-boundary Installer scenario; that scenario's actual result remains
pending.
[Local journal regression](../artifacts/owner99-local-journal-regression-20261025.json) ·
[Native controller checks](../artifacts/owner99-native-source-ci-20261025.json) ·
[Controller source CI](../artifacts/owner99-controller-source-ci-20261025.json) ·
[Qualification source CI](../artifacts/owner99-qualification-source-ci-20261025.json) ·
[Package 99 build](../artifacts/owner-upgrade99-build-20261025.json) ·
[Package 99 inputs](../artifacts/owner-upgrade99-installer-inputs.json) ·
[Package 99 refusal](../artifacts/owner-upgrade99-installer-refusal-20261025.json) ·
[Current live-process evidence](../artifacts/owner99-live-witness-20261025.json).

Package 100 corrects that wrapper binding without changing the
signed native helper or diagnostic owner app. The builder now checks the exact
shell digest guard against the actual helper both before packaging and after
independent expansion. Fifty local builder checks pass, including the exact
rejected package 99 wrapper and an ordinary-user execution of its hash guard
against owned fictional bytes. The actual package 100 guard also accepts the
frozen signed helper while the rejected package 99 guard refuses those same
bytes; this ordinary-user check does not execute the helper. Package 100's
13,983,039-byte build has SHA-256
`f0703c7e89d68ff29668c72803b644a73ca0f9ad701258a5913bb1c0e9e86710`.
The independent extracted inventory, shell binding, signature and no-restart
query pass; all three private draft assets match their hashes. All 104 focused
builder, plan and Installer-acceptance contract checks passed. Its actual
Installer run failed before native execution on macOS 15: the manual helper
rebuild omitted the standard builder's deployment target, so its Mach-O minimum
was macOS 27 and dyld could not load `libswift_DarwinFoundation1.dylib`. The shell
binding check passed. The first failure archive and all 63 referenced log hashes
were verified; the remaining run was canceled. The unchanged owner app 96 declares
macOS 14 in both slices. Package 100 was not installed on the owner Mac.
[Package 100 build](../artifacts/owner-upgrade100-build-20261025.json) ·
[Exact shell binding](../artifacts/owner100-shell-binding-20261025.json) ·
[Package 100 inputs](../artifacts/owner-upgrade100-installer-inputs.json).
[Package 100 loader failure](../artifacts/owner-upgrade100-installer-refusal-20261025.json).

Package 101 preparation uses the standard builder's explicit macOS 14 target.
The builder now inspects the actual ARM64 Mach-O load commands before signing
and after independent package expansion. Its 66 local contract checks reject
the exact package 100 build-version record, newer deployment targets, wrong
platforms/architectures and malformed commands. A new hosted-Mac compatibility
probe will verify the package's metadata, wrapper and signature, then run only
the ordinary-user refusal before any installed-image reconstruction. Its four
guard checks ensure it refuses owner machines, root, unrelated repositories and
unrecognized temporary paths before touching inputs. The standard builder
produced package 101 with the actual helper minimum set to macOS 14, matching
wrapper binding, a valid signature, ordinary-user refusal and an independently
expanded matching inventory. Its 13,696,702-byte package has SHA-256
`a63affe44b86f36c32a60913a365bb8cf45824a4b6eb278892895c9b36764c0d`.
All three private draft assets match their hashes. All 128 focused builder,
compatibility-guard, plan and Installer contract checks pass. The hosted macOS
15.7.9 launch check passed all five checks and all 18 referenced log hashes were
verified. The helper actually loaded and returned its expected ordinary-user
refusal before any installation. Qualification source `43c4c7a` also passed
4,368 Python tests (112 skipped), dependency auditing and all three native jobs;
the three native archives and all 53 source hashes were independently verified.
The live Apple-identity and surviving-job prerequisite passed all five checks
with 17 verified log hashes. The publication-boundary interruption scenario
also passed actual Installer execution, retry and reapplication: all 79 log
hashes, eight ordinary-identity runtime checks and seven running-broker
observations were independently verified. The local journal was sealed before
publication, the public image remained unchanged at the interruption, and
service disabling had not started. This directly qualifies that recovery case;
all six additional cases also passed: install/reapply, alias-repair recovery,
owner-identity interruption, owner-helper interruption, host interruption and
service-quiescence recovery. Across all seven actual Installer scenarios, the
independent verifier checked 562 referenced log hashes, 56 ordinary-identity
observations and 43 running-broker observations. The owned-helper interruption
tests do not simulate installer-daemon interruption, power loss or an OS
restart. Package 101 remains uninstalled on the owner Mac. The outer package
has no signature and is not notarized; this is still a private QA draft, not a
production installer.
On 26 October, the owner Mac's attempted package 101 install reached the native
helper and refused with `owner_upgrade_transition_conflict` at `predecessor`.
The package receipt is absent, the installed owner remains version 92, and its
code signature still verifies. See [owner-machine refusal evidence](../artifacts/owner101-owner-mac-install-refusal-20261026.json).
The seven disposable-Mac passes did not cover this existing owner state, so
they do not qualify package 101 for upgrade or establish production readiness.
The local signing inventory contains one Developer ID Application identity but
no Developer ID Installer identity, which Apple requires for a signed package.
No notarization submission or stapling has been made. The signing pipeline is
documented and locally tested, but this Mac currently lacks the identity needed
to produce the trusted installer. [Local signing readiness](../artifacts/owner101-installer-signing-readiness-20261025.json) ·
[Apple certificate types](https://developer.apple.com/help/account/certificates/certificates-overview/).
[Package 101 build](../artifacts/owner-upgrade101-build-20261025.json) ·
[Standard build command](../artifacts/owner-upgrade101-build-command.py.txt) ·
[Package 101 inputs](../artifacts/owner-upgrade101-installer-inputs.json) ·
[Actual macOS 15 launch](../artifacts/owner101-macos15-entrypoint-20261025.json) ·
[Source CI](../artifacts/owner101-qualification-source-ci-20261025.json) ·
[Native source evidence](../artifacts/owner101-native-source-ci-20261025.json) ·
[Live-process evidence](../artifacts/owner101-live-witness-20261025.json) ·
[Full Installer acceptance](../artifacts/owner-upgrade101-installer-acceptance-20261025.json).

Qualification source `d81e11f` passed 4,344 Python tests (112 skipped), dependency
auditing and all three native jobs. The three native archives and all 53 source
pins were independently verified, as were the current live observer's five
checks and 17 witness logs. These do not qualify the failed package 100.
[Source CI](../artifacts/owner100-qualification-source-ci-20261025.json) ·
[Native evidence](../artifacts/owner100-native-source-ci-20261025.json) ·
[Live-process evidence](../artifacts/owner100-live-witness-20261025.json).

The separate-user Mac fixture now additionally exercises an already-enrolled
client upgrading both exact legacy skills against its actual isolated worker.
It preserves the previous current trees, verifies both upgraded launchers and
idempotent reapplication, and contains no historical token or executable. This
additional integration scenario passed at source `6ea62ab`: five verified
archives contain 28 passing reports and 502 named checks, including all ten
new upgrade and launcher checks. Its approval remains synthetic and does not
qualify the owner Mac's connection.
[Legacy-upgrade worker evidence](../artifacts/legacy-agent-upgrade-source-mac-acceptance-20261025.json).

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

The Android publisher build at `ff6ee30` accepts an existing private signing key
and independently recorded certificate fingerprint. It requires increasing
version codes for updates, refuses development certificates and never generates
or uploads a replacement key. The actual SDK fixture signed versions 2 and 3
with one disposable certificate and refused a wrong signer and non-increasing
version before requesting a password. Its archive and report hashes were
verified. Android 11/15 emulator workflows also passed at that source. No
publisher key, physical installation or real update/pairing was qualified.
[Publisher-signing fixture](../artifacts/android-publisher-signing-fixture-20261025.json).

Phone source `b3c48ef` also bundles the unchanged upstream ZXing 3.5.3 license
and notice text, with an offline license viewer. The publisher builder records
the asset in its source manifest and refuses extra asset files or linked asset
directories. Its actual local SDK fixture passed all 21 checks. Android 11/15
emulator journeys and the hosted signing fixture also passed; all three archives,
their reports and notice inclusion in both preview APKs were independently
verified. These are synthetic emulator and signing results, not physical-phone
delivery or publisher-key acceptance.
[Notice provenance](../artifacts/android-zxing-notice-provenance-20261025.json) ·
[Local SDK fixture](../artifacts/android-notices-local-sdk-20261025.json) ·
[Verified hosted evidence](../artifacts/android-notices-sdk-emulator-20261025.json).

An additional hosted-emulator scenario now checks normal package updates from
version 2 to 3 and reapplication of version 3 with the same disposable certificate.
It must preserve app UID, encrypted pairing bytes, Keystore decryption and SMS
preferences. It refuses non-hosted environments and physical or ambiguous ADB
targets before installation. Local compilation and all 27 focused checks pass.
The first new fixture run stopped before the emulator because its strict file
list did not account for the SDK's optional signature sidecar. The corrected
test signer emits a self-contained instrumentation APK; its v2/v3 signatures
were verified locally. At source `1663f42`, both actual emulator update journeys
and the signing fixture passed. All five archives and reports were independently
verified; the Android 11 update's certificate and APK hashes also match the
retained signing report. Pairing decrypted after update and reapplication with
unchanged encrypted bytes, preferences and app UID on Android 11 and 15. This
does not test an existing real Bluetooth association, carrier SMS, a publisher
key or a physical-phone update.
[Verified signed-update evidence](../artifacts/android-signed-update-pairing-20261025.json).

Phone source `f0fe6b7` declares Android's documented companion background-run
and background-data permissions and explains their purpose before pairing.
Notification forwarding still requires the current saved pairing and Android
association. Its actual SDK signing and Android 11/15 emulator journeys passed.
All five archives were independently verified, including the exact four
permissions and upstream notices in both APKs. Android 15 forwarding remained
refused without association, and signed updates preserved encrypted pairing on
both emulators. This is not positive background delivery: screen-off, Data Saver,
reconnect and carrier SMS remain physical-phone acceptance gates.
[Verified companion-background candidate](../artifacts/android-companion-background-sdk-emulator-20261025.json).

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
