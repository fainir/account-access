# Production acceptance

**Account Access is a preview, not a production release.** The requested outcome
is a simple installation, one-time local enrollment, and later routine sign-ins
through the user's existing AI agent. Passing fictional-account tests does not
establish that experience on personal accounts.

## Current candidate

### Runtime dependency update — 24 October 2026

Current CI reported CVE-2026-112940, CVE-2026-112913 and CVE-2026-112907
against the runtime's filelock 3.32.7. Source now requires filelock 4.2.4 and
regenerates the hash-pinned runtime requirements. The local dependency audit
reports no known vulnerabilities. Supervisor/provisioning checks and password
sync contention tests passed with the new dependency. Rebuilt runtime 89 passed
fresh installation/reapplication; packages 85/87/88 retain their frozen
older runtime and are not production release candidates. The fresh-87 build is
only a packaging/installation investigation of those exact historical bytes.

Fresh runtime **89**, built from `57663aa`, now contains filelock 4.2.4. That
source passed 4,053 Python tests with 108 skipped, the dependency audit and
native UI/gateway checks. Independent expansion verified all 25,167 public
files, 2,297 directories and 21 aliases, the exact source wheel, native signatures
and native manifest counts. Actual fresh installation/reapplication passed all
13 checks in run `40053834768`; the downloaded report and all 29 referenced log
hashes were verified. The 27,485 installed public nodes matched, and reapplication
preserved public bytes and inodes. The service was observed live and the GUI
quit normally after each installation; these are not owner-store readiness tests.
Its container is unsigned and not notarized. Updating an existing different
public image also remains unqualified.
[Build review](../artifacts/fresh-runtime89-build-review-20261024.json) ·
[Source CI](../artifacts/runtime89-source-ci-20261024.json) ·
[Actual fresh Installer acceptance](../artifacts/fresh-runtime89-installer-acceptance-20261024.json).

### Broker store repair candidate — 24 October 2026

The next controller removes redundant recovery-view and operation-state walks
only when reading an already completed predecessor. Both full new-image
verification passes remain, around the completion evidence read; the head is
also checked against the exact intent. Mutable repair and recovery retain their
existing sequence. Fixed stage names and monotonic elapsed seconds now report
progress without paths, account data or underlying errors. Native source
validation passed, including 250 installed-adapter checks and the existing
predecessor, journal, namespace and repair suites; 86 focused Python tests passed.
This is source qualification, not a successful owner installation. Severe system
load was observed during the timeout; redundant scans are a possible contributor,
not a measured root cause. Package 90 is built and independently verified: all 27,523 expanded entries
matched, with only the signed controller and its wrapper changed from package
87. Its SHA-256 is `a9830e12cbaaf95ce2fe80add81d116498d571c57bbd9509b70f20a59f62f0a4`.
Draft assets are frozen by ID, size and SHA-256. The updated asset contracts and
Installer harness passed 97 focused checks. All three actual Installer scenarios
passed in run `40103870112`: install/reapply, owned-helper interruption/recovery,
and foreign-binding rollback. Each passed 13 repair, 15 predecessor and 11 root
revalidation checks. All 120 referenced log hashes and all three archive hashes
were verified; two owned-helper logs are additionally bound by their whole-archive
hash. Closed progress records show both full verification passes. The normal
repair completed in 167 seconds on the disposable Mac and reapplication took
13 seconds. These timings do not establish owner-Mac performance.

Controller source `4807187` passed 4,065 Python tests (108 skipped), lint,
dependency auditing, native UI/gateway and Mac/Linux/Android suites. The latest
qualification controller's Python suite passed 4,076 tests (108 skipped). An owner
public-image preflight still matched image 85; the installed account launcher
returned `RETRYABLE / service_unavailable`. The owner installation then passed both
full-image verification passes and reached migration at 163 seconds, where it
refused with `component_base_not_verified`. The user confirmed Installer failure.
A complete public-image comparison confirmed image 85 was restored: 25,165 files,
2,297 directories and 21 links matched. It read no private store and does not
prove service health. The failing migration predicate remains unidentified;
owner installation, store access and personal sign-ins remain unqualified.
[Owner failure](../artifacts/owner-mac-repair90-attempt1-result-20261024.json) ·
[Public rollback verification](../artifacts/owner-mac-after-repair90-attempt1-20261024.json). The first workflow attempt stopped before tests because an
action pin was altered during copying; the corrected run and regression check
are recorded separately.
[Package review](../artifacts/broker-repair-package90-20261024.json) ·
[Actual Installer acceptance](../artifacts/broker-repair90-installer-acceptance-20261024.json) ·
[Controller source CI](../artifacts/repair90-controller-source-ci-20261024.json) ·
[Initial workflow setup failure](../artifacts/repair90-first-workflow-setup-failure-20261024.json).
[Source validation](../artifacts/repair90-progress-source-20261024.json).

Package **88** is built from repair-controller source `eba8057`, while preserving
package 87's exact application payload and repair plan. Independent expansion
verified all 27,523 entries, with only the repair helper and its hash-checking
wrapper changed. The helper's Developer ID signature and ordinary-user refusal
passed. Its draft assets are pinned by ID, size and SHA-256 for the three actual
Installer scenarios. All three passed in run `40051324286`: install/reapply,
owned-helper interruption/recovery, and foreign-binding rollback. Each passed
13 repair, 15 predecessor and 11 root-revalidation checks. All 120 referenced
log hashes were independently verified. The foreign-binding case applied and
restored five changes on each of two attempts without publishing a head. This
is not a power-loss test. The owner installation failed on 24 October after
the package script exceeded its 1,800-second deadline. A full read-only check
confirmed the previous image 85 remained intact: 25,165 files, 2,297 directories
and 21 links matched. No private account store was read. Store/GUI acceptance
remains unqualified. The container remains unsigned; this is not a production
runtime update.
[Owner timeout](../artifacts/owner-mac-repair88-attempt1-result-20261024.json) ·
[Post-attempt image verification](../artifacts/owner-mac-after-repair88-attempt1-20261024.json).
[Package 88 build evidence](../artifacts/broker-repair-package88-20261024.json) ·
[Actual Installer acceptance](../artifacts/broker-repair88-installer-acceptance-20261024.json) ·
[Owner public-image preflight](../artifacts/owner-mac-broker-repair88-preflight-20261024.json).

The owner's installed public image was still full image 85 after a Mac restart
on 24 October. The first owner attempt at package 87 did not complete. A fresh
read-only comparison against image 87 found exactly its three changed public
paths unmatched; all unchanged entries in the inventory of 25,165 files,
2,297 directories and 21 links matched. Those three paths were independently checked against image
85 and matched that predecessor, including the expected absent repair-identity
file. Together these checks establish an intact image 85, not a completed repair
or a mixed image. No private store was read. The retry of the same hash-verified
package reached its native helper and refused with `broker_repair_not_verified`
at `predecessor`; Installer displayed failure. Another complete public-image
check plus the three-path predecessor comparison again establishes intact image
85. The repair namespace is absent. Store access and GUI acceptance remain
unqualified. Source review identifies a completed full-image journal's transient
device-number requirement as a restart compatibility gap; the coarse owner
checkpoint does not identify which nested predicate failed.

A source fix now verifies completed historical records through the existing
volume receipt and exact predecessor evidence without rewriting the records.
The corrected native fixtures passed, including 429 directory-storage and 312
mixed file/tree checks. The initial reproduction had a missing canonical newline;
that limitation is retained alongside the corrected evidence. Successor package
88 passed actual Installer acceptance but timed out on the owner Mac; owner
verification remains unqualified.
[Restart source evidence](../artifacts/full-image-restart-source-20261024.json).

[Post-restart target comparison](../artifacts/repair87-restart-owner-mac-after-repair87.json) ·
[Predecessor confirmation](../artifacts/repair87-restart-owner-mac-restart87-predecessor.json) ·
[Retry result](../artifacts/owner-mac-repair87-retry1-result-20261024.json).

Package **87**, built from `c4cf1b0`, passed all three actual Installer scenarios
in run `39989349794`: installation/reapplication, interruption after broker
replacement followed by recovery/reapplication, and foreign-binding rollback.
Each passed all 13 repair checks, plus the predecessor installation and volume
revalidation checks. Downloaded report ZIPs and every referenced log were
hash-verified. The foreign-binding case proves five changes applied and five
restored on each of two attempts, with no head published and the foreign binding
unchanged. Both native refusals occurred at migration. Interruption uses an
owned helper child; it is not a machine power-loss test.

The package SHA-256 is
`27ee29eea45992461d0d8e5d2f36878a784b15f52713066f9710647715420994`.
Its independent expansion verified 27,523 entries. The exact source passed
4,000 Python tests with 107 skipped tests, lint, dependency auditing, the native
suite including 40 namespace and 74 repair-transaction checks, Android CI, and
the Mac fixture suite. Android 15 coverage proves refusal without association;
it does not qualify physical delivery.

Package 86 was withdrawn before owner installation. Its new directory could
inherit the parent's group on macOS; package 87 normalizes only its exclusively
created directory and refuses existing mismatches. Failed and cancelled runs
remain recorded. The container is unsigned, and no Developer ID Installer
identity is currently available locally. The release remains draft.

Owner GUI, agent connection, personal-account login and physical-phone QA,
production signing and notarization remain open. No fixture result establishes
those outcomes.

[Exact Installer evidence](../artifacts/broker-repair87-installer-acceptance-20261023.json) ·
[Package review](../artifacts/broker-repair-package87-20261023.json) ·
[Native and Python CI](../artifacts/broker-repair-c4-native-ci-20261023.json) ·
[Mac fixture CI](../artifacts/broker-repair-c4-mac-ci-20261023.json) ·
[Owner preflight](../artifacts/owner-mac-broker-repair87-preflight-20261023.json) ·
[Withdrawn candidate](../artifacts/broker-repair86-withdrawal-20261023.json).

### Current application candidate — 23 October 2026

Installer 84 combines the protected-volume repair with app source `d30fda7`
and updater source `d5cd6b7`. Its complete image, signed application, exact
16-check native plan, package contents and corresponding-source archive passed
separate reviews. The app-source suite passed 3,828 tests with 107 skipped;
native UI/gateway, Android, Linux and Mac acceptance workflows passed within
their existing controlled-account scopes. The new Installer cohort passed 106
focused checks. Actual install/reapply and both interruption scenarios each
passed all 18 checks in run `39922461687` against those exact draft assets.
The first owner-Mac attempt failed with a package-script timeout. A subsequent
public-image check found exactly five owner-app files changed, all matching the
target image; the remaining predecessor files, directories and aliases still
matched. This is an interrupted update, not an intact predecessor or a completed
installation. The same-package recovery attempt also timed out. A subsequent
check of all 411 changed manifest entries found five matching the target and
406 matching the predecessor, with no unrecognized entry. This limited delta
check does not qualify the complete installed image.
[Owner attempts](../artifacts/owner-mac-update84-result-20261023.json).

Apple's installed `pkgbuild(1)` documentation specifies a ten-minute default for
top-level scripts. A separate disposable-Mac probe tests a fixed script timeout
in the native package envelope. All five checks passed in run `39940826551`
on macOS 15.7.9: a 15-second deadline terminated the short fixture in 16.621
seconds, while a 900-second deadline allowed the 610-second fixture to complete
in 612.428 seconds. Both earlier preparation failures are retained.
[Deadline evidence](../artifacts/installer-deadline-acceptance-20261023.json).

A deadline-only derivative sets the existing package's timeout to 1,800 seconds.
An independent XAR-header, checksum and streamed-member review confirms that
the compressed Scripts archive is byte-identical; only the PackageInfo timeout
content changes. The exact candidate passes its source contract, and 13 altered
inputs are refused. Actual candidate installation/reapplication and both
interruption scenarios passed all 18 checks each in run `39945206041`. Each
downloaded report and its retained log digests were independently checked. The
controller suite passed 3,906 tests with 107 skipped, with native UI/gateway,
lint, dependency audit and source/wheel builds passing. Native Installer completed
the verified repair on the owner Mac. Independent verification matched 25,165
files, 2,297 directories and 21 aliases and confirmed all 237 removed public
paths are absent. This qualifies the public image, not account access.
[Exact derivative and draft assets](../artifacts/full-image85-deadline-package-20261023.json).

The native owner app still refuses to open the protected store, including after
one Check again. Public Python imports and the native public runtime/ACL checks
pass. The exact store failure is not yet exposed by the installed broker.
The corrected read-only native diagnostic now confirms that the directory inode
pair matches the registration but the filesystem device number has changed.
The installed skill launcher also discovers only a legacy controlled demo at
service version 0.6.0. It has not been reconnected to this protected installation.
Only root-owned registration metadata and directory stat metadata were inspected;
credential contents, client tokens and private account configuration were not.
[Owner result](../artifacts/owner-mac-update85-result-20261023.json).
[Registration result](../artifacts/store-registration-device-result-20261023.json).

New source retains fixed store-startup checkpoints and failure categories for
native owner state/health and system diagnostics. Known categories get fixed
UI explanations; arbitrary error text is never rendered. Device-only changes
in the publication record are distinguished from changed directories, but both
remain refused without an independent volume binding. The device-number mismatch
has now been observed on this Mac.
This diagnostic source has not been installed and does not perform migration,
replace keys, reset a store, retry a login or authorize new account access.
Its source suite passed 3,906 tests with 107 skipped. Native UI/gateway, Mac,
Android and Linux workflows passed. The disposable-Mac first-store/restart
report passed all 43 checks, including a device-change refusal with a fixed
diagnostic and a missing-key refusal without creating a replacement key.
[Native diagnostic evidence](../artifacts/store-startup-diagnostics-native-ci-20261023.json).

A separate no-payload registration diagnostic ran on the exact installed image.
The first version refused before reading policies because it incorrectly
required a `0700` broker directory. The corrected version matches the provisioner's
`0755` mode, passed 65 tests and independent package review, and completed with
`device_number_changed`. It read only root-owned registration metadata and stats
for the two store directories; it used no credential, configuration, Keychain,
service or network APIs. New broker source adds persistent volume binding, with
30 native checks passing; legacy migration and successor installation remain
unqualified. [Repair scope](store-volume-repair.md).
[Diagnostic scope](store-registration-diagnostic.md).

The configuration-model change has one fixed source-hash profile. Storage,
enrollment and agent-setup sources remain byte-identical. Seven public examples
and three legacy empty-selector cases preserve account fingerprints through
serialization and reload. The current app has not been tested against every
possible owner configuration. Installer 84 is unsigned and unnotarized, and
physical Android delivery and real-provider acceptance remain open gates.
[Candidate evidence](../artifacts/full-image84-current-app-package-20261023.json).
[Configuration transition](../artifacts/configuration-extension-source-20261023.json).

A separate build request now packages the same reviewed image for a first
installation. The first build refused because the old packager admitted only
image 80. Packaging source `47eac17` adds only the exact reviewed image 84 to
that allowlist; its other 15 functions are unchanged. Packaging tests passed
81 checks and build/controller tests passed 87 checks. Corrected build run
`39925295516` passed. An independent local review matched all 27,496 expanded
nodes, the complete packaging source snapshot and four genuine peer signatures.
The fresh acceptance controller passed 98 checks. Actual clean installation
and identical-package reapplication passed all 13 checks in run `39927710046`,
including public-file identity preservation and service startup. The complete
controller suite passed 3,865 tests with 107 skipped; native UI/gateway, Mac,
Android and Linux workflows also passed. No production release has been published.
[Fresh-image request](../artifacts/fresh-image84-build-request.json).

### Owner-approved diagnostic update — 23 October 2026

The owner completed macOS authentication for package 82. Native Installer ran
the package scripts and then failed. The bounded observer returned only
`component_transition_conflict` at `predecessor_worker_binding`; no raw Installer
log or private account store was exported. A subsequent public-image check still
matches all 25,283 predecessor files, 2,305 directories and 21 aliases.
[Owner result](../artifacts/owner-mac-update82-result-20261023.json).

The failing comparison binds the saved worker-policy file's device number,
inode, mode, byte count and content hash. Its exact differing field is not yet
established on the owner Mac. Source now supports a device-number change only
through the existing validated root-volume receipt, matching the component plan
and unchanged worker/service hashes. All historical objects must share one
device number and all observed objects must belong to the validated current
volume. Inodes and bytes remain exact; no receipt is rewritten. Current dynamic
policies are checked again after the full public-image scan.

The final ordinary-user native fixture passed 516 assertions, including changed
volume, plan, policy, inode, metadata and mixed-device refusals. A broader Python
selection passed 353 checks before the final dynamic-file recheck, and the final
21 report-contract tests, lint and whitespace checks passed. This is a source
candidate; owner repair has not yet been qualified.
[Source evidence](../artifacts/completed-volume-binding-source-20261023.json).

Package 83 was built from controller commit `662692d` and passed a separate
read-only review of its 15 compiled inputs and 27,513 script-tree nodes. Its
matching source archive also passed a separate stream review of both complete
Git snapshots and the embedded third-party corresponding source. All four draft
release asset digests match the local files. The installer controller's 100
focused checks passed. Actual installation/reapplication, interrupted-create
recovery and interrupted-remove recovery each passed all 18 checks in run
`39915497523` with those exact bytes. These controlled-Mac results do not
qualify an owner-Mac installation.
The application image remains build 80; newer application features are not
included in this controller repair. The container is unsigned and unnotarized.
[Package evidence](../artifacts/full-image83-volume-binding-package-20261023.json).

### Resumed acceptance — 22 October 2026

The corrected-controller package 81 matrix is now terminal: both interruption
scenarios passed all 18 checks, while the normal installation hit the controller's
420-second deadline after 10 checks. The failed normal result is retained. A prior
normal installation of these exact package bytes completed in 398 seconds; this
does not prove the cause of the later timeout or make it a pass.

A new normal-only QA workflow preserved the exact asset contract and passed all
18 checks. Its initial full upgrade completed in 455.702 seconds under an
840-second deadline; reapplication completed in 188.211 seconds under the
unchanged 420-second deadline. Package and product bytes were unchanged. Both
interruption/recovery scenarios had already passed all 18 checks on the corrected
controller, so the three scenarios now have verified successful results. No
personal account or owner enrollment was used by these tests.
[Bound results and new acceptance scope](../artifacts/full-image-installer81-normal-acceptance.json).
[Verified terminal results](../artifacts/full-image-installer81-acceptance-20261022.json).

The requested personal acceptance targets now include Harel and Phoenix SMS
sign-in using an Android phone. Neither insurer currently has a reviewed bundled
connector. Public login-page review, local owner enrollment, physical SMS delivery
and completed sign-in are separate remaining gates; they are not covered by the
existing fictional-password/email/SMS/TOTP journey.

The resumed local four-account journey passed: Chrome CSV import, mailbox/SMS
fixture enrollment, authenticator enrollment, fresh logins, session expiry and
durable task resumption. Physical Android delivery remains untested. The installed
owner app currently reports that it cannot safely open its protected account
store; no private store was inspected or modified to bypass that refusal.

Source now refuses a preview install or skill refresh that would change an
existing connection's client configuration. All detected aliases are checked
before client rotation or skill writes. Focused tests verify preservation of
both protected and other-preview connections, existing tokens and launchers.
This change is not in the frozen image80 payload. One earlier combined local
test run reported a rollback-repair failure; the focused recovery case passed
30 repetitions and the complete agent/mailbox selection passed 58 checks. The
original failed observation is retained; its cause is not established.

Fresh-install packaging was built on a disposable hosted Mac from the unchanged
signed image inside package81, using packaging source `56f83bb`. The build run
failed its static envelope check: the controller expected `payload.pkg`, while
native `productbuild` emitted the embedded reference `#payload.pkg` and a separate
bundle-version metadata reference. That failed run is retained. The corrected
review accepts that exact embedded reference and still refuses remote URLs,
other components, additional payloads and altered installation scope. All 74
focused checks passed. Expansion and public-image validation of the unchanged
package also passed locally, without installing it. The exact package subsequently
passed all 13 checks in clean-Mac install/reapplication run `39841274212`. The
installed public image matched all 27,483 nodes, the service was observed running,
and identical-package reapplication preserved public bytes and inodes, original
receipts and policies. The GUI was observed starting and quitting normally;
owner enrollment and personal authentication were not part of this test.
[Fresh package review](../artifacts/fresh-image80-static-review-20261022.json) and
[actual fresh-install result](../artifacts/fresh-image80-installer-acceptance-20261022.json).
The accepted installer and recovery checks remain separate from real provider
authentication and public release signing/notarization.

After package81 passed upgrade/reapplication and both interruption scenarios,
read-only inspection of the owner's installed public software matched the exact
predecessor manifest: 25,283 files, 2,305 directories and 21 aliases, with no
mismatches. No private store, credential, token or owner configuration was read.
The exact package was opened in macOS Installer. The owner approved system
authentication. Installer subsequently reached its package scripts, then failed
with error 112. The helper's closed result was `component_transition_conflict`
at `predecessor`. A separate read-only public-image check still matches the
complete predecessor exactly and does not match the target. The exact failing
predecessor predicate is not yet known; the passing hosted-Mac matrix does not
qualify this owner-Mac attempt. No private account store was inspected or changed.
[Owner-Mac preflight](../artifacts/owner-mac-update81-preflight-20261022.json).
[Terminal owner-Mac result](../artifacts/owner-mac-update81-result-20261022.json).

The next controller source identifies predecessor refusals with fixed categories
for receipt, policy, object and journal checks. It retains the same validation
predicates and never includes underlying error text or record values. All 488
native assertions and ordinary-user entrypoint/argument refusals passed, along
with 236 focused Python checks and the 21 updated report-contract checks. The
first diagnostic controller run retained a stale assertion-count expectation;
its native checks passed, and a fresh complete run with the corrected expected
counts passed. This qualifies source diagnostics, not an owner repair or another
installed package. [Diagnostic source evidence](../artifacts/predecessor-diagnostics-20261022.json).

Diagnostic package 82 now builds and passes an independent read-only review of
its staged and expanded trees, all 15 compiled inputs and original command logs.
The first build refused a changed device number in the staged inventory; a full
public-content check found only that metadata change. The second stopped at its
disk reserve. Both attempts are retained, and the successful third attempt keeps
the same guards. This device-number change is a lead, not a confirmed explanation
of the owner's failure. Package 82 passed all three actual hosted Installer
scenarios in run `39852501340`: normal installation/reapplication and interruption
before both optional creation and removal. Each exact downloaded report passed
all 18 checks; package, controller and recorded-log hashes match. This does not
repair or qualify the owner's protected store. The owner's public predecessor
still matches all 25,283 files, 2,305 directories and 21 aliases. A first local
checker wrongly expected a mode field in alias records; its failed observation
is retained and the corrected complete check passed. Package 82 is open in
native Installer pending the owner's system authentication.
[Installer acceptance](../artifacts/full-image-installer82-acceptance-20261022.json)
and [owner preflight](../artifacts/owner-mac-update82-preflight-20261022.json).
Its source CI passed 3,777 tests with 107
skipped, plus native UI and gateway checks; the new installer-controller selector
passed 98 focused checks. [Candidate evidence](../artifacts/full-image82-diagnostic-package-20261022.json).

The exact Android 11-tested APK at `0823275` was downloaded and independently
checked for archive/APK hashes, v2/v3 signatures, package metadata and manifest
permissions. It remains a development preview with no physical-phone acceptance.
The requested phone runs Android 15 or newer, where Android may redact OTPs from
ordinary notification listeners. The first implementation at `e098c6f` attempted
a self-managed association. Android 15 rejected it before consent because that
permission is reserved for privileged apps. The failed run and diagnostic
follow-up are retained. The replacement uses ordinary Bluetooth LE discovery,
with a short-lived public UUID added by the Mac's pairing screen. It requests
no privileged self-managed, computer or watch permission. Pairing payloads are
also removed from the copy button's accessibility identifier. New tests separate
successful Android 11 delivery from Android 15 refusal without an association;
the latter is not a positive pairing result. Both corrected PR jobs passed at
`07ce7b0` in run `39860255127`: Android 11 completed one synthetic browser SMS
verification, and Android 15 refused the actual notification with zero accepted
codes. The first replacement run had a stale positive-only count assertion; that
failure remains recorded. The exact Android 15 APK was downloaded and its hash,
v2/v3 signature and two manifest permissions independently checked. Native Mac
UI and gateway checks also passed for the Bluetooth source; its full regression
passed 3,787 tests with 107 skipped, dependency audit and source/wheel builds
in run `39859402352`. Bluetooth
permission/discovery, actual system consent and physical phone delivery remain
release gates. [Scoped source and APK evidence](../artifacts/android-ble-discovery-source-20261022.json).
[Tested old APK](../artifacts/android-phone-preview-0823275.json),
[first Android 15 result](../artifacts/android-computer-association-first-run-e098c6f.json),
and [Android's OTP restriction](https://developer.android.com/about/versions/15/behavior-changes-all#otp-redaction).

Public-page research and the personal acceptance requirements for Harel/Phoenix
are recorded in [insurer login acceptance](insurer-login-acceptance.md).
A distinct identity/phone/SMS login model and masked native/browser enrollment
now support controlled session-status checks. Password imports and sync are
excluded; existing password fingerprints stay unchanged. This is an engine
foundation, not a supported Harel or Phoenix connector. Their ordered JavaScript
requests, real code screens and authenticated markers still need qualification.
The final identity/security/session suite passed 35 checks, and the native UI
compiled with warnings treated as errors and passed its checks. An earlier
focused run passed 82 checks. The broader run passed 324 and exposed one stale
historical-schema fixture; the corrected old-fingerprint checks passed
separately. Full CI at `8a4e290` subsequently passed 3,804 tests with 107 skipped,
lint, the dependency audit and source/wheel builds in run `39864084255`.
Native UI and gateway jobs passed. The same source's Android run `39864084266`
completed one synthetic browser SMS verification on Android 11 and refused
forwarding without association on Android 15, accepting zero codes. Neither
result qualifies physical Bluetooth pairing or carrier delivery. The separate-user
Mac run `39864084288` also passed, including controlled password/email/SMS/TOTP
recovery and offline/prepared development package installation. No personal
account or physical phone was used in those checks.
[Identity/phone foundation evidence](../artifacts/identity-phone-login-foundation-20261022.json).
[Current source CI evidence](../artifacts/identity-phone-source-ci-20261022.json).
The owner selected Lemon Squeezy for authenticator-app acceptance. Its official
documentation confirms authenticator support, and anonymous form inspection
confirms email/password POST to `https://auth.lemonsqueezy.com/login`. The actual
challenge, authenticated marker and local enrollment remain unqualified. No
personal identifier is stored in this repository and no login was submitted.

Source now supports an explicitly granted browser session-status operation that
returns only `{"authenticated": true}` after the ordinary ready-marker and
presence/transaction checks pass. It cannot include page-read fields. Existing
field-read fingerprints remain unchanged; changing the result kind requires a
new grant. Controlled tests cover recovery, reuse, expiry, TOTP, unknown pages,
transaction challenges and refusal of unapproved field reads. This enables
limited provider login acceptance but does not itself qualify any new provider,
and it is not part of the frozen image80 packages.

### Latest owner-Mac result — 21 October 2026

The startup component at `213509c` completed successfully in macOS Installer on
the affected Mac. A separate public observer found all nine expected public
files and the launchd plist matching, and observed the recognized service
running twice with the same process identity. Native owner setup and the shared
AI connection upgrade subsequently completed. The owner-approved personal
Chrome export was selected through the native picker; one Namecheap credential
was imported locally with only the username-check operation granted.

The installed Codex launcher and an ordinary Claude Code request discovered
the account and stopped at its existing `browser_state_unrecognized` challenge.
This establishes agent discovery and challenge handling, **not a successful
personal login**. The observed device-verification redirect remains outside the
reviewed Namecheap flow. No further retry is justified by the passing fixture
tests. The owner subsequently enrolled Gmail locally, and the installed native
app independently displayed **Mailbox connection checked**. No credential or
message was read for that observation. Actual website email-code delivery,
real SMS delivery and owner authenticator enrollment remain incomplete.

[Sanitized owner-Mac observations](../artifacts/owner-startup-and-import-213509c-20261021.json)
and [Gmail connection observation](../artifacts/gmail-owner-check-20261021.json).

The authentication improvements at `cba1dfc` passed all nine first-attempt
workflows and all 15 required jobs. They add checked Gmail-source reuse and
bounded Android delivery retries. A subsequent display-only status snapshot
fix passed 56 focused checks. The complete-image upgrade core passed 127 Python
planner checks, 217 native storage assertions, 11 actual-image plan checks,
24 mixed-transition checks and 134 durable-journal assertions. These checks
use controlled public data. The fixed installed adapter at `4deaacc` now passed
its ordinary-entrypoint checks and all nine first-attempt source workflows;
actual upgrade acceptance is still pending. Build 79, from the authentication
and status source at `5ba276b`, compiled and signed for Apple Silicon and Intel. Independent
source, wheel, signature and compiled-slice verification passed. The complete
target image and its 402-node update plan also passed actual data verification
and Python/native agreement checks. Installed adapter qualification is separate,
and the installed app remains build 76.

[Authentication CI](../artifacts/ci-authentication-cba1dfc-20261021.json),
[status snapshot checks](../artifacts/owner-status-snapshot-20261021.json), and
[complete-image core checks](../artifacts/full-image-transition-core-20261021.json),
and [build 79 review](../artifacts/build79-review-20261021.json). The
[complete build 79 image record](../artifacts/full-image-build79-20261021.json)
preserves its assembly and plan checks without claiming installation.

The complete build 79 package is now assembled and independently reviewed.
The package, recursive file inventory and corresponding source archives are
pinned for a three-scenario disposable-Mac Installer run: installation and
reapplication, interruption after optional-file removal, and interruption after
optional-file creation. **The first actual matrix failed in all three scenarios.**
The base and startup-component installations passed. The normal full upgrade's
signed helper refused with `component_transition_conflict` at `predecessor`;
the interruption runs stopped within their original coarse interruption stage.
The exact package remains unqualified and unchanged. The source correction
accepts inherited directory groups that the prior installer allowed, while
retaining root ownership, mode `0700`, ACL checks and exact immutable metadata.
Whether that mismatch caused the actual refusal still needs a fresh-Mac test.
No full-image update has run on the owner's Mac. The package container is unsigned
and unnotarized.
[Exact candidate evidence](../artifacts/full-image-candidate79-20261021.json).
[Failed actual Installer matrix](../artifacts/full-image-installer79-first-attempt-20261021.json).
[Inherited-group source checks](../artifacts/predecessor-inherited-group-20261021.json).

Subsequent source also stores a bounded structural summary from a first stopped
browser attempt for owner-only review. Pending challenge polling never retries
the website, and the agent API receives no diagnostics or secrets. The focused
Python checks and native UI fixture passed. A wider local run retained one
temporary SQLite setup error alongside 155 passes; that setup test passed in an
isolated recheck. These changes are now included in build 80, whose signed GUI,
wheel, source correspondence and complete public image passed static review.
The image has 404 changed manifest nodes; only the two owner-app executables
changed among its 41 native files. Build 80 failed actual Installer
qualification and has not been installed on the owner's Mac.
[Source diagnostics checks](../artifacts/authentication-first-stop-20261021.json).
[Build 80 static evidence](../artifacts/authentication-candidate80-20261021.json).

The build 80 package and matching source archive are assembled and independently
reviewed. Its complete staged and expanded images match; the new signed helper
preserves the inherited-group correction. The source kit contains the actual
compiler inputs, separate app/controller Git trees and matching GPL sources.
The package remains unsigned and unnotarized. Its first actual Installer matrix
failed in all three scenarios. The base and startup component passed, and the
predecessor check accepted the measured inherited group `80`. The full-image
helper then refused at `preparation` with `full_image_update_unavailable`.
Ten of eighteen checks passed in each scenario; target-image installation,
interruption recovery and reapplication were not reached. The exact preparation
predicate was not measured. Source inspection found a separate group-contract
mismatch: existing tree parents and old tree contents were required to use the
new staged tree's group. The correction pins canonical parent groups separately
and binds old tree contents to the qualified unchanged support root's group.
New staged trees and journals still require group `0`; uniform tree metadata,
ownership, modes, ACL and content checks remain. Its ordinary native dispatcher
passed 376 assertions, five argument refusals and the ordinary-user updater
refusal. Another 195 focused Python checks passed. These are source and
synthetic-fixture checks; the failed package remains unchanged and unqualified.
[Exact build 80 candidate](../artifacts/full-image-candidate80-20261021.json) and
[failed actual matrix](../artifacts/full-image-installer80-first-attempt-20261021.json).
[Legacy-group source correction](../artifacts/full-image-legacy-group-20261021.json).

Replacement package 81 is now built from controller `740fe3c`. It retains the
signed app 80, complete target image and plan unchanged. Independent review
passed its 54 inputs, 15 compiler copies, package expansion, inventory and
signatures. The matching source archive contains both actual Git trees, the
compiler inputs and matching GPL material; its independent stream review also
passed. Four uploaded draft assets have exact backend hashes in a new frozen
ten-asset Installer contract. Its controller source at `740fe3c` passed all nine
first-attempt source workflows and all fifteen executed jobs.
[Controller source CI](../artifacts/ci-authentication-740fe3c-20261021.json).

The first actual package 81 matrix passed installation/reapplication and
creation-interruption/recovery, with all eighteen checks true in both scenarios.
The removal scenario stopped at its test controller's coarse stopped-state
inspection; it emitted no native refusal. The exact failed predicate was not
recorded. Source review found a stale test requirement for group `0` on a
retained old tree, conflicting with the qualified legacy-group contract.
[Original matrix results](../artifacts/full-image-installer81-first-attempt-20261021.json).

The corrected controller binds removal's group to the fixed support root
observed before launching its owned helper and requalifies that root after
stopping it. New trees still require group `0`; history, quiescence, head,
ownership and exact-object checks remain. Sixty-nine focused checks and
independent source review passed. A separate frozen contract contains the
identical package/source asset bytes for a fresh corrected-controller matrix;
the original failure is retained. Full recovery qualification remains pending.
The package is neither installed on the owner's Mac nor a production release.
[Controller correction](../artifacts/installer81-stopped-tree-controller-20261021.json)
and [exact package 81 evidence](../artifacts/full-image-candidate81-20261021.json).

The QA-only head `b881873` also recorded an Android SDK setup failure:
`sdkmanager` reported an invalid archive while installing the fixed API 30
emulator image. Both APK builds had finished, but the emulator and actual login
journey never started. The underlying download or cache cause is unknown. A
small workflow change installs that same image once with verbose output before
the unchanged emulator action, preserving failure exit codes and adding no
retry. Its local command/exit checks passed; a fresh actual journey is still
required. [Original SDK failure](../artifacts/android-sdk-first-failure-b881873-20261021.json).

The first build-80 source workflows at `d5741bc` found one stale test mock that
did not accept the new optional diagnostics callback. Each full suite recorded
3,591 passes, 107 skips and that one failure; the Mac subsets found the same
failure. The fixture now accepts the callback and retains its token-redaction
assertions. Its isolated check passed. Fresh source CI and the new package's
actual Installer matrix are separate gates; the earlier failures remain
recorded and do not establish personal authentication acceptance.
The corrected source at `d503ac3` has since passed all nine first-attempt source
workflows and all 15 executed jobs. Both full suites recorded 3,592 passes and
107 skips; the separate Mac worker and offline-package checks also passed.
[Exact source CI results](../artifacts/ci-authentication-d503ac3-20261021.json).

All nine first-attempt source workflows passed for `f073afb`, including the
actual hosted-Mac Installer and separate-user checks. That source result does
not deliver a new GUI to this Mac: the startup component deliberately retains
build 76. A signed build 77 and its runtime inspection are prepared separately;
the complete-image upgrade controller, actual upgrade acceptance and consumer
distribution are still required. The later local setup-feedback proposal has
45 passing transport checks and 50 UI PASS lines compiled without optimization;
its optimized UI compile reached its local deadline, so it is not qualified by
that run.

### Earlier repair qualification

Development source now includes explicit installation-root revalidation for a
changed device number with both original inodes still matching. It preserves
the original receipts and requires a newly verified current volume binding.
[Checks and limitations](installation-root-revalidation.md).

The signed-native packages at source `93fc906` passed all nine required source
workflows on their first attempts. Actual installation and same-package
reapplication passed on a fresh hosted Mac (**15 checks**). A separate fresh Mac
passed the complete recovery route (**26 checks**): a synthetic device-number
mismatch with unchanged inodes, supplementary receipt publication, repeated
revalidation, recovery of an interrupted pending write, component installation
and reapplication, and revalidation after the component update. The original
receipt files remained unchanged after the disposable test fixture was created.

The recovery test's first controller refused the wrong fixed expansion folder
before any Installer ran. The reviewed controller-only correction at `abe6e02`
passed 291 focused checks and then qualified the **same package bytes**. The
original failed run remains recorded; it was not rerun or relabeled as passed.
Earlier source candidates, including `12306c3`, remain unqualified by their own
results.

On the affected personal Mac, native Installer ran and failed. Its newly
published, root-owned public result reports `REFUSED` at checkpoint `publish`.
That checkpoint covers several final consistency/publication operations; it
does not identify the failed predicate or prove whether a supplementary receipt
was created. No private installation log or journal was read to interpret it.
The component installation was not attempted, and protected owner enrollment
and personal sign-in acceptance remain incomplete.

A separate signed read-only diagnostic subsequently published `REFUSED` at
`first_service_job`, with `namespace_state: absent`. This is the first repeated
service check after the initial one succeeded. It can fail on the fixed command,
the individual live-process attestation, or a changed process identity. Ordinary
public service observations showed running-to-stopped transitions. These results
identify a concrete lifecycle-stability overconstraint for correction, but do
not establish which branch failed. The diagnostic Installer transaction's
completion was not independently verified; the newly published result was
inspected without claiming transaction completion. No private log or journal
was read. [Diagnostic and observation record](../artifacts/installation-root-revalidation-diagnostic-93fc906-20261021.json).

The development correction independently attests each current service
observation, allowing authentic restarts between observations without retaining
process authority. All installation and image checks remain, and the component
transaction's separate process-ownership rules are unchanged. Its ordinary
optimized native fixture passed **257 assertions**, including 21 new lifecycle
and refusal checks; **183 focused Python checks** also passed. Its exact-source
CI at `5b09c50` finished with seven successful workflows and two failed security
audits. Both audits reported development dependency `certifi 2026.7.22`
(`PYSEC-2026-4320`); the native checks and full Python suites passed. That source
is unqualified, and the failed attempts remain recorded.

The successor updates only certifi to `2026.10.19`, with published archive
hashes. All other locked packages and the exported runtime requirements are
unchanged. The local dependency audit now reports zero known vulnerabilities
among its external dependencies; the unpublished project itself is skipped by
that tool. CI now performs the same audit before browser setup and long tests.
This correction does not assess or replace the frozen runtime's pip-vendored
certificate bundle; that remains a separate full-image security check.
The successor still needs exact-source CI and actual Installer qualification.
[Failed candidate and dependency correction](../artifacts/ci-certifi-refusal-5b09c50-20261021.json).

The owner-app source also corrects its Claude Code action and unsupported
visible-sign-in help. Its optimized UI fixture passed **49 checks** using
temporary files and injected channels, profiles and helpers. Those UI changes
are not delivered by the startup component, which retains the frozen build 76
GUI; a full owner-image update still needs separate qualification.

The package containers remain unsigned and unnotarized. These clean-Mac tests
do not validate personal email/SMS/authenticator sources or consumer distribution.
[Exact source, package and actual Installer evidence](../artifacts/installation-root-revalidation-93fc906-20261020.json).

The current builder allows one strictly proven unacquired-runner retry while
preserving the original failed attempt. Executed code or test failures remain
ineligible. See [CI qualification](installation-root-revalidation.md#ci-qualification).

### Retained build 76 base

Build **76** is a controlled local installer candidate at `fbd2a73`. Its native
mailbox retry preserves nonsecret settings, clears passwords on submission and
navigation, requires explicit retry and rejects stale callbacks. The optimized
native journey passed **47 checks** using fictional inputs. The actual universal
GUI was rebuilt and signed; the complete archive and its frozen-source bindings
were verified. [Build 76 record](../artifacts/build76-review-080.json).

All eight exact-source CI workflows subsequently passed their first attempts
(14 jobs). Each Main regression passed **2,794 tests with 93 skips**. The original
review's pending-CI snapshot remains unchanged.

The owner-approved local installation completed through macOS Installer, but
the installed protected service exits **78 (`EX_CONFIG`) before enrollment**.
The app cannot connect to it. A later isolated socket reproduction identifies
a concrete rejection mechanism described below; its causal role in the installed
service still needs validation. No protected-store enrollment, shared AI connection upgrade or personal sign-in
was completed on this installation.
[Installation and CI record](../artifacts/runtime-acceptance-080-build76-20261020.json).

The owner-approved startup check subsequently ran through Installer, but its
report says `diagnostic_tool_unavailable` with no captured startup reason.
Cleanup remains pending: capture consumption and restoration of stdout to
`/dev/null` are unconfirmed, so the guarded private target was retained.
[Diagnostic attempt and exact public result](../artifacts/startup-check-attempt-080-build76-20261020.json).

An approved follow-up inspection recovered the historical code
`system_broker_unavailable` without starting or changing the service. That generic
code does not identify the failing startup stage. Cleanup and stdout restoration
remain unverified, and owner enrollment is still blocked.
[Capture inspection result](../artifacts/startup-capture-inspect-attempt-080-20261020.json).

The diagnostic also generated root-only Python cache directories and rewrote
three baseline cache files in the installed runtime. This happened after the
original startup failure. The diagnostic source now disables bytecode writes;
the separately approved cache-only repair then completed through native
Installer. Its report confirms three restored baseline files and eight extra
cache directories moved to retained private backups. Independent public-code
checks confirm the original bytes, root ownership, mode `0644`, single links,
eight directory absences and unchanged build 76 executable pins.
[Repair result and verification](../artifacts/runtime-cache-repair-attempt-080-20261020.json).

The fixed signed metadata checker confirmed policy paths, worker and enrollment
plans, the broker domain and the agent socket. The owner-socket check returned
`invalid_worker_launcher_descriptors`; that combined check does not identify
which socket property failed or establish the original startup cause. The repair
did not start or stop the service, inspect account data or restore stdout.
Fresh startup and owner enrollment remain unverified.

An isolated ordinary-user LaunchAgent on this Mac returned a named socket whose
`getsockname` was an internal launchd path, while its configured filesystem path
and listening endpoint remained valid. The original strict path equality check
rejects that descriptor pattern. This proves the mechanism, not the cause of the
installed service failure. The temporary job and files were removed; no root or
account operations were involved.
[Reproduction and retained first attempt](../artifacts/launchd-socket-name-080-20261020.json).

Source `9e47dfc` introduces an explicit `AALSN002` worker handoff that binds each
socket role to its root-validated named activation, descriptor identity, canonical
filesystem identity and observed bind address. Directly bound sockets retain
strict canonical-address checks. The enrollment channel is unchanged. The source
passed all eight required CI workflows on their first attempts, including both
Mac service integration runs. It has not been installed. The earlier source
review remains separate from the completed exact-source CI record.
[Source review and limits](../artifacts/listener-v2-source-080-20261020.json).
[Completed exact-source CI](../artifacts/ci-observations-9e47dfc-20261020.json).

A dedicated build76-to-worker-v2 component updater is now source-ready. It stages
and verifies the complete ABI group, preserves the owner and store IDs, keeps the
fixed job persistently disabled during mutation, and publishes the verified image
head after all files and peer pins agree. Interrupted preparation remains
non-authoritative; a matching complete intent supports manual same-package retry.
Original installation receipts and private account directories remain untouched.

Local ordinary checks passed **177 Python tests**, **87 optimized native
assertions** and **41 public-policy assertions**. The production entry point
compiled and refused an ordinary caller before filesystem work. These are source
and synthetic checks. Source `939fdda` subsequently passed all nine required
CI workflows on their first attempts. Its signed-native component package was
assembled, independently expanded and checked against all 42 frozen source inputs
and 15 script resources. The package container remains unsigned and unnotarized.
No new root helper or account login was run on the owner Mac.

The first actual Installer QA run expanded the package successfully, then its
controller refused the expanded resources before either Installer ran. Archived
script resources carry the builder UID, while the controller expected root-owned
files; the exact remote failed predicate was not retained. The controller is
being corrected and given bounded public metadata diagnostics. Actual
base/candidate installation and same-package reapplication on a fresh hosted Mac
remain required before owner installation. The failed attempt is retained.
[Exact source CI, package review and first actual attempt](../artifacts/component-update-candidate-939fdda-20261020.json).

A second fresh Mac run at controller `68c6635` passed expanded-resource
verification, the genuine helper signature, actual base installation and complete
base-image verification. It then stopped at the fresh GUI quit step, before the
candidate Installer or reapplication. The exact command outcome was not retained.
The frozen installation transaction opens the GUI, whose startup can be busy;
the next controller will observe presence, allow bounded startup settling and
retain timeout outcomes. The package stays unchanged. Both earlier attempts are
preserved. A separate ordinary read on the owner Mac now confirms both public
service output paths are `/dev/null`; private capture cleanup remains unverified.
[Second actual attempt and source observations](../artifacts/component-update-installer-gui-attempt-080-20261020.json).

A third fresh Mac run at controller `143788d` confirmed normal GUI quit and
observed absence, then actually invoked the candidate Installer. That command
returned 1 with a package-script failure; it did not time out. Candidate success,
target-image verification and reapplication were not reached. The helper's exact
refusal was absent from the command's ordinary output. The next controller adds
Installer's detailed logs and bounded head/tail capture; the package remains
unchanged. No update has been installed on the owner Mac.
[Actual candidate refusal and retained evidence](../artifacts/component-update-installer-refusal-080-20261020.json).

A fourth fresh Mac run at controller `87ccf1d` again passed base installation,
base-image verification and observed GUI closure. Actual candidate Installer
returned 1. Its complete detailed client output still reported only the
package-script error, without the native refusal reason. The next controller
captures at most 128 KiB appended to the fixed Installer daemon log during this
fresh-VM attempt; it reads no existing log bytes and preserves the original
Installer outcome if diagnostic capture fails. Its 165 ordinary contract tests
and independent review passed. The candidate package remains unchanged and
uninstalled on the owner Mac; target verification and reapplication remain open.
[Detailed Installer attempt and diagnostic review](../artifacts/component-update-installer-daemon-attempt-080-20261020.json).

The fifth actual run at controller `d2a65d8` captured the signed helper's specific
refusal: `component_service_quiescence_not_confirmed`. Base installation,
base-image verification and normal GUI closure passed again. No candidate files
were verified as updated, and reapplication was not reached. The fixed service
was absent at cleanup, but the narrower process/API cause remains unclassified.
The next diagnostic measures only bounded process aggregates for the dedicated
service identity in the disposable test Mac. The update barrier remains intact.
[Specific native refusal and retained evidence](../artifacts/component-update-quiescence-attempt-080-20261020.json).

The sixth run at controller `744ee05` measured one stable unidentified process
under the dedicated service identity after the broker/bootstrap executable
references were gone. The candidate again refused quiescence. A sentinel
user-domain query succeeded, so it did not establish an absent-domain response.
The next disposable-Mac canary identifies the remaining executable and measures
only that test installation's dedicated user-domain teardown and recreation
after fixed-job cleanup. No owner installation or account operation is involved.
[Process measurement and limits](../artifacts/component-update-process-attempt-080-20261020.json).

The seventh run at controller `cb90937` identified the remaining process as
`/usr/sbin/distnoted`. Dedicated-domain bootout returned 0 and cleared all
service-identity processes, including on repetition. Immediate recreation then
returned `124: Domain is tearing down`; the canary stopped before its later
stages. Final process count was zero, but final bootout also returned 124, so
completed teardown was not proven. The source repair now adds dedicated-domain
lifecycle handling with bounded retries for only that exact action-specific
response, preserving all existing process, group, owner and job checks. It needs
new source qualification and successful actual apply/reapplication before owner
installation. No update or personal sign-in has occurred on the owner Mac.
[Measured domain lifecycle and limits](../artifacts/component-update-domain-canary-080-20261020.json).

The repair passed 133 optimized ordinary native assertions across 30 groups,
including real shared-helper failure/retry ordering. Its production entry point
refused an ordinary caller with exit 78 before installed reads. The producer and
builder contracts passed 95 Python tests; the controller passed 212 tests and
now refuses its lifecycle canary after uncertain Installer completion. Source,
logs and exact proof contracts passed independent review. These local results
do not replace the pending new-source CI, signed-package assembly or actual
Installer apply/reapply checks.

[Source review and retained earlier attempts](../artifacts/component-update-source-080-20261020.json).
The build gate also preserves the measured skipped state of the review push's
two dispatch-only jobs. That frozen gate required first-attempt success for all
applicable jobs; the current narrowly bounded infrastructure exception is
described above.
[Earlier CI applicability correction](../artifacts/component-update-ci-applicability-080-20261020.json).

The first updater CI attempts refused the disable-state output. A read-only
measurement confirmed that this Mac renders the states as `enabled` and
`disabled`; the native and probe parsers now recognize those exact forms and
retain only the unique test fixture's observations. Fresh CI at `1098a2d` passed the complete
disable, registration-exclusion, reenable and cleanup sequence. Its native
compile then hit an older Swift compiler complexity limit in the reserve
calculation. Explicit typed accumulation preserves the amount and passed local
optimized checks; the new exact source still requires full CI.
[Earlier rendering correction](../artifacts/component-update-disabled-rendering-080-20261020.json).
[Compiler compatibility correction](../artifacts/component-update-swift-compat-080-20261020.json).
The required ordinary review check now runs on every push; a native-only change
can no longer lose its ninth exact-source gate to a path filter.
[Trigger correction and current source evidence](../artifacts/component-update-required-push-080-20261020.json).


The package remains **unsigned and unnotarized**. Successful package installation
does not establish a working setup. Personal-account acceptance, protected
different-version upgrades, Chrome live sync and arbitrary website coverage
remain open. This candidate is not a production release.

## Preserved build 75 review

Build **75** is the current source/package review candidate at `43c82fb`.
Reapplying an otherwise unchanged prepared installation now restores its missing
service registration while preserving the enrollment policies and identity.
Both disposable Mac provisioning reports passed all **39 checks**, including
removed-registration recovery and preservation of the empty fixture vault.
This does not establish recovery of an installed personal vault.

All eight exact-source CI workflows passed **their first attempts**. Each Main
regression passed **2,794 tests with 93 skips and zero warnings**; lint, Python
dependency audits, wheel/source builds and the native checks passed.
[Exact build 75 record](../artifacts/build75-review-080.json).

The actual complete offline package was expanded and checked against its
manifest. All 79 application files match the frozen source; the app and runtime
payload have genuine publisher signatures. The package container remains
**unsigned, unnotarized and uninstalled**. Its adjacent corresponding-source
archive is required for the included Bitwarden program. The separate signed
app ZIP requires protected registration. Neither artifact is a consumer release
or genuine owner installation result.

The provider release guard now binds the exact worker, allowed commands and
official JavaScript assets, and checks the actual resolved dependency consumers.
Fresh static review and **14 targeted tests** passed. The new source archive
changes only its advisory-ledger member; staged provider code and dependencies
match the actual build 74 package. The unpatched node-forge advisory remains
**under investigation**. This bounded check supplies no cryptographic patch,
blanket clean audit or whole-package non-exploitability claim.
[Provider proof and limits](../artifacts/provider-release-guard-20261019.json).

Strict QA probes of installed Codex and Claude executables are **unverified**:
their required
effective execution boundaries could not be attested before startup. They
started no fixture or model and performed no private sign-in. Historical agent
results do not validate this source. Normal installed clients do not run this optional QA preflight.
[Agent acceptance boundary](agent-qa-boundary.md).

Production readiness remains **false**. Publisher Installer/Notary configuration,
genuine owner installation, mailbox consent, physical SMS delivery,
authenticator enrollment and current installed-agent private journeys remain
open. Password-manager private enrollment/rotation/revocation also remains
unverified. Chrome password exports are snapshots; live Chrome password sync
and arbitrary website/webmail coverage are not implemented.

## Preserved build 74 review

Build **74** was the source/package review candidate at `def66480`.
Unsent masked inputs clear on actual view changes, confirmed Pause and page
exit, while same-view refresh preserves active drafts. Rejected mailbox setup
stays open with its nonsecret fields ready for retry and its password blank. Actively edited mailbox and authenticator setup survives unrelated background
login refresh. Saving clears secret fields before submission; navigation,
changed enrollment and Pause discard stale drafts and delayed replies. A
composed fictional-account test imports a Chrome-format password, enrolls an
authenticator through the actual owner page, completes a fresh password/TOTP
login and reuses that session.

Latest attempts of all eight QA workflows at `d089e2a` passed. Its product files match application
source `def66480` exactly; the later commit changes tests and evidence only.
Each Main regression passed
**2,751 tests with 93 skips and zero warnings**. The final focused setup cleanup/retry group
passed 35 cases. Both Main regressions for build 72 failed a mailbox
retry race; that failure is preserved separately and is fixed here. See the
[exact build 74 record](../artifacts/build74-review-080.json).

The original application-source Main push failed waiting for a response, while
its PR counterpart passed. A controlled experiment demonstrated that the test's
late observer could miss an already completed correct reply. The QA-only update
subscribes before submission, removes the fixture's independent reply deadline
and awaits the original handler through completion. The precise ordering or
transport cause of the original CI failure remains unestablished; its log and
same-source results are retained.
[QA measurement proof](../artifacts/qa-account-response-20261019.json).

The first Android PR attempt at the QA revision failed SDK/emulator provisioning
before emulator or project startup. One failed job was retried on the identical
source; the original setup failure and log remain separate from its later result.
The invalid archive's underlying cause is not established.

After disk space was freed, the complete build 74 offline review package was
assembled and expanded for verification. Its actual inventory matches the
reviewed payload manifest; all 79 bundled application files, genuine publisher
payload signatures and provider/source pins match the reviewed inputs. The
installer container remains **unsigned, unnotarized and uninstalled**. The
separate app ZIP also passed signature/source review and requires protected
registration. These are maintainer review artifacts, not a consumer release.
The preserved build 71 package contains its own earlier source only.

The publisher helper now supports flat-PKG notarization and rejects modified
submission/output bytes. A copy-only check with an already accepted public
vendor package passed actual Apple signature, fresh stapling and install-policy
tools; an inserted-padding case is rejected. This used no publisher credentials
and proves neither Apple acceptance for Account Access nor installation.
[Native public-package proof and limits](../artifacts/flat-pkg-notarization-20261019.json).
Account Access still needs its Installer certificate, Notary credentials and
genuine owner installation/private-account acceptance.

Build **73** at `82ed5215` repaired the mailbox retry. Its exact CI results remain
[recorded](../artifacts/build73-review-080.json). Later new tests against its
unchanged product found that an unsent masked account password remained after
view changes, confirmed Pause and page exit: three failed and one preservation
case passed. Those new cases were absent from its immutable CI. Build 74 clears
all masked inputs at those boundaries and preserves the same-view draft. No
account-add request or website login was started by the new lifecycle cases.
[Before/after cleanup evidence](../artifacts/owner-secret-cleanup-20261019.json).

Build **72** at `028f181b` passed app signature/source review but **failed both
Main regressions**: 1 failed, 2,746 passed and 93 skipped in each. Rejected mailbox
setup closed its form and lost nonsecret retry details after refresh. Its local
focused pass did not override that failure. Build 73 repaired that path by keeping
the form open with its password blank. The regression waits for the full refresh. The failed artifact and logs remain
[recorded](../artifacts/build72-review-080.json).

Build **71** at source `a5c3c6e` is the earlier full-package review. Google
Messages browser setup now prepares its actual local bridge, shows the Chrome
installation steps and keeps preparation separate from permissions and code
delivery. Active review survives background login polling; revocation or changed
source context discards stale review and ignores delayed completion. Restricted
worker pages direct local preparation to the desktop app.
[Google Messages setup and limits](google-messages.md).

The actual build 71 archive passed inventory, source-binding and payload
signature review. Latest attempts of all eight source-specific workflows passed;
each Main regression passed 2,671 tests with 93 skips and zero warnings. Seventeen
focused owner-page tests passed, including seven Google Messages cases. The
container remains **unsigned, unnotarized and uninstalled**. These checks use
fictional accounts and do not establish genuine owner installation, private
account sign-in or physical delivery.
The first Android PR attempt failed Android SDK provisioning before emulator
or project startup; the identical-source retry is recorded separately from
that retained failure.
[Exact build 71 record](../artifacts/build71-review-080.json).

The existing installed preview separately completed three approved public-example
reads through Codex. Saved sessions may have been reused and its source revision
was not attested; this does not validate these protected candidates. A separate strict Claude
installed-preview preflight did not start a model because its optional invocation
guard could not be attested. This is a QA boundary, not a normal-client failure.
[Installed agent evidence and limits](agent-qa-boundary.md#installed-preview-checks-on-19-october-2026).

Build **70** introduced explicit Bitwarden connection, imported exact-item
suggestions, unattended refresh and restrictive disconnect. Its official OSS
CLI uses protected Node; packaging includes corresponding source and notices.
Consent discloses broad vault-decryption authority, with exact-item restrictions
enforced by Account Access. Private enrollment remains unverified.
[Bitwarden setup and limits](bitwarden-sync.md).
Its source `fecb17a` and identical-product QA `e90eaf3` passed all eight workflows,
including two Main regressions of 2,664 tests. A guarded Claude request completed
four fictional password logins with email, SMS and TOTP at that earlier source.
[Historical build 70 record](../artifacts/build70-review-080.json).

Build **69** at application source `2fb0e54` corrected the email regression
below and passed a fresh guarded Claude Code fictional-account journey. Its
actual unsigned installer also passed inventory, source-binding and payload
signature review. A later concurrent-disconnect test exposed a security failure:
an operation could still fill/submit a captured password and recreate its session
after its Bitwarden source had been disconnected. That package is quarantined;
passing compatibility checks do not override this failure. Build 70 binds browser
disclosure, dispatch, redirects and session publication to the original source
enrollment, including while codes or owner review are pending. Its source-bound
browser path stops unsupported child-frame/worker transport. The
[build 69 failure record](../artifacts/build69-review-080.json) is retained.

Build **68** at `8d831d1` was assembled for review but failed regression QA:
the new source route shadowed the existing email/OAuth connection worker.
The failure is retained; that package is not a release candidate. Build 69
aliases the provider function so the original connection worker remains usable.
Earlier passing source and packaging checks do not erase this failure.

Build **67** at source `e2c8bc4` adds manifest-derived installation-space checks,
safe low-space retry and a reviewed Read the Docs password/authenticator pilot.
Its app and three protected runtime components have genuine Developer ID
signatures; an independent check matched every bundled source file to that
revision. Its offline package has now been assembled with production payload
verification. The container is **unsigned, unnotarized and uninstalled** and is
for maintainer review. An initial `pkgbuild` failure during disk pressure is
retained; the same product source built successfully after space was freed.

All eight fresh CI runs at QA revision `c2748c8` passed. Each Main regression
passed **2,467 tests with 93 skips and zero warnings**; dependency audits and
wheel/source builds passed. Its product tree is identical to `e2c8bc4`; the QA
change gives the device-email fixture enough time for the deliberate TOTP
rollover guard. The original failed run remains part of the evidence. This
changes no production timeout or security check.

Both source-`e2c8bc4` Macs also passed 1,215 focused tests and 22 reviewed-browser
tests each; all 18 report pairs match through their strict validators and
package contracts. The actual build 67 package's manifest, source bindings and
low-space refusal passed independent review. The
[exact build 67 record](../artifacts/build67-review-080.json) includes current CI
links, package hash and scope. No personal-account sign-in or owner installation
was performed.

Build **66** remains the earlier completed offline review package, assembled
from genuine Developer ID signed components. Its container is **unsigned,
unnotarized and uninstalled**, and it does not contain the build 67 changes.
All eight CI runs at its QA revision `0398ec1` passed. The
[build 66 record](../artifacts/setup-completion-080.json) preserves its exact
source revisions, installer hash and scope. The public download remains the
0.7.4 preview; these review artifacts are not consumer releases.

The candidate now includes:

- An explicit **Upgrade AI connection** action for recognized older managed
  installations. It preserves unrelated agent settings and instructions,
  verifies the replacement client before publishing it, and does not copy old
  credentials or migrate the old vault.
- One portable agent skill, with protected setup honoring a safe owner-local
  `CODEX_HOME`. No agent-selection step or routine slash command is required.
- A reusable Gmail OAuth mailbox: consent is followed by a mailbox-address
  check, then the checked connection appears in the verification-source picker.
  Normal token renewal preserves the connection; new consent, revocation or
  identity changes require a fresh review.
- Separate connection and delivery status. A saved grant or successful mailbox
  check never claims that a real website email or SMS was delivered.

An earlier [Claude Code check at source da2bb94](../artifacts/agent-tests/claude-verification-080-build66-da2bb94.json)
completed four fictional password logins with email, SMS and TOTP verification
from an ordinary request. Its invocation-only tool guard and independent trace
check passed. This is controlled compatibility evidence, not personal-account
acceptance or proof of the protected consumer installation.

See [agent setup and upgrades](mac-agent-setup.md),
[Google mailbox setup](device-email-setup.md), and
[the validation record](validation.md) for source-specific evidence. Older
reports retain their original revision and scope; their test counts must not be
presented as results for a later candidate.

## Release requirements

| Area | Implemented or controlled coverage | Still required |
| --- | --- | --- |
| Mac installation | Build 76 installation, successful startup component, owner setup and shared AI connection on the affected Mac; exact-source disposable Mac CI passes | Developer ID Installer certificate, Notary credentials, Apple acceptance and stapling; clean downloaded installation and reboot QA |
| Upgrade and repair | Recognized-preview agent connection upgrade observed; atomic launcher replacement and rollback; same-image/same-owner package recovery; successful startup component | Complete-image protected-package upgrade and interrupted upgrade acceptance; vault migration |
| Password import | Reviewed Chrome, Apple Passwords, compatible 1Password and Bitwarden CSV; unencrypted Bitwarden JSON; one approved personal Chrome credential imported through protected owner setup | Successful private-website sign-in from the imported credential and representative export coverage |
| Password synchronization | Approved 1Password items through service-account SDK or Connect; separately consented Bitwarden CLI source with exact-item checks, bounded updates and restrictive disconnect | Private enrollment, rotation and revocation QA. **Chrome live sync is unimplemented**; file imports remain snapshots |
| Gmail and other email | Renewable Gmail authorization, checked reusable mailbox selection, and TLS IMAP; one real Gmail app-password mailbox check passed; freshness, sender, template and authorization checks | Actual website code delivery and login. Consumer OAuth also needs a publisher-configured Google application and real consent/renewal QA. Arbitrary webmail is unsupported |
| iPhone SMS | Signed narrow Mac Messages reader and composed password/SMS/session fixtures | Genuine Full Disk Access, forwarded physical SMS and completed private login |
| Android SMS | Paired pinned HTTPS delivery and notification-listener emulator fixtures | Physical pairing, carrier/notification delivery, reconnect and private login QA |
| Google Messages Web | Reviewed browser/desktop preparation, refresh/revocation UI checks, unchanged extension scripts in a synthetic Messages document, stable Chrome/native transport and controlled SMS-login composition | Genuine positive owner approval and complete private/physical SMS login; broader language coverage and extension distribution |
| Authenticator | Local original-key, supported QR and complete Google Authenticator transfer-batch import; TOTP login fixtures | Owner-approved real phone export/enrollment and provider login. Push approvals, nonstandard TOTP and Google Authenticator cloud sync are unsupported |
| Agent integration | Portable installed CLI/skill; protected Codex discovery and ordinary Claude Code request both preserve an existing private sign-in challenge; historical controlled login fixtures | Successful private sign-ins and session reuse through both agents. The optional nested Codex QA harness remains unverified before startup |
| Website coverage | Reviewed public examples and narrow Namecheap, PyPI and Read the Docs pilots; password, email, SMS and TOTP engine fixtures | More reviewed connectors and representative private acceptance. Importing a password does not add arbitrary website support |
| Security and operations | Separate service identity, native owner authorization, protected key custody, permission/revocation checks and disposable cross-user/crash fixtures | Genuine consumer deployment and owner approval, real logout/reboot and active-operation recovery; independent security review and release provenance |

The optional Codex QA refusal is a test-harness boundary. The installed launcher
and client do not perform that preflight. It must not be described as a runtime
failure, or bypassed to manufacture a passing nested-agent test.
[Agent QA boundary](agent-qa-boundary.md).

The earlier same-user preview does not provide the protected runtime's separate
OS identity. Genuine-publisher pre-enrollment transport checks do not establish
positive owner enrollment, key creation or an authenticated protected-worker
journey. Source-image recovery also does not establish different-image updates,
physical power-loss recovery or a machine reboot.

## Personal-account acceptance

A production claim needs the actual downloaded installer and genuine local
owner setup, followed by read-only website checks through the installed agents:

1. Import an approved real password and connect the account's actual code source
   locally.
2. Complete fresh password/email, password/SMS and password/TOTP sign-ins,
   recording delivery separately from code-request acceptance.
3. Repeat the permitted operation to verify session reuse without routine owner
   intervention.
4. Verify expiry, password change, source revocation, wrong-account rejection,
   restart and recovery without reviving revoked permissions.

A provider-required passkey, phone unlock, biometric or administrator approval
still needs genuine owner presence. Setup can require the owner once; routine
supported sign-ins should then use the enrolled access.

Private GitHub testing was stopped at the owner's request. Namecheap's blocked
private attempt is quarantined. Neither should be retried merely to increase
test counts. Gmail's mailbox check passed, while real website email-code
delivery and authenticator enrollment remain incomplete; fictional substitutes
cannot close those gates.

Keep passwords, exports, cookies, QR images, message contents and raw agent
traces out of public evidence. Publish sanitized failure classes and coverage,
preserve blocked task IDs, and distinguish fictional, public-example,
unclassified and private results. Another application's CLI token or a copied
session is not evidence of fresh password/email/SMS/authenticator login.

[Provider scope](other-service-validation.md) ·
[Password sync](security-and-password-sync.md) ·
[Security architecture](architecture.md)
