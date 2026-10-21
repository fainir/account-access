# Production acceptance

**Account Access is a preview, not a production release.** The requested outcome
is a simple installation, one-time local enrollment, and later routine sign-ins
through the user's existing AI agent. Passing fictional-account tests does not
establish that experience on personal accounts.

## Current candidate

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
use controlled public data; the fixed installed adapter and actual upgrade
acceptance are unfinished. Build 79, from the authentication and status source
at `5ba276b`, compiled and signed for Apple Silicon and Intel. Independent
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
