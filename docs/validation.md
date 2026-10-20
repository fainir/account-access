# Validation of Account Access

## Current build 76 review

The [build 76 record](../artifacts/build76-review-080.json) binds the rebuilt app,
actual offline package and **47 passing optimized native checks** to `fbd2a73`.
The [native log](../artifacts/native-mailbox-retry-080.log) includes rejected Gmail
and custom IMAP retries, blank passwords, clearing an unsent replacement during
navigation, explicit retry, stale callbacks and verification shortcuts.
The earlier baseline exit 133 remains unclassified because buffered output did
not identify its precise failed assertion.

The actual package inventory reproduces **25,281 files, 2,305 directories and
21 aliases**; all 79 application files match source. App/runtime signatures
verify. The provider inventory is unchanged from build 75. Full CI was pending
when that historical record was captured. The later
[runtime acceptance record](../artifacts/runtime-acceptance-080-build76-20261020.json)
preserves the completed results: all **eight workflows and 14 jobs passed their
first attempts** at the exact build 76 source. Both Main regressions passed
**2,794 tests with 93 skips**, in **1015.00 and 911.60 seconds**; both native UI
jobs passed 47 checks. A retried log download was not a CI rerun.

The owner-approved package installation subsequently completed in macOS
Installer. Opening the installed app failed to reach enrollment: its protected
service repeatedly exits **78 (`EX_CONFIG`)**, and the app reports that the
protected app did not respond. The original job sends stdout/stderr to
`/dev/null`, so this exit did not identify the underlying cause. Public code
and job metadata were checked without reading credentials.

The owner-approved, source-bound diagnostic package subsequently ran through
normal macOS Installer, which reported installation success. Its fixed public
report instead says **`diagnostic_tool_unavailable`**, with `reason: null`,
`cleanup_pending: true`, `failure_capture_consumed: false` and
`default_stdout_requested: false`. No startup reason was captured. Restoration
of stdout is unconfirmed; the guarded private target remains retained. Only
the public result was read. This attempt changes no protected executable or
policy and establishes no repair or successful startup.
[Diagnostic attempt](../artifacts/startup-check-attempt-080-build76-20261020.json)
and [exact public result](../artifacts/startup-check-result-080-build76-20261020.json).

The separately approved, inspection-only package then recovered
`system_broker_unavailable` from the retained capture. Its source is `b5a0967`;
101 ordinary fixtures and independent package expansion checks passed before
execution. The recovered output is historical: no service start, stop, redirect
or reset was attempted, and no exact startup stage or repair was established.
Cleanup remains pending. [Inspection attempt and byte-exact public result](../artifacts/startup-capture-inspect-attempt-080-20261020.json).

Ordinary metadata inspection subsequently found eight generated root-only cache
directories and three rewritten baseline cache files. The first diagnostic had
omitted Python's `-B` flag. The installed startup failure predates these writes.
The helper and its generated invocation now require bytecode writes to be
disabled; the focused suite passes 102 ordinary tests, including refusal before
source-backed imports when the flag is absent. No account credentials were
involved.

The separately approved cache-only repair at `058511d` subsequently completed
through native Installer. Its byte-exact public result says
`restored_build76_cache`: three baseline files restored, eight extra directories
moved and private backups/journals retained. Independent public-code inspection
confirmed all three original hashes, sizes, root ownership, mode `0644` and
single links; all eight extra directories are absent from the runtime. Four
public build 76 pins remain unchanged. The 16 ordinary repair fixtures and
independent package review preceded this execution.
[Actual repair result and public-code verification](../artifacts/runtime-cache-repair-attempt-080-20261020.json).

The signed read-only metadata checker confirmed policy paths, worker and
enrollment plans, the broker domain and the agent socket. Its owner-socket row
reports `invalid_worker_launcher_descriptors`, which combines existence, type,
ownership and mode checks; the specific failed property remains unknown. This
does not identify the original startup cause or establish successful startup.
The repair did not start/stop a service, change stdout or read account data.
Private backups remain untouched; journal recovery requires manual review.

No protected-store enrollment, shared AI connection upgrade, personal login or
real-device delivery was completed on this installation. Passing CI did not
establish a working owner setup. The installer remains unsigned and
unnotarized; production readiness remains **false**.

## Preserved build 75 review

The [build 75 record](../artifacts/build75-review-080.json) binds application,
QA, package and CI to `43c82fb`. All eight workflows passed their first attempt.
Both Main regressions passed **2,794 tests, 93 skips and zero warnings** in
**1021.90 and 1019.89 seconds**; Python dependency audits,
lint and wheel/source builds passed. Actual run records and job logs are retained.

Both exact-run Mac provisioning artifacts passed all **39 required checks**.
Their report files, source/run API bindings, GitHub artifact digests and archive
members were verified. The new checks remove service registration and reapply
the same prepared installation, then confirm restored registration and unchanged
policies, identity and empty fixture vault. These are controlled development
installations in disposable Macs, with no genuine owner approval or consumer
package acceptance.

The actual offline package was expanded. Its **25,281 files**,
**2,305 directories** and **21 aliases**
match the manifest; all 79 application files match the exact source, and app/Node
signatures verify. Node retains only its reviewed JIT entitlement with library
validation enabled. The installer container is **unsigned, unnotarized and
uninstalled**. The separately verified app ZIP requires protected registration.
These archive checks do not establish consumer installation.

Fresh provider source/graph guards and **14 cases** passed in **0.22 seconds**
(console timing; retained JUnit suite timing is **0.118 seconds**).
All 867 source materials and notices remain; the newly measured source archive
changes only the advisory ledger. Actual provider inventory comparison finds
only that ledger and runtime-manifest metadata changed from the preserved build
74 package. Current review executes no provider CLI or upstream source script.
Older execution/audit records remain explicitly historical. The remaining
node-forge advisory stays **under investigation**; no crypto patch, blanket clean
audit or whole-package non-exploitability is claimed.
[Fresh guard and recovery evidence](../artifacts/provider-release-guard-20261019.json).

The earlier 213-case local result (3.03 seconds) was reported from the console
before scratch loss. Its raw log/JUnit is unavailable and is not presented as a
retained current proof. Fresh retained guard results and exact-source full CI
provide the independently inspectable test evidence.

Strict QA probes of installed agent executables record Codex 0.163.0 and Claude
Code 2.1.112
as **unverified**. Neither starts a fixture, model or private login because the
required effective invocation boundary could not be attested. This limits the
optional strict QA run; it does not establish a normal-client failure.
[Codex report](../artifacts/agent-tests/codex-verification-080-build75-43c82fb.blocked.json),
[Claude report](../artifacts/agent-tests/claude-verification-080-build75-43c82fb.blocked.json).

No owner app was launched/reinstalled, no owner credential files were accessed,
and new private sign-ins remain **zero**. Publisher, owner-enrollment, physical
mail/SMS/authenticator and installed-agent acceptance remain open. Production
readiness remains **false**; see [production acceptance](production-gates.md).
Build 74's original failures, later QA fix and scope are preserved below and in
its unchanged record.

## Preserved build 74 review

The preserved [build 74 review](../artifacts/build74-review-080.json) binds application
source `def66480` and QA `d089e2a`; their product files are identical. All eight
QA workflows passed on their latest attempts; both Main regressions
passed **2,751 tests with 93 skips and zero warnings**, with Python dependency
audits and wheel/source builds. The actual signed app ZIP verifies against the
genuine publisher and all 79 bundled application source files match that commit.
The complete build 74 offline review package was assembled after space was
freed, then expanded to verify its actual manifest, all 79 source files, signed
runtime payload and pinned provider materials. Its installer container remains
**unsigned, unnotarized and uninstalled**. The separate app ZIP requires protected
registration. Neither artifact establishes consumer installation or production
acceptance. Build 71 remains a separate earlier package.

At application source `def66480`, the setup cleanup/retry group passed **35 cases
in 74.97 seconds**. The QA-only observer change then passed **13 focused cases
in 43.98 seconds**.
New cases confirm that unsubmitted masked fields clear on view changes, Pause
and actual page exit while same-view refresh preserves the active draft.
The full suite also checks mailbox and TOTP drafts that
survive unrelated actual owner-job polling; submission clears masked secrets;
Pause, navigation and changed enrollment prevent stale replies from restoring
controls or starting verification. A composed sandboxed-browser fixture imports
a fictional Chrome-format password, enrolls TOTP through the real owner HTTP
page, completes a fresh password/code login and reuses the resulting session.
It does not install or invoke an AI agent or access a physical authenticator.
Build 72 failed both full regressions on a rejected-mailbox retry
race. Its original failures are preserved separately from this source repair.

The unchanged app/flat-package notarization helper passed **112 targeted tests**
at source `028f181b`, including 52 flat-package cases, and is covered again in
this source's Main regressions. The actual helper also verified a freshly stapled copy
of an already accepted public Homebrew package with Apple tools. The original
archive remained unchanged; a fixed inserted-padding case that native tools
accepted was rejected by the helper's stricter framing check.
[Public native proof](../artifacts/flat-pkg-notarization-20261019.json).
No Account Access package was submitted to Apple or accepted for this release.
No owner installation or app launch occurred on this Mac during this review;
disposable CI separately installs development fixtures.

Original application-source CI passed its PR Main regression but failed the push
copy while awaiting a response. That failure remains recorded. A controlled
experiment demonstrated a late-response-observer window; the precise failed-CI
ordering or deadline/transport trigger remains unestablished. The QA-only change
observes before request initiation and awaits the actual handler through finally,
without changing product files or production timeouts. Expected rejection,
secret clearing, duplicate prevention, Pause, unchanged configuration and zero
website-login assertions remain enforced.
[Measurement diagnosis and limits](../artifacts/qa-account-response-20261019.json).

The QA revision's first Android PR attempt failed SDK/emulator provisioning
before emulator or project startup. A single failed-job retry used the same
source; the failed attempt, raw log and uncertain invalid-archive cause remain
recorded separately from the later result.

Independent bounded UI/helper review found no further concrete defect. New
private sign-ins remain **zero**. No current protected installed Codex/Claude
journey or physical mailbox/phone acceptance was performed. Historical agent,
package and provider reports retain their original sources and limitations.
Production readiness remains **false**; see [production acceptance](production-gates.md).

## Preserved build 73 coverage gap

The [build 73 record](../artifacts/build73-review-080.json) retains its original
CI results and app proof. Additional newly written local regressions against
that unchanged source had three failures and one pass in 7.77 seconds. Unsent
account-password fields stayed masked in the owner DOM on navigation, Pause
and page exit. These tests were not part of its frozen CI and made no account
submission or website login. [Build 74's cleanup proof](../artifacts/owner-secret-cleanup-20261019.json)
binds the before/after JavaScript and regression-test hashes; passing historical
CI does not override a later reproduced gap.

## Preserved build 72 regression

The [build 72 record](../artifacts/build72-review-080.json) retains source
`028f181b`, its signed app proof and both full-regression failures. Each had
1 failed, 2,746 passed and 93 skipped. The failed mailbox retry could locally
run before the handler's final refresh; waiting for completion exposed that
the form had closed and lost its nonsecret fields. Build 73 fixed the product
and made the regression await the completed handler rather than adding sleeps
or weakening the assertion. The failed source was not rerun to replace its result.

## Earlier build 71 evidence

The earlier [build 71 review](../artifacts/build71-review-080.json) binds application
and QA source `a5c3c6e`. The actual unsigned archive inventory, 79 bundled source
files, app/runtime payload signatures and provider materials passed review.
Seventeen focused owner-page tests passed, including seven Google Messages
cases exercising preparation, restricted-worker guidance, real pending-job
polling, duplicate prevention and revocation during a delayed response. All
eight source-specific workflows passed on their latest attempts; both Main
regressions passed **2,671 tests with 93 skips and zero warnings**. Python
dependency audits and wheel/source
builds passed. The separate provider record retains the node-forge advisory and
its bounded call-site assessment; this is not a blanket clean dependency audit.
The initial Android PR attempt failed SDK provisioning before the emulator or
project journey started; its failure remains recorded alongside the
unchanged-source retry.

The existing installed preview also completed three public-example reads through
Codex. That task may have reused sessions and does not attest the installed
revision or validate the protected candidate. A stricter installed-preview Claude
preflight did not start a model.
[Agent evidence and QA boundaries](agent-qa-boundary.md#installed-preview-checks-on-19-october-2026).

The [earlier build 70 review](../artifacts/build70-review-080.json) retains its
frozen application source `fecb17a`, identical-product QA `e90eaf3`, 2,664-test
Main regressions and guarded fictional Claude journey. Those are historical
results, not a fresh build 71 agent run. Production readiness is **false**, owner
installation was not performed and new private sign-ins remain **zero**;
[production acceptance](production-gates.md) lists the open requirements.

Build 69 is [quarantined](../artifacts/build69-review-080.json): disconnecting
its Bitwarden source during login could still submit a captured password and
recreate a session. Build 70 guards disclosure, dispatch and session publication
with the original enrollment. Earlier passing compatibility checks do not erase
that failure. The earlier identical-source Mac run also has an unclassified
CLI transport failure in one copy and a passing counterpart; current QA adds
failure-only bounded diagnostics without changing production timeouts.

The [build 67 record](../artifacts/build67-review-080.json) remains historical
evidence for its own earlier source, including eight passing CI workflows.
Sections below retain earlier source-specific results.

## In-app confirmation email and interrupted setup — 18 October 2026

Application revision `1bba84f` passed all eight push/PR workflows. Both full
regressions passed **2,339 tests with 92 platform skips and zero warnings**,
in **824.24 and 822.08 seconds**. Both focused Macs
passed **1,098 cases with one skip**, in **178.04 and 203.05
seconds**. Lint, locked dependency exports, audits and wheel/sdist builds passed.
[Exact source-bound evidence](../artifacts/consumer-mail-setup-080.json).

Each Main run executed **40 native owner UI scenarios**, including mailbox
review, cancellation, expiry, pause/navigation cleanup and broken-binding repair.
All eighteen Mac report pairs match through their strict validators/package
contracts; actual Installer-context and native handoff checks pass. The paired
native, Linux isolation and Android emulator reports also match. These controlled
phone paths do not establish physical carrier delivery.

PyPI confirmation email can now be connected in native or web **Verification**.
Choose an already checked saved TLS IMAP mailbox, review its address and the
existing approved reads, then confirm once. Gmail app-password mailboxes are
supported. Setup reads no messages and starts no website sign-in. A configured
but broken connection remains disconnectable and replaceable. The picker does
not infer a Gmail OAuth mailbox or claim that saving setup verifies delivery.
[Consumer steps and limits](device-email-setup.md).

The encrypted review is single-use, expires after ten minutes, and binds the
current connector, mailbox authority and grants. Before connector publication,
a durable transaction quarantines existing authority using a unique value that
cannot match a connector fingerprint. Device-email writer acquisition now uses a
monotonic deadline rather than SQLite's accumulated-sleep timeout, keeping a
contended setup request responsive without
relaxing its timing check. Final commit migrates only surviving
unchanged valid reads, sessions and exact-item password-source bindings.
Revocation wins; a failed or terminated change cannot reactivate stale authority
when a fingerprint later cycles. Six actual ordinary-user child SIGKILL tests
cover connection/removal after quarantine, configuration publication and final
commit. Fresh stores check permission, session/link state, repeated cycles,
independent presence gates and encrypted data. This proves process interruption,
not physical power-loss recovery or real owner approval.

Fresh genuinely signed Mac build **65** passes five executable audits, sixteen
static peer checks and the **60-module** source pin. Its prepared runtime passes
native/crypto/SDK-child and sandboxed-browser probes with library validation
intact. The [genuine Chrome/native-host review](https://github.com/fainir/account-access/actions/runs/39134544440) passes **28 checks** at
controller `ec80ae8`, against this exact source and archive. Both reads reach the
publisher-pinned service and receive the expected pre-enrollment denial; cleanup
passes. This remains transport before genuine enrollment or website login.

Claude Code completed a fresh ordinary-language four-account fictional task in
**75.85 seconds**, covering four password logins and one
each of email, SMS and authenticator verification through the guarded fixture
client. It does not test the protected signed worker, private accounts or
physical delivery.
[Claude report](../artifacts/agent-tests/claude-verification-080-1bba84f.json).
Current Codex QA refuses before fixture/model startup because a complete
execution/tool boundary cannot be attested.
[Blocked report](../artifacts/agent-tests/codex-verification-080-1bba84f.blocked.json),
[officially documented boundary](agent-qa-boundary.md).

New private sign-ins remain **zero**. The owner's installed app and unfinished
mailbox form were preserved. Real Google publisher configuration/consent,
Gmail OAuth-only consumer mailbox selection, private email/SMS/TOTP and
password-manager acceptance, physical phones, genuine owner enrollment,
protected installed agent journeys, notarized consumer installation/update and
Chrome/Bitwarden continuous sync remain release gates. Their file imports are
snapshots. Production readiness remains **false**. Earlier sections retain
historical source-specific results.

## Mailbox authorization, sync repair and device email — 18 October 2026

Application revision `6414df4` passed all eight push/PR workflows. Both full
regressions passed **2,273 tests with 92 platform skips and zero warnings**,
in **759.12 and 782.00 seconds**. Both focused Macs
passed **1,037 cases with one skip**, in **149.13 and 151.88
seconds**. Lint, locked dependency exports, audits and wheel/sdist builds passed.
[Source-bound evidence](../artifacts/mail-source-authority-080.json).

Each Main run executed **36 native owner UI scenarios**. Paired reports pass
**67 gateway, 38 desktop, 18 framing and 23 Gmail callback checks**, alongside
**24 Linux isolation** and **6 Android emulator delivery** checks. All eighteen
Mac reports match across their sixteen strict validators and the original
**16-check** / prepared **23-check** package contracts. Actual Installer-context
and native source-handoff checks passed with shared permissions preserved.

Gmail authorization alone no longer enables a website's email source. Starting
code recovery requires explicit source enrollment; pending windows recheck source
authority before accepting delivered codes. An existing 1Password connection can
replace just its token: the exact item, identity and
site stay fixed, and the repair checks the original enrollment generation and
connector authority. A failed replacement preserves the previous connection.
Native and web repair forms clear their secret fields.
[Sync repair](onepassword-sync.md).

The PyPI engine can follow the reviewed new-device email after its native
password/TOTP exchange, when an operator explicitly binds the mailbox. It
matches the fresh template and recipient, checks the fixed action and canonical
token identifiers, and compares the user UUID to the observed password response.
PyPI verifies the link signature and IP. The original confirmation
redirect and cookies are preserved. The automatic projects redirect is blocked
before dispatch, then the already-approved username operation verifies session
reuse. Account/source changes invalidate pending mail; missing TOTP stops before
optional mail or password work. Controlled Gmail and IMAP paths pass. The
standard account picker does not yet configure this binding, and private PyPI
acceptance remains unverified. [Provider limits](other-service-validation.md).

Fresh genuinely signed Mac build **63** passes five executable audits and
sixteen static peer checks. Its wheel matches all **59** current Python modules.
The prepared runtime passes native callbacks, crypto, SDK-child and sandboxed
browser checks with library validation enabled. A fresh
[production Chrome/native-host review](https://github.com/fainir/account-access/actions/runs/39127001363) passes **28 checks** at controller
`d1e0fed` against exactly this source and archive. Both reads reach the
publisher-pinned service and receive the expected pre-enrollment denial; cleanup
passes. This does not exercise owner approval, enrollment or a website sign-in.

Claude Code completed an ordinary-language task against four fictional accounts
in **53.23 seconds**, using four password logins, one email verification, one SMS
verification and one TOTP verification. Its invocation guard and trace checks
passed. This uses synthetic IMAP, Messages and authenticator inputs, not private
accounts or physical delivery.
[Claude report](../artifacts/agent-tests/claude-verification-080-6414df4.json).
Local Codex acceptance is **unverified**: the harness cannot attest its effective
execution permissions and refuses before fixture or model startup.
[Blocked report](../artifacts/agent-tests/codex-verification-080-6414df4.blocked.json),
[boundary and next acceptance environment](agent-qa-boundary.md).

New private sign-ins: **zero**. The owner's installed app and unfinished mailbox
form were preserved. Real Google publisher setup/consent, private email/SMS/TOTP
and password-manager acceptance, physical phones, genuine owner enrollment,
protected installed agent journeys, and notarized consumer installation/update
remain release gates. Chrome and Bitwarden imports are snapshots; continuous
sync from those managers is unimplemented. Production readiness remains
**false**. Earlier sections retain historical source-specific results.

## Password imports, Gmail repair and PyPI pilot — 18 October 2026

Application revision `972b800` passed all eight push/PR workflows. Both full
regressions passed **2,130 tests with 92 platform skips and zero warnings**,
in **727.68 and 728.80 seconds**. Both focused Macs passed **1,037 cases with
one skip**, in **155.43 and 151.57 seconds**. Lint, locked exports, dependency audits and wheel/sdist builds passed.
[Exact source and evidence](../artifacts/unattended-import-080.json).

The executed native UI suites each passed **35 scenarios**, including bounded
CSV/JSON reads and Gmail repair. Native reports passed **67 gateway, 38 desktop,
18 framing and 23 Gmail callback checks**. Linux isolation passed **24 checks**;
Android emulator delivery passed **6**. Both Macs produced eighteen matching
reports, validated through sixteen strict validators and the original **16-check**
and prepared **23-check** package contracts. Actual Installer-context checks and
eight native source-handoff checks passed while preserving shared permissions.

Reviewed Bitwarden unencrypted JSON imports now accompany CSV snapshots. Only
selected supported logins are enrolled; authenticator import stays opt-in.
Current connector authority and preview expiry are rechecked under locks before
publication; opted-in authenticator imports also recheck enrollment generation. The native reader uses one bounded,
non-following UTF-8 regular-file descriptor. Web replacement clears the old
review and rejects invalid UTF-8 before submission. See [password imports](password-import.md).

New Gmail OAuth authorization must contain exactly the reviewed read-only scope and
its own refresh token before access is saved. Revoked, uncertain, nonrenewable
and incorrectly scoped connections show reconnection instead of saved success.
The PyPI pilot binds its short-lived verification URL to the observed native
password POST redirect and permits one corresponding TOTP submission. Public
form preflight passed ten checks without a credential or POST. Private PyPI
login, new-device email verification and manual setup remain unverified or
unsupported. See [provider scope](other-service-validation.md).

Fresh genuinely signed Mac build **62** passes five executable audits and
sixteen static peer checks; its wheel matches all **58** current source modules.
The separately prepared runtime passes crypto/callback, SDK-native-child and
sandboxed-browser probes with library validation enabled. A fresh
[production Chrome/native-host review](https://github.com/fainir/account-access/actions/runs/39122546678) passes **28 checks** at
controller `97af5c6` against exactly this source and archive. Both requests
reach the publisher-pinned service and receive the expected pre-enrollment
denial. The temporary image, registration, profile, service and policy are
removed; the runner identity is unchanged. This does not exercise owner
approval, vault enrollment or a website sign-in.

New private sign-ins: **zero**. The installed owner app and unfinished mailbox
form were preserved. Real Google publisher configuration/consent, private
email/SMS/TOTP delivery, physical phones, private password-manager access,
real isolated Claude Code/Codex sessions, genuine owner enrollment and signed,
notarized consumer installation remain release gates. Chrome and Bitwarden
file imports are snapshots; continuous synchronization from them is unimplemented.
Production readiness remains **false**. Earlier sections retain their historical
source revisions and evidence.

## Connected setup and protected app layout — 18 October 2026

Application revision `57e7702` passed both Main regressions: **1,797 tests,
92 platform skips and zero warnings**, in **677.48 seconds** for push and
**603.99 seconds** for PR. Ruff, locked dependency exports, Chromium sandbox
checks, dependency auditing and wheel/sdist builds passed. Both native report
sets passed **67 gateway, 38 desktop, 18 framing and 23 Gmail callback checks**.
Both Linux isolation reports passed **24 checks**; both Android emulator reports
passed **6 checks**. These push/PR report pairs match canonically.
[Candidate source and evidence](../artifacts/connected-setup-080.json).

Both focused Mac suites passed **1,018 cases with one platform skip** and no
warnings summary, in **143.21 and 158.55 seconds**. Each Mac produced eighteen
reports; sixteen strict validators and both original **16-check** and prepared
**23-check** package contracts pass, with matching canonical report hashes.
The actual Installer sandbox and eight native source-handoff checks also pass;
the canonical app and exact public alias verify without changing shared-parent
permissions. All eight application workflows passed at this revision.

A separate [genuine publisher transport
review](https://github.com/fainir/account-access/actions/runs/39118694398) passes **28
checks** at QA controller `84452a4`, with unchanged application source `57e7702`. Signed
stable Chrome loads the unchanged production extension and launches the production
native host, which reaches the publisher-pinned desktop/XPC service and returns the
exact pre-enrollment denial twice. A fresh browser profile receives an exact copy of the
production-created host registration so Chrome can discover it in the selected data
directory. The runner identity is preserved; the temporary profile, exact registrations,
children, service, policy and public image are removed. No owner approval, vault
enrollment or website sign-in occurs.

The canonical owner app now lives at
`/Library/Application Support/Account Access/owner.app`. The public
`/Applications/Account Access.app` entry is one fixed relative symlink, used only
as a launcher. Execution, resources and code identity bind to the protected
bundle. The complete canonical app is inventoried before exclusive public
publication; recovery checks the staged/published alias inode and refuses
substituted names. The standard shared `/Applications` permissions are preserved.

The candidate adds a signed-desktop Gmail browser/PKCE handoff, complete
Google Authenticator transfer batches with local selection of one account, and
exact-item password updates through the official 1Password service-account SDK.
Contract and browser fixtures cover callback cancellation/expiry, incomplete or
mixed QR batches, source replacement and bounded SDK failure. These are setup
and protocol checks; consumer Google consent, private manager access and actual
factor delivery remain unverified. Chrome CSV imports remain snapshots;
continuous Chrome password sync is unimplemented.

New private sign-ins: **zero**. The installed owner app and unfinished mailbox
form were preserved. Genuine owner approval, private password/email/SMS/TOTP
logins, physical phones, broader providers, real isolated Codex/Claude sessions,
signed/notarized consumer installation and clean downloaded-install QA remain
release gates. Consumer deployment and production readiness are **false**.
The sections below retain their historical source revisions and evidence.

## Verification authority and signed Chrome — 18 October 2026

Application revision `585412e` passed all eight push/PR workflows. Both full
regressions passed **1,605 tests with 79 platform skips**, in 633.43 and 630.24
seconds. Both focused Mac suites passed **889 tests with one skip**, in 115.63
and 148.93 seconds. Lint, dependency auditing and package builds passed. These
Python runs have no warnings summary; existing native-test and upload-action
deprecation notices remain. [Exact source and evidence](../artifacts/verification-authority-080.json).

All **eighteen worker reports match across the two disposable Macs**. A new
**17-check journey uses genuine signed stable Chrome 152.0.7977.83** and the
unchanged packaged extension. Chrome directly launches the pinned fixture
native host; the production Chrome parent predicate is checked before and after
requests. Pending reads reach the enrolled isolated worker through native
framing, the desktop connection and system XPC. Native-port reuse, unsupported
cookie-import denial and extension reload/reconnection pass. No website or
cookie permission is granted, and no external website is opened. The temporary
profile, setup policy, jobs and fixture key are removed afterward.

This verifies the signed-parent and native transport path. Its compile-only
fixture entrypoint does not verify the installed app's production profile
entrypoint, Google Messages DOM, a Chrome password/SMS login, genuine owner
approval or consumer deployment. The separate protected password/SMS composition
remains controlled coverage; these reports must not be combined into a claim of
one completed private browser journey.

The **37-check provisioning report** now includes two actual subprocess kills
immediately after public-directory creation, before validation or mask
restoration, under an inherited `0777` mask. Retry preserves the published inode
and exact requested `0755` or `0700` mode. Five private-directory staging and
publication kill boundaries still pass. Conflicting existing directories are
preserved and refused. Original **16-check** and prepared **23-check** actual
Installer journeys also pass; genuine positive consumer setup remains open.

Verification windows now bind to an internal enrollment revision and current
mailbox authorization. Revoking or replacing a source, including re-enrolling
identical values, invalidates old windows and in-flight phone pairing/sender
matches. Source changes and window publication are serialized; pairing/source
replacement is atomic. OAuth lock waits reload live authority, and a canceled
Gmail read stops before mailbox requests. Normal token refresh, legacy mailbox
profiles and health rechecks preserve compatible active windows. No extra
routine approval was introduced. The final local source and code-resolver suites
pass **33** and **41** cases; the full CI above includes the final source changes.

A fresh genuinely signed review app passes five executable audits and sixteen
static peer checks. Its pinned wheel matches all 55 current Python modules;
extension and installer resources match the same source. Production native
sources are unchanged from `b2dddbc`; the complete genuine-runtime audit remains
tied to that earlier revision. This review app was neither installed nor
launched on the owner's Mac.

Installed-client discovery exposed no additional eligible private provider.
GitHub testing remains stopped, Namecheap remains quarantined, and Gmail and
authenticator enrollment remain deferred or unavailable. The installed app and
unfinished mailbox form were preserved. New private sign-ins in this validation:
**zero**. Chrome live password sync is unimplemented; CSV imports are snapshots.
Signed/notarized consumer installation, genuine enrollment, private email/SMS/TOTP
delivery, physical phones, broader providers and real isolated agent sessions
remain release gates. The candidate is **not production ready**.

## Protected recovery and password-source repair — 18 October 2026

Revision `304df4c` passed all eight push/PR workflows. Both full regressions
passed **1,517 tests with 77 platform skips**, in 609.32 and 606.69 seconds.
Both focused Mac suites passed **799 tests with one skip**, in 89.65 and
104.29 seconds. Lint, package builds and dependency audits passed. The focused
Python runs have no warnings summary; existing native test and upload-action
deprecation notices remain. [Exact evidence](../artifacts/protected-recovery-080.json).

All **seventeen worker reports match across the two disposable Macs**. The
original 16-check and prepared 23-check package installations still pass. The
provisioning report now requires **34 checks**, including actual subprocess
SIGKILL at five empty-private-directory publication boundaries. Retry preserves
the published inode, restores the exact private identity and leaves no staging
container. Existing private contents are never traversed or rewritten. These
checks do not establish recovery from every positive provisioning step, power
loss, migration or reboot.

The new **18-check composition** sends native frames through the real desktop
connection and system XPC into the System-key worker under a separate identity.
It completes a fictional username/password/SMS login and a second CLI read using
the saved session. Baseline arming precedes credential submission; wrong source,
window, stale messages, replay and unapproved setup are refused. Exact CLI reply
shapes and bounded process cancellation are checked. Its compile-only fixture
calls the framing entrypoint directly: signed Chrome parentage, the extension,
Google Messages DOM, genuine approval and physical delivery remain unverified
together. This is controlled coverage, not a private sign-in.

Password-manager rotation no longer clears unrelated login challenges. Explicit
owner credential edits detach the old source, delayed enrollment cannot undo a
later owner action, and bounded background scans rotate past busy accounts.
Verified source reconnection clears only its repaired prerequisite immediately,
allowing the original task to resume without another source-poll interval.
Failed reconnection and independent website/presence gates remain pending.
These recovery tests use a fictional 1Password Connect endpoint.

A freshly built, genuinely signed review app passes all five executable audits
and sixteen static peer checks. Its pinned wheel matches the current owner,
password-sync, provisioner and image modules. Native production sources are
unchanged from `b2dddbc`; the complete genuine-runtime audit remains tied to that
earlier revision. No review app was installed or launched on the owner's Mac.

Installed-client discovery exposed no additional ready private provider for this
QA. GitHub testing remains stopped, Namecheap remains quarantined, and Gmail and
authenticator enrollment remain deferred or unavailable. No new private sign-in
was requested; the installed app and unfinished mailbox form were preserved.
Chrome live password sync, consumer installation/notarization, genuine enrollment,
physical devices, broader providers and real isolated agent sessions remain open.
The candidate is **not production ready**.

## Genuine publisher and runtime checks — 18 October 2026

Revision `b2dddbc` passed all eight push/PR workflows. Both full regressions
passed **1,445 tests with 75 platform skips**, in 526.13 and 593.23 seconds.
Both Macs passed 745 focused cases with one platform skip and no warnings,
including the fresh-interpreter crash checks and a real requirement-parser
regression. Their sixteen worker reports match, with original 16-check and
prepared 23-check Installer recovery journeys. Lint, dependency audits and
package builds passed. [Current recovery evidence](../artifacts/resumable-installer-080.json).

A genuine Developer ID staging check exposed a production-only signature
failure: the `codesign -R` argument treated the requirement source as a filename.
The correction uses `-R=` with the same publisher/identifier/debugger predicate.
All four genuinely signed universal peers now pass the production checker, and
all five executable files pass Developer ID purpose, secure timestamp and
hardened-runtime checks. Sixteen static native checks accept the expected
publisher/identifier/hashes and reject wrong values using the production policy.

A separate genuine private runtime build signed 41 native files and ten bundle
seals with JIT permissions bound to fourteen of sixteen executable hashes.
Library validation stays enabled and unsigned executable memory is not allowed.
Its complete 64-native-file, 23-executable, eleven-bundle, 33-wheel audit passed,
followed by callbacks/crypto/validation and a fresh headless browser. The observed
browser launch retained sandboxing and requested a mock keychain; original Python,
32 dependency wheels and the lock remain unchanged. These ordinary-user checks
installed no app and changed no System Keychain, AuthDB policy or service identity.

Publisher-signed installed deployment, genuine owner setup, private factor
delivery, physical phones and the complete protected Chrome/agent journey remain
open. Developer ID Installer signing and live Apple notarization are still
required. Chrome CSV imports remain snapshots. The candidate is **not production
ready**. [Method and exact genuine-runtime evidence](publisher-runtime-checks.md).

## Resumable source-image installation — 17 October 2026

Revision `a777168` passed all eight push/PR workflows. Both complete regressions
passed **1,445 tests with 74 platform skips**, in 598.26 and 582.19 seconds.
Lint, package builds and dependency auditing passed. Both disposable Macs
produced identical sets of sixteen complete worker reports, including the
**16-check original** and **23-check prepared** package installations.

The package now contains its public image in protected script resources and
has no automatic PackageKit target payload. Native code verifies the complete
source before replacing itself with the isolated source interpreter. Only
public descriptors 3 and 4 cross this boundary; unrelated handles are closed,
stdin is `/dev/null` and caller environment variables are removed. An actual
Installer fixture checks those properties independently of the Python runtime.
The complete-package journey separately executes the real runtime and copies
the image into its final protected locations.

An exclusive lease and immutable journal bind the exact image, interactive
owner and published directory identities. Matching partial files can resume;
unknown or conflicting data is preserved and refused. In each package journey,
CI kills the actual coordinator after its protected intent, reinstalls the same
package, then retries again and verifies that the public roots and verification
receipt keep their device/inode identities. Native code rechecks the installed
image before provisioning. Package-bound peer identities are checked before
provisioning writes, and existing private branches remain opaque.

The original image contains 5,260 files, 927 directories and 25 aliases;
the prepared image contains 5,271 files, 937 directories and 25 aliases.
Both retain CPython 3.12.15 and 33 runtime distributions. Native byte/signature
checks, dependency imports, prepared callbacks/crypto and sandboxed browsing
pass after recovery. The two 744-case focused Mac suites passed with one
platform skip each. Their nine warnings came from the test runner's use of
`fork`; a follow-up switches those child checks to fresh interpreters. All 34
recovery cases pass locally with deprecation warnings treated as errors.

These are controlled development packages. Unsigned owner setup deliberately
refuses before vault creation, service identity or registration; the actual
package test therefore does not exercise completed consumer registration or
interrupted positive provisioning. Same-image/same-owner recovery does not
provide different-image updates, migration or physical power-loss guarantees.
Genuine publisher/notary acceptance, genuine owner setup, private login-code
delivery, physical phones and protected installed real-agent sessions remain
open. Chrome CSV imports remain snapshots. The installed owner app and deferred
Gmail form remain untouched. The candidate remains **not production ready**.
See [exact source and sanitized recovery evidence](../artifacts/resumable-installer-080-a777168.json).

## Native verification before privileged Python — 17 October 2026

Revision `5802fde` passed all eight push/PR workflows. Both full regressions
passed **1,380 tests with 66 platform skips**, in 580.07 and 565.25 seconds.
Lint, package builds and dependency auditing passed. Both disposable Macs
produced identical sets of sixteen complete worker reports, including the
**13-check original** and **20-check prepared** package installations.

A universal native helper now verifies the fresh public image before privileged
Python provisioning. Its bounded parser binds the fixed roots, file bytes and
modes, directory children and confined alias graph. Descriptor walks check
ownership, ACLs, file type, hard links and stable metadata without following
unapproved aliases. The ordinary-user builder also preflights source and final
inventories through metadata-only stdin. That `INSPECTED` response cannot
substitute for the installed-image `VERIFIED` receipt required by acceptance.

The first Installer runs stopped before Python because the checker refused
Apple's script-resource ancestor `/private/tmp`. A tiny actual-Installer probe
isolated the root-owned sticky parent. Only the resource walk now permits that
exact ancestor with mode `01777`, no ACL grants and protected root-owned
descendants. Installed payload walks retain their strict policy. Thirteen new
synthetic boundary cases reject missing sticky protection, writable children,
ACL grants and aliases; all 59 native component cases pass. The corrected tiny
Installer probe also passes twice with matching results and unchanged parent
permissions. Three signed ad-hoc universal peers build locally; ordinary
invocation of the production verifier refuses before reading installed paths.

Both full-package variants pass native verification before their deliberate
refusal of unsigned owner setup. The complete inventories contain 5,257 files,
927 directories and 25 aliases for the original package, and 5,268 files,
937 directories and 25 aliases for the prepared package. Native inventory is
64 files, 23 executables, eleven bundles and 33 wheels; each runtime has
CPython 3.12.15 and 33 distributions. Desktop/Chrome component reports match,
as do Linux's 24-check and Android's six-check reports.

These are controlled development fixtures. They do not validate genuine owner
approval, positive consumer installation, private code delivery or physical
phones. At that revision, protected interrupted-install retry was unimplemented. Owner
build 53 and the unfinished Gmail form remain untouched; Gmail is deferred,
GitHub personal QA remains stopped and Namecheap was not retried. Chrome CSV
imports remain snapshots. The candidate remains **not production ready**.
See [exact source, workflow links and sanitized evidence](../artifacts/native-install-verification-080.json).

## Complete preassembled runtime image — 17 October 2026

Revision `3a54663` passed all eight push/PR workflows. Both full regression
runs passed **1,342 tests with seven platform skips**, in 584.15 and 511.32
seconds. Lint, package builds and dependency auditing passed. Two disposable
Macs produced identical sets of sixteen complete worker reports, including
the **19-check prepared** and **12-check original** package installations.

The maintainer now assembles the complete runtime from the exact approved
binary wheels before packaging. No wheel code or setup script executes during
that assembly, and it compiles no bytecode. The administrator-level installer
uses the complete image; it no longer creates a virtual environment, runs pip
or recursively changes runtime permissions. Original runtime inputs and signing
receipts stay unchanged. Original filenames/hashes, wheel records, Python/ABI
compatibility and the complete dependency graph are checked before assembly.

Actual Installer acceptance confirms the relocated runtime's public files,
permissions and aliases match its build inventory, then exercises installed
imports, SSL/SQLite, native callbacks, crypto, validation and sandboxed browsing.
Each image contains 33 installed distributions and CPython 3.12.15. The final
native inventory covers 63 files, 22 executables, eleven bundles and 33 wheels.
These counts include the original Python and its complete runtime copy; the
preparation receipt still covers 41 native entries and ten bundle seals.
Ad-hoc signatures and explicit fixture permissions remain development-only.

The candidate runtime requires Apple silicon and macOS 14 or later. The pinned
cryptography release has no Intel Mac wheel. Shell/direct bootstrap tests refuse
Intel or Rosetta before downloads/runtime changes, and package assembly refuses
Intel before opening payload inputs. Universal native executables do not prove
Intel runtime support. No Intel installation or source-build fallback is claimed.

Native desktop/Chrome component reports match; Linux isolation and both Android
emulator journeys passed. This does not establish publisher-signed consumer
installation, interrupted-install retry, migration/update/reboot, genuine owner
approval, full installed Chrome/native/XPC/worker acceptance, protected real-agent
sessions, private factor delivery or physical phones. Chrome CSV imports remain
snapshots. Owner build 53 and the unfinished Gmail form remain intact; Gmail
connection is deferred. The candidate remains **not production ready**. See the
[exact source, workflow links and sanitized reports](../artifacts/complete-runtime-image-080.json).

## Public package inventory acceptance — 17 October 2026

Revision `e5c09ae` passed all eight push/PR workflows. The two full regression
runs passed **1,276 tests with seven platform skips**, in 586.09 and 576.30
seconds. Lint, package builds and dependency auditing passed. Both disposable
Macs produced identical sets of sixteen complete worker reports. The actual
package archive is expanded and its complete public payload inventory rebuilt
before Installer runs; both the original **11-check** package and the prepared
**18-check** package passed. Native desktop and Chrome-bridge reports also match;
Linux isolation and both six-check Android emulator journeys passed.

The inventory binds file bytes and permissions, directory modes and confined
aliases under the two fixed public roots. It grants no retry, overwrite or
deletion authority. The protected interrupted-install transaction remains
unimplemented. Newer source adds build-time complete runtime assembly; its
Installer results are recorded separately above and are not covered by these
older inventory-only results.
No new private sign-in or physical phone was validated. Owner build 53 and the
unfinished Gmail form remain intact; Gmail connection is deferred. The candidate
remains **not production ready**. See the
[exact source, workflow links and sanitized reports](../artifacts/package-recovery-inventory-080.json).

## Complete prepared Mac runtime installation — 17 October 2026

Code revision `3c59a87` passed all eight push/PR workflows. Both regression runs
passed **1,235 tests with seven platform skips**, in 584.64 and 588.49 seconds.
Lint and package builds passed; the Python dependency audit found no known
vulnerabilities. [Regression CI](https://github.com/fainir/account-access/actions/runs/39045910620).

Two disposable Macs produced identical sets of **sixteen complete worker
reports**, including the new **17-check prepared-package installation**. Each
uses Apple's actual Installer on a complete, privately prepared development
runtime. The test checks installed native bytes, CodeDirectory runtime flags,
signatures and bundle seals, root-controlled paths without privileged modes,
the immutable project-wheel pin, and original/derived dependency lock bindings.
The installed Python constructs an SSL context, runs an SQLite query, and
executes CFFI/ctypes callbacks, crypto, greenlet, Pydantic and fictional TOTP
operations; its installed browser opens a static page with the sandbox enabled.

The development inventory records 45 native files, 20 executables, 11 bundles
and 33 wheels. Runtime preparation records 41 native entries, ten bundle seals
and 32 dependency wheels, leaving the app-pinned project wheel unchanged. These
counts describe the fixture inputs, not publisher acceptance. The explicit
ad-hoc permission plan includes library-validation exceptions for executables
without a publisher team and reviewed fixture JIT roles. It is not a production
permission profile. The ad-hoc owner app still refuses setup before any service
identity, vault or registration is created; cleanup preserves shared system
parent permissions. The original ten-check unprepared-package regression also
passes. Neither package is uploaded as a consumer download.

Both Macs actually ran the separate Node-preparation/browser probe: one passed
test in 4.26 and 4.79 seconds. Their native desktop and Chrome-bridge component
reports also match, with 38 and 18 checks. Linux isolation passed. Both Android
emulator runs produced identical six-check reports, each completing one actual
notification → certificate-pinned HTTPS relay → browser SMS verification.
Physical phones and carriers remain unverified.

The independent runtime check exposed a parser error in preceding Mac runs:
`codesign` reports both CodeDirectory and executable-segment flags. All three
validators now require exactly one CodeDirectory flag field; segment flags
cannot substitute for it, and missing/duplicate directory metadata is refused.
A preceding Android run missed its notification after a fixed 300 ms delay.
Instrumentation now waits a bounded interval for the exact tag, ID and package,
while still requiring actual listener and browser delivery. Product delivery
policy is unchanged. App notarization also validates the explicitly versioned,
exact six-file SMS helper through its final archive; Apple responses in those
unit tests are simulated.

These results establish controlled runtime compatibility and refusal behavior.
They do not establish a genuine publisher, Apple acceptance/stapling, positive
consumer installation, migration/update/reboot, genuine OS approval, complete
installed Chrome/native/XPC/worker acceptance, real protected agent sessions or
new private password/email/SMS/authenticator sign-ins. Owner build 53 and the
unfinished Gmail form were preserved; Gmail remains deferred. Chrome CSV
imports remain snapshots. The candidate remains **not production ready**.

See [sanitized evidence](../artifacts/prepared-runtime-install-080.json),
[runtime preparation and installation](mac-system-provisioning.md) and
[production requirements](production-gates.md).

## Two-page password and protected SMS recovery — 17 October 2026

Revision `a6bdebc` passed **1,120 tests, five platform skips, in 594.49 seconds**,
lint, package builds and an audit with no known vulnerabilities. All eight
push/PR workflows passed. [Regression CI](https://github.com/fainir/account-access/actions/runs/39037809838).

The candidate supports a reviewed email/username page followed by its password
page. The identity stage accepts one exact declared POST and requires a real
accepted response before the expected password page. Password controls and their
POST destination are checked again. Early, duplicate, wrong-endpoint or replayed
requests stop. Native and explicitly configured JavaScript flows complete
password-only, email, SMS and authenticator journeys with saved-session reuse in
controlled tests. Missing sources, changed forms/pages and priority challenges
stop before password disclosure. Temporary failures retain durable retry and the
normal cooldown. No new end-user command or routine approval is added.

Verification-source preflight now precedes either credential fill, and page/form
checks repeat after single-page username input handlers. A fixed hash recorded
before the new schema confirms unchanged connectors retain their permission
fingerprint. The compatibility test's reconstruction of an old model was fixed
to omit the new empty field; the expected golden hash was not changed.

Two disposable Macs produced identical sets of fifteen complete worker reports.
The **18-check System-key/native-SMS journey** now requires two independently
confirmed identity steps as well as two password/SMS logins, session reuse,
cold-host reopening, automatic cooldown recovery and complete process/job/key
cleanup. It invokes the product CLI under another UID through the actual root
host, System key, isolated worker and native owner-UID reader. The standalone
single-page native SMS journey remains a separate regression.

The SMS browser harness now accepts only expected late-delivery refusals after
an acknowledged first delivery. Deterministic tests require rejection after code
consumption and window cleanup; the product policy was not loosened. A preceding
PR run exposed that test race while its parallel push run passed.

The native desktop and Chrome-bridge component reports also remain identical.
Linux isolation and Android emulator acceptance passed. These are controlled
fixtures with fictional website credentials, messages and seeds. They do not
validate a new private provider, physical phone delivery, genuine OS approval,
consumer installation or real agents against the protected deployment. The full
installed Chrome/native/XPC/worker journey remains unverified.

Owner build 53 and the unfinished Gmail form were preserved; Gmail setup remains
deferred. No new private sign-in was requested. Chrome CSV imports remain
snapshots; the public Chromium review does not establish a safe continuous-sync
connection. The candidate remains **not production ready**.

See [sanitized evidence](../artifacts/username-password-pages-080.json),
[connector behavior](username-password-pages.md),
[Chrome sync research](chrome-password-sync-research.md) and
[production gates](production-gates.md).

## Protected Chrome SMS bridge — 17 October 2026

Revision `8ccdd74` passed **1,086 tests, five platform skips, in 503.7 seconds**,
lint, package builds and an audit with no known vulnerabilities. All eight
push/PR workflows passed. [Regression CI](https://github.com/fainir/account-access/actions/runs/39033139504).

The legacy Chrome native host opens the same-user vault and cannot serve the
isolated installation. The candidate now registers the native app as its SMS
host. The app uses the pinned owner channel to send fixed messages to the
protected worker; it does not read a vault, keyring or broker capability. Its
protocol accepts only account discovery, connection and active-window SMS
poll/reply methods. Cookie import and arbitrary owner routes are refused.
Connecting/enabling a source requires the existing setup approval. Routine
polling and delivery require no new approval and remain bound to the worker's
enrollment, freshness, cancellation and revocation checks.

Two CI runs produced identical **18-check native component reports**. These cover
framing, exact origin, shell-parent rejection, method bounds, approval gating and
sanitized failures. Registration tests use a temporary home and check fixed
protected app/resources, complete payload equality, unsafe paths, refusal before
changes and recognized legacy-host migration without opening a store. A separate
private-Unix → DOM reader → worker/browser fixture completes fresh password/SMS
login and keeps the code out of the result. Wrong capabilities/windows, revoked
sources, cookie imports and agent transport are refused.

These remain **separate component and worker/browser tests**. They do not prove
the complete installed Chrome → native app → XPC → worker journey, a positive
signed-Chrome parent check, genuine owner approval or physical SMS. Stable Google
Chrome is the initial parent policy; other branded/testing browsers are not
included. Root-protected app/resources also do not make the owner's Chrome
registration or inbox inaccessible to software that can control that browser.
A read-only check of the already-running Chrome process matched the configured
signing requirement through the same strict dynamic-code API. That checks public
code identity; it does not establish native-host parentage or a Chrome connection.

The fifteen Mac worker reports remain complete and identical across two Macs,
including the 17-check System-key/native-SMS restart journey. Linux and Android
emulator acceptance passed. Owner build 53 and its unfinished mailbox form were
preserved; Gmail connection was deferred by the owner and no new private sign-in
was requested. The candidate remains **not production ready**.

See [sanitized evidence](../artifacts/mac-browser-bridge-080.json),
[Google Messages setup and limits](google-messages.md) and
[production gates](production-gates.md).

## System-host SMS recovery — 17 October 2026

Revision `020e9eb` passed **1,065 tests, five platform skips, in 511.46 seconds**,
lint, package builds and an audit with no known vulnerabilities. All eight
push/PR workflows passed. [Regression CI](https://github.com/fainir/account-access/actions/runs/39031475490).

[Mac acceptance](https://github.com/fainir/account-access/actions/runs/39031475505) and a
[second disposable Mac](https://github.com/fainir/account-access/actions/runs/39031478145) produced identical sets of fifteen
complete reports. The new **17-check system-host journey** uses the actual
`RootBrokerHost`, supervisor, launchd-activated sockets and System vault key.
The product CLI runs under a separate unprivileged UID. Its scoped read reaches
the isolated worker, native collector and owner-UID reader, completes a fresh
password/SMS login and reuses the saved session.

The test stops that host and its worker, expires only the synthetic website
session, then starts a cold host against the same protected store and System
key. A direct read observes the normal login cooldown. A durable task waits
through that guard and completes a second password/SMS login without owner
intervention; a subsequent read reuses the second session. The provider
independently confirms exactly two password logins and two accepted SMS codes
across four completed reads. Shutdown receipts must match both host PIDs and
their workers must be absent. Temporary jobs, setup policy and fixture key are
removed. Result-field, code-output, store and private-collector restrictions
remain enforced.

This is controlled acceptance through a CI entrypoint with synthetic enrollment,
website and Messages data and hash-pinned ad-hoc peers. It does **not** establish
consumer installed startup, genuine owner approval, Full Disk Access attribution,
physical SMS, real AI CLI sessions against this protected deployment or private
email/SMS/authenticator sign-ins. The candidate remains **not production ready**.
Owner build 53 and its unfinished mailbox form were preserved; no new private
sign-in was requested.

The preceding 14 reports remain complete, including the standalone ten-check
native browser journey and 13 native reader-process checks. See
[sanitized system-host evidence](../artifacts/mac-native-system-browser-080.json),
[collector design](mac-isolated-sms.md) and [remaining gates](production-gates.md).

## Composed native SMS browser journey — 17 October 2026

Revision `04e8193` passed **1,047 tests, five platform skips, in 484.65 seconds**,
lint, package builds and an audit with no known vulnerabilities. All eight
push/PR workflows passed. [Regression CI](https://github.com/fainir/account-access/actions/runs/39027669545).

[Mac acceptance](https://github.com/fainir/account-access/actions/runs/39027669558) and a
[second disposable Mac](https://github.com/fainir/account-access/actions/runs/39027672013) produced identical sets of fourteen
complete reports. The new **ten-check composed journey** invokes the product CLI
as an unprivileged account. Its approved read reaches the actual isolated
worker, which requests a baseline and fresh code from the production native
collector. The signed, hash-pinned reader runs under a separate owner UID. The
worker supplies the code to the fixture website, completes the read and reuses
its saved browser session for a second CLI request. The provider independently
confirms one password login and one accepted SMS code.

The CLI returns exactly the approved summary fields, contains no six-digit code,
cannot fetch internal collector requests and remains unable to read the worker's
vault. The root collector stops cleanly and its temporary job is removed. The
existing 13 process-specific SMS checks and the twelve earlier Mac reports
remain complete.

This closes the gap between separate native-reader and browser-transport tests
for the **controlled worker/browser journey**. It uses a CI root collector host
and test bootstrap material: **the production composed host and System vault key
are not used in this journey**. Their other controlled tests are separate.
Real Codex/Claude sessions against that protected deployment, genuine Full Disk
Access attribution, physical SMS and private-account acceptance remain required.
Installed owner build 53 and its unfinished mailbox form remain untouched. No
new private sign-in was requested. The public download remains the preview and
the candidate is **not production ready**.

See [sanitized journey evidence](../artifacts/mac-native-browser-080.json),
[collector boundary](mac-isolated-sms.md) and [production gates](production-gates.md).

## Isolated Mac SMS collection and concurrent stop — 17 October 2026

Revision `73b7c06` passed **1033 tests, 5 platform skips, in 518.55 seconds**,
lint, package builds and a dependency audit with no known vulnerabilities. All
eight push/PR workflows passed. [Regression CI](https://github.com/fainir/account-access/actions/runs/39026369253).

[Mac acceptance](https://github.com/fainir/account-access/actions/runs/39026369231) and an
[second disposable Mac](https://github.com/fainir/account-access/actions/runs/39026372636) produced identical sets of thirteen
complete reports. The new native SMS report contains **13 checks**. The root
host starts a code-pinned reader under the actual owner UID, authenticates both
ends of an inherited private socket and supplies only bounded active-login
metadata. A kernel audit token binds the root peer to its code and process
identity. Wrong peers, forged reader PIDs, stale/used/ambiguous codes,
future-dated texts and truncated result sets are refused. No reader key or vault
credential is copied into the owner account.

Two synthetic browser tests separately complete password/SMS login through the
private Unix collector transport, reuse the saved session and stop code
submission after source revocation. These tests do not switch OS users or invoke
the native reader. The native process journey and browser transport journey are
separate: **a complete isolated native-reader/browser SMS login is still open**.
Neither uses a private message or physical phone.

Regression testing also exposed a concurrent stop/read failure in the legacy
desktop supervisor. Reading one pinned descriptor now treats a removed or
replaced registration as inactive while preserving ownership, private-mode and
link checks. Three deterministic cases exercise removal during open/read and
replacement during a read. The 23 local supervisor tests passed. The protected
system job now associates the owner app's bundle identifier, following Apple's
responsible-code guidance; this does not grant Full Disk Access.

The existing twelve Mac reports remained complete, including 40 first-vault/client,
26 provisioning, 10 negative package, 31 coordinator and 25 worker checks. Signed
positive installation, genuine OS privacy approval, private email/SMS/TOTP,
physical Android/iPhone, isolated Chrome ingress and continuous Chrome password
sync remain release gates. Installed owner build 53 and its unfinished mailbox
form were preserved. No new private sign-in was requested. The candidate remains
**not production ready**, and the public download remains the 0.7.4 preview.

See [sanitized evidence](../artifacts/mac-native-messages-080.json),
[collector boundary](mac-isolated-sms.md) and [production gates](production-gates.md).

## Protected Mac provisioning and offline package — 17 October 2026

Revision `a03b241` passed **994 tests, five platform skips, in 455.31 seconds**,
lint, an audit with no known vulnerabilities, package builds, native app checks
and all eight push/PR workflows. [Regression CI](https://github.com/fainir/account-access/actions/runs/39021348603),
[Linux worker](https://github.com/fainir/account-access/actions/runs/39021348638)
and [Android emulator](https://github.com/fainir/account-access/actions/runs/39021348632)
passed. These do not establish physical-phone delivery or private sign-ins.

[Mac acceptance](https://github.com/fainir/account-access/actions/runs/39021348626)
and an [independent repeat](https://github.com/fainir/account-access/actions/runs/39021351108)
produced identical sets of twelve complete reports. New coverage includes
**26 provisioning checks** and **10 negative package-installation checks**.
The existing reports retained 40 initial-vault/client, 18 initial gateway,
28 publication, 31 coordinator, 21 supervisor, 33 handoff, 20 System-key,
24 owner-host, 16 setup-policy and 25 isolated-worker checks. Native owner
transport retained 67 checks and desktop transport retained 38.

The provisioner creates a dedicated non-login identity, private empty stores,
root-controlled policies and a persistent launchd job. Identical preparation is
idempotent. The actual service starts without a key or worker, recreates its
missing user bootstrap domain and rejects unapproved setup through native XPC.
Directory Services values use structured plist output. Cleanup verifies the
canonical records rather than stale passwd-cache results. Python and native
runtime checks reject allow ACL entries; ordinary temporary-file tests confirm
that restrictive deny ACLs remain accepted. This is not a full-machine reboot.

The package journey uses Apple's actual Installer in a disposable VM. The
included Python creates its environment at the installed path; dependencies
install offline from required hashes, and a relocated sandboxed browser renders
a fictional page. Shared system-folder ownership and modes remain unchanged.
The ad-hoc development app is refused before any vault, service identity or
registration is created, and its credential-free payload is removed. The owner
app requires protected registration and cannot fall back to legacy storage when
that registration is missing. This is a **negative development-package test**,
not signed positive consumer installation or genuine owner consent.

A separate local build/unpack check also loaded the offline dependencies and
ran the relocated sandboxed browser, without installing the package. All root
installation experiments occurred only in disposable CI. Installed owner build
53 and its unfinished mailbox form remain untouched. No new private sign-in was
requested. The development archive is not published as a user download.

See [provisioning evidence](../artifacts/mac-system-provisioning-080.json),
[package evidence](../artifacts/mac-system-package-080.json) and the
[installation contract](mac-system-provisioning.md). Signed/notarized positive
installation, interrupted-package recovery, migration/update continuity, genuine
OS approval, trusted isolated host collectors and real email/SMS/authenticator
and physical-device QA remain release gates. Chrome password imports remain
snapshots; continuous Chrome synchronization is still unmet. The public download
remains the **0.7.4 preview**, and this candidate is **not production ready**.

## Portable client bootstrap through native owner setup — 17 October 2026

Revision `0a473b8` passed **946 tests, three platform skips, in 508.62 seconds**,
lint, an audit with no known vulnerabilities, packaging, native screen checks
and all eight push/PR workflows in
[regression CI](https://github.com/fainir/account-access/actions/runs/39016682285).
The [Linux 24-check worker](https://github.com/fainir/account-access/actions/runs/39016682312)
and [Android emulator journey](https://github.com/fainir/account-access/actions/runs/39016682286)
also passed. Seventy focused cases passed locally on Mac, including the two
Darwin ACL cases skipped by the Linux regression job. Native owner-channel
acceptance retained **67 checks** with ad-hoc peers.

The native app now connects a fresh isolated vault to one `generic` client,
without a Claude/Codex selector. An owner-user helper prepares private client
files, the approved native setup path enrolls its digest, and the helper verifies
an account read before publishing the portable launcher and detected-host session
guidance. Confirmation contains only the public ID and known host names. The
broker returns no token and grants no account access during enrollment. Repeating
the same connection preserves its token and grants; different, revoked or orphaned
principal history requires repair rather than silent replacement.

[Mac CI](https://github.com/fainir/account-access/actions/runs/39016682451/job/117350116965)
and an [independent repeat](https://github.com/fainir/account-access/actions/runs/39016685806/job/117350126691)
produced identical sets of ten complete reports: **40 first-vault/client setup**,
18 initial native gateway, 28 publication, 31 composed host, 21 supervisor,
33 handoff, 20 System-key, 24 root owner-host, 16 policy and 25 worker checks.
An ordinary fixture owner prepares and installs the shared client against the
actual dedicated worker. Both portable and Claude launchers discover an empty
permitted-account set, omit the capability from output and preserve existing
Codex/Claude instruction text. Opening the broker store raises an actual permission
error. Client installation state survives worker reopening.

Positive authority in that journey is a synthetic in-process native setup session;
it is not a genuine OS approval or positive separate-process owner-XPC acceptance.
Neither real AI product is invoked in this new bootstrap test. The test also does
not sign into a private website. Those scopes remain separate from the earlier
private-session evidence and the owner's stop on further GitHub QA.

The [desktop transport](https://github.com/fainir/account-access/actions/runs/39016682285/job/117350116464)
and its [independent repeat](https://github.com/fainir/account-access/actions/runs/39016685782/job/117350126423)
passed **38 controlled checks**. The added cases require setup authorization and
reject malformed client requests, caller-selected principals and unknown hosts.
Native screen checks hold the account view until client setup finishes, connect
both hosts without a selector, and reopen without another enrollment or approval.
A changed local capability digest is refused before any request. These helper,
channel and positive approval implementations are synthetic.

Two earlier revisions failed the new Mac bootstrap gate and are excluded. Source
review found the disposable marker was supplied before `sudo` reset the environment,
then found the helper's verified virtual-environment path was replaced with its
resolved base interpreter. A local Swift `Process` regression proves the latter:
the virtual-environment path imports the package, while its resolved base binary
does not. Both desktop and QA callers now validate the target but launch the
original environment path. Subsequent complete repeats pass. Earlier runtime
diagnostics retained only the phase, so their exact child exception was not
captured; new diagnostics report fixed process/response failure classes without
secret values. See [structured evidence](../artifacts/mac-agent-setup-080.json).

Consumer provisioning, genuine OS approval through the screens, complete trusted
email/SMS/browser collectors, migration and client-revocation repair, publisher
continuity, notarized installation and private/physical-phone QA remain open.
Continuous Chrome synchronization remains unmet. Installed build 53 and its
unfinished mailbox form, the 0.7.4 download and older staged build 61 were preserved.
The [client setup contract](mac-agent-setup.md) describes the implemented flow and
its limits. This remains a development candidate, not production acceptance.

## Native desktop integration and initialized-vault Pause — 17 October 2026

Revision `5356e8a` passed **910 tests, one platform skip, in 495.93 seconds**,
lint, an audit with no known vulnerabilities, packaging and native UI checks in
[regression CI](https://github.com/fainir/account-access/actions/runs/39013969385).
All eight push/PR workflows passed. The
[Linux 24-check worker](https://github.com/fainir/account-access/actions/runs/39013969316)
and [Android emulator journey](https://github.com/fainir/account-access/actions/runs/39013969365)
also passed. The owner-channel suite retained **67 passing checks** with ad-hoc
peers. Local production desktop code type-checked for both arm64 and x86_64,
targeting macOS 14; 35 focused evidence cases passed locally.

The [desktop transport checks](https://github.com/fainir/account-access/actions/runs/39013969385/job/117342119864)
passed **31 cases**, with an identical
[independent report](https://github.com/fainir/account-access/actions/runs/39013972012/job/117342127557).
They cover protected profile ownership, mode bits, ACLs, links, size, identity and
schema; refusal before proof/credential release; setup-lease expiry and reuse;
malformed responses; and lost-write responses followed by read-only reconnect.
These channel and positive-approval implementations are synthetic, not native
XPC or genuine OS approval evidence.

Native screen checks render first setup, paused and repair states without
exposing arbitrary error text. An asynchronous synthetic enrollment accepts 202,
then automatically reads the full worker state and opens the account view. It
uses no legacy capability registration. A second enrollment loses its response;
reopening performs only a read, with no replay or new approval. Production mode
selects the fixed protected registration before the old installer/runtime path.
Missing or invalid native state cannot silently choose the legacy connection.

[Mac service CI](https://github.com/fainir/account-access/actions/runs/39013969327/job/117342119300)
and an [independent repeat](https://github.com/fainir/account-access/actions/runs/39013972022/job/117342127456)
produced identical sets of ten raw reports: **18 pre-enrollment gateway, 27 first
coordinator**, 28 publication, 31 composed host, 21 supervisor, 33 handoff,
20 System-key, 24 root owner-host, 16 policy and 25 worker assertions. The new
separate-process desktop transport assertions load the protected root-owned
public profile, read actual service state without approval and refuse an invalid
OS proof before enrollment. These are native XPC reads/refusals; genuine positive
approval remains unverified.

Pause after first-worker readiness now persists in the enrollment journal and
keeps native owner state readable. A quick approved Resume handles either a
completed pause or a superseded queued pause, without trying to start an already
running worker. The added coordinator regression checks this with a real
fixture store, key and worker, using synthetic in-process setup authority.

The [connection contract](mac-desktop-connection.md) and
[structured evidence](../artifacts/mac-desktop-connection-080.json) retain those
separate scopes. Consumer provisioning, genuine positive approval through the
screens, complete isolated source setup/collectors, client issuance, migration,
publisher continuity and full setup crash/power-loss recovery remain open.
This adds no private email/SMS/authenticator or physical-phone acceptance, and
continuous Chrome password synchronization remains unmet. Installed build 53
and its unfinished mailbox form, the 0.7.4 preview and older staged build 61
were preserved; no private sign-in was attempted.

## System entrypoint and initial native connection — 17 October 2026

Revision `cf313f6` passed **15 pre-enrollment gateway checks** in
[Mac CI](https://github.com/fainir/account-access/actions/runs/39012690226/job/117338380658)
and an [independent repeat](https://github.com/fainir/account-access/actions/runs/39012692656/job/117338387612).
All ten complete raw reports agree, retaining the separate 24 positive coordinator,
28 publication, 31 composed-host, 21 supervisor, 33 handoff, 20 System-key,
24 root owner-host, 16 policy and 25 cross-user worker assertions.

The production system entrypoint hosts the first-enrollment mode with activated
listeners and a real native owner connection before a vault key exists. The
pinned owner can read setup state and health. Wrong owner UID, wrong client or
server code, unapproved enrollment, an invalid OS proof and caller-provided
configuration are refused. No key or worker starts. After the rejected requests
and service shutdown, the same entrypoint signature checks key absence while
removing its QA setup rule. Temporary system jobs are removed.

The service uses a permanent dispatch loop and retains its host and signal
sources. QA writes readiness metadata once; no test-only main-queue timer keeps
the daemon alive. The production build accepts no arguments and has a fixed
protected host-policy path. Its ordinary-user launch exits 78 before reading
configuration. Both service and bootstrap build as universal arm64/x86_64 tools
targeting macOS 14 and pass signature checks locally and in CI. Local builds and
the VM use ad-hoc identities, not a publisher-signed installed deployment.

The native owner-channel suite passed **67 checks** locally and in
[CI](https://github.com/fainir/account-access/actions/runs/39012690209/job/117338380736).
A new regression failed before the fix: malformed enrollment data on a prepared
client returned channel-unavailable 503. It now returns policy-refusal 403 with a
fixed reason before forwarding. Unprepared or closed channels still refuse setup
input. Earlier revision `eb250e6` failed both new Mac gateway runs and is excluded.
The older fixture client did not retain assertion names, so those runtime reports
alone do not identify the exact assertion. The deterministic regression and later
complete repeats are recorded in [evidence](../artifacts/mac-initial-gateway-080.json).

Matching source passed **910 tests, one platform skip, in 514.17 seconds**,
lint, an audit with no known vulnerabilities, packaging and native UI checks in
[regression CI](https://github.com/fainir/account-access/actions/runs/39012690209).
The [Linux 24-check worker](https://github.com/fainir/account-access/actions/runs/39012690259)
and [Android emulator journey](https://github.com/fainir/account-access/actions/runs/39012690281)
also passed. All eight push/PR workflows passed. The focused local evidence group
passed 55 cases; the SDK/evidence group passed 31, with overlapping cases.

This new journey exercises separate-process native reads and refusals before
enrollment. Positive setup authority remains a separate in-process synthetic
coordinator test. Genuine positive approval, consumer package/native UI, client
issuance/migration, setup crash/power-loss recovery and publisher continuity remain
unverified. Private email/SMS/authenticator/physical-phone acceptance and notarized
clean installation remain open. Installed build 53 and its unfinished mailbox form
were untouched; no private sign-in was attempted. Continuous Chrome password sync
remains unmet; the source/API review is in [password-source limits](security-and-password-sync.md#password-source-updates).

## Native first-vault coordinator — 17 October 2026

Revision `1bb6992` passed **24 first-enrollment checks** in
[Mac CI](https://github.com/fainir/account-access/actions/runs/39010365682/job/117331438897)
and an [independent repeat](https://github.com/fainir/account-access/actions/runs/39010368012/job/117331446556).
All nine complete raw reports agree, including the existing 28 publication,
31 composed-host, 21 supervisor, 33 handoff, 20 System-key, 24 root owner-host,
16 setup-policy and 25 worker checks.

The production coordinator connects setup-session authority to a fresh System
key, staged initialization, atomic publication and an actual dedicated worker.
Fresh startup without recorded approval and rejected setup requests create no key.
Native owner state and health stay available before enrollment. A new setup
route accepts only an empty object and uses an opaque native approval type;
caller-selected IDs, paths, credentials and commands are rejected, and the
legacy owner backend cannot receive key-creation requests.

The real production verifier rejects an invalid proof. Positive setup authority
is synthetic and passed through an in-process `OwnerGatewaySession`. A controlled
checkpoint before initialization makes Pause/Resume deterministic. Pause before
approval persists across coordinator reopening. Pause during initialization
blocks progress, and an approved immediate resume completes one pipeline.
Another coordinator reopens the published store without new approval. Removing
the fixture key makes the published store require repair while keeping owner
reads available; it never creates a replacement key. Fixture keys are removed.

The native owner-channel suite passed **66 checks** locally and in
[CI](https://github.com/fainir/account-access/actions/runs/39010365609/job/117331438983)
with ad-hoc peers. Its eight added checks cover the new route, typed authority,
unapproved/invalid/expired/closed sessions and legacy-backend refusal. Earlier
publisher-signed results retain their own source scope.

Matching source passed **893 tests, one platform skip, in 501.66 seconds**,
lint, an audit with no known vulnerabilities, packaging and native UI checks in
[regression CI](https://github.com/fainir/account-access/actions/runs/39010365609).
The [Linux 24-check worker](https://github.com/fainir/account-access/actions/runs/39010365642)
and [Android emulator journey](https://github.com/fainir/account-access/actions/runs/39010365669)
also passed. All eight push/PR workflows passed; the focused local evidence
group passed 49 cases. Both production Mac architectures type-check, and the
native QA harness links locally.

This is first-store coordinator acceptance, not a genuine positive owner
approval or consumer setup. The new `RootBrokerHost` enrollment mode is compiled
but not yet exercised through a separate native XPC owner process. Setup objects
reopen their durable files within the same hosting process; setup-process kill,
full crash/power-loss recovery, native consumer screens/installer, client
issuance and migration remain unverified. The existing-store composed-host
parent-crash journey is separate. Private email/SMS/authenticator sign-ins,
physical phones, publisher continuity and notarized clean installation remain
open. No private login was attempted; installed build 53 and its unfinished
mailbox form were preserved. See [evidence](../artifacts/mac-initial-setup-080.json)
and [flow/limits](mac-initial-enrollment.md).

## Staged vault setup and publication — 17 October 2026

Revision `a0c6cd9` passed **28 native setup/publication checks** in
[Mac CI](https://github.com/fainir/account-access/actions/runs/39008738855/job/117326487756)
and an [independent repeat](https://github.com/fainir/account-access/actions/runs/39008741585/job/117326495917).
All eight raw reports agree between those runs: 28 setup/publication, 31
composed host, 21 supervisor, 33 handoff, 20 System-key, 24 root owner-host,
16 setup-policy and 25 worker assertions. The System key and fictional accounts
remain separate from private-account or genuine owner-approval acceptance.

The actual initializer reads its inherited key only after permanent identity
drop. The native parent checks the child's kernel identity and private
authenticated receipt and requires a normal child exit. The initializer
atomically claims an empty stage and writes an
encrypted enrollment marker. The ordinary worker authenticates encrypted data
before readiness; wrong-key and record-free stores cannot report a verified
key. Parsing the plaintext configuration or returning an empty account list
alone does not establish that the key works.

The publisher keeps a private root-owned journal and exclusive parent lock.
It accepts only the completed initializer receipt, binds both original
directory identities and atomically swaps the verified stage with the empty
destination. A competing publisher, nonempty destination, replacement directory
or missing verification is refused without deleting data. Journal reopening
and repeated publication preserve the completed orientation. The original
files retain their inodes, and the ordinary worker opens the published store.
A populated destination prevents another initialization. These journal reopen
checks occur in the same hosting process; killing the publication process and
power-loss durability are not covered.

Matching source passed **875 tests, one platform skip, in 489.12 seconds**,
lint, a dependency audit with no known vulnerabilities, packaging and native
checks in [regression CI](https://github.com/fainir/account-access/actions/runs/39008738987).
The [Linux 24-check worker](https://github.com/fainir/account-access/actions/runs/39008738818),
[Android emulator journey](https://github.com/fainir/account-access/actions/runs/39008738862)
and [58 native owner XPC checks](https://github.com/fainir/account-access/actions/runs/39008738987/job/117326488304)
also passed. All eight push/PR workflows passed. Focused local groups passed
57 shutdown/health/boundary cases and 39 initializer/signal/evidence cases;
these groups overlap and are not added together.

Earlier revision `c4fd001` is excluded: one run failed the existing
`worker_graceful_shutdown_verified` check, and another reached initialization
but failed `initialized_store_worker_stops_cleanly`. Inspection found server
signal replay and a health watcher that could classify intentional shutdown as
failure. Managed signal ownership now lasts through private cleanup, and the
watcher distinguishes stopping from a failed background loop. A real-server
regression delivers a second SIGTERM during cleanup and requires exit zero.
Both later Mac runs passed; failure links remain in the
[sanitized evidence](../artifacts/mac-staged-enrollment-080.json).

Consumer setup still needs genuinely authorized initial System-key creation,
native UI/source integration, client issuance and migration. Full setup crash
recovery, publisher update continuity, notarized clean installation, private
email/SMS/authenticator delivery and physical phones remain open. Installed
build 53 and its unfinished mailbox form were preserved. Read-only discovery
found no additional private service; the original Namecheap task still reports
its existing browser-state challenge and was not resubmitted. Private GitHub
testing remains stopped.

## Composed Mac system-host recovery — 17 October 2026

Revision `e756d18` passed **31 composed-host checks** in
[Mac CI](https://github.com/fainir/account-access/actions/runs/39006452093/job/117319816135)
and an [independent PR run](https://github.com/fainir/account-access/actions/runs/39006454910/job/117319824512).
Both complete sets of seven reports agree: 31 composed host, 21 supervisor,
33 native handoff, 20 System-key, 24 root owner-host, 16 setup-policy and
25 cross-user worker assertions.

The actual `RootBrokerHost` activates its system job's listeners, loads the
fixture System key, starts the dedicated worker on an existing empty encrypted
Store and accepts the pinned native owner client. Wrong client code, owner UID,
server code and ungranted configuration writes are refused. The journey kills
the named supervisor job with SIGKILL, verifies the old worker exits, checks the
replacement's kernel parent/group/UID/GID, confirms socket identity continuity,
rejects the old owner connection and reads the reopened Store. It also removes
and re-registers the service and preserves Pause across another parent crash;
the paused native gateway remains available without starting a worker.
The QA authorization rule and System key are removed afterward.

Matching source passed **836 tests, one platform skip, in 430.71 seconds**,
lint, a dependency audit with no known vulnerabilities and package/native
checks in [regression CI](https://github.com/fainir/account-access/actions/runs/39006452116).
The [Linux 24-check worker](https://github.com/fainir/account-access/actions/runs/39006452059),
[Android emulator journey](https://github.com/fainir/account-access/actions/runs/39006452079)
and [58-check ordinary-user owner XPC journey](https://github.com/fainir/account-access/actions/runs/39006452116/job/117319816349)
also passed. All eight push/PR workflow runs passed. The earlier local publisher-signed XPC
result retains its own revision scope. Local focused boundary/evidence checks passed 146 cases; the
readiness/health group passed 55. A native listener regression verifies actual
accept/relisten behavior and rejects regular files and connected streams.

Earlier attempts are excluded. `f39079f` failed new host startup; the Darwin
Unix-socket SO_ACCEPTCONN query proved unavailable locally and was replaced by
listen-based readiness. At `114cdc1`, one run refused initial socket metadata;
initial activation now sets and strictly verifies required group/mode on its
own root-owned socket. Later acquisition only validates metadata/inode identity.
Another run failed an existing handoff/lifecycle boolean before coordinator
startup; that report did not identify the exact assertion. Code inspection found
owner health could precede agent-server startup. Managed health now stays 503
until the server has started, and fixed failing assertion names are retained.
Tests also reject non-boolean or throwing readiness callbacks without exposing
exception text. See [evidence and failed-run links](../artifacts/mac-root-coordinator-080.json).

This is an actual system-host composition in a disposable VM with ad-hoc pins,
not consumer deployment or genuine positive owner approval. Cold service
removal/re-registration is not a full machine reboot. Active browser descendants
and interrupted account tasks are not tested by the empty-store journey.
Consumer setup, enrollment/client issuance, source collectors, migration,
publisher update continuity, notarized installation and private email/SMS/TOTP
and physical-phone acceptance remain open. Installed build 53 and the unfinished
mailbox form were preserved.

## Native existing-store supervision — 17 October 2026

Revision `40c9fa4` passed **21 native supervisor checks** in the
[disposable Mac VM](https://github.com/fainir/account-access/actions/runs/39004132984/job/117312998074),
alongside 33 System-key handoff, 20 key-custody, 25 cross-user worker,
24 root owner-host and 16 setup-policy checks. The actual dedicated worker
reopens an empty encrypted fixture Store after observed owned-child crashes.
The scheduler enforces one/two/four-second backoff and a three-restart budget,
resets the budget after observed stable running, preserves Pause (including a
dangling symlink), keeps paused native health available and never recreates a
missing key. The monotonic clock is controlled; processes, signals, reaping,
System key, encrypted storage and listener cleanup are real. Supervisor session
checks use an in-process synthetic verifier.

The same revision passed **58 native owner-channel checks** locally with
Developer ID signed peers and in
[ordinary-user CI with ad-hoc peers](https://github.com/fainir/account-access/actions/runs/39004132894/job/117312997677).
The helper stays alive across generation retirement: its old setup session is
refused, and the new connection needs its own approval. A deliberately stalled
Unix responder checks the 150 ms health deadline; invalid timeout values send
no request. Root worker readiness uses separately bounded health probes.
The focused Python boundary/evidence regression passed **135 cases** locally.

Matching source passed **811 tests, one platform skip, in 435.16 seconds**,
lint, a dependency audit with no known vulnerabilities and package/native
checks in [regression CI](https://github.com/fainir/account-access/actions/runs/39004132894).
[Linux's 24-check worker](https://github.com/fainir/account-access/actions/runs/39004132859)
and the [Android emulator journey](https://github.com/fainir/account-access/actions/runs/39004132911)
also passed. An [independent Mac CI run](https://github.com/fainir/account-access/actions/runs/39004135625/job/117313005496)
passed the same six native reports. All eight push/PR workflow runs passed.

An earlier docs-only revision, `7600988`, had a
[failed Mac handoff run](https://github.com/fainir/account-access/actions/runs/39003591785):
its enclosing 45-second phase budget expired without a complete report. The
inner operation was not identified. The readiness call could wait up to 35
seconds, and the outer budget covered several starts/stops. The new readiness
probe is bounded separately; aggregate handoff/supervision budgets cover their
multi-worker journeys. The failed run is excluded. Superseded in-progress CI
runs were cancelled to free capacity; cancelled runs are not acceptance.

See [supervision evidence](../artifacts/mac-root-supervisor-080.json),
[owner XPC evidence](../artifacts/mac-owner-gateway-080.json) and
[component design/limits](mac-supervision.md). These tests do not deploy the
consumer composition, prove a genuine owner approval, recover a crashed parent
daemon/reboot or test active browser descendants/durable operations after a
crash. Native consumer setup/source collectors, client issuance/migration,
private email/SMS/TOTP, physical phones and notarized clean installation remain
open. Installed build 53 and its unfinished mailbox form were preserved.

## System key to actual worker service — 17 October 2026

Revision `d8264cd` passed **33 native handoff/lifecycle checks** in
[Mac CI](https://github.com/fainir/account-access/actions/runs/39002897216/job/117309356475).
A native sender loaded the real fixture System key and sent exactly 64 bytes
through an anonymous pipe. The launcher permanently dropped to the dedicated
broker identity; production Python bootstrap/storage code created and reopened
an encrypted fixture Store in separate processes. Private receipts, kernel
UID/GID, descriptor closure, replay/failure/cancel behavior were checked.

The same native lifecycle component started the actual worker on that Store,
confirmed private owner state and kernel identity, stopped/reopened it, refused
the previous owner capability, and preserved Pause. A killed owned worker was
reaped; another worker reopened the same encrypted data. Wrong launcher
signature was refused and created listener paths were removed. The Store is
empty of website accounts: this does not add private sign-in coverage. These
checks ran alongside the 20 System-key, 25 worker, 24 owner-host and 16 policy
checks, whose scopes remain separate.

Matching source passed **794 tests, one platform skip, in 433.65 seconds**,
lint, audit with no known vulnerabilities, packaging and native checks in
[regression CI](https://github.com/fainir/account-access/actions/runs/39002897235).
[Linux's 24-check worker](https://github.com/fainir/account-access/actions/runs/39002897242)
and [Android emulator journey](https://github.com/fainir/account-access/actions/runs/39002897234)
also passed. See [native handoff evidence](../artifacts/mac-key-handoff-080.json).

This verifies an existing fixture Store under a live native parent. It does not
verify parent-daemon crash/reboot, consumer provisioning/installation, genuine
initial owner enrollment, native phone/source collectors or migration. Signed
build 61 is still the older staged payload; installed build 53 and its mailbox
form remain untouched. Private email/SMS/TOTP and physical phones remain open.

## Strict Mac setup policy and stop recovery — 17 October 2026

Revision `d402c5d` passed **16 native policy checks**, alongside the existing
20 System-key, 24 root owner-host and 25 worker checks in the same
[Mac VM](https://github.com/fainir/account-access/actions/runs/38999652539/job/117299684300).
The daemon created the exact user/session-owner rule, verified its own registrar
identity, preserved an existing matching rule, refused altered rules and foreign
registrar metadata, and removed the QA right. A real OS proof obtained only under
the fixture's temporary permissive rule was refused by the production root
verifier. This is explicitly synthetic proof testing, not genuine owner approval.
The installed owner's authorization database and app were unchanged.

Matching source passed **778 tests, one platform skip, in 468.24 seconds**,
lint, dependency audit with no known vulnerabilities, package and native checks
in [regression CI](https://github.com/fainir/account-access/actions/runs/38999652497).
[Linux's 24-check worker](https://github.com/fainir/account-access/actions/runs/38999652516)
and the [Android emulator journey](https://github.com/fainir/account-access/actions/runs/38999652533)
also passed. All eight push/PR workflow variants succeeded. The updated owner
channel passed 54 checks locally with ad-hoc peers; the earlier Developer ID
run retains its own source scope. See [policy evidence](../artifacts/mac-owner-policy-080.json).

An earlier full run at `7ebf887` exposed a genuine shutdown race: supervision
could close the owner listener after authenticated readiness but before Stop's
POST. That failed run is excluded. Stop now tolerates a transport failure only
while still requiring both actual process leases to finish; explicit HTTP
rejection and held leases still fail. A deterministic real-process regression,
29 targeted lifecycle tests and 64 installer/bootstrap tests passed. See
[stop-race evidence](../artifacts/stop-race-080.json).

Consumer supervision/key handoff, native enrollment/collectors, genuine owner
approval, migration, notarized installation, real private verification sources
and physical phones remain open. Installed build 53 and its unfinished mailbox
form were preserved. The production goal is not complete.

## Mac system key custody — 17 October 2026

Revision `d402c5d` passed **20 daemon key-custody checks** alongside the Mac
worker's 25 and root owner host's 24 checks in the same
[disposable VM](https://github.com/fainir/account-access/actions/runs/38999652539/job/117299684300).
The key was confirmed independently in System, recovered by a new system
process, and refused to a separate user (`errSecAuthFailed`). Invalid/other vault
identities, duplicate enrollment, missing-key non-enrollment, zero core-dump
limits and fixture removal were checked. Eleven pure metadata tests also passed.
File-based Keychain queries now resolve one unique persistent reference before
reading data; repeated identical references are tolerated, distinct records fail.
No key was supplied through a file, argument, environment or agent response.

This is process-restart component acceptance, not reboot, signed-binary update,
consumer supervision, key handoff or installed-owner migration. Private mailbox,
SMS and TOTP coverage remains open. The separately tested authorization-policy
provisioner does not establish genuine owner approval. See
[key-custody evidence](../artifacts/mac-key-custody-080.json) and its
[contract and remaining work](mac-key-custody.md).

## Root Mac owner service integration — 17 October 2026

Revision `de1b0d7` passed **24 root owner-service checks** alongside the worker's
25 cross-user checks in the same
[disposable Mac VM](https://github.com/fainir/account-access/actions/runs/38995617514/job/117287405676).
The host ran as UID 0 under launchd's system namespace. A pinned client under a
temporary non-admin owner identity reached the actual separate-user worker and
revoked an approved operation; the agent then confirmed denial. Wrong client
code, OS user and server code were refused. A live owner connection failed after
service removal while approved browser reads through the worker still worked.
The service, daemon process, temporary OS users and their domains were removed.

The capability crossed once in memory through a root-private, peer-checked Unix
socket, never a file, argument or environment variable. It was absent from client
output. Setup credentials and grants without OS authorization were rejected;
this test deliberately did not register an authorization rule or claim a
genuine owner approval. CI pins ad-hoc code hashes, so publisher trust remains a
separate scope. The existing **54 ordinary-user checks** also passed locally
with actual Developer ID signatures after the connection-lifecycle change.
**53 focused Python cases** and both native architecture type-checks passed.
Matching source passed **740 tests, one platform skip, in 485.01 seconds**,
lint, dependency audit with no known vulnerabilities, packaging and native
checks in [regression CI](https://github.com/fainir/account-access/actions/runs/38995617512).
The [24-check Linux journey](https://github.com/fainir/account-access/actions/runs/38995620477)
and [Android emulator journey](https://github.com/fainir/account-access/actions/runs/38995620442)
also passed; their synthetic/physical-device limits remain distinct.

The host bounds active connections and closes their setup sessions on stop.
There is still no production supervisor/key custody, consumer UI/source-collector
integration or installed-owner migration. Installed build 53 and its unfinished
mailbox form were preserved. See [root integration evidence](../artifacts/mac-root-owner-080.json)
and the [channel contract](mac-owner-gateway.md). These are synthetic account and
message sources, not private Gmail/SMS/TOTP or physical-phone acceptance.

## Separate-user Mac worker — 17 October 2026

Revision `40ad638` passed **25 cross-user checks** in
[Mac CI](https://github.com/fainir/account-access/actions/runs/38994642402/job/117284376640).
A root-owned runtime, native identity-drop launcher and two temporary non-admin
OS users exercised the actual broker. Four fictional password logins completed
with one TLS IMAP email code, one certificate-checked synthetic handset SMS and
one TOTP verification. The agent could not read or change the vault, replace
runtime/policy files, signal or obtain a task port for the worker, impersonate
its identity, use passwordless sudo or reach the private owner channel.
Revocation stopped an approved read; graceful shutdown produced no credentials.

The native launcher rejects writable runtime descendants, including code behind
a directory symlink, before key handoff. Its kernel descriptor allowlist passed
a native regression with an open descriptor above a lowered soft limit and
preserved the PID. Both Mac architectures type-check; the cross-user runtime
journey ran on the hosted arm64 Mac. This is not a production supervisor or
installed-owner migration. See [evidence](../artifacts/mac-worker-boundary-080.json)
and the [component contract](mac-worker.md).

Initial attempts are excluded: Darwin pipe stat ownership differs from Linux;
UID-only launches did not establish the user's Mac execution context; the first
blank-page canary lost its browser setting through sudo; and the first recursive
runtime guard rejected the installed layout. The corrected path checks root
ownership/modes throughout alias targets, normalizes vendor permissions and
adopts the dedicated user's launchd context. The browser sandbox stayed enabled.
The final run removed both temporary users/domains and its runtime.

The separately staged **Developer ID signed build 61** corrects the consumer
minimum to macOS 14 and passed local packaging/pin checks. Matching application
source `aeb1d28` passed **724 tests, one platform skip, in 502.56 seconds**, lint,
dependency audit, packaging/native checks and the Android emulator journey.
See [build evidence](../artifacts/mac-platform-061.json). Its consumer transport
is still the earlier same-user service; the isolated components are not enabled.
Installed build 53 and the unfinished mailbox form were preserved. Real mailbox,
physical phone and private authenticator acceptance remain open.

## Native Mac owner channel — 17 October 2026

Revision `712f1a1` passed **54 native owner-channel checks** locally with actual
Developer ID signed helper processes, and on
[Mac CI](https://github.com/fainir/account-access/actions/runs/38991224960/job/117273831671)
with ad-hoc hash-pinned peers. Both architectures type-check against macOS 13.
The accepted peer reached the Python owner server over Unix IPC for a grant,
authenticator enrollment, CSV preview and revocation. Wrong code identities,
wrong expected OS users, unauthorized/expired setup and disconnected sessions
were rejected. The owner capability and known fictional secrets were absent
from returned data; helper processes exited.

One initial CI host allowed an undefined authorization right through its default
policy, invalidating the test's blanket expectation of OS denial. The product's
dedicated-rule preflight already rejected that situation. The corrected checker
also requires the exact granted right and flags, and the tests now verify an OS
reference round-trip plus rejection without the dedicated rule. QA uses a
separate authorization-right name and never changes the database. The dedicated
production rule requires an unshared session-owner authorization, a short
handoff and no root shortcut. Setup sessions expire and do not apply to routine
agent operations.

Final component revision `712f1a1` passed **710 Python tests in 440.90
seconds**, lint, dependency audit (no known vulnerabilities), package and native
checks in [CI](https://github.com/fainir/account-access/actions/runs/38991224960).
Its [Android emulator journey](https://github.com/fainir/account-access/actions/runs/38991224921)
and the separate [24-check Linux worker journey](https://github.com/fainir/account-access/actions/runs/38991224853)
also passed. The two native/platform fixtures retain their distinct scope;
these results do not establish consumer Mac deployment.

See [sanitized evidence](../artifacts/mac-owner-gateway-080.json) and the
[channel contract](mac-owner-gateway.md). These are ordinary-user fixtures with
separate native processes. Positive setup authorization uses a QA-only verifier;
genuine owner approval, root deployment and consumer wiring remain unverified.
No installed app, owner form, privacy permission or real account was changed.
This is not a Mac cross-user installation claim. The production supervisor,
protected installation/key custody, migration/client issuance, notarization and
private email/SMS/authenticator acceptance remain open.

## Separate-user worker acceptance — 17 October 2026

Internal worker revision `60e34d2` passed **24 cross-user checks** in a
[disposable Linux CI VM](https://github.com/fainir/account-access/actions/runs/38987941570).
A root-owned runtime launched a dedicated non-root broker; a different locked,
non-sudo account ran the ordinary client. It completed an approved OAuth API
read and four fictional browser password logins, including one email, SMS and
authenticator challenge each. Email traveled over TLS IMAP; a synthetic handset
sent the SMS message through the paired, certificate-checked HTTPS relay. No
personal account, real carrier, physical phone or installed owner store was used.

The agent was denied vault/configuration reads, database writes, runtime
replacement, policy changes, process memory/environment/descriptors, signaling,
the private owner socket, owner routes on the agent API and worker identity
impersonation. Owner revocation stopped a previously permitted read. Worker
shutdown completed without credential output. The worker received its initial
vault key and owner capability through the inherited bootstrap pipe.

The first workflow incorrectly looked green because a shell pipeline hid an
upstream runtime preflight failure and uploaded an empty report. It is excluded.
The workflow now propagates failures and requires a complete, non-empty report
with every required assertion exactly true. A later attempt caught an HTTP
client context-manager bug in the harness; wire-request regression tests cover
the correction. Worker SIGTERM now completes owner cleanup after Uvicorn replays
its signal. Earlier failed attempts are not counted as acceptance.

See [sanitized evidence](../artifacts/worker-boundary-080.json) and the
[component contract](isolated-worker.md). The matching application runtime on
`95023e5` passed **696 tests in 458.75 seconds** in
[regression CI](https://github.com/fainir/account-access/actions/runs/38987658984),
plus lint, dependency audit (no known vulnerabilities), package build, native
owner UI, Messages-reader, background-helper and startup checks. The later
`60e34d2` extension changes the acceptance harness, not application/runtime
modules; its [Android emulator journey](https://github.com/fainir/account-access/actions/runs/38987945192)
also passed. The consumer Mac installer does not
enable this component. A production supervisor, secure key custody and client
issuance, trusted owner enrollment and Mac deployment remain required. Signed
Mac build 60 and the existing ordinary-language model fixtures are separate
earlier artifacts; this work did not replace the installed app or unfinished
setup form. Private Gmail/SMS/authenticator acceptance remains open.

## Bound runtime activation — 17 October 2026

Candidate build 60 binds the installed wheel record to the activated interpreter,
launcher digest and fixed isolated-import command. The native app and background
helper require that complete binding before reopening or executing the runtime.
A native regression demonstrated that the preceding verifier accepted a different
managed environment using the active wheel's digest. That environment is now
rejected. Changed launcher bytes, a launcher pointing to a different interpreter,
invalid metadata and legacy unbound records also require repair.

The installer recognizes a private legacy record for backup/rollback, then
publishes schema 2 only after successful startup and launcher installation.
Failed repair preserves the preceding record. A managed client using the new
logic starts the activated launcher when its service is cold, even if that client
runs from a retained environment. Invalid activation cannot fall back to the
retained interpreter; Pause still stops on-demand startup first. Ordinary
standalone/developer installations retain their existing startup path. Unmodified
pre-60 clients do not gain this behavior retroactively; known host integrations
are refreshed by installation, and long-running old clients need a restart.

Installer preflight also checks private runtime/environments directories,
bin directories without group/world write, and an owned regular single-link 0700
launcher before executing an existing installation. A marker alone cannot
authorize that execution. Unsafe modes, hard links, FIFOs and non-regular lock
files stop before any installer subprocess runs. A readable but non-writable
bin directory remains valid. An unsafe existing runtime needs owner maintenance;
the app does not loosen permissions or execute it to repair itself.

The focused bootstrap/automatic-session and native policy/path checks exercise
these cases, including paths with spaces and apostrophes. Final candidate/package
validation is recorded below. This is update consistency and
preflight protection, not independent code attestation or a separate OS
credential identity. Complete broker/runtime isolation and a trusted owner
enrollment channel remain production work.

Initial Mac acceptance stopped before service startup because Foundation
normalizes an existing `/private/tmp` directory to its `/tmp` alias. The verifier
had compared those path strings literally. Managed locations are now compared
after normalization, while launcher bytes remain bound to the original recorded
path and traversal components remain forbidden. The native regression now uses
that actual system alias. The rejected fixture's job and key were cleaned up.
An added preflight check reports only fixed metadata checks before registering
another QA job. A separate CI failure came from a negative-test directory being
made private by an earlier restrictive umask; the fixture now explicitly sets
and checks its intended unsafe mode. Product checks were not relaxed for it.

Final runtime revision `c40d962` passed **661 tests in 480.93 seconds** in
[CI](https://github.com/fainir/account-access/actions/runs/38983709256), plus
lint, dependency audit (no known vulnerabilities), package build, **26 native
UI checks**, **eight background-policy checks**, Messages-reader and startup
checks. Its [Android emulator journey](https://github.com/fainir/account-access/actions/runs/38983709263)
also passed. All **49 focused bootstrap/automatic-startup cases** passed in
9.36 seconds with restrictive umask explicitly applied.

The rebuilt signed build 60 passed actual Mac acceptance on this final revision:
registered-job crash recovery continued the original task; Pause blocked both
a fresh job invocation and a managed client; and a client using the same
candidate code from a second retained environment cold-started the activated
runtime rather than itself. This does not validate unchanged pre-60 clients.
The temporary job was unregistered, its key removed, and its processes confirmed
quiescent before fixture removal. All **61 application files** match source.
Main/helper Developer ID/team, hardened-runtime, timestamp, both architectures
and the fixed LaunchAgent policy passed local preparation. No Apple submission
or private website sign-in was made. Ordinary-language model fixtures remain
separate earlier evidence on `321d143`; they were not rerun for this managed
startup change. See the [sanitized build 60 report](../artifacts/mac-runtime-activation-080.json).

The installed owner app/form were preserved. A status-only UI check still
showed Connect mailbox without checked/saved confirmation, leaving enrollment
unconfirmed. Private email/SMS/authenticator acceptance, installed owner upgrade,
actual logout/reboot, notarized distribution, isolated custody and independent
review remain open.

## Update rollback after an uncertain stop — 17 October 2026

The next candidate fixes two additional installer failures reproduced by new
regressions. If starting a replacement fails and stopping it also fails, its
environment is retained and the previous service is not restarted concurrently.
The previous runtime launcher is restored so a later repair can recover safely.
If payload publication fails after changing the desktop launcher, that launcher
is restored too, including its previous data-directory arguments; a newly
created launcher is removed instead.

The CLI's stop command now waits for both the supervisor and service leases
before reporting success. Accepting an HTTP stop request alone is insufficient
evidence that removing a runtime is safe. Waiting does not load the vault key,
and a failed stop cannot authorize deleting a possibly running environment.
The supervisor also holds its lease until its owned child has finished cleanup,
including a child that has not yet acquired the service lease. A deterministic
cleanup-barrier regression reproduced the preceding lock-release race.

All **49 bootstrap, supervision, automatic-session and guided-setup cases**
passed in 41.60 seconds on revision `6dc9600`. Four added regressions first
failed on the prior implementation. Real subprocess cleanup now verifies that both leases can be
acquired immediately after stop returns. Lint passed. This is controlled local
testing; private account/MFA acceptance and installed owner upgrade remain open.

Ordinary-language agent fixture checks on `321d143` passed with bundled Codex
CLI 0.162.0-alpha.17.2 in **22.91 seconds** and guarded Claude Code 2.1.112 in
**73.24 seconds**. Each completed four fictional password logins and one
email/SMS/TOTP verification. Claude recorded 16 guard decisions, six denied;
every successful tool stayed within the fixture policy. Codex's four successful
commands were the fixture skill read, discovery, task submission and wait.
An earlier attempt using Codex CLI 0.155.1 failed because that CLI login did not
support its configured model; it made no account login attempts. Host settings
were not changed. The subsequent supervisor cleanup change was tested separately.

Final runtime revision `6dc9600` passed **637 tests in 515.14 seconds** in
[CI](https://github.com/fainir/account-access/actions/runs/38979943215), along
with lint, dependency audit (no known vulnerabilities), package build, 26 native
UI checks, six background-policy checks, Messages-reader and startup checks.
Its [Android emulator journey](https://github.com/fainir/account-access/actions/runs/38979943214)
also passed. Build 59 was rebuilt with the child-cleanup fix; its signed main
and helper passed Developer ID/team, hardened-runtime, timestamp and universal
architecture checks. Its wheel pin and all 61 application files match source.
Local notarization preparation passed without submitting anything to Apple.

A unique Mac QA app then passed actual registered-job crash recovery and Pause
again on this final revision, with its job and fixture Keychain item removed.
The installed owner app and enrollment form were not changed. Real private
email/SMS/authenticator acceptance, installed owner upgrade and actual
logout/reboot remain open. See the [sanitized build 59 record](../artifacts/mac-background-update-080.json).


## Mac service-manager recovery — 17 October 2026

Build 58 embeds a universal, separately signed background helper and a fixed
LaunchAgent policy. The saved Applications copy uses Apple's SMAppService API;
no legacy plist installation, approval reset or force-enable fallback is added.
Changed helpers use asynchronous unregister completion before re-registration.
The helper validates private generation/runtime metadata and the installed wheel
record, then executes the managed interpreter with isolated imports. Replacing
its process preserves the OS-tracked PID. Its guardian waits for the active
process lease and can take over after supervisor loss. Setup failures and Pause
exit normally so abnormal-exit restart cannot create an owner-prompt loop.

A real, uniquely identified QA app registered through ServiceManagement and
started a service backed by an isolated fixture Keychain item. After both its
service and guardian were killed, macOS restored the original queued task
without client reconnection. Pause held through the restart throttle and a fresh
job invocation. The job was unregistered, confirmed absent in launchd, and its
fixture Keychain item removed. This passed again on final revision `b66dd43` after
the payload-handshake update. No installed production app or existing approval
was changed. An earlier probe correctly failed because its fixture principal was
inactive; its job/key cleanup also passed, and that setup was corrected.

The same-version update review found that old 0.8 runtimes could be reused despite
a changed signed wheel. The installer now publishes a private payload digest
only after successful startup; failed repair preserves the preceding digest and
launcher. The native app requires the signed bundle's digest before reopening,
and its helper refuses a stale runtime. This record supports the update decision;
it is not independent runtime attestation or separate-OS-identity protection.

All **77 bootstrap/supervision/release cases** passed in 24.43 seconds, including
actual two-process loss, standby Pause, five payload-record/rollback cases and
46 simulated signing/notary cases. All **26 native UI checks** and **six background
policy/path checks** passed. Native Pause sends one stop request, clears local
setup secrets, and offers Resume. Approval-required status has a Login Items
action; that revoked-approval path is contract-tested, not a live settings toggle.

Final revision `b66dd43` passed **633 tests in 442.89 seconds** in
[CI](https://github.com/fainir/account-access/actions/runs/38977626518), plus lint,
dependency audit, package build, native UI/policy, inert helper entrypoint,
Messages reader and startup checks. Its [Android emulator journey](https://github.com/fainir/account-access/actions/runs/38977626521)
also passed. Fresh ordinary-language fixtures passed on bundled Codex CLI
**30.40 seconds** and guarded Claude Code **33.91 seconds**. Each completed four
fictional password logins and one email/SMS/TOTP verification. Claude's six guard
decisions included two denials; all successful trace tools passed the policy.
Codex's four successful commands stayed within the fixture skill/discovery/task
flow. These host fixtures and actual OS-job tests are separate controlled tests.

Both main and helper executables passed real Developer ID/team, hardened-runtime,
timestamp and universal-architecture checks. The final staged wheel pin and all
**61 application files** match source. Its exact LaunchAgent policy is pinned;
notarization preparation is local-only and creates no Apple submission.

Installed build 53 was preserved. A status-only native check still showed Connect
mailbox with no checked/saved confirmation; enrollment remains unconfirmed. No
credential field values were emitted and no private website login was requested.
Real logout/reboot, consumer upgrade of that installation, notarized distribution,
private email/SMS/authenticator delivery, independent review and separate-identity
custody remain gates. See the [sanitized Mac evidence](../artifacts/mac-background-recovery-080.json).

The opt-in `scripts/mac_background_smoke.py` uses a unique QA app identity,
synthetic store and fixture Keychain namespace. Cleanup failure retains only
that private fixture for recovery. It never registers the production app,
approves a prompt, resets Login Items or accesses personal accounts.

## Supervised local task recovery — 17 October 2026

Build 57 starts a separate user-space supervisor for the desktop service. A
child crash restarts the host with bounded interruptible backoff, allowing saved
tasks to continue without another agent request. A generation marker and actual
process lock prevent competing supervisors; stale markers and PIDs do not prove
liveness. Pause/update disables the current generation. Setup/keyring errors
stop retries, and only an owned child can be signalled. The supervisor loads no
vault key. A dead API or recovery thread closes the owner endpoint for restart.

The native app verifies current owner metadata and its HMAC proof before each
setup request, under a serialized connection lock. Endpoint rotation preserves
idle form controls. A failed proof sends no setup action, and a lost response is
not retried. The native checks use an isolated temporary root and fictional
credentials; they never read or change the installed owner setup.

All **22 supervision, worker-health and install/service cases** passed in 37.09
seconds, including actual child termination, continuation of the same queued
task without client reconnection, a second crash without replaying its completed
read, pause/reopen, observation of an existing unowned host, dead API-thread
cleanup, private control files and a single rejected setup attempt. The separate
**14 startup/upgrade checks** passed in 15.70 seconds. All **24 native UI checks**
passed. A further import-path check then passed **19 supervision/automatic-session
cases in 24.43 seconds**, and **12 installer/guided cases in 14.14 seconds**.
These launch real subprocesses from a hostile working directory with fake
package, JSON and startup modules on `PYTHONPATH`; no hostile code ran. Generated
launchers, client startup and supervisor children use isolated Python imports.
The skill fallback also specifies isolated Python. Lint and skill validation
passed. Final revision `5fbeaef` passed **613 tests in 468.16 seconds** in
[CI](https://github.com/fainir/account-access/actions/runs/38972780892), along
with lint, dependency audit, package build, native UI, Messages reader and startup
checks. Its [Android emulator journey](https://github.com/fainir/account-access/actions/runs/38972780993)
also passed. The preceding supervision revision passed **612 tests in 464.17
seconds**. The final signed candidate was rebuilt and checked against source.

Fresh ordinary-language fixture checks on final revision `5fbeaef` passed:
Codex CLI **32.93 seconds**, guarded Claude Code **41.05 seconds**. Each completed
four password logins and one email/SMS/TOTP verification with fictional sources.
Claude's six guard decisions included two denials; every successful trace tool
satisfied the fixture policy. Codex's four successful command calls were reviewed:
one skill read, fixture discovery, task submission and task wait. These agent
checks and the process-crash tests are separate controlled checks; neither
validates private mailbox or physical-phone delivery.

The separately staged universal build has a matching wheel pin and all **61
application files** match current source. Strict/deep/all-architecture signature
verification passed. Installed build 53 and the pending owner Gmail form remain
preserved. No private website login was requested by these tests.

This is user-space process recovery, not separate-OS-identity credential custody,
OS-managed startup after simultaneous supervisor/host loss or shutdown, or proof
of private mailbox/physical-phone authentication. Existing Namecheap browser
verification, owner enrollment, Apple notarization and other production gates
remain open. An already-open web owner tab must be reopened after a host restart.
See the [sanitized supervision evidence](../artifacts/supervised-recovery-080.json).

## Resumable Mac release preparation — 17 October 2026

The new maintainer helper verifies an Apple-anchored Developer ID signature and
expected team on both CPU architectures, hardened runtime, timestamp, executable
permissions and the wheel pin before preparing a copied app. It does not change
the signed input, installed app, owner credentials or OS security settings.

The upload boundary is persisted before contacting Apple. A known submission ID
or archive-bound receipt survives interruption; uncertain outcomes do not cause
automatic reuploads. Apple's accepted log must match the job, archive and full
SHA-256. Only ticket stapling/validation, unchanged code hashes and a successful
`syspolicy_check distribution` permit packaging. Before finalizing the ZIP, the
helper checks its entry paths and size, extracts it privately, and repeats the
signature, wheel, ticket and distribution checks on the extracted app. Cached
state cannot report a newly verified release. The helper never publishes to GitHub.

All **35 protocol/security cases** passed in 0.72 seconds. They use simulated
Apple tools and cover rejected/unknown jobs, incorrect digests and IDs,
interrupted uploads and state writes, stapling recovery, modified app/archive,
policy failure, a lost packaged ticket, changed packaged code, archive traversal,
redaction, private paths and concurrent publishers. Fixed system
tool paths avoid PATH-based tool replacement. Lint passed. A helper-only
Bandit 1.9.4 scan reported two low subprocess warnings, no medium/high warnings
and no scanner errors. The reviewed call uses fixed executable paths and an
argument array without a shell; no suppressions were added. This is an internal
review, not an independent audit.

Final helper revision `62517dc` passed **601 tests in 405.04 seconds** in
[CI](https://github.com/fainir/account-access/actions/runs/38969904248), along
with lint, dependency audit, package build, native owner UI, Messages reader and
startup checks. The [Android emulator journey](https://github.com/fainir/account-access/actions/runs/38969904185)
also passed. These are automated/controlled results, not physical-phone or
private-account acceptance. The earlier release-helper revision passed 598 tests.

Real local preparation of signed universal build 56 passed, including the exact
certificate requirement and both architecture code hashes. The first real run
caught an inline codesign-requirement argument-format error; it was corrected
before acceptance. The actual distribution tool returned exit 70 and reported a
missing notarization ticket, with no signature error. Calling submit without a
profile was denied before upload, and the job ID remains absent. No Apple
notarization submission or credential lookup was performed. A real extraction of
the prepared ZIP also passed both staged/extracted signature checks and then
correctly failed ticket validation. It left the state and submission archive
unchanged and produced no release artifact. The actual codesign requirement
also rejected a deliberately wrong expected publisher team before any Apple
service request; the prepared state remained unchanged.

Live Apple acceptance, ticket stapling and a clean downloaded-install test remain
open. These results do not validate private email/SMS/authenticator delivery or
separate-identity credential custody. The installed owner Gmail form remains
preserved and enrollment unconfirmed. The current app runtime is unchanged, so
the previous build 56 agent checks are retained rather than rerun for this
maintainer-only tool. See [maintainer steps](../macos/README.md#maintainer-notarization).

## Account source classification — 16 October 2026

The installed preview's discovery response labeled public test-site aliases as
live Personal/Work accounts. Build 56 derives per-account source labels and a
mixed-list environment without modifying the owner configuration. Exact reviewed
origins identify SauceDemo, The Internet and Duende examples. All configured
connector destinations must be examples; look-alike hosts, unreviewed ports and
connections spanning other origins do not receive that label. A test-mode flag
alone cannot label an external service as a local fixture.

The reviewed destinations are documented as testing/demo services in
[Sauce Labs' example](https://docs.saucelabs.com/visual-testing/integrations/nightwatch/),
[The Internet's login page](https://the-internet.herokuapp.com/login) and
[Duende's demo server](https://demo.duendesoftware.com/). Direct extraction of
SauceDemo's page was unavailable to the browsing tool; the official Sauce Labs
example supplies the supporting reference. This review starts no private login.

The catalog, CSV review and owner/agent discovery show the derived classification.
Ready examples are counted separately in native and web screens. New results
record the classification at read time; old results lacking it are projected as
unclassified without rewriting checkpoints or repeating completed steps. Labels
describe configured sources, not verified account ownership or fresh sign-in.
The portable skill tells agents to label examples and use them for example/test
requests instead of substituting them for personal/work accounts.

The import summary also requires current saved readiness before showing
Connected. All 21 native UI checks passed, including separate source counts,
example prompts, verified imports and pending challenges. All 30 focused
classification/catalog/import cases passed in 16.66 seconds, and 43 companion
catalog/import/access/worker cases passed in 39.68 seconds. Lint, package build
and skill validation passed. The signed candidate is staged separately.

Fresh ordinary-language host checks on the main classification implementation
`24a5253` passed: Codex CLI **31.08 seconds**, guarded Claude Code **63.75 seconds**.
Each completed four password logins and one email, SMS and TOTP verification
using the controlled fixture. Successful Claude trace tools satisfied the
fixture policy; thirteen guard decisions included three denials. A final
malformed-legacy-URL fallback then passed all **10 classification cases** in
3.23 seconds; it preserves discovery instead of inferring a source label from
an invalid URL. The skill guidance now explicitly uses outer metadata rather
than provider-supplied labels inside data.

The main classification revision passed **565 tests** in 437.01 seconds in
[CI](https://github.com/fainir/account-access/actions/runs/38964320295). Final
revision `5c98d67` passed **566 tests** in 424.10 seconds in
[CI](https://github.com/fainir/account-access/actions/runs/38964735661), native
owner UI, Messages/startup checks, lint, dependency audit and package build. The
[Android emulator journey](https://github.com/fainir/account-access/actions/runs/38964735811)
also passed. Strict/deep signature verification passed for the staged universal
build; all **60 bundled application files** match source and the embedded wheel
pin. See the [sanitized build record](../artifacts/account-classification-080.json).

The metadata tests use local providers and mocked public result bodies; the web
test uses stored-state projections only. They are not real website or private
account sign-in acceptance. Installed build 53 remains open for the pending
owner Gmail enrollment. No further GitHub or Namecheap sign-in is requested.
The installed native form was rechecked without emitting or changing field
values: Connect mailbox remained available, with no checked/saved confirmation
visible. Enrollment remains unconfirmed. Repository-level secret metadata also
shows no configured secrets for a notarization workflow; no secret values were
read. The [Mac isolation prerequisites](security-and-password-sync.md#verified-mac-service-prerequisites)
remain separate from the preview's passing tests.

## Visible background recovery health — 16 October 2026

Build 55 addresses silent background-loop failures identified by the internal
review below. The service tracks fixed status/counter/timestamp fields in memory;
no exception object, message, traceback, account identifier or provider payload
enters that health state. Internal failures retry with interruptible backoff
from one to thirty seconds. Success clears the active failure state. Shutdown
cleanup runs even if the lifespan raises, and another lifespan cannot start a
second worker while the previous one is still stopping.

Agent discovery and nonterminal tasks expose the recovery state without changing
task IDs, status, completed steps or account challenges. The native Accounts
screen shows fixed retry/stopped messages when refreshed. The web owner UI polls
a separate authenticated health endpoint without rebuilding credential forms;
pausing the app stops that polling. A standalone owner process without an
attached worker reports Unknown rather than claiming a separate service is
running. Worker health does not establish website authentication or code delivery.

Tests inject a private-looking exception, confirm it stays out of owner/agent
responses and logs, then let the same queued task complete through a real local
OAuth provider. They cover backoff, shutdown/restart, unauthenticated health
access, native fixed-message rendering and real-browser health updates while a
fictional password remains typed in its input. One initial browser test failed
because its fixture had not opened the Add an account panel; the fixture was
corrected before acceptance. The first 31 companion cases passed, followed by
all five then-existing health cases in 15.29 seconds. All **20 native UI checks**
passed. The final health/access/installation run passed **27 cases** in 31.23
seconds, including the lifespan failure-cleanup case. Lint and package build
passed. The staged signed universal build passed strict/deep verification;
all **59 bundled application files** match source and the embedded wheel hash.

Fresh build 55 ordinary-language fixture runs passed on the desktop-bundled
**Codex CLI** in **26.83 seconds** and guarded **Claude Code** in **141.91 seconds**.
Each used its project launcher and completed four password logins with one
email, SMS and TOTP verification. All successful Claude trace tools satisfied
the fixture policy; 29 guard decisions included eight denials. Its code-free
audit is retained privately. These are controlled accounts, not private-source
acceptance or proof of global-skill precedence.
See the [build 55 evidence](../artifacts/worker-health-080.json).

Final implementation `557f166` passed **556 tests** in 461.64 seconds in
[CI](https://github.com/fainir/account-access/actions/runs/38961805399), native
owner UI, Messages/startup checks, lint, dependency audit and package build. The
[Android emulator journey](https://github.com/fainir/account-access/actions/runs/38961805393)
also passed.

Installed build 53 remains untouched with the owner Gmail enrollment pending.
This phase makes no new private website sign-in request. Physical-device and
private-source acceptance remain open.

## Verified mailbox repair and authorization binding — 16 October 2026

The next candidate repairs a missing step after mailbox enrollment: a task
paused for rejected mailbox credentials used to need another website-check
click after the owner fixed the password. New internal source/fingerprint
context allows only recognized mailbox-access prerequisites to clear after a
fresh successful check, unchanged account/mailbox configuration and active
standing permissions. Ordinary authentication and permission checks then run
for the remaining steps of the original task. There is no new agent secret API.

Real local TLS IMAP/browser cases repair reusable and inline mailbox passwords,
resume the original task and retain its already-completed step. Negative cases
retain disabled sources, changed connectors, revoked grants, stale/unverified
checks, historical unbound failures, delivery problems, wrong source identities
and independent presence/action challenges. A 21-account case verifies fairness
of the bounded scan without contacting website providers.

Configured Gmail health checks now bind to their OAuth provider configuration,
authorization identity and revoked/uncertain-refresh state. A real local OAuth
renewal preserves the identity, including a legacy migration; a new owner
authorization invalidates the previous check. Gmail profile contracts require
the correct current mailbox identity. Reusable mailbox passwords are included
in result redaction, with an adversarial provider-echo regression.

Revision `9afb021` passed **503 tests** in 386.31 seconds in
[CI](https://github.com/fainir/account-access/actions/runs/38956897845), all
nineteen native UI checks, lint, dependency audit and package build. The
[Android emulator journey](https://github.com/fainir/account-access/actions/runs/38956897897)
also passed. Cold-restart tests now reconstruct the service after the owner
repair and resume both reusable and inline mailbox tasks (2 cases, 8.25 seconds).

Build 54 is signed and staged separately. Build 53 remains installed with the
owner Gmail form left untouched while one-time Google credential enrollment is
pending. Private mailbox and physical-phone acceptance remain incomplete.

### CLI test isolation failure and remediation

The fresh Codex fixture run passed in 25.43 seconds. A Claude retry exited
successfully but **failed acceptance**: it selected the global skill/client
instead of the temporary project client and read four global connection results,
including one private-service profile after testing that service had been
stopped. This was a test-isolation mistake, not proof of private-account success.
An earlier timeout retained no trace and cannot be counted as a pass.
The installed service's local audit subsequently confirmed another completed
stopped-service profile read during that earlier attempt: **two reads total**
in the unguarded QA windows, and none after the guarded runs began. Reading that
local audit did not start another website login. Both unguarded runs remain
excluded from acceptance.

The harness now uses a distinct temporary Claude skill, binds the fixture client
environment, exposes only Read/Skill/Bash with no external MCP/browser tools,
and installs an invocation-only tool guard. The guard permits only the pinned
fixture launcher, declared fixture operations and instruction-file reads. It
denies global clients, shell expansion/compound commands, writes, background
execution and other tools; changed launcher/client files fail closed. Global
host permissions and hooks are preserved. This is a narrow QA boundary, not a
sandbox for arbitrary same-user programs.

The initial **43 guard cases** passed, including the generated hook's real
subprocess contract. The combined guard/evidence/recovery run passed **78 cases**
in 22.16 seconds. A fresh guarded Claude run then passed in **74.18 seconds**:
four password logins and one email, SMS and TOTP verification. Its thirteen
guard decisions included four denials, and all seven successful Bash calls used
the fixture launcher. This uses a uniquely named temporary project skill; it
does not establish global-skill precedence or private website acceptance.

The legacy `agent_smoke.py` and `implicit_agent_smoke.py` entry points now refuse
before connecting to accounts. Additional tests check retirement and reject any
successful out-of-policy tool in the trace. The guard/evidence run passed
**65 cases** in 0.51 seconds. Future runs also retain the code-free guard audit
privately alongside the trace. The
[sanitized record](../artifacts/verified-mailbox-repair-080.json) retains the
failed-run evidence without personal identifiers or raw traces.

The final harness revision `773568e` was exercised again: Claude passed in
**102.33 seconds**, with all successful trace tools independently checked
against the fixture policy. Nineteen guard decisions included six denials; the
code-free audit was retained privately with mode 0600. Four password logins and
one email, SMS and TOTP verification completed. This validates the new trace
acceptance check and audit retention as well as the underlying controlled flow.
The first guard revision `2ce1c9c` also passed **546 tests** in 427.67 seconds in
[CI](https://github.com/fainir/account-access/actions/runs/38959218904), along
with native checks, lint, dependency audit and package build.

Final revision `773568e` passed **550 tests** in 431.92 seconds in
[CI](https://github.com/fainir/account-access/actions/runs/38959629461), native
owner UI, Messages/startup checks, lint, dependency audit and package build. The
[Android emulator journey](https://github.com/fainir/account-access/actions/runs/38959629189)
also passed. These checks do not close the private mailbox, physical-device,
distribution or credential-isolation release gates.

### Internal static-analysis review

Bandit 1.9.4 scanned the application package with no scanner errors and reported
two medium and 25 low warnings (exit 1), with no high warnings. Both SQL warnings
use constrained literal choices and bound values. Reviewed hardcoded-password
matches are fictional credentials, a selector and protocol/status literals;
subprocess sites use argument arrays. No blanket suppressions were added.
The review also records missing owner-visible health for unexpected background
worker errors as release work. The
[sanitized review](../artifacts/static-analysis-review-080.json) is internal,
application-only analysis, not an independent audit or proof of security.

## Reusable mailbox setup — 16 October 2026

The next candidate makes Gmail/TLS IMAP setup available before a website
connector has an email source. The owner can save one encrypted mailbox, check
its access, update its application password or disconnect it. Approved website
sources can reuse only an exact matching server, port and recipient. Neither
mailbox connection nor linking creates a connector or grants account operations.
The agent API has no mailbox-list or mailbox-secret endpoint.

Tests connect a real local TLS IMAP fixture without fetching mail or starting
website login, share it across exact approved sources, recover website access
and reuse the saved session. They reject mismatched servers/ports/recipients,
invalid setup and agent/cross-origin owner requests. Removing or changing a
mailbox prevents pending code retrieval; a health recheck alone does not
interrupt an active window. A changed application password can be repaired
locally without changing the mailbox identity or destination.

The actual owner web UI test imports a fictional password, connects its mailbox,
uses the preselected matching mailbox for the website email source, completes
email-code login and confirms session reuse. That test found and fixed a real
delay: failed source preflight used to charge the password cooldown even though
no password was submitted. The cooldown now begins immediately before an actual
submission attempt, while the existing account lock and retry throttle remain.

Transient IMAP timeouts/socket resets return a normal retry instead of an owner
challenge. A TLS certificate-verification failure still requires repair and
never permits an unverified connection. A real TLS fixture test loses access
before password submission, then recovers the original queued task through the
ordinary scheduler with one password login and one delivered email code.

Gmail setup shows only the email address and masked application-password field;
server/port are supplied by the preset. Other providers require explicit TLS
settings. A selected saved mailbox hides redundant credential fields. Initial
Google app-password creation still belongs to the owner, and a consumer Google
OAuth application is not bundled. This phase adds no private mailbox or carrier
delivery acceptance and makes no further private Namecheap/GitHub request.

The local full run passed **475 tests** in 384.69 seconds before the final five
outage cases were added. All **31 focused mailbox-health/browser cases** then
passed in 17.70 seconds, and the original-task outage recovery case passed in
4.07 seconds. All **19 native UI checks**, lint and package build passed. Signed
universal Mac build **53** was installed through graphical repair; staged and
installed signatures passed strict/deep verification, and bundled mailbox/auth
files matched source. The actual installed Gmail screen shows the email field
and masked app-password field with server details hidden. The original private
Namecheap task/challenge survived and remains blocked.

Fresh ordinary-language CLI tests used the new reusable-mailbox owner API and
independently confirmed the four fictional account results:

- [Desktop-bundled Codex CLI](../artifacts/agent-tests/codex-verification-080-reusable-mailbox-53.json):
  **24.90 seconds**, four password logins and one email, SMS and TOTP verification.
- [Claude Code](../artifacts/agent-tests/claude-verification-080-reusable-mailbox-53.json):
  **73.54 seconds**, the same completed task and verification counts.

Both used their installed project launcher without a command/skill prefix in
the prompt. Global host settings and model defaults were preserved. These are
controlled fixture results; private Gmail/carrier/authenticator acceptance is
still open. See the [sanitized record](../artifacts/reusable-mailboxes-080.json).

Final implementation `b71c831` passed **480 tests** in 402.66 seconds in
[CI](https://github.com/fainir/account-access/actions/runs/38953515321), all
nineteen native UI checks, Messages/startup checks, lint, dependency audit and
package build. The
[Android emulator journey](https://github.com/fainir/account-access/actions/runs/38953515196)
also passed. These results do not close private provider, physical-phone,
notarization, isolated-custody or independent-review gates.

## Mailbox readiness and credential repair — 16 October 2026

The next candidate adds an owner-only mailbox connection check. Real TLS IMAP
fixtures verify correct and rejected application passwords without fetching
messages or starting website login. Gmail profile contracts verify the approved
mailbox identity, missing scope and bounded token renewal. Native/web setup
distinguishes a saved source, a checked mailbox and completed website code
delivery. Saving verification setup cannot retry an unrelated browser gate.

IMAP recovery now searches from its pre-password UID boundary and rejects
excessive/partial results, invalid tracking numbers and mismatched fetched UIDs.
Gateway SMS recovery records existing message IDs before password submission,
rejects pagination/duplicate identities and excludes future, stale, outgoing and
different-purpose texts. Revocation during retrieval prevents code return.

Editing a browser credential invalidates the old session when its value changes.
It only clears explicit password/client-secret setup challenges; browser checks,
unknown pages, device/passkey/admin/recovery and independent action challenges
stay pending, with the original task preserved. Focused tests cover that boundary.

These are controlled tests. No additional private Namecheap or GitHub request
was made for this change. Private password/email/SMS/authenticator acceptance
and the remaining distribution/security gates remain open.

The local full suite passed **454 tests** in 350.09 seconds before the final
credential-edit cases were added. All **45 focused mailbox, SMS gateway and owner
boundary cases** then passed in 24.52 seconds, including the two added credential
cases. All **17 native UI checks**, lint, package build and strict/deep signature
verification passed; the dependency audit reported no known dependency
vulnerabilities. Signed universal Mac build **52** was installed through graphical
repair. The original private Namecheap task and challenge are still pending.

Fresh ordinary-language agent tests independently confirmed all four fictional
account results and actual installed-project-launcher execution:

- [Claude Code 2.1.112](../artifacts/agent-tests/claude-verification-080-mailbox-52.json):
  58.32 seconds, four password logins, one email, one SMS and one TOTP verification.
- [Desktop-bundled Codex CLI 0.162.0-alpha.17.2](../artifacts/agent-tests/codex-verification-080-mailbox-52.json):
  25.34 seconds, the same four login and verification results.

Both checked the TLS IMAP connection before the agent ran, with no mailbox
message fetch or website login during that check. They used fictional credentials,
a TLS IMAP fixture, a Messages database fixture and a fictional Authenticator
transfer key. Model defaults and global host settings were preserved. These runs
do not establish a private Gmail connection or physical phone delivery.

Final implementation `e1c5fac` passed **456 tests** in 394.71 seconds in
[CI](https://github.com/fainir/account-access/actions/runs/38950534510), all
seventeen native UI checks, Messages/startup checks, lint, dependency audit and
package build. The
[Android emulator journey](https://github.com/fainir/account-access/actions/runs/38950534522)
also passed. See the [sanitized record](../artifacts/mailbox-readiness-080.json).

## Private Namecheap import and browser-verification stop — 16 October 2026

The owner approved a Namecheap username check and selected a real Chrome
password export locally. The native app imported only one matching Namecheap
entry and completed its normal Trash cleanup. The installed launcher discovers
the new approved operation, and its original durable task remains pending.
No further GitHub account test was performed.

The private Namecheap sign-in **did not pass**. Its visible browser review
showed a JavaScript/cookie verification page; the owner console also recorded
HTTP 429. This does not establish password validity or email/SMS/authenticator
delivery. Further website requests stopped. The diagnostic update preserves
the original imported credential, permission, task and unresolved challenge.

Signed universal Mac build **51** was installed by graphical repair and passed
strict/deep signature verification. It recognizes Cloudflare's documented
main-document challenge header, explains the unsupported browser gate, and
always exposes a finish action during a visible review, including when detailed
diagnostics are empty. A more specific challenge explanation can retain the
original ID without clearing the gate or retrying the site. A confirmed owner
repair is still required before the saved task can resume.

The full local suite passed **412 tests** in 335.80 seconds, all **15 native UI
checks** passed, and lint/build/signature checks passed. A final focused case
also verified that the same fictional task resumes after a successful owner
repair with one password login and preserved session reuse. The seven new
browser-gate cases use local fixtures, not real CAPTCHA solving. No further
private Namecheap request was made after installation because of the recorded
rate limit. See [provider scope](other-service-validation.md) and the
[sanitized record](../artifacts/site-verification-080.json).

The first Linux CI run passed 411 cases and exposed a timing assumption in the
extended task-recovery test: it asserted completion before the scheduler's
one-second resume interval had elapsed. The regression now waits for the normal
scheduled resume, with a five-second bound. No application or installer change
was needed for that test correction.

Final revision `16d87ae` passed **412 tests** in 324.22 seconds in
[CI](https://github.com/fainir/account-access/actions/runs/38947177682), all
fifteen native UI checks, native Messages/startup checks, lint, dependency audit
and package build. The
[Android emulator journey](https://github.com/fainir/account-access/actions/runs/38947177564)
also passed. These passing checks do not establish private Namecheap sign-in or
production readiness.

## Other services — 16 October 2026

GitHub account testing stopped at the owner's request. The next native candidate
adds a Namecheap username-only read and explicit exact-origin password-export
aliases. Its anonymous form preflight passed through the production browser
guard; no personal credentials or verification codes were submitted. Railway's
email option was inspected without entering an address; it is not a connector.
See [the scope and remaining private gates](other-service-validation.md).

Signed universal Mac build **50** passed strict/deep signature verification and
was installed through graphical repair. The native picker shows the new
Namecheap permission, and existing connections remain present. All fourteen
native UI checks and twelve focused catalog/import-alias cases passed. The full
local run passed 404 cases and failed one historical-format test fixture, which
still included the newly added empty alias field in its legacy expected hash.
After correcting that fixture, both legacy-compatibility checks passed.

Functional revision `8466af1` passed **405 tests** in 324.69 seconds in
[CI](https://github.com/fainir/account-access/actions/runs/38941709228), all
fourteen native UI checks, native Messages/startup checks, lint, dependency
audit and package build. The
[Android emulator journey](https://github.com/fainir/account-access/actions/runs/38941709131)
also passed. See the [sanitized record](../artifacts/other-services-080.json).
These checks do not establish private Namecheap password or code delivery.

## Private GitHub session reuse and original-task recovery — 16 October 2026

The owner approved the new Chrome session connection. Real use then found and
fixed a popup permission handoff, a changed GitHub profile-heading marker and a
historical verification-method challenge that remained pending after verified
session adoption. The heading repair preserves the existing result label,
approved URL and single heading read. Confirmed login can now clear that method
challenge; independent transaction approvals remain pending.

Implementation `95e3358` passed **393 tests** in 326.16 seconds in
[CI](https://github.com/fainir/account-access/actions/runs/38930850399), fourteen
native owner checks, Messages/startup checks, lint, audit and package build. The
[Android journey](https://github.com/fainir/account-access/actions/runs/38930849847)
also passed. The preceding full local run passed 390 tests in 351.49 seconds;
focused tests then covered the three added method-challenge cases.

The private Chrome session passed exact website/username verification, and the
original saved task completed with **Public profile**. Fresh ordinary-language
agent requests independently exercised the installed global connection:

- [Claude Code 2.1.112](../artifacts/agent-tests/claude-private-session-080.json):
  47.01 seconds, successful launcher use and one independently audited read.
- [Codex CLI 0.162.0-alpha.17.2](../artifacts/agent-tests/codex-private-session-080.json):
  118.15 seconds, successful launcher use and two independently audited reads.

No global host settings changed. Passwords, cookies, codes, account identifiers,
task IDs and raw agent traces are excluded from the public evidence. This is one
personal GitHub connection; the other three app entries are public test accounts.
The agents reused a real verified browser session. These runs do not validate
fresh password/SMS sign-in or a personal mailbox/authenticator source.

Signed universal Mac build **49** and helper **0.8.2** add a visible check of
Chrome's temporary cookie/site permission state. Build 49 was installed through
graphical repair and passed strict/deep signature verification. The verified
account and original completed task survived repair; a further approved live
profile read also completed after repair. Final implementation `d58b15c` passed
**393 tests** in 317.59 seconds in
[CI](https://github.com/fainir/account-access/actions/runs/38933505085), fourteen
native owner checks, Messages/startup, lint, audit and build, plus the
[Android journey](https://github.com/fainir/account-access/actions/runs/38933505107).
Live confirmation of the
helper's permission-status display remains unconfirmed because browser policy
rejected automating its extension page. The owner subsequently stopped GitHub
testing and requested other services; no further GitHub check is pending.
Controlled cleanup contracts passed.
See the [sanitized record](../artifacts/private-github-session-080.json).

## Verified Chrome session candidate — 16 October 2026

Implementation `9e34b6c` passed **379 tests** in 319.82 seconds in
[CI](https://github.com/fainir/account-access/actions/runs/38927298081), plus
thirteen native owner-screen checks, the native Messages reader, optimized
startup/reopen, Ruff, dependency audit and package build. The
[Android emulator journey](https://github.com/fainir/account-access/actions/runs/38927298067)
also passed. Signed universal Mac build **44** was installed through graphical
repair and passed strict/deep signature verification.

Fresh [Claude Code 2.1.112](../artifacts/agent-tests/claude-verification-080.json)
and [desktop-bundled Codex CLI 0.162.0-alpha.17.2](../artifacts/agent-tests/codex-verification-080.json)
runs each completed a four-account durable task through the installed project
launcher from an ordinary prompt. Claude took 67.01 seconds and Codex 26.87
seconds; each independently recorded four password logins and one email, SMS
and authenticator verification. These use fictional accounts, TLS IMAP and
Messages fixtures, and a fictional authenticator export. No global host settings
changed. They are not real mailbox, phone or private-account acceptance.

The new owner-requested Chrome session path verifies the exact approved website
and expected GitHub username before adopting a session. Tests cover original-task
resume, wrong-user rejection, expired/replayed requests, cancelled or changed
grants, atomic rollback, exact native framing, selected Chrome cookie stores and
temporary-permission cleanup. The browser-helper cookie API behavior is contract
tested; a separate real extension load checks the initial absence of cookie and
site permission. The retired unverified import path cannot save a session or
clear a challenge. See the [sanitized record](../artifacts/browser-session-hardening-080.json).

At this earlier revision, private transfer was awaiting new cookie permission and
the original task was blocked. The later follow-up above records its completion.
No new private password/SMS request was made during these session checks. Session
reuse does not establish that the unresolved fresh GitHub SMS flow works.
Real email and authenticator enrollment/delivery, continuous Chrome password
sync, broader private connectors, consumer distribution and OS-isolated custody
remain separate production gates.

## Email recovery and shared verification channels — 16 October 2026

Candidate `2a7cf4b` passed **340 tests** locally in 272.11 seconds, eleven native
owner-screen checks, Ruff, the dependency audit and package build. Signed
universal Mac build **43** passed strict/deep signature verification and was
installed through graphical repair. The app and installed client retained the
four account entries, their existing approved reads, and the enrolled Google
Messages source. The saved private GitHub task remains blocked; no new private
sign-in request was made during these checks.

The same implementation passed **340 tests** in 292.95 seconds in
[CI](https://github.com/fainir/account-access/actions/runs/38919671268), plus all
eleven native owner checks, the native Messages reader, optimized startup/reopen,
lint, dependency audit and package build. Its
[Android emulator journey](https://github.com/fainir/account-access/actions/runs/38919671276)
also passed. See the [sanitized validation record](../artifacts/email-code-hardening-080.json).

Both fresh agent sessions independently completed the four fictional-account
task through their installed project launchers, from an ordinary prompt:

- [Claude Code 2.1.112](../artifacts/agent-tests/claude-verification-email-080.json):
  50.25 seconds, four password logins and one email, SMS and authenticator check.
- [Codex CLI 0.162.0-alpha.17.2](../artifacts/agent-tests/codex-verification-email-080.json),
  bundled with the desktop app: 32.02 seconds, the same completed factor counts.
  The older CLI 0.155.1 on PATH rejected its configured model before any launcher
  or website request. The successful rerun used the bundled CLI for that
  invocation only; no global model, path or approval settings changed.

These are real CLI/browser runs against fictional TLS IMAP, Messages and
authenticator fixtures. They do not establish personal mailbox, physical SMS or
private authenticator delivery. The host failure is retained in the Codex report
instead of being counted as a successful Account Access run.

New browser cases complete password → HTML email → SMS → authenticator, and a
Gmail API-contract → HTML email → browser sign-in with later session reuse.
Existing message IDs, stale/future dates, duplicate headers, attachments,
forwarded messages, malformed or oversized MIME, incomplete mailbox results and
multiple matching codes cannot supply a login code. Gmail access can renew once
after rejection; lost rotating-token responses and removed scope stop safely.
Near-expiry TOTP waits for a fresh interval without extending its login window.

Two concurrent accounts with different source names now share the email/SMS
channel lock. Tests keep the first account waiting for its message, confirm the
second makes no password request or owner challenge, then complete both in
sequence using their own fresh boundaries. Pairing and disabled-source checks
also stop before password submission. These checks reduce interruptions; they
do not prove that an enrolled phone is online.

## Browser verification and repair candidate — 16 October 2026, version 0.8

The current local candidate passed **274 tests** in 247.80 seconds; four owner
review cases also passed after adding best-effort website-window focus. Signed
build 41 passed ten native owner-screen checks and strict/deep signature
verification. Follow-up
`eb27c05` passed **265 tests**, ten native owner-screen checks, Messages and
startup/reopen checks, lint, audit and build in
[CI](https://github.com/fainir/account-access/actions/runs/38909036249), plus the
[Android journey](https://github.com/fainir/account-access/actions/runs/38909036547).
The latest follow-up exercises owner completion, cancellation, a denied check and
a separate transaction authorization. Only a
confirmed ready page after permitted owner review saves the session and clears
the challenge; subsequent reads reuse that session. Cancellation and denied
checks preserve the block, and completed sign-in never clears a transaction
authorization. This closes a gap where the troubleshooting window
waited for the owner but failed to retain a completed sign-in. This is fixture
evidence, not a physical passkey or personal-account success.

GitHub's recovery-code marker now has its own login-recovery classification.
The connector repair can reclassify a historical action challenge only when its
entire old action selector was the exact recovery marker and its reason was the
browser login gate. Mixed selectors and independently created action challenges
remain blocked. A duplicate recovery gate remains pending during the repair.
Recovery codes are never retrieved or submitted by this adapter.

Follow-up
`0431688` passed **263 tests**, native owner,
Messages and startup/reopen checks, lint, audit and build in
[CI](https://github.com/fainir/account-access/actions/runs/38907392229), plus the
[Android journey](https://github.com/fainir/account-access/actions/runs/38907392302).
Follow-up `1f6f7df` passed all 237 tests, native owner,
Messages and optimized startup/reopen checks, lint, dependency audit and build in
[CI](https://github.com/fainir/account-access/actions/runs/38903426784), plus the
[Android journey](https://github.com/fainir/account-access/actions/runs/38903426763).

GitHub changed its asset versions again during private QA. The connector now
learns exact hashed script/style URLs only from reviewed HTTPS main-frame login
responses and their public scripts' literal imports. Downloads are anonymous,
redirect-free GETs to GitHub's exact asset directory, with eight workers, transfer
and request limits, and an in-memory cache. They cannot receive browser cookies,
credentials, request bodies or a Referer. Queries, asset POSTs, unrelated page
discovery and arbitrary destinations stay blocked. Tests cover these boundaries
and prove declaration processing precedes browser script requests. An anonymous
Chrome check loaded the current public login page in 5.84 seconds with 77 asset
downloads and no failures; it submitted no credentials. See
[public asset results](../artifacts/github-public-assets-080.json).

Native builds 33–41 restored owner-window control and were installed through
graphical repair while preserving account reads and the connected SMS source.
The latest real GitHub check selected SMS and received an accepted HTTP response
to its request, then reached a recovery-code page before receiving/filling a
fresh code. Automatic sign-in stopped there. Additional owner diagnostics now
show only the request's HTTP status, transport and closed-vocabulary redirect
route, to distinguish a normal form submission from the site's JavaScript flow.
Private sign-in and physical delivery remain unverified.
The owner will complete genuine local GitHub verification later. The original
blocked task remains saved; no additional account access or phone-code disclosure
was requested.

Signed build 37 adds **Finish review** when a website check has already
stopped, so the owner can close that review immediately without waiting five
minutes or finding the isolated browser window. Its owner-only endpoint cannot
cancel a running sign-in before an attention state, does not mark an account
connected, and rejects agent tokens and cross-origin requests. An unenrolled
authenticator also no longer counts as a usable alternative when the SMS source
is offline; the browser stops before submitting the password if every source is
unavailable. Regression cases cover both boundaries. Clicking Finish review on
the pilot Mac ended the stopped review in about two seconds. Build 38 returns
that review to the account card with its failed status and diagnostics, rather
than asking the owner to restart the app. The last confirmation form had only
hidden fields and its send button; the response showed no recognized delivery,
rate-limit or invalid-request notice. The cause of the recovery redirect remains
unresolved; this is not evidence of successful SMS delivery.

Follow-up `6db076d` fixes the reviewed SMS-request guard for a connected Google
Messages source and adds nine exact public GitHub assets used by the passkey
page's alternative-method control. An owner-reviewed connector update preserves
the enrolled SMS source and read grants. All **235 tests**, nine native
owner-screen checks, native Messages checks, Ruff, dependency audit and build
passed in [CI](https://github.com/fainir/account-access/actions/runs/38899053403).
The [Android emulator journey](https://github.com/fainir/account-access/actions/runs/38899053946)
also passed. The preceding local full suite passed 234 tests; the asset-refresh
grant-preservation test and eight related cases then passed locally.

The latest follow-up preserves Chromium's native main-frame transport and final
redirect URL while checking every redirect response before it is followed. Tests
cover credential-bearing 307/308 redirects and requests from pages, fetches,
iframes, workers and popups. Candidate `81e3ec7` passed all **233 tests**, eight
native owner-screen checks, native Messages checks, Ruff, dependency audit and
package build in [CI](https://github.com/fainir/account-access/actions/runs/38895850906).
Its [Android emulator journey](https://github.com/fainir/account-access/actions/runs/38895850882)
also passed. The local full run passed 229 tests before four additional targeted
cases covered extension identity/permissions, revocation and an offline paired tab.

The optional [Google Messages connection](google-messages.md) has 26 passing
synthetic tests, including password → paired-page DOM reader → framed native host
→ browser SMS verification. A real extension load used a separate temporary
Chromium profile and verified that message-site access was absent initially.
Only structural metadata and fresh-message indicators were inspected on the
owner's paired Google Messages tab; no code was returned to the agent. The owner
loaded the extension and its approved GitHub SMS connection is enabled. Private
sign-in validation is still in progress; connection enrollment is not completed
SMS-delivery or website-login QA.

Native checks now also distinguish a timeout before confirmed SMS dispatch from
unconfirmed delivery after dispatch. A provider-required owner action or unknown
sign-in page is reported before the owner review window ends. Graphical repair
to signed build 30 preserved saved accounts and permissions. The owner view now
exposes closed route/control diagnostics and exact public vendor asset names,
excluding credentials, code values, arbitrary page text and URL queries. Chrome
Web Store distribution remains outstanding.

After the build 30 live attempt, desktop control could reach Chrome but could
not attach to Account Access while two app instances were running. Signed repair
now asks older same-bundle owner windows to terminate normally before replacing
the bundle, waits up to fifteen seconds, and refuses replacement if a window
remains busy or unresponsive. It does not force-terminate an owner step or stop
the independent account service. A fresh signed build restored control and
normally closed the older native instances. Explicit delegate lifetime and reopen
handling also passed optimized native launch checks; the lifetime change alone
has not been established as the original fault's cause.

The functional candidate at `9fbcad0` passed 173 tests, native owner/reader checks,
Ruff, dependency audit and build in [CI](https://github.com/fainir/account-access/actions/runs/38886257072).
Its [Android emulator journey](https://github.com/fainir/account-access/actions/runs/38886257119)
also passed. Eighteen additional evidence-checker cases cover successful absolute
and relative launcher execution and reject merely echoed/read paths, failed
commands and unrelated launchers.

Native build 21 was installed through graphical repair on the pilot Mac. Its
bundled wheel matched the signed checksum, its installed dependency lock matched
the tested source, and existing account/grant state was preserved. The installed
skill then completed a public SauceDemo inventory read. This is local repair
evidence, not a clean notarized installation on a separate Mac.

Fresh ordinary-language Codex and Claude Code sessions each completed one durable
task across four fictional browser accounts, with four password submissions and
one email, SMS and authenticator verification. Independent provider counters and
task results confirm completion. Claude used `cd` into the project skill followed
by `scripts/access`; the checker was corrected to recognize that successful form
and the actual trace was rechecked. These fixtures do not establish private
mailbox or physical-phone delivery. Evidence: [Codex](../artifacts/agent-tests/codex-verification-080.json),
[Claude](../artifacts/agent-tests/claude-verification-080.json).

The personal browser pilot used its imported website password and reached the SMS
request form. An instrumented reviewed POST received an HTTP-accepted response,
but no new incoming text appeared on the Mac in the bounded window. The owner
reported no phone delivery for the preceding attempt. No SMS source was enabled,
no private verification code was submitted, and the original blocked task was
preserved. Real mailbox/authenticator enrollment and private sign-in completion
remain outstanding. [Production acceptance](production-gates.md) records the
remaining isolation, distribution and service-coverage gates.

## Automatic sessions and revised UX — 14 October 2026, version 0.6

The native Mac app and responsive local console now show account status, actual approved reads, verification setup and password-import guidance separately. Desktop and 390-pixel mobile console layouts were rendered and checked; the native dashboard, verification empty state and password-import navigation were inspected on the Mac.

Fresh CLI sessions received an ordinary-language comparison request with no skill name, slash command or launcher command in the prompt. Codex automatically selected the integration and completed a saved three-account task. Claude Code automatically selected it, completed all three reads and saved a comparison file. The service audit independently confirmed each completion. Both used only the configured public SauceDemo and The Internet accounts, with existing host hooks and general approval modes retained. Codex's installed rule permits only the exact client launcher and supported client commands; it does not allow general Python or shell commands.

The installed Codex CLI rejected the profile's default model before any work. The successful isolated test used the CLI's bundled `gpt-6-astra` model without changing the user's default. Claude's unrelated stop hook attempted four blocked writes to its sensitive session-log path after the requested account work had finished. Those denials are retained in the report; Account Access had zero permission denials. These results do not establish compatibility with every host policy.

A cold local service was then restarted by the installed client without opening owner setup. All three accounts were discovered and the client token and grants remained unchanged. Deliberate pause and response-timeout replay behavior are covered by regression tests. The full local suite passed 75 tests, and the universal Mac build is Developer ID signed. Apple notarization and real private account / physical-phone validation remain outstanding.

Evidence: [Codex session](../artifacts/agent-tests/codex-implicit-06.json), [Claude session](../artifacts/agent-tests/claude-implicit-06.json), [automatic startup](../artifacts/automatic-start-06.json), [dashboard](account-dashboard.png). Raw traces, personal instructions and owner metadata remain excluded from Git.

## Earlier 0.3.1 checks

Observed on 12 October 2026 on macOS, Python 3.13 and Chromium installed through Playwright. This is a **working release candidate**, not a certification of production financial access. No private bank, insurance, Google, Meta or other personal account was connected or tested. No phone inbox was accessed.

## Public release verification — 13 October 2026

The public GitHub repository was verified as readable without authentication. A clean checkout was synchronized, built and installed in an isolated tool directory, then completed all three local demo reads as one durable task. Existing host skill directories were not modified by that verification. Gitleaks reported zero findings in the publication tree and public history; runtime vaults, keys and raw agent traces are excluded. The original local development history was preserved locally, and only the fresh public history with GitHub's no-reply commit email was pushed.

[Linux CI](https://github.com/fainir/account-access/actions/runs/38374863318) passed **43 regression tests**, lint, dependency auditing and distribution building for code revision `0cc7863ea9f1cb478e9da641933926a10ca7acc0`. The first Linux run exposed Ubuntu's restrictions on sandbox namespaces for the downloaded browser. CI now loads an AppArmor policy scoped to the exact installed browser executables and verifies launch with Chromium's sandbox enabled. An initial helper assumed the older headless executable filename; it was corrected for the current and older names before the successful run. The application sandbox setting was not weakened.

Machine-readable publication results are in `artifacts/public-release.json`. These publication checks add Linux and installation evidence to the earlier experiment; they do not add private-account, mobile or thirty-day reliability validation.

## Measured checks

| Check | Result | Evidence |
| --- | --- | --- |
| Regression suite | 43 passed, 93.75 seconds | `uv run pytest -q`; tests in `tests/` |
| Source lint | Passed | `uv run ruff check account_access tests scripts` |
| Known dependency vulnerabilities | None reported at test time | `artifacts/dependency-audit.json`; `pip-audit --local` |
| Portable skill schema | Passed | Bundled skill-creator `quick_validate.py` |
| Distribution | Wheel and source archive built; UI and skill resources present; runtime keys/databases/raw agent traces absent | `dist/account_access-0.3.1-py3-none-any.whl`, `dist/account_access-0.3.1.tar.gz` |
| Owner console | Rendered in Chromium and visually inspected | `artifacts/owner-console.png`; fake UI data |
| Codex CLI 0.155.1 | Five-account task completed; exit 0; 46.633 seconds | `artifacts/agent-tests/codex-summary.json` |
| Claude Code CLI 2.1.112 | Five-account task completed; exit 0; 51.730 seconds; zero permission denials | `artifacts/agent-tests/claude-summary.json` |

An earlier full-suite run had one ten-second subprocess timeout while other workloads were active. The isolated retry passed in 1.92 seconds. The CLI integration test now allows thirty seconds, and the final full suite passed. The dependency audit originally found advisories in the older cryptography dependency; the implementation now requires cryptography 50.x, and the final audit reported none. These are observed checks, not a comprehensive security audit.

## Controlled repeated access

The benchmark creates real HTTP OAuth and website fixtures, runs a real Chromium browser, reopens the encrypted store/broker for every run, and checkpoints each read as a durable task. Enrollment is programmatic with fictional credentials; human onboarding effort is **not measured**.

| Account route | Runs | Unattended completions | Post-setup challenges | Automatic recovery |
| --- | ---: | ---: | ---: | --- |
| OAuth API | 30 | 30 | 0 | 30 refreshes; local expiry forced before each read |
| Password website | 30 | 30 | 0 | One password login, then session reuse |
| Password + TOTP website | 30 | 30 | 0 | One password login and one TOTP submission, then session reuse |

The final accelerated experiment took 85.023 seconds. This is 90/90 unattended completions under controlled conditions, **not thirty days of uninterrupted access**. After invalidating refresh access, five blocked jobs shared one challenge. One simulated owner reconnection resumed all five jobs automatically. The exact recovery timing is in `artifacts/benchmark.json`; it depends on execution and polling rather than a guaranteed SLA.

Regression tests separately cover rotating refresh tokens across threads and processes, lost refresh responses, interrupted work, grant expiry/revocation, configuration drift, denied operations, provider outages, session expiry, code ambiguity and action-authorization challenges.

## External public demo integrations

Only identities deliberately published for testing were used. The experiment enrolled seven identity cases across **three external testing services**. Each of the five positive identities completed five reads with a freshly constructed broker on every run.

| Service and case | Successful reads | Automatic password attempts | Automatic OAuth refreshes | Unique authentication challenges |
| --- | ---: | ---: | ---: | ---: |
| SauceDemo standard user | 5/5 | 1 | 0 | 0 |
| SauceDemo problem user | 5/5 | 1 | 0 | 0 |
| The Internet valid account | 5/5 | 1 | 0 | 0 |
| Duende Alice | 5/5 | 0 | 5 | 0 |
| Duende Bob | 5/5 | 0 | 5 | 0 |

Both Duende identities renewed access using the real external token endpoint, and all ten refreshes returned a different refresh token. Local expiry was accelerated; no access or refresh token was forged. The provider publishes a seventy-five-second client and a `https://notused` redirect. The owner test harness intercepts that redirect in memory before requesting the host, then uses the application's PKCE/state-bound exchange. This validates the provider protocol integration, **not** that provider's compatibility with the application's ordinary loopback owner enrollment UI.

Clearing saved sessions for SauceDemo and The Internet caused one automatic password attempt each and successful recovery. The locked SauceDemo identity and deliberately incorrect The Internet password each stopped after one login attempt. A second request reused the same durable challenge without another login. Client revocation returned `DENIED`.

The complete external experiment took 101.685 seconds. The report contains outcomes, rotation counts, recovery results, limits and source links in `artifacts/public-demos.json`. Public JavaScript demonstration login does not establish server-side session security, and demo behavior does not establish bank or SaaS compatibility.

Initial external runs exposed an unapproved SPA fallback redirect and asynchronous navigation/state timing. Those adapters and bounded marker waits were corrected before the final run. Investigation also found that normal Playwright routing checks only the first request in a redirect chain. The implementation now fetches and validates every hop with automatic redirects disabled. Tests prove that a 307 cannot forward a password to an unapproved destination and that an unapproved read redirect is blocked.

Sources establishing intentional demo use: [Sauce Labs demonstration scripts](https://docs.saucelabs.com/web-apps/automated-testing/selenium/sample-scripts/), [The Internet login page](https://the-internet.herokuapp.com/login), [Duende demo](https://demo.duendesoftware.com/), [Duende published client configuration](https://github.com/DuendeSoftware/demo.duendesoftware.com/blob/main/src/Config.cs). Another examined practice site used a public success URL and client-side credential comparisons; it was excluded as evidence of authenticated session reuse.

## Actual agent execution

The installed wheel runs the service; the skills point at its stable interpreter and private client configuration. Distinct Codex and Claude principals use the same service. Both CLI agents discovered all five accounts, selected their permitted operations, submitted one durable task and obtained five completed results. Completion was independently read through the authenticated service API; an agent's final claim alone was not counted as success.

The account set was `demo-api`, `demo-web`, `demo-mfa`, `sauce-standard`, `internet-valid`. The first three are local fixtures; the last two use public testing sites. Outputs are demo data. The service version returned by discovery was 0.3.1.

Codex ran in an ephemeral workspace sandbox with network access. Claude ran with only Read, Skill and the installed client-command Bash pattern; no MCP servers were loaded. Existing Claude hooks remained enabled. An earlier smoke run completed its service task but could not finish its report because the user's stop hook required project records. The isolated test workspace was given truthful records of that completed experiment, and subsequent runs finished normally. No global hook was removed or modified.

Raw traces can contain unrelated host metadata, so they are private and ignored by Git. The checked-in summaries contain only the test result, service task evidence and demo report. These are **CLI integration tests**; the user still needs to try skill discovery in a fresh Codex desktop chat. No additional named agent host has been executed. The portable client path and installed-script-to-private-service integration are regression-tested.

## Reproduce

```sh
uv sync --locked
uv run playwright install chromium
uv run pytest -q
uv run ruff check account_access tests scripts
uv run pip-audit --local
uv run python scripts/benchmark.py
# Network calls only to published testing identities:
uv run python scripts/public_demos.py --runs 5
uv build
uv tool install ./dist/account_access-0.3.1-py3-none-any.whl
account-access --root "$HOME/.local/share/account-access-demo" demo --install --public-sites
```

The opt-in CLI acceptance harness checks its client boundary before starting
fictional providers, a private fixture service and client. Current Codex and
Claude QA both refuse at that preflight because the effective execution/tool
boundary cannot be attested. The commands below produce separate blocked
reports and leave the requested workspace and fixtures uncreated:

```sh
uv run python scripts/agent_verification_smoke.py codex --workspace /absolute/path/to/new-codex-test
uv run python scripts/agent_verification_smoke.py claude --workspace /absolute/path/to/new-claude-test
```

These preflights inspect only bounded public CLI version/help, create no API
keys, and start no model, account fixture, or private website login. A future
live run needs a disposable environment with dedicated QA authentication and
controlled configuration, or a supported pre-execution boundary attestation;
that requirement remains open. Historical successful reports do not override
this refusal. See the [current boundary](agent-qa-boundary.md). The older smoke
scripts have been retired. For normal user testing, use the short prompts in
README.md; no test harness is necessary.

## Remaining production work

| Area | Current evidence | Required before claiming production coverage |
| --- | --- | --- |
| Private service coverage | Public demos and controlled fixtures; Google Drive configuration example | Named authorized service adapters, approved operator OAuth apps, real account pilots and provider conditions |
| Long-term interruptions | Accelerated measurements | At least thirty-day per-service observations with real onboarding and notification counts |
| Gmail and SMS codes | Contract tests for precise filtering | Live provider/source enrollment and code-delivery tests; support for the intended phone number |
| iPhone and Android | Ordinary provider owner handoff; no native companions | Platform-specific enrollment, live SMS/device handoff validation, native companion implementation where feasible |
| Passkeys/biometrics/admin | Challenge classification and genuine owner handoff | Real platform/provider tests; mandatory presence remains a user gesture |
| Chrome convenience | Native bridge and origin-filter unit tests | Extension installation/live Chrome session adoption, compatibility testing and signed distribution |
| Credential isolation | Private files, encrypted records and API boundaries | Broker under a separate OS identity/host for unrestricted agents; deployed TLS and operational validation |
| Notifications | Durable shared challenges | Real delivery, cross-chat deduplication and wake/resume integration |
| Packaging/operations | Wheel, portable skill, TLS example, macOS tests and passing Linux CI | Signed installer/updater, service lifecycle management, recovery/backup procedures and broader platform coverage |

Payments, tax filings and account-changing writes are unsupported. No test result in this report authorizes or validates those operations. The goal of a broad production consumer product remains open; this release establishes a tested, usable foundation and the measurements needed for a real pilot.
