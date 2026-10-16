# Validation of Account Access

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

The current opt-in CLI acceptance harness creates its own fictional providers,
private fixture service and client. Use a **new empty workspace** for each run,
and satisfy existing host instructions/hooks:

```sh
uv run python scripts/agent_verification_smoke.py codex --workspace /absolute/path/to/new-codex-test
uv run python scripts/agent_verification_smoke.py claude --workspace /absolute/path/to/new-claude-test
```

These use the user's existing CLI login and can consume agent usage. They create
no API keys and do not use private website accounts. Codex uses a fixture-socket
permission profile; Claude uses the tool gate described above. The older smoke
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
