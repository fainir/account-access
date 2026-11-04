# Owner-requested verification order - 4 November 2026

Order: Chrome import and email/password sign-in, then email verification, then
SMS, then authenticator transfer. Existing approvals/data are preserved.

## Step 1: actual Chrome-import/password baseline

The real native Chrome import and initial Betterloop email/password sign-in
were observed on 2 November: [native journey](../betterloop-private-2026-11-02/acceptance.md).
Only the owner-selected account/status grant was saved; no credential file was
opened by the agent. The installed 127 login code for this password-only
connector retains that path. Current normal installed [Codex](codex-password-status.json)
and [Claude](claude-password-status.json) operations each return
COMPLETED/environment live and only authenticated=true. These two current reads
confirm the existing session; they are not fresh password submissions. No
session/credential was erased, no new import/grant or duplicate login challenge.

## Step 2: Harel email, then Step 3: Harel SMS

The owner explicitly selected Harel and identified its email/SMS choice.
This reopens Harel's earlier v1 exclusion; Phoenix stays excluded. Public review
already identified identity/mobile fields and a native GET form wrapped by
JavaScript. The generic GET refusal must remain; IDs/phone/codes must never enter
URLs, agent output or logs. Review the exact provider-owned API sequence before
an installed connector or local personal enrollment is requested. Only boolean
session status is in scope; no insurance policies/medical/payment data.

Best way: use Harel's official public entry/application assets as primary
implementation evidence and enforce a closed, attempt-bound request/response
state machine. Stop on declarations, document-issue-date, card or stronger identity
branches. Reuse the already checked mailbox through native owner binding;
request no saved mailbox password again. Provider and controlled fixture proof
remain distinct from a real email/SMS login. Existing insurer observations:
[review](../../docs/insurer-login-acceptance.md),
[official entry](https://www.harel-group.co.il/Pages/login-page/Login.aspx).

Authenticator action 18 is deferred by the owner until the preceding stages are
accepted. Preserve the existing paused Lemon task/challenge and Namecheap pause;
request no further QR, authenticator setup or manual login codes now.

## Implemented source candidate; installed 127 is unchanged

Fresh anonymous HTTP inspection retrieved the current official entry and
[microfrontend configuration](https://digital.harel-group.co.il/portal-config-backend/api/v1/micro-frontends/get-config/cus).
The public customer-header and Scanovate ver61 bundles match the previously
reviewed bytes. The selected radio is passed into ContextConfig: email is 1,
SMS is 0. This corrects the earlier description of an unconditional SMS request.
No identity, phone, code request, private profile or insurance data was used.

The new fixed client itself reached the real entry, anonymous GetCurrentDetails
(authenticated=false), then email ContextConfig successfully:
[actual anonymous client result](harel-anonymous-client.json). This does not
establish private-account acceptance. CurrentProcess is an integer discriminator,
not an attempt nonce; the private cookie context and enrolled local code window
bind the attempt.

The source adapter uses only the exact reviewed POST endpoints. It selects the
channel before identity submission, refuses native GET submission, resends,
channel changes, redirects, uncertain replay and stronger identity branches.
After code verification it requires UserLoggedIn plus the current-user marker
and a separate cookie-authenticated status response. Only a boolean leaves it.
The inferred success contract still needs live native qualification.

- [158 component cases](harel-component-tests.log): protocol state/response
  guards, source-backed TLS test-mailbox delivery, reuse/expiry, revocation,
  scope mutations, cookie restoration and redacted first-use pattern proposals.
- [191 focused regressions](source-tests.log): existing password/identity,
  catalog, grants, security, metadata and Chrome import boundaries. These overlap
  the component cases; do not add the counts as distinct cases.
- [63 MIME/pattern cases](email-pattern-tests.log): no automatic adoption of a
  sender or message; one local owner-reviewed code proposes an exact filter.
  No actual email was fetched or sender/template invented.
- [Owned UI checks](owner-ui-tests.log) pass at 375 and 1200 pixels, with no app
  console errors or horizontal overflow. Email identity/mobile stay masked and
  are cleared before changing to password fields. [375](harel-owner-375.png),
  [1200](harel-owner-1200.png). The catalog was a controlled fixture, not an
  installed Harel entry. Native screen checks are recorded separately.
- [61 native screen groups](native-ui.log) pass in the locally compiled controlled
  app, including distinct masked identity/mobile fields for email and SMS,
  password-kind switching, cleared values and no credential export/sync choice.

The first UI fixture omitted the install mock and correctly hit the existing
protected-skill guard. No installation occurred; normal installed discovery
still returns exactly the four prior grants. The fixture now isolates install.
An eval-based QA wait was also replaced with an attached-element wait under
the unchanged CSP. These were fixture failures, not private provider verdicts.

## Native setup candidate and safety fixes

The native Harel wizard is implemented. It reuses a checked TLS mailbox, keeps
identity/mobile/first-code input local and masked, reviews one actual new
UID/arrival/profile/attempt-bound message, then explicitly asks permission for
one additional email to prove fresh automatic sign-in. Credentials, the new
source, session and only the status grant are published only after that fresh
automatic test succeeds. Existing configuration fingerprints/grants are retained.
Cancellation, mailbox changes, expiry and uncertain delivery stop safely.

- [196 integrated Harel cases](harel-component-tests.log) pass, including the
  [35 setup cases](harel-setup-tests.log); these counts overlap.
- [43 release-profile/identity regressions](harel-release-profile-tests.log)
  pass, including both corrected old-label UI assertions.
- [64 compiled native UI groups](harel-native-ui.log) pass, including actual
  code/approval controls held across injected old polling responses.
- [84 synthetic native XPC/gateway checks](harel-native-gateway.json) pass
  against the actual Python owner fixture. Ad-hoc fixture peers are explicitly
  not publisher/private/installed acceptance.
- [Dependency audit](harel-dependency-audit.log) reports no known vulnerabilities;
  full ruff check passes. Project account-access itself is not a PyPI package.
- D24/D25/D26 safety findings were fixed and tested; the independent
  [final review](../../readiness/harel-final-review.md) reports no remaining
  concrete release-critical defect. [Detailed safety evidence](../../readiness/harel-setup-safety.md).

D27 fixed a long consent title that forced the native window wider. The full permission now wraps above a short checkbox; a compiled assertion keeps the setup at the app’s 880px minimum width.

Owned native UI snapshots use only the compiled synthetic fixture and its
checked example.test mailbox: [setup](harel-native-setup.png),
[first code](harel-native-code.png), [redacted review](harel-native-review.png),
[automatic-test progress](harel-native-testing.png). The fixture cannot touch
installed account data or send actual Harel mail. Earlier web 375/1200 evidence
still covers distinct masked identity/email fields.

## Qualification policy and remaining acceptance

The previous source CI completed with two stale UI-label test failures, now
corrected and passed locally. Its Mac worker never acquired a runner; GitHub's
annotation reports hosted arm64 capacity constraints. Previous Android, Linux
worker and component Installer fixtures completed successfully. These are
historical results, not new 128 delivery proof.

On 4 November Nir replaced the CI policy: GitHub Actions budget is $0 and
Actions must not be used. The repository’s actual Actions settings now read
[`enabled=false`](actions-policy.json); all 30 automatic workflow triggers are
removed. Before pushing,
run the repository's local CI through the shared wrapper and compile matching
release inputs locally. Retain historical 120-127 release contracts.

D23 remains buildable: qualify and deliver the matching signed 128 image/update
from installed 127. Harel email and SMS remain unverified until real native
owner enrollment and actual private sign-in. No new installer, private request,
actual message read, grant or personal enrollment occurred in this component
phase. Do not ask for the checked mailbox password again. The existing two-hour
follow-up continues delivery and stays quiet on unchanged state.

The [local CI migration](../../readiness/local-ci-transition.md) passed306 workflow/asset checks,14 gateway report checks, shell syntax, minimal-PATH input validation and a controlled dependency-failure/cleanup run. Full local CI is next, after this clean source push.

## Actual signed image and native updater qualification

The actual signed128 image qualifies from127, with unchanged third-party dependency bytes and the publisher-signed sandboxed browser READY. [Image report](image128-qualification.json). All196 controlled Harel checks pass in the actual packaged Python3.12.16 using its imported program modules; the image manifest remains unchanged afterward. [Runtime log](packaged-harel-tests.log).

The actual exact update plan has15 units,24 changed nodes and73 project source files. The current native [shared adapter](native-full128.json) and [direct128 plan](native-direct128.json) report PASSED, retain six ordinary-user refusal guards and do not access installed paths. The same current compiled direct binary passes every retained120-127 fixture with its original counts, namespace and source binding; no eightfold recompilation or historical contract modification. [Eight actual results](native-compatibility128.log). The integrated profile/planner/package/probe suite passes254 tests; full lint is clean. [Test log](helper-profile-tests.log).

All72 [runtime native checks](native-runtime128.json) and the actual ordinary-user updater refusal also pass. Signed package assembly and one final corrected full clean-source local CI remain required before staging installation. The initial full run is recorded honestly as failed; its29 fixture/clean-source failures all pass targeted corrected rechecks. [Initial and corrected evidence](local-ci-initial.md). No128 installer, native owner Harel enrollment, private email or SMS success is claimed here.

The exact local [signed128 updater](signed-update128.json) is Apple Accepted, stapled and Gatekeeper accepted,6,099,873 bytes. Both retained package copies match its final digest. Actual127 preflight matches14 selected public files and preserves all12 prior metadata identities; no private file read. [Preflight](owner128-preflight.json).

The Q full CI stopped at67% before the confirmed19:46:58UTC Mac reboot; the later19:54 heartbeat was not the cause. The managed CI/pytest process is confirmed gone; there is no final pytest result or green status. The next clean documentation source will rerun the same shared wrapper in a detached ordinary process session; code/image/helper/package bytes are unchanged. Installation stays unstaged until the complete final result is read back.

## New postboot release hold

The completed detached [full local CI](local-ci-final.md) passes5145 tests/5 skips, all permitted native stages and actual GitHub local-ci success. Current127 nevertheless fails its first worker-start deadline after the newly observed kernel reboot; both installed launchers are unavailable. Hold the uninstalled signed128 candidate, implement and independently review D29 safe bounded initial-start recovery, then qualify one necessary corrected image/update. Do not ask for installation or personal Harel setup yet. No current private sign-in succeeds or new owner action is claimed.

D29 acceptance checks: (1) only exact initial worker timeout gets at most two additional cleaned-up launches, with published owner authority and pause rechecked; (2) security/key/journal/cleanup failures, cancellation and Pause never retry or report false readiness; (3) a corrected signed image/update preserves all120-127 contracts and saved data; (4) actual installed worker/browser and both approved launchers recover, then remain healthy after a new kernel boot. Real Harel email follows these checks and its native owner enrollment. The native app has no public HTTP health URL; verification uses the installed launcher and exact public-image/build read-back instead of inventing a web endpoint. Independent review is the live safety lane that found and rejected the paused-launch defect.

D29 source/helper verification passes2 tests, covering13 new recovery groups and6 existing readiness groups. Independent [safety/deadline review](../../readiness/cold-start-review.md) finds no remaining concrete issue after fixing the paused-launch Boolean. The 35/40-second native RPC acknowledgments do not enclose the asynchronous recovery; the actual held package's1,800-second postinstall deadline needs no widening. Full universal broker compilation and a corrected signed image/update are next; actual cold-boot recovery remains unverified. The first128 package stays held and uninstalled; a corrected candidate is justified by this observed defect rather than a repeat of an unchanged build.
