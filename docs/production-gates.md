# Production acceptance

**Account Access is a preview, not a production release.** The requested outcome
is a simple installation, one-time local enrollment, and later routine sign-ins
through the user's existing AI agent. Passing fictional-account tests does not
establish that experience on personal accounts.

## Current candidate

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
The app cannot connect to it; the exact startup cause is still unknown. No
protected-store enrollment, shared AI connection upgrade or personal sign-in
was completed on this installation.
[Installation and CI record](../artifacts/runtime-acceptance-080-build76-20261020.json).

The owner-approved startup check subsequently ran through Installer, but its
report says `diagnostic_tool_unavailable` with no captured startup reason.
Cleanup remains pending: capture consumption and restoration of stdout to
`/dev/null` are unconfirmed, so the guarded private target was retained.
Startup investigation remains open.
[Diagnostic attempt and exact public result](../artifacts/startup-check-attempt-080-build76-20261020.json).

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
| Mac installation | Build 76 package inventory/source/payload-signature review and owner-approved local Installer completion; exact-source disposable Mac CI passes | Repair the installed service's exit 78 before enrollment; Developer ID Installer certificate, Notary credentials, Apple acceptance and stapling; clean downloaded installation, working owner enrollment and reboot QA |
| Upgrade and repair | Explicit recognized-preview agent connection upgrade; atomic launcher replacement and rollback; same-image/same-owner package recovery | Genuine installed owner upgrade and interrupted positive provisioning; different-image protected-package updates and vault migration |
| Password import | Reviewed Chrome, Apple Passwords, compatible 1Password and Bitwarden CSV; unencrypted Bitwarden JSON; hidden-password local review | Representative real export-to-private-website acceptance, including the new protected installation |
| Password synchronization | Approved 1Password items through service-account SDK or Connect; separately consented Bitwarden CLI source with exact-item checks, bounded updates and restrictive disconnect | Private enrollment, rotation and revocation QA. **Chrome live sync is unimplemented**; file imports remain snapshots |
| Gmail and other email | Renewable Gmail authorization, checked reusable mailbox selection, and TLS IMAP; freshness, sender, template and authorization checks | Publisher-configured Google application, real owner consent/mailbox setup and actual website code delivery. Arbitrary webmail is unsupported |
| iPhone SMS | Signed narrow Mac Messages reader and composed password/SMS/session fixtures | Genuine Full Disk Access, forwarded physical SMS and completed private login |
| Android SMS | Paired pinned HTTPS delivery and notification-listener emulator fixtures | Physical pairing, carrier/notification delivery, reconnect and private login QA |
| Google Messages Web | Reviewed browser/desktop preparation, refresh/revocation UI checks, unchanged extension scripts in a synthetic Messages document, stable Chrome/native transport and controlled SMS-login composition | Genuine positive owner approval and complete private/physical SMS login; broader language coverage and extension distribution |
| Authenticator | Local original-key, supported QR and complete Google Authenticator transfer-batch import; TOTP login fixtures | Owner-approved real phone export/enrollment and provider login. Push approvals, nonstandard TOTP and Google Authenticator cloud sync are unsupported |
| Agent integration | Portable installed CLI/skill; historical source-specific guarded Claude/Codex fixtures; separate revision-unattested installed-preview public reads | Current protected owner installation and private sessions through both agents. The optional nested Codex QA harness remains unverified before startup |
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
test counts. Gmail setup and real authenticator enrollment remain incomplete;
fictional substitutes cannot close those gates.

Keep passwords, exports, cookies, QR images, message contents and raw agent
traces out of public evidence. Publish sanitized failure classes and coverage,
preserve blocked task IDs, and distinguish fictional, public-example,
unclassified and private results. Another application's CLI token or a copied
session is not evidence of fresh password/email/SMS/authenticator login.

[Provider scope](other-service-validation.md) ·
[Password sync](security-and-password-sync.md) ·
[Security architecture](architecture.md)
