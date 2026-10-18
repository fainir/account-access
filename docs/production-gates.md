# Production acceptance

**Account Access is a preview, not a production release.** The requested outcome
is a simple installation, one-time local enrollment, and later routine sign-ins
through the user's existing AI agent. Passing fictional-account tests does not
establish that experience on personal accounts.

## Current candidate

Build **68** is the current source candidate, adding explicit Bitwarden
Password Manager connection, imported exact-item suggestions, unattended
password refresh and restrictive source disconnect. Its official OSS CLI uses
the protected Node runtime instead of the standalone client's older embedded
runtime. Packaging requires the corresponding source and dependency notices.
The connection retains broad vault-decryption authority with explicit owner
consent; exact-item restrictions are enforced by Account Access. Private
enrollment and consumer installation are not established by its controlled
tests. Earlier build evidence below does not validate this new product tree.
[Bitwarden setup and limits](bitwarden-sync.md).

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

A fresh [Claude Code check at source da2bb94](../artifacts/agent-tests/claude-verification-080-build66-da2bb94.json)
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
| Mac installation | Offline protected package, native inventory and publisher-signature checks; actual Installer-context and same-image recovery fixtures; build 67 adds native capacity preflight and non-destructive low-space retry | Developer ID Installer certificate, Notary credentials, Apple acceptance and stapling; clean downloaded installation, genuine owner enrollment and reboot QA |
| Upgrade and repair | Explicit recognized-preview agent connection upgrade; atomic launcher replacement and rollback; same-image/same-owner package recovery | Genuine installed owner upgrade and interrupted positive provisioning; different-image protected-package updates and vault migration |
| Password import | Reviewed Chrome, Apple Passwords, compatible 1Password and Bitwarden CSV; unencrypted Bitwarden JSON; hidden-password local review | Representative real export-to-private-website acceptance, including the new protected installation |
| Password synchronization | Approved 1Password items through service-account SDK or Connect; separately consented Bitwarden CLI source with exact-item checks, bounded updates and restrictive disconnect | Private enrollment, rotation and revocation QA. **Chrome live sync is unimplemented**; file imports remain snapshots |
| Gmail and other email | Renewable Gmail authorization, checked reusable mailbox selection, and TLS IMAP; freshness, sender, template and authorization checks | Publisher-configured Google application, real owner consent/mailbox setup and actual website code delivery. Arbitrary webmail is unsupported |
| iPhone SMS | Signed narrow Mac Messages reader and composed password/SMS/session fixtures | Genuine Full Disk Access, forwarded physical SMS and completed private login |
| Android SMS | Paired pinned HTTPS delivery and notification-listener emulator fixtures | Physical pairing, carrier/notification delivery, reconnect and private login QA |
| Google Messages Web | Unchanged production scripts in a synthetic Messages document, stable Chrome/native transport and controlled SMS-login composition | Genuine positive owner approval and complete private/physical SMS login; broader language coverage and extension distribution |
| Authenticator | Local original-key, supported QR and complete Google Authenticator transfer-batch import; TOTP login fixtures | Owner-approved real phone export/enrollment and provider login. Push approvals, nonstandard TOTP and Google Authenticator cloud sync are unsupported |
| Agent integration | Portable installed CLI/skill; current guarded Claude fictional-account journey; earlier source-specific Codex results | Current protected owner installation and private sessions through both agents. The optional nested Codex QA harness remains unverified before startup |
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
