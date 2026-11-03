# Build 126 qualification and installed acceptance - 3 November 2026

Build 126 is installed on the owner Mac after a full OS restart. One-time setup,
batch Google Authenticator review and no-match password-import recovery are
built and delivered. Real private Lemon credential/grant/authenticator enrollment
has not happened. No password, private QR/key, code, Chrome store or protected
configuration file was read by the agent.

## Source and native UI

[Program/helper CI](https://github.com/fainir/account-access/actions/runs/41622483380)
passes 4,742 tests/114 skips, lint, dependency audit and native checks
[source summary](source-helper-ci-summary.log). The new atomic batch engine also
completes a controlled actual local-browser password/TOTP login. Native compiled
UI passes 61 groups; actual CUA [valid mappings](authenticator-mappings.jpg),
[duplicate refusal](authenticator-duplicate.jpg), Cancel, [empty import](empty-import.jpg)
and [setup](setup-top.jpg) were inspected. Local web [375px](web-empty-375.png)
and [1440px](web-empty-1440.png) empty-import flows pass without overflow/errors.
[Detailed source limits](notes.md). These use fictional fixtures, not private keys.

[Mac worker CI](https://github.com/fainir/account-access/actions/runs/41622483229)
passes all 18 actual reports and 427 checks. All 15 workflow validators pass
[read-back](worker-validation.log). Current reports are retained under worker/.
All nine [native updater reports](native/direct.json) pass in
[run 41622483331](https://github.com/fainir/account-access/actions/runs/41622483331).
The exact current plan has 15 units/17 changed nodes and a separate recovery namespace.

## Final packages and actual Installer

The [signed public image](target126-qualification.json),
[6.1 MB updater](updater-qualification.json) and
[289 MB full installer](fresh-qualification.json) are qualified. Both packages
are signed, Apple-accepted, stapled and Gatekeeper accepted. Native publisher
signatures and actual sandboxed-browser execution pass. Exact final public
bytes are pinned in the [Installer contract](../../artifacts/runtime126-installer-inputs.json).
Program is 2ca9de3; image builder c96b2e1; updater/compiler a53567d/41622483331;
full-package builder 0714900. Test-only 633d8ee repairs the fixture's omitted
build-125 source pin. No production image/package was rebuilt for that repair.

| OS | Fresh / identical repair | Update / reapply |
|---|---|---|
| 14.8.9 arm64 | [11 checks](macos14-fresh/report.json) | [27 checks](macos14-upgrade/report.json) |
| 15.8.2 arm64 | [11 checks](macos15-fresh/report.json) | [27 checks](macos15-upgrade/report.json) |
| 26.6.2 arm64 | [11 checks](macos26-fresh/report.json) | [27 checks](macos26-upgrade/report.json) |

All 114 checks pass. Upgrades preserve all six retained 120-125 histories,
private fixture inode, receipts/policies, recovery binding and old unpublished
preparation. Browser executes sandboxed and patched dependencies pass. Every
created fixture job was stopped/absent. No personal account was used. Fresh
reports come from 41625148580/41625153664/41625157789; corrected update-only
reports from 41626228498/41626232760/41626568521. Passed fresh journeys were kept.

## Actual owner Mac

Before installation, [13 selected public files](owner-preflight.json) matched
qualified 125; ten existing root/alias metadata identities were captured. Worker
was RUNNING with zero consecutive failures and browser READY. No owner GUI was
running. The exact customer-named updater was selected in Finder and opened in
Installer; [staged review](owner-installer-pending.jpg). Native approval remained
with the owner. SecurityAgent was not inspectable with native control; no secret
or authorization bypass was attempted.

After interruption, actual read-back found installation complete at 13:39:44
and kernel boot at 13:40:40. [Scoped postinstall outcome](owner-installer-outcome.log)
reports UPDATED_GUI_UNVERIFIED at checkpoint complete. Actual owner build is
126 on macOS 27.2. [Public/metadata read-back](owner-installed126.json) verifies all
13 selected files against qualified 126, all ten prior inode/mode/UID/GID
identities preserved, and the new root-owned 0700 Automatic Setup namespace.
Do not repeat this completed installation or reapply its predecessor updater.

[Actual installed health](installed126-health.json) is worker RUNNING, zero
failures and browser READY. Both actual installed launchers complete the approved
Betterloop status read: [Codex](installed126-codex-private.json),
[Claude](installed126-claude-private.json), each outer environment live and only
authenticated=true. Separate [Codex](installed126-codex-public.json) and
[Claude](installed126-claude-public.json) public-example reads each return six
names/prices. Namecheap remains paused; no operation against it was retried.
No Lemon grant exists. Native UI tools were removed after the Mac restart, so
no new post-restart GUI interaction or private batch import is claimed.

The existing customer draft has 11 verified, labeled assets. All nine earlier
IDs/bytes and matching Bitwarden source are preserved. Server digest, size,
complete state, tested source target, current notes and unpublished state were
read back. Owner installation is complete; private enrollment and publication
remain separate. The technical follow-up account-access-one-time-setup-release
was deleted after installation and all available automated acceptance finished.
No personal-enrollment monitor or repeated completed approval is needed.

The owner identified Google Authenticator. The previously selected password
export showed four unsupported entries and zero selectable accounts. Remaining
personal enrollment starts with a complete Chrome export that actually matches
Lemon Squeezy, reviewed/imported locally with its status-only grant. Then the
owner can transfer the existing authenticator keys locally. Do not repeat the
withdrawn manual password handoff, completed Chrome MFA or mailbox setup. Private
QR/key/code input and passkey/security-key/biometric/push presence remain local
owner actions. Physical SMS and publication stay in the ledger.
