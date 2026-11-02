# Account Access 0.8.0 - build 125

Publication-review draft. The public download is still the 0.7.4 preview.
The publisher approved the complete privacy notice and terms on 1 November
2026. Build 125's source and signed-Installer checks pass. It adds bounded
slow-start handling and precise exit diagnostics after the owner Mac's
build-124 restart exposed a service-startup failure. Worker qualification and
actual owner-Mac recovery remain pending; publication is on hold. Automated
private MFA acceptance is separate and remains pending.

## Choose your Mac package

- **New clean Mac, Apple silicon:** [current build-125 full signed installer](https://github.com/fainir/account-access/releases/download/v0.8.0/Account-Access-0.8.0-build125-Mac-arm64.pkg).
- **Existing qualified protected build 124:** [exact build-124-to-125 updater](https://github.com/fainir/account-access/releases/download/v0.8.0/Account-Access-0.8.0-update-from-build124.pkg). It checks the exact predecessor and receipts before changing anything.
- **Existing qualified protected build 123:** first use the [123-to-124 bridge](https://github.com/fainir/account-access/releases/download/v0.8.0/Account-Access-0.8.0-update-from-build123.pkg), then the current updater above.
- **Existing qualified protected build 122:** start with the [122-to-123 bridge](https://github.com/fainir/account-access/releases/download/v0.8.0/Account-Access-0.8.0-update-from-build122.pkg), followed by 123-to-124 and 124-to-125.
- **Existing qualified protected build 121:** start with the [121-to-122 bridge](https://github.com/fainir/account-access/releases/download/v0.8.0/Account-Access-0.8.0-update-from-build121.pkg), then follow each bridge in order to 125. Each accepts only its reviewed predecessor.

The current full installer supports clean installation and qualified identical-
image repair. It does not replace another protected image. The 0.7.4 preview
is not a qualified protected predecessor. Earlier full installers and bridges
are retained and labeled legacy; new installations should choose build 125.

Before updating, choose **Account Access > Quit Account Access** and let the app
exit. Then open the exact updater in macOS Installer and follow its native prompts.
If an update fails while the app is still open, quit it from that menu and rerun
the same updater. The updater stops before changing the installation in that case.
After installation, open Account Access and finish local owner setup. Start a
fresh Codex or Claude Code session after agent integration is connected.
Passwords, codes and authenticator keys belong in local setup, never in chat.

## Included third-party source

**No additional charge:** download the [Bitwarden corresponding-source archive](https://github.com/fainir/account-access/releases/download/v0.8.0/account-access-bitwarden-2026.10.0-corresponding-source.tar.gz)
alongside either installer. Its digest matches both runtime manifests.
Dependency, JIT and Bitwarden bytes are unchanged from the qualified predecessor.
The archive includes pinned upstream materials, dependencies, derivation/build
instructions and notices. Account Access retains its MIT license; bundled
programs retain their licenses.

## What this candidate has passed

The signed, notarized and stapled build-125 packages passed actual fresh/repair
and upgrade/reapply on macOS 14.8.9, 15.8.2 and 26.6.2 arm64, 114 checks total.
Reports verify build 125, live sandboxed browser execution, patched dependency
checks and preservation of private test data, receipts, policies and all five
earlier recovery histories. Native qualification preserves all earlier update
contracts. Complete source regression passes 4,712 tests with 114 skips, Ruff,
dependency audit and native UI/gateway/updater checks. Matching Mac worker
acceptance, including a real delayed-bootstrap journey, is being finalized.
These controlled tests use no personal accounts.

Build 125 allows a finite 120-second startup window and distinguishes timeout
from early worker exit. Child ownership, signatures, protected paths, identity
drop, listener checks and key custody stay enforced. It changes seven public
files; the Python wheel, dependencies and JIT bytes are unchanged from 124.

Build 124 adds a reviewed Lemon Squeezy password/authenticator connector whose
only operation reports whether the session is authenticated. It returns no
dashboard contents, passwords or authenticator keys to AI agents. The owner
completed manual Chrome MFA to qualify the website's actual forms and success
state. Installed protected-service login and authenticator enrollment remain
separate acceptance; no automated private Lemon Squeezy success is claimed.

The owner-selected Betterloop Chrome import and real private password/session
login passed on installed build 123. Both Codex and Claude Code returned only
authenticated=true, classified as live. That build also passed installed
runtime/public-example checks after a full OS restart. Build 124's later reboot
exposed the current startup defect; its recovery is not established by these
historical reads. Real private email, SMS and TOTP acceptance remain unqualified.

## Current scope and remaining acceptance

Reviewed connectors and explicitly approved operations only. Harel and Phoenix,
arbitrary websites, payments and portable protected-vault backup are outside v1.
Existing mailbox setup is checked; real website email/TOTP acceptance and the
paused Namecheap challenge remain separate. The withdrawn Read the Docs handoff
does not require signup or credentials from the owner.

The Android 0.8.0 candidate has its first publisher identity in native Mac
Keychain custody and passes signed-APK emulator UI acceptance. No phone is
connected. Bluetooth association, carrier SMS delivery and physical performance
remain unqualified. No Android APK is part of this Mac upload or Play submission.

Publisher-approved [privacy notice](https://github.com/fainir/account-access/blob/7903cafa50d1510dd56011e5450b48df415aca7a/docs/privacy.md)
and [terms](https://github.com/fainir/account-access/blob/7903cafa50d1510dd56011e5450b48df415aca7a/docs/terms.md)
identify Nir Fainshtein, עוסק פטור, and the selected support/privacy contact.
Their approved substantive text is unchanged and takes effect with public release.
This draft adds no subscription, purchase or cloud SMS relay.

Full acceptance evidence: [production ledger](https://github.com/fainir/account-access/blob/codex/production-security-authlib-20261028/READINESS.md).
These customer download URLs become public after the release is published.
