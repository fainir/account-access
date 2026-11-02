# Account Access 0.8.0 - build 124

Publication-review draft. The public download is still the 0.7.4 preview.
The publisher approved the complete privacy notice and terms on 1 November
2026. Build 124's signed Installer and source qualification are complete.
Owner-Mac installation and automated private MFA acceptance remain pending.

## Choose your Mac package

- **New clean Mac, Apple silicon:** [current build-124 full signed installer](https://github.com/fainir/account-access/releases/download/v0.8.0/Account-Access-0.8.0-build124-Mac-arm64.pkg).
- **Existing qualified protected build 123:** [exact build-123-to-124 updater](https://github.com/fainir/account-access/releases/download/v0.8.0/Account-Access-0.8.0-update-from-build123.pkg). It checks the exact predecessor and receipts before changing anything.
- **Existing qualified protected build 122:** first use the [122-to-123 bridge](https://github.com/fainir/account-access/releases/download/v0.8.0/Account-Access-0.8.0-update-from-build122.pkg), then the current updater above.
- **Existing qualified protected build 121:** use the [121-to-122 bridge](https://github.com/fainir/account-access/releases/download/v0.8.0/Account-Access-0.8.0-update-from-build121.pkg), followed by 122-to-123 and 123-to-124. Each accepts only its reviewed predecessor.

The current full installer supports clean installation and qualified identical-
image repair. It does not replace another protected image. The 0.7.4 preview
is not a qualified protected predecessor. Earlier full installers and bridges
are retained and labeled legacy; new installations should choose build 124.

Open the appropriate package in macOS Installer and follow its native prompts.
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

The signed, notarized and stapled build-124 packages passed actual fresh/repair
and upgrade/reapply on macOS 14.8.9, 15.8.2 and 26.6.2 arm64, 114 checks total.
Reports verify build 124, live sandboxed browser execution, patched dependency
checks and preservation of private test data, receipts, policies and all four
earlier recovery histories. Native qualification preserves all earlier update
contracts. Complete source regression passes 4,704 tests with 113 skips, Ruff,
dependency audit and native UI/gateway/updater checks. The matching runtime's
Mac worker acceptance passes 18 reports and 426 checks, including actual
prepared-runtime execution. These controlled tests use no personal accounts.

Build 124 adds a reviewed Lemon Squeezy password/authenticator connector whose
only operation reports whether the session is authenticated. It returns no
dashboard contents, passwords or authenticator keys to AI agents. The owner
completed manual Chrome MFA to qualify the website's actual forms and success
state. Installed protected-service login and authenticator enrollment remain
separate acceptance; no automated private Lemon Squeezy success is claimed.

The owner-selected Betterloop Chrome import and real private password/session
login passed on installed build 123. Both Codex and Claude Code returned only
authenticated=true, classified as live. That build also passed installed
runtime/public-example checks after a full OS restart. Real private email,
SMS and TOTP acceptance remain unqualified.

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
