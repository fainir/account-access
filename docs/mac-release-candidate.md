# Account Access 0.8.0 - build 123

Publication-review draft. The public download is still the 0.7.4 preview.
The publisher approved the complete privacy notice and terms on 1 November
2026. Personal/private MFA acceptance remains recorded in READINESS.md before
publication. Build 123 is installed on the owner Mac; protected-service health
and both approved public-example agent reads pass after a confirmed full OS restart.

## Choose your Mac package

- **New clean Mac, Apple silicon:** [current build-123 full signed installer](https://github.com/fainir/account-access/releases/download/v0.8.0/Account-Access-0.8.0-build123-Mac-arm64.pkg).
- **Existing qualified legacy protected build 122:** [exact build-122-to-123 updater](https://github.com/fainir/account-access/releases/download/v0.8.0/Account-Access-0.8.0-update-from-build122.pkg). It checks the reviewed predecessor and installation receipts before changing anything.
- **Existing qualified legacy protected build 121:** first use the [build-121-to-122 bridge](https://github.com/fainir/account-access/releases/download/v0.8.0/Account-Access-0.8.0-update-from-build121.pkg), then the build-122-to-123 updater above. Each package accepts only its reviewed predecessor.

The current full installer supports clean installation and qualified identical-
image repair. It does not replace another protected image. The 0.7.4 preview
is not a qualified protected predecessor. Earlier build-122 full-installer
assets are retained and labeled legacy; choose the build-123 link above.

Open the appropriate package in macOS Installer and follow its native prompts.
After installation, open Account Access and finish local owner setup. Start a
fresh Codex or Claude Code session after agent integration is connected.
Passwords, codes and authenticator keys belong in local setup, never in chat.

## Included third-party source

**No additional charge:** download the [Bitwarden corresponding-source archive](https://github.com/fainir/account-access/releases/download/v0.8.0/account-access-bitwarden-2026.10.0-corresponding-source.tar.gz)
alongside either installer. Its digest matches both included runtime manifests.
Dependency and JIT bytes are unchanged from build 122. The archive includes the
pinned upstream materials, dependencies, derivation/build instructions and notices.
Account Access retains its MIT license; bundled programs retain their licenses.

## What this candidate has passed

The signed, notarized and stapled build-123 packages passed actual fresh/repair
and upgrade/reapply on macOS 14.8.9, 15.8.2 and 26.6.2 arm64, 114 checks total.
The reports verify build 123, live sandboxed browser execution, patched dependency
checks and preservation of private sentinel data, receipts and earlier recovery
histories. Native qualification also preserves all earlier update contracts.
Current-source regression passes 4,656 tests with 113 skips, Ruff, audit and
native UI/gateway/updater checks. Eighteen completed Mac worker fixture reports
pass all 426 checks, including actual prepared-runtime execution.

Build 123 adds a reviewed Betterloop password connector whose only operation
returns authenticated session status. It does not return page text, project
information, API keys or billing data. Its native multipart form passed 11 live
anonymous checks; this is not completed private account acceptance. The owner
Mac also passes installed-runtime and public-example checks after a full OS
restart. Successful private-provider login remains unqualified.

## Current scope and remaining acceptance

Reviewed connectors and explicitly approved operations only. Harel and Phoenix,
arbitrary websites, payments and portable protected-vault backup are outside v1.
Existing mailbox setup is checked; real private website email/TOTP acceptance
and the paused Namecheap challenge remain separate. The withdrawn Read the Docs
handoff does not require signup or credentials from the owner.

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
Asset URLs become public only after the release is published.
