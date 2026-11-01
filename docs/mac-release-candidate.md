# Account Access 0.8.0 - build 122

Publication-review draft. This is not the public 0.7.4 preview download.
The publisher approved the complete privacy notice and terms on 1 November
2026. Remaining private/physical verification acceptance is recorded in READINESS.md
before publication. macOS 14 qualification is complete.

## Choose your Mac package

- **New clean Mac, Apple silicon:** [full signed installer](https://github.com/fainir/account-access/releases/download/v0.8.0/Account-Access-0.8.0-Mac-arm64.pkg).
- **Existing qualified build 121 protected installation:** [exact build-121-to-122 updater](https://github.com/fainir/account-access/releases/download/v0.8.0/Account-Access-0.8.0-update-from-build121.pkg). It checks the predecessor and preserves the vault and previous recovery histories.
- The full installer also supports qualified identical-image repair. Do not apply
  it over another protected image or use the build-121 updater for a different
  predecessor. An older 0.7.4 preview is not the qualified build-121 predecessor.

Open the appropriate package in macOS Installer and follow its native prompts.
After installation, open Account Access and finish local owner setup. Start a
fresh Codex or Claude Code session after agent integration is connected.
Passwords, codes and authenticator keys belong in local setup, never in chat.

## Included third-party source

**No additional charge:** download the [Bitwarden corresponding-source archive](https://github.com/fainir/account-access/releases/download/v0.8.0/account-access-bitwarden-2026.10.0-corresponding-source.tar.gz)
alongside either installer. Its digest matches both included runtime manifests.
It contains the pinned upstream materials, dependencies, derivation/build
instructions and notices used for this CLI variant. The Account Access
application retains its MIT license; bundled programs retain their own licenses.

## What this candidate has passed

The unchanged signed, notarized and stapled build-122 packages passed actual
fresh/repair and upgrade/reapply on macOS 14.8.9, 15 and 26.6.2. The installed owner Mac
on 27.2 runs the protected browser and recovery worker with zero failures.
The approved public example returns only names/prices through both installed
AI launchers. No full OS reboot or successful private-provider login is claimed.
The minimum macOS 14 Apple silicon configuration passed actual hosted execution
on 1 November, including signed browser startup under the service identity.

## Current scope and remaining acceptance

Reviewed connectors and explicitly approved operations only. Harel and Phoenix,
arbitrary websites, payments and portable protected-vault backup are outside v1.
Existing mailbox setup is checked; real private website email/TOTP acceptance
and the paused Namecheap challenge remain separate owner actions.

The Android 0.8.0 candidate has its first publisher identity in native Mac
Keychain custody and passes actual signed-APK emulator UI acceptance. No phone
is connected. Bluetooth association, carrier SMS delivery and physical phone
performance remain unqualified. The Android APK is not part of this Mac upload
and nothing has been submitted to Play Store.

Publisher-approved [privacy notice](https://github.com/fainir/account-access/blob/7903cafa50d1510dd56011e5450b48df415aca7a/docs/privacy.md)
and [terms](https://github.com/fainir/account-access/blob/7903cafa50d1510dd56011e5450b48df415aca7a/docs/terms.md)
identify Nir Fainshtein, עוסק פטור, and the owner-selected support/privacy contact.
The owner approved both complete documents on 1 November 2026. Their reviewed
substantive text is unchanged and takes effect only with the public release.
This draft adds no subscription, purchase or cloud SMS relay.

Full acceptance evidence: [production ledger](https://github.com/fainir/account-access/blob/codex/production-security-authlib-20261028/READINESS.md).
The asset URLs above become public only after an approved release is published.
