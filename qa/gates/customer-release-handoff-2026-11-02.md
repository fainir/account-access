# Customer release handoff - 2 November 2026

Build 124's [source/native/signed-package acceptance](../release124-2026-11-02/acceptance.md)
passes: 4,704 tests/113 skips, Ruff/audit/native checks, all 18 Mac worker reports
with 426 true checks, and 114 actual signed Installer checks across macOS
14.8.9, 15.8.2 and 26.6.2 arm64. Owner-Mac installation and private automated
MFA acceptance remain pending. Installed build 123 retains the verified real
Betterloop password/session acceptance; this does not establish Lemon MFA.

The existing 0.8.0 customer release remains **unpublished** with seven complete
assets. Current/legacy labels and the exact [notes](../../docs/mac-release-candidate.md)
were read back. All asset IDs, bytes and digests remained unchanged by the notes/
label update; none was deleted or overwritten. Target is the tested source
d833d43ee2e5d75a453362488d7ed1e53ee6bbce, isDraft=true, publishedAt=null.

| Download | Bytes | Purpose |
|---|---:|---|
| Account-Access-0.8.0-build124-Mac-arm64.pkg | 289,321,568 | Current clean installation / identical-image repair |
| Account-Access-0.8.0-update-from-build123.pkg | 6,074,988 | Exact qualified 123-to-124 update |
| Account-Access-0.8.0-build123-Mac-arm64.pkg | 289,327,752 | Retained legacy full installer |
| Account-Access-0.8.0-update-from-build122.pkg | 6,072,318 | Legacy 122-to-123 bridge, then current updater |
| Account-Access-0.8.0-update-from-build121.pkg | 5,813,686 | Legacy 121-to-122 bridge, then 122-to-123-to-124 |
| Account-Access-0.8.0-Mac-arm64.pkg | 289,330,711 | Retained legacy build-122 full installer |
| account-access-bitwarden-2026.10.0-corresponding-source.tar.gz | 219,117,936 | Required unchanged matching source, no charge |

Current draft: https://github.com/fainir/account-access/releases/tag/untagged-2da58b8621908bd00cb4

Both current package digests are bound in the [actual Installer contract](../../artifacts/runtime124-installer-inputs.json).
Dependencies, JIT and Bitwarden bytes are unchanged. Previously approved privacy/
terms text and publisher/contact details are unchanged; no repeated legal approval
is needed. No public-download success, independent legal certification, Play
upload, physical-phone acceptance or automated private Lemon MFA is claimed.
The hourly qualification follow-up checks only the active installation handoff,
stays quiet while unchanged, and retires after installation/available checks.

Owner update: build 124 is installed after a full OS restart; public bytes and
eight identities match. Post-reboot worker startup fails and D18 is buildable.
The exact current draft notes now include that hold and the Quit Account Access
preflight; read-back confirms the body, seven assets and unpublished state.
No new installation or private MFA success follows from those metadata edits.
