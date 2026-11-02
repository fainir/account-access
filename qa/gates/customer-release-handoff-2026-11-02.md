# Customer release handoff - 2 November 2026

Build 125's [source/native/signed-package acceptance](../release125-2026-11-02/acceptance.md)
passes 4,712 tests/114 platform skips, Ruff/audit/native checks, all eight native
updater reports and 114 actual signed Installer checks on macOS 14.8.9,
15.8.2 and 26.6.2 arm64. The final real delayed-worker/key-custody run remains
in progress. Owner-Mac build-125 recovery and private automated MFA are pending.
Installed build 124 followed a full OS restart but its worker is unavailable;
build 123's real private Betterloop acceptance remains historical evidence.

The existing 0.8.0 release remains **unpublished** with nine complete assets.
Current/legacy labels and the exact [125 notes](../../docs/mac-release-candidate.md)
were read back. All nine asset IDs, bytes, digests and upload states match the
pre-edit inventory; no asset was replaced or deleted. The tested source target
is f352d391e0ffb210699685e7367da5765745f328, isDraft=true, publishedAt=null.

| Download | Bytes | Purpose |
|---|---:|---|
| Account-Access-0.8.0-build125-Mac-arm64.pkg | 289,324,400 | Current build 125: clean Mac or identical-image repair |
| Account-Access-0.8.0-update-from-build124.pkg | 5,499,724 | Current: exact protected 124-to-125 update |
| Account-Access-0.8.0-build124-Mac-arm64.pkg | 289,321,568 | Legacy build 124 full installer; choose build 125 |
| Account-Access-0.8.0-update-from-build123.pkg | 6,074,988 | Legacy 123-to-124 bridge; follow with 124-to-125 |
| Account-Access-0.8.0-build123-Mac-arm64.pkg | 289,327,752 | Legacy build 123 full installer; choose build 125 |
| Account-Access-0.8.0-update-from-build122.pkg | 6,072,318 | Legacy 122-to-123 bridge; then 123-to-124-to-125 |
| Account-Access-0.8.0-update-from-build121.pkg | 5,813,686 | Legacy 121-to-122 bridge; then 122-to-123-to-124-to-125 |
| Account-Access-0.8.0-Mac-arm64.pkg | 289,330,711 | Legacy build 122 full installer; choose build 125 |
| account-access-bitwarden-2026.10.0-corresponding-source.tar.gz | 219,117,936 | Matching Bitwarden corresponding source; no charge |

Current draft: [https://github.com/fainir/account-access/releases/tag/untagged-dc4097c7d3e8960615db](https://github.com/fainir/account-access/releases/tag/untagged-dc4097c7d3e8960615db).

Current package digests are bound in the [actual Installer contract](../../artifacts/runtime125-installer-inputs.json).
Dependencies, JIT and Bitwarden bytes are unchanged from 124. The matching source
archive retains its original digest and is offered without charge. Previously
approved privacy/terms bodies and publisher/contact details are unchanged.

Before updating, use **Account Access > Quit Account Access**, then open the
exact 124-to-125 updater. The current owner GUI is still running; native UI
control is unavailable after reboot, so no new Installer or authorization dialog
is claimed open yet. [Pre-update public-byte and metadata checks](../release125-2026-11-02/owner-installed.log)
match build 124 and capture nine existing directory/alias identities. No private
file/configuration, key or credential was read.

The hourly follow-up stays quiet while an unchanged owner action is pending,
checks installed recovery/available launcher acceptance and retires after those
checks finish. No public-download success, physical-phone acceptance or automated
private Lemon Squeezy MFA is claimed.
