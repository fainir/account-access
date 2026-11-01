# Customer release handoff - 1 November 2026

The current candidate is build 123. Its [signed-package and source acceptance](../release123-2026-11-01/acceptance.md)
passes on macOS 14.8.9, 15.8.2 and 26.6.2 arm64. Current-source CI passes 4,656
tests, Ruff/audit/native checks, and all 18 Mac worker reports pass 426 checks.
The owner Mac now has build 123 installed. Protected-service health, qualified
runtime/catalog bytes and both approved public-example launcher reads pass
after a confirmed full OS restart, with all seven original directory/alias
inode identities, permissions and ownership preserved.

## Actual customer draft read-back

The existing 0.8.0 draft now has **five complete assets**, with qualified current
files and explicit legacy labels. No earlier asset was deleted or overwritten.
Exact server bytes/digests match the qualified inputs, and server notes match
[the prepared notes](../../docs/mac-release-candidate.md). The release remains
`isDraft: true`, `publishedAt: null`, targeting qualified source commit
`e3aaa9e6272bb810cf5519536ed4a652b13fa2da`.

| Download | Bytes | Purpose |
|---|---:|---|
| Account-Access-0.8.0-build123-Mac-arm64.pkg | 289,327,752 | Current clean install or qualified identical-image repair |
| Account-Access-0.8.0-update-from-build122.pkg | 6,072,318 | Exact qualified legacy protected 122-to-123 update |
| Account-Access-0.8.0-update-from-build121.pkg | 5,813,686 | Legacy 121-to-122 bridge, followed by the current updater |
| Account-Access-0.8.0-Mac-arm64.pkg | 289,330,711 | Earlier build-122 full installer, explicitly labeled legacy |
| account-access-bitwarden-2026.10.0-corresponding-source.tar.gz | 219,117,936 | Required unchanged matching third-party source, no additional charge |

Current draft: https://github.com/fainir/account-access/releases/tag/untagged-728152bbd8832eb5491b

The current image changes only the runtime catalog module and related package/
owner metadata. Dependency/JIT and Bitwarden program/source bytes are unchanged.
Existing third-party source verification remains valid. No independent legal
certification or successful public download is claimed.

## Remaining owner acceptance

The complete privacy notice and terms were approved on 1 November; do not ask
again for the unchanged bodies. Store listing copy remains proposed. Native
installation is complete; personal connection acceptance remains. No new
credential handoff is staged while native UI control is unavailable.
No unfamiliar-service signup, password/code in chat, Play upload or phone action.

The earlier macOS 14 follow-up was deleted when that check passed. The new hourly
release-acceptance follow-up was deleted through the app tool after the installed checks completed.
No personal-enrollment polling remains.
Final installers, matching source and linked QA evidence are retained; temporary
package-assembly copies were removed automatically by their builders.
