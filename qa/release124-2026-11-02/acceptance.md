# Build 124 qualification - 2 November 2026

The owner completed manual Lemon Squeezy MFA in personal Chrome. That established
the exact password, authenticator and dashboard contracts, not automated acceptance.
Build 124 adds a separate status-only connector, a distinct unenrolled TOTP source
and a script-free server-page readiness predicate. No installed account, password,
seed or grant was used for image/package assembly.

The [matching owner/broker compile](https://github.com/fainir/account-access/actions/runs/41435565761)
uses source 276207e. Build metadata and both embedded/source wheel bytes agree.
The [qualified image](image-qualification.json) verifies all 49 native publisher
signatures, unchanged dependency/JIT bytes and actual sandboxed browser execution.
59 native owner-screen PASS cases and two mailbox-retry CHECK lines are true.
The 110 focused provider/marker/MFA tests and 164 packaging/refusal tests pass.

The [native updater qualification](https://github.com/fainir/account-access/actions/runs/41437170446)
uses source 49a20fa. All seven actual result files were downloaded and read:
[shared adapter](full-image.json), [72 runtime checks](runtime.json),
[123-to-124](direct.json), and earlier [110-to-120](direct-compat.json),
[120-to-121](jit-compat.json), [121-to-122](connection-compat.json),
[122-to-123](betterloop-compat.json). The new plan has 15 units, 18 changed nodes,
19 journal operations, two projections, eight refusal checks and nine retained
preparation checks. No installed reads or service actions occurred in these probes.

The full signed installer is Apple Accepted, stapled and Gatekeeper accepted.
Actual stapler validate succeeds; pkgutil reports trusted Apple notarization and
the existing Developer ID Installer. Its final hash starts 33ecb2e9. The exact
updater is currently being notarized, followed by actual Installer acceptance.
Neither package has been installed on the owner Mac.

## Historical regression correction

[Complete source regression](https://github.com/fainir/account-access/actions/runs/41435565661)
ran 4,695 passing tests, 113 skips and one stale historical assertion. It compared
the old signed configuration-model upgrade with the moving current models.py.
The historical Python/native pins stay unchanged. The corrected test exercises
refusal of the actual newer model through that old transition. All 160 focused
historical/image/update tests pass with lint. This changes only a test; program
and package bytes remain unchanged. Corrected complete CI is required before
owner installation. Private automated TOTP acceptance remains separate.
