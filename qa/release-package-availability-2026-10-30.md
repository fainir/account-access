# Build 119 release-package availability - 2026-10-30

- Expected owner path `/Users/nirfeinstein/Downloads/Account-Access-Direct-Upgrade-119-signed.pkg` does not exist. A filename search of Downloads also returned no build-119 package.
- The recorded temporary build path `/private/tmp/account-access-direct119-candidate/Account-Access-Direct-Upgrade-119-signed.pkg` and target-image path `/private/tmp/account-access-direct119-target` do not exist.
- The only matching direct-upgrade package found in Downloads and `/private/tmp` is the older build-117 package. It is not suitable for this update and must not be installed.
- The connected GitHub releases endpoint returned 44 releases; none contains a build-119 direct-upgrade installer. Artifacts for the full CI and Mac acceptance runs (40981448282, 40981440339 and duplicate 40981448295) contain native test evidence, not the signed installer.
- The prior build-119 qualification remains historical evidence that its package passed Developer ID signing, notarization, stapling, Gatekeeper and independent expansion. It does not establish that the binary is currently available.
- Result: no owner installation action is possible. The package or its exact build inputs must be recovered before reissuing an install request. The direct updater builder is being extended to publish the verified package atomically to a durable path and recheck trust there.

## Durable publisher verification

- Added `--publish-to` to `scripts/build_direct_runtime_upgrade_candidate.py`. It copies the final qualified package through a same-directory temporary file, refuses to overwrite an existing destination, verifies the copied SHA-256, then repeats package-signature, stapler and Gatekeeper checks at the published path.
- `uv run --no-sync pytest -q tests/test_direct_runtime_upgrade_plan.py` -> 16 passed, including durable copy, overwrite refusal, bad-digest cleanup and symlink-parent refusal.
- Ruff and Python compilation passed for the changed builder and test module.
- The complete signed-package publish path could not be run because the build-119 package and pinned build-118 target image are absent. No install request should be made until the package has been restored or rebuilt and this end-to-end check passes.
