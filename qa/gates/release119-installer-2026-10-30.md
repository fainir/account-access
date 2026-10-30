# Release 119 Installer acceptance

The existing build-119 updater safely refused a replaced support-root binding. Its source correction validates the exact predecessor, signatures, policies, console owner and live service before publishing a recovery binding. This run packages that correction and qualifies the clean-Mac route from the same target image.

- Exact public predecessor archive: 27,485 public manifest nodes; no broker, vault, home, control, run or owner-data branch was copied.
- Reconstructed target image matches the independently qualified build-119 manifest. The derived 184-unit, 216-node direct plan matches the native QA inputs.
- `uv run --no-sync pytest -q tests/test_system_package_preassembled.py tests/test_system_package.py tests/test_direct_runtime_installer_probe.py`: 99 passed, 1 platform skip. The separate updated probe boundary suite passed 8 tests. Ruff, workflow parsing and diff checks passed.
- Current implementation CI: [Mac and Installer sandbox](https://github.com/fainir/account-access/actions/runs/41071862536), [main checks](https://github.com/fainir/account-access/actions/runs/41071862535), [Android](https://github.com/fainir/account-access/actions/runs/41071863029), [cross-user worker](https://github.com/fainir/account-access/actions/runs/41071863034), all passed at e992e37. Later probe-only and package-cohort commits do not change the target application or native runtime source.
- Added `.github/workflows/mac-direct-runtime-recovery-review.yml`: separate empty hosted Macs run the actual signed Installer for the current direct update and fresh install, then repeat it and compare installed app version, complete public manifest, protected receipts and a synthetic private inode. It cannot run on an ordinary owner context.
- Package signing, notarization and actual Installer results are pending. No corrected installer is eligible for owner installation yet. The installed owner app and personal vault have not been changed.
