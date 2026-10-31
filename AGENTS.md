# Account Access - agent notes

Production work follows the ship and production-ready skills in ~/.agents/skills/ (shared by Codex and
Claude Code). READINESS.md is the definition of done; PRODUCT.md is the spec; GOAL.md is the goal sentence.

- Run / test / deploy: see PRODUCT.md "Stack and hosting".
- Owner-only items: one exact action at a time (owner-actions skill). Third-party reviews are waiting rows.
- Evidence under qa/. Commit and push after each verified flow. Only commit files you changed.

## Working here

- `uv run python -m macos.system_package` builds a fresh-install package and an identical-image retry. It does not update an existing different image. Keep `fresh_install_only: true` in its report and never ask the owner to run it over an existing install.
- Existing-image upgrades use the separate owner/full-image update path with pinned predecessor and target inputs. Require ordinary-user native fixtures, disposable-Mac Installer acceptance, signature, notarization, Gatekeeper and Installer parser checks before asking the owner to install a candidate.
- An Installer success screen can mean only its Scripts completed; verify both the installed owner-app build and protected-service version before accepting an update. Build 114 completed Installer while leaving both runtime components unchanged (`qa/owner-upgrade114-installed-2026-10-29.log`).
- `scripts/mac_full_image_installed_probe.py` freezes exact Swift inputs in `EXACT_INPUTS`. If one changes, refresh that source digest and the combined `COMPOSED_SHA256` when a composition fragment changes, run `uv run pytest -q tests/test_mac_full_image_installed_probe.py`, then run the native probe with a new absolute output directory. Its successful result verifies source fixtures only, not production installation.
- Focused package checks: `uv run pytest -q tests/test_system_package.py tests/test_system_package_preassembled.py`; lint with `uv run ruff check` on changed Python files. Mac Swift compiler/SDK mismatches on the owner machine are not resolved by syntax parsing; use the disposable Mac CI checks for native type-check and Installer-sandbox evidence.
- Before building an updater, verify the exact installed receipt and require the package predecessor to match it; never advance the candidate chain from an installer that did not complete successfully. (2026-10-29)
- For owner app updates, inspect the actual running GUI bundle ID before quitting: the stale per-user UI uses com.fainir.accountaccess.verification, while the canonical /Applications app uses com.fainir.accountaccess. Verify the UI process exits before starting Installer. (2026-10-30)
- Before requesting an owner install, verify the exact persistent package path exists and recheck its signed, stapled and Gatekeeper state; temporary build candidates can disappear, making an old Downloads claim stale. (2026-10-30)
- Before handing off an owner installation, reveal the verified package in Finder at its persistent location so it is selected and easy to find. (2026-10-30)
- For root-only native verifier probes, open manifest fixtures inside the privileged child; sudo closes inherited FDs, and a user-owned manifest fails the owner check before image verification. (2026-10-30)
- The full combined Swift updater fixture can exceed local Mac 27.2 compile timeouts; the exact-source disposable-Mac CI type-check and Installer matrix are required for native qualification. (2026-10-30)
- The disposable macOS 15 worker may attach FinderInfo to its preinstalled Google Chrome bundle. Remove only `com.apple.FinderInfo` on that ephemeral runner before the signed-Chrome probe; retain strict `codesign` verification so resource forks and signature changes still fail. (2026-10-30)
- Run the pinned dependency audit before release assembly. Build 120 replaces joserfc 1.7.5 after CVE-2026-119284; the installed-interpreter pre-allocation regression must pass in both Installer modes. (2026-10-30)
- The build-110 support root can be root:admin while its runtime is root:wheel. Direct-update trees use the published predecessor group throughout observation, rollback and snapshots; the original full-image units retain their legacy rule. (2026-10-30)
- The direct plan hash is shared through FullImageFileOperation.directRuntimePlanSHA256. Qualify every direct file and the mixed journal limit against it; changing only DirectRuntimeUpgradeSource leaves a safe refusal. (2026-10-30)
- Installer QA must assert the top-level launchd state is running with a stable positive PID; launchctl print exit zero proves registration only. Build 120 owner startup required safe restoration of missing run/control directories, not another approval or installer build. (2026-10-31)
- If native AI upgrade stops at install with client_upgrade_needs_repair, inspect only the public skill backup slot. scripts/retain_duplicate_preview_skills.py checks and optionally retains exact recognized duplicates outside discovery; unknown content stays untouched. Retry only through the app, never by reading a client token or invoking owner enrollment commands. (2026-10-31)
