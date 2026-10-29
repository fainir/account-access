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
- `scripts/mac_full_image_installed_probe.py` freezes exact Swift inputs in `EXACT_INPUTS`. If one changes, refresh only that source digest, run `uv run pytest -q tests/test_mac_full_image_installed_probe.py`, then run the native probe with a new absolute output directory. Its successful result verifies source fixtures only, not production installation.
- Focused package checks: `uv run pytest -q tests/test_system_package.py tests/test_system_package_preassembled.py`; lint with `uv run ruff check` on changed Python files. Mac Swift compiler/SDK mismatches on the owner machine are not resolved by syntax parsing; use the disposable Mac CI checks for native type-check and Installer-sandbox evidence.
- Before building an updater, verify the exact installed receipt and require the package predecessor to match it; never advance the candidate chain from an installer that did not complete successfully. (2026-10-29)
- For owner app updates, inspect the actual running GUI bundle ID before quitting: the stale per-user UI uses com.fainir.accountaccess.verification, while the canonical /Applications app uses com.fainir.accountaccess. Verify the UI process exits before starting Installer. (2026-10-30)
