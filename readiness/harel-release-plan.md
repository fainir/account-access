# D23 - Harel email build 128 release preparation

Prepared 2026-11-04 from HEAD `3c5520a4030f0cfb846e080053b6de2677a35807` plus the coordinator's unfinished D22 tree. This lane inspected public source and release evidence only. No build, signing, installation, dispatch, upload, publication, private account read or owner request was performed. The coordinator owns implementation, ledger, processes and git.

## Actual qualification update - 4 November, 21:20 local

The original planning snapshot below is historical. Program P is now `13fc473136e6f7d0f932bc3e171d248cebdf8a7d`; image builder B is `3891173bd79ca0a894f111e34bb23dfd33cf774f`. The actual signed128 image qualifies from127, all196 Harel tests pass in its packaged Python3.12.16, and the real15-unit/24-change plan is registered. Shared/direct native qualification, eight retained120-127 fixtures and254 integrated Python profile tests pass. All72 runtime native checks and the ordinary-user refusal also pass. Clean helper source Q, signed exact update assembly and corrected full local CI remain. No128 installer or private Harel acceptance is claimed. See [current ledger](../READINESS.md) and [image qualification](../qa/ordered-verification-2026-11-04/image128-qualification.json).

## Current policy

Nir superseded hosted CI on 4 November: Actions budget is $0 and no GitHub Actions may run. The hosted-workflow sequence below is retained as the prior release reference only. New 128 owner/wheel/native builds and native probes must run locally with exact source binding, ordinary-user synthetic roots and the existing builder local-compiler path (omit `--compiled-run`). Never run disposable-root Installer/cross-user probes on the owner Mac. Current source qualification uses `bash ~/.agents/skills/ship/scripts/ci-local.sh`; new final-byte multi-OS Installer acceptance needs an available isolated Mac environment before claiming those results.

## Immediate delivery scope

Prepare the exact 127-to-128 **local update candidate** first so the unknown private Harel contract can be accepted before another full customer release is assembled. Source/ordinary native qualification, signing/notarization and installed checks remain required. Preserve existing full127/download assets. New full128 and final multi-OS publication acceptance follow real provider qualification on an available isolated surface; do not infer them from local fixtures or use the owner Mac as a disposable test host. The Mac currently has roughly 1-2GiB free, so avoid parallel native compilers and redundant full-image/package copies.

## Approach and fixed predecessor

Follow the already qualified 127 sequence: finish and freeze program source, compile matching owner/wheel/helpers, prepare one image from the exact public predecessor, qualify a new exact delta, then qualify the final signed packages in disposable Installer journeys. Retain every older tuple, namespace and asset. This follows the repository's demonstrated pattern rather than introducing a new release path. Sources: [127 acceptance](../qa/release127-2026-11-04/acceptance.md), [image publisher](../scripts/build_owner_routes_update_image.py), [updater publisher](../scripts/build_direct_runtime_upgrade_candidate.py), [Installer probe](../scripts/mac_direct_runtime_installer_probe.py).

- Installed predecessor is **127**; its complete public manifest is `82b953e0698ee73468c2cff8aa546c5b94368fbf1fe24036e2623d039fee2f06`. Never use the completed 126-to-127 package for this delivery.
- Target 128's program/source, manifest, plan and new identity are **not qualified yet**. Do not invent their pins or treat current source CI as signed delivery.
- Email is first. SMS and existing Google Authenticator acceptance follow later; preserve all four current grants, Lemon's durable paused task, Namecheap's paused challenge and prior owner actions.

## Qualified inputs that can be retained

Paths below exist under `dist/root-recovery-release/login127/` unless stated otherwise.

| Input | Reuse and current read-back |
|---|---|
| `PublicImage/` and `TargetManifest127.json` | Use an invocation-owned 0700 **copy** for preparing 128; preserve the qualified original. Manifest hash matches 127's native `after.json`; public owner Info.plist reads build 127. Recheck complete inventory before copying/assembly. Do not use `PublicImage-unqualified/`. |
| `PublicImage/Library/Application Support/Account Access/package-identity.json` or `native-inputs/new-identity.json` | Exact 128 predecessor identity; both files match. Public identity digest is `d5d21bd2f1aaa7e7ed9d83d0a937036998b7f3d285bc2386cddba9fd19818268`. `BaseIdentity126.json` is the wrong predecessor. |
| Signed dependency Python/browser/wheel bytes in `PublicImage/` | Preserve the already fixed JIT/Node/Chromium and dependency preparation. Existing publisher enforces unchanged dependency trees, wheel hashes, signatures and an actual bounded offline sandboxed-browser probe. |
| `release127-native-inputs.tar.gz` and `native-inputs/` | Retain as the **126-to-127 compatibility fixture**, not the 128 plan. Its five files are `plan.json`, `before.json`, `after.json`, `old-identity.json`, `new-identity.json`; pin is [release127-native-inputs.json](../artifacts/release127-native-inputs.json). Retain matching 120-126 archives/contracts too. |
| `baseline.tar.gz` / `qa-assets/baseline.tar.gz` | **Cannot** serve 127-to-128: the archive's `BaseManifest.json` hash is the 126 manifest `0e1c1f3a2b05f3eb5f9acd32b7a55bea28d775411519d41be0401b43d852d20f`. A new 128 fixture baseline must contain qualified 127's `PublicImage` and `BaseManifest.json` with exact manifest membership. |
| `dist/customer-release-0.8.0/Account-Access-0.8.0-build127-Mac-arm64.pkg` | Retain unchanged. Current digest/size match [runtime127-installer-inputs.json](../artifacts/runtime127-installer-inputs.json): 289,354,598 bytes. |
| `dist/customer-release-0.8.0/Account-Access-0.8.0-update-from-build126.pkg` | Retain unchanged as the historical updater. Current digest/size match the same contract: 6,104,806 bytes. It is already installed. |
| Existing corresponding Bitwarden source and all 13 customer draft assets | Preserve IDs, bytes, labels and unpublished state. A Harel-only project-wheel change does not justify rebuilding unchanged dependency source. This lane did not access or change the remote draft. |

The read-back above verified selected public manifest/identity/build and package digests; it did not rescan the entire image or requalify installation. Installed acceptance remains the coordinator's existing [127 evidence](../qa/release127-2026-11-04/acceptance.md).

## Exact source locations to extend

Add 128 alongside existing releases; keep 120-127 values byte-for-byte. Proposed new 128 filenames and namespace below do not exist yet.

| Source | Required addition |
|---|---|
| `scripts/build_owner_routes_update_image.py` | `RELEASES['128'] = (127, 128, <127 manifest>)`; this also admits `--release 128` in the CLI. This is the current successor image publisher; `build_direct_runtime_target_image.py` retains the older fixed 118/119 route and only supplies its wheel helper. |
| `.github/workflows/mac-runtime-owner-release.yml` | Add 128 choice/default as intended. Build from frozen D22 program source with `ACCOUNT_ACCESS_MAC_BUILD=128`, `ACCOUNT_ACCESS_SYSTEM_INSTALL=1`; expect artifact `runtime128-owner-image`, including owner ZIP, wheel, owner-checks log and native broker/bootstrap/installerverify. |
| `macos/direct_runtime_upgrade_plan.py` | Add `RELEASES['128'] = (<127 manifest>, <128 manifest>, <frozen program commit>)`. Use `derive(..., release='128')`; collect `target_source_files` from **all** target image project `.py` entries, including new `harel_setup.py`, rather than a hand-picked list. |
| `scripts/build_direct_runtime_upgrade_candidate.py` | Add complete `RELEASE128` tuple: plan/before/after/program source/image builder/image base/public predecessor identity/component ID/package stem; register it in `RELEASES`, the `verify_target_qualification` successor branch and `reviewed_ci_helper` artifact allowlist (`release-compiled-updater-128`). Set `before` and `image_base` to qualified 127. |
| `macos/FullImageGlobalJournal.swift`, `DirectRuntimeUpgradeSource.swift`, `FullImageTransitionStorage.swift` | Add a distinct compiled namespace (suggested `.harelEmail` / `Account Access Harel Email`), exact complete 128 tuple, and the new plan hash in the direct-file/mixed-journal admission list. Replacing the original `directRuntimePlanSHA256` would break recovery. Do not choose a namespace from package JSON. |
| `scripts/mac_full_image_installed_probe.py` | Refresh `EXACT_INPUTS` for each actually changed pinned Swift source. Refresh `COMPOSED_SHA256` **only if** a composed fragment/base changes. Require the focused pin test before a new native run. |
| `macos/Tests/DirectRuntimeUpgradeSourceChecks.swift` | Add 128 classification, actual derived tree/fixed/direct counts and namespace expectation. Retain old tuples, cross-tuple refusals and legacy projections. New counts must come from 128's plan, not copied 127 numbers. |
| `macos/system_package.py` | Add `PREASSEMBLED_BUILD128_MANIFEST_SHA256` and admit that exact digest in `preassembled_manifest`; retain every existing allowlist entry and the fresh-only contract. |
| `.github/workflows/mac-release-native-review.yml` | Add new proposed `artifacts/release128-native-inputs.json` and five-file archive; keep all eight 120-127 input/probe steps. Make 127 a compatibility result, run 128 as current `direct`, compile `RELEASE128`, and emit `release-compiled-updater-128`. Retain shared/runtime results and add an eighth historical result, for eleven expected native result reports. |
| `scripts/mac_direct_runtime_installer_probe.py` | Add 128 `Release` with exact 127 predecessor, 128 target/plan and new namespace; include 128 in **all three** successor sets (recovery/history seeding, upgrade browser/history checks, fresh browser check). Extend history for 128 to **120-127**. Keep the original root recovery plan and generic cleanup unchanged. |
| `.github/workflows/mac-direct-runtime-recovery-review.yml` | Add 128 choice/default, paths and **both** contract-name maps for proposed `artifacts/runtime128-installer-inputs.json`; retain 120-127. New contract pins final `baseline.tar.gz`, `candidate.pkg`, `fresh.pkg` bytes/sizes and 127/128 manifests. |
| `tests/test_runtime_release_profiles.py`, `test_direct_runtime_upgrade_plan.py`, `test_direct_runtime_installer_probe.py`, `test_system_package_preassembled.py`, `test_mac_full_image_installed_probe.py` | Extend applicable release parameter lists and exact-profile/allowlist/tuple/history coverage. Preserve refusal checks and real readiness requirement. |

## Ordered execution for the coordinator

1. Finish D21/D22, including controlled native/gateway UI, checked-mailbox/profile/UID/arrival/attempt binding, local redacted review, cancellation/expiry and no extra send. Preserve grants. Freeze a clean **program commit P** after relevant workflow/profile support is present; no distribution builder accepts the current dirty tree. Inspect the existing source jobs first, then run changed-source checks once.
2. Compile the actual 128 owner, project wheel and native helpers from **P** using the existing successor-owner workflow. The old 127 owner/wheel/helpers do not contain Harel setup. Retain returned metadata and inspect the artifact contents/build/wheel binding.
3. Prepare one new private copy of qualified 127 with the owner-routes publisher and `--release 128 --source P --owner-source P --native-source P`, plus the new matching owner/native/wheel inputs and new manifest/report destinations. This operation signs and belongs only to the authorized coordinator release step. Its report must say target 128, source image 127, unchanged dependencies, real browser READY, and no installed/private-data access. Record the actual image-builder commit **B**. The publisher requires `account_access` and `macos` to match P and a completely clean tree: finish image preparation **before** adding manifest-dependent updater Swift pins. If later changes alter the program, repeat qualification for that changed source rather than relabeling P.
4. With actual manifest/identity bytes available, derive and freeze the 127-to-128 plan; add exact Python/native tuples, namespace, manifest allowlist and source pins. Commit updater source **Q**. Keep P (program), B (image publisher), Q (helper compiler) and the later final Installer-contract commit distinct in evidence. No placeholder hash can enter a published profile.
5. Qualify shared adapter/runtime plus new plan and all retained 120-127 plans at Q; obtain `release-native-results` and `release-compiled-updater-128` from the same successful exact-source run. The updater builder's `--source Q --compiled-run <run>` rejects a successful artifact from any other source/workflow.
6. Assemble the new exact updater with `uv run python -m scripts.build_direct_runtime_upgrade_candidate --release 128` and its required target image/manifest/qualification, base manifest/identity, plan and three QA reports. Independently prepare the full installer with `uv run python -m macos.system_package --preassembled-image <128 image> --preassembled-manifest <128 manifest> --preassembled-sha256 <128 hash> --architecture arm64 --output <new output>` and existing publisher parameters. Retain `fresh_install_only: true`; it cannot update 127. Existing `macos.notarize` prepare/submit/check/finalize and updater builder enforce notarization, ticket, signature and Gatekeeper; do not rebuild unchanged 127.
7. Create the exact public-127 baseline fixture and final-byte 128 Installer contract, then use the existing fresh/repair and upgrade/reapply workflow on **macOS 14, 15 and 26**. Each actual report must be PASSED, show build 128/exact public bytes, stable running service, service-identity signed sandboxed browser, patched dependency guard, original receipts/root binding, synthetic vault inode, **all eight 120-127 histories**, prior unpublished preparation and successful cleanup. Historical 127's six reports remain historical evidence, not 128 acceptance.
8. Only after qualification, coordinator rechecks installed predecessor/public metadata and normal GUI exit, stages the persistent exact 127-to-128 package, handles authorized local installation, and reads back scoped completed postinstall, target owner/wheel/native bytes, service/browser health, preserved metadata/grants and both installed launchers' already approved checks. Stage Harel local setup only after matching native delivery exists. A fresh email attempt and actual private status acceptance remain distinct from fixture/package success. Do not request saved mailbox credentials again or infer SMS/authenticator success.

Focused pre-assembly checks, using existing tests:

```sh
uv run pytest -q tests/test_harel_protocol.py tests/test_harel_setup.py tests/test_harel_email_review.py tests/test_harel_owner_ui.py
uv run pytest -q tests/test_runtime_release_profiles.py tests/test_direct_runtime_upgrade_plan.py tests/test_direct_runtime_installer_probe.py tests/test_system_package.py tests/test_system_package_preassembled.py tests/test_mac_full_image_installed_probe.py
uv run pip-audit --local
```

Use `.github/workflows/check.yml`'s full lint/test/native checks for P/Q, not only this focused subset. Native probes remain `uv run python scripts/mac_full_image_installed_probe.py --output <new absolute directory>`, `scripts/mac_runtime_upgrade_probe.py`, and `scripts/mac_direct_runtime_upgrade_probe.py --inputs <five public files> --output <new absolute directory>`. Real Installer probe is restricted to its hosted disposable Mac guard and must never run on the owner Mac. Local SDK/compiler mismatch is not qualified by syntax parsing.

The release workflows' push filters currently name `codex/production-security-authlib-20261028`; changing their YAML on that branch can already start the new owner/native jobs. Inspect the automatic runs before any later dispatch, and bind every downloaded artifact to the expected source commit.

## Existing jobs and what their outputs can prove

Statuses here are the ledger's recorded snapshot, **not a live CI read-back**. Reuse those runs; this lane did not poll or dispatch.

| Existing source/run | Reuse | New work still required |
|---|---|---|
| `3c5520a`: [checks 41858715306](https://github.com/fainir/account-access/actions/runs/41858715306), [Mac worker 41858715218](https://github.com/fainir/account-access/actions/runs/41858715218) | Inspect their actual finished source/native and `mac-worker-boundary-acceptance` reports when available; avoid duplicate unchanged runs. | They precede uncommitted D22. Changed owner/gateway/Python setup needs checks and worker reports at P; these cannot qualify 128 bytes. |
| `3c5520a`: [Linux worker 41858715378](https://github.com/fainir/account-access/actions/runs/41858715378), [component fixture 41858702396](https://github.com/fainir/account-access/actions/runs/41858702396) recorded success; [Android 41858715246](https://github.com/fainir/account-access/actions/runs/41858715246) recorded running | Retain unchanged component/Android evidence and inspect pending completion once. | No Android release/build is needed for email. Changed shared/native updater source still needs its applicable current checks. |
| 127 owner compilation 41814053787 / `runtime127-owner-image` | Public reference and qualified predecessor inputs. | New `runtime128-owner-image` from P is mandatory. |
| 127 native qualification 41825605936 / ten retained reports and helper | Reuse immutable 120-127 archives and historical results; keep 127 helper for its own package. | Eleven current reports and a new exact-Q `release-compiled-updater-128`; old helper cannot carry the new compiled tuple. |
| 127 actual Installer runs 41828689075, 41828681946, 41828695162 | Preserve demonstrated OS coverage and fixture contract. | Final 128 package digests and 127 baseline require new six journeys; no substitute with 127 results. |

## Dependencies and handoff

- D22 source/UI is still in progress. Build 128, manifest/plan/identity pins and its native/Installer archives do not exist yet; these are buildable dependencies, not owner blockers.
- The current successor-owner, native release and Installer workflows stop at 127. New source/configuration is required before they can produce 128 artifacts. New archive hosting/upload and CI dispatch are later coordinator actions; none is authorized or performed by this memo lane.
- Existing publisher identity/tooling can be reused; no new account, identity, spending, public release or upload is needed **for this preparation**. Signed delivery later must remain within the coordinator's standing authorization.
- Keep the full post-127 kernel reboot and Google Authenticator owner actions deferred as recorded. Do not silently treat either as verified or use them to stall buildable Harel work.

P2 handoff: preparation complete; only this memo was written. P1/D22 remains with the coordinator; D23 can start its source/profile work after the candidate is frozen. No owner action is requested.
