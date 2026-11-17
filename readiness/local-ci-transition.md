# Local CI transition - 4 November 2026

The current policy is **$0 GitHub Actions: no dispatches and no automatic runs**. All 30 workflow files now contain only historical `workflow_dispatch` definitions. Existing jobs, asset contracts, action pins and dispatch inputs are preserved, including the coordinator's uncommitted owner build-128 choices/defaults. Push, pull-request and other automatic triggers are absent. No Actions run was dispatched by this lane.

The coordinator additionally disabled repository Actions and independently read back `enabled=false` on 4 November. This lane did not repeat that API mutation; the retained YAML is historical reference under the current disabled repository setting.

## Local runner

Run through the coordinator's existing compiler/SDK wrapper:

```sh
bash scripts/ci-local.sh --check
bash scripts/ci-local.sh
```

`--check` validates inputs and every workflow's trigger policy without syncing, testing or compiling. A full run uses the existing installed `uv`, including `/opt/homebrew/bin` when it is absent from the incoming PATH. It runs locked dependency sync, dependency audit, runtime requirements-pin comparison, repository lint, unchanged full pytest, one Python distribution build, production owner/gateway type-checks for arm64 and x86_64, compiled synthetic UI/XPC gateway/desktop/browser/mailbox/launch checks and ordinary-user shared/runtime/owner-upgrade source probes.

Dependency resolution and Python builds use `UV_OFFLINE=1`; no dependency or browser artifact download is attempted. The audit retains its normal advisory lookup. No browser/phone installation, hosted-runner impersonation, publisher credentials or genuine OS-approval request is added. Existing temporary ad-hoc signing fixtures remain part of full pytest and the synthetic gateway; they do not qualify publisher identity.

The runner uses one short invocation-owned `/tmp/aa-ci.XXXXXX` scratch root, avoiding Darwin socket-length limits. It removes pytest scratch immediately after that stage and each ordinary probe's compiled/source tree after retaining its concise result/diagnostics. The exit trap removes the remaining scratch. Reports and the single reusable Python build default to ignored `dist/local-ci-<UTC timestamp>`; this leaves source cleanliness intact. A caller can supply a new quoted `--output` directory. Missing/failed stages return a nonzero result; unsupported external journeys are explicitly **UNRUN**.

The launch check uses the existing compile-time fixture initializer, blocked managed-agent helpers, a temporary data/runtime root and a refusing profile loader. It deliberately avoids the old `ACCOUNT_ACCESS_LAUNCH_CHECKS` production initializer, which could discover installed build 127. `mac_owner_gateway_smoke.py` gained optional `--workdir` and `--diagnostics` parameters so its existing synthetic gateway runs inside this scratch root and retains bounded failure diagnostics instead of writing the historical artifacts/video path. Its Harel check set and successful report contract are preserved.

## Concrete build-128 compiler qualification without Actions

1. Freeze clean program source P and run local CI with the existing compatible Swift compiler/SDK. Retain the actual reports; syntax parsing or a previous source's result cannot replace compilation. Build matching owner/wheel/broker inputs locally through existing `macos/build.sh` and `macos/build-broker.sh` in new output directories when the coordinator reaches assembly. Publisher signing remains its separate authorized release step.
2. Prepare the exact 127-to-128 public image and plan, then freeze helper source Q with the actual 128 tuple/namespace/pins. Reuse retained public 120-127 five-file fixtures as compatibility inputs and run the existing ordinary-user `mac_full_image_installed_probe.py`, `mac_runtime_upgrade_probe.py` and `mac_direct_runtime_upgrade_probe.py` against Q and each exact plan in fresh disposable output directories. Keep current JSON reports; never run privileged Installer probes on this Mac or invent hosted environment variables.
3. The existing `build_direct_runtime_upgrade_candidate.py` already has a **local compiler path**: omit `--compiled-run`. It composes the reviewed sources and exact plan, invokes local `swiftc`, verifies ordinary-user refusal, then performs the separately authorized signing/packaging steps. `--compiled-run` is exclusively a historical GitHub artifact path and must not be supplied. This lane inspected that path without changing the builder or invoking it.
4. Real final-byte Installer fresh/repair/update/reapply, dedicated-service execution and macOS 14/15/26 acceptance still need a safe already-owned disposable Mac/VM surface. Physical phone, private MFA, Linux sandbox and publisher-signed XPC are not covered by local source CI and remain UNRUN until their actual required surface is used. Existing hosted-only safety guards stay intact; the owner's installation is not a substitute sandbox.

Retained 127 hosted reports remain valid historical evidence for their exact 127 source/package bytes. They do **not** prove current Harel source, new build 128 bytes, local compiler output, a 127-to-128 plan or current multi-OS Installer acceptance. Nothing in the manual workflow definitions authorizes a new run under the current policy.

## Validation in this lane

- **306 focused workflow/asset-contract tests passed in 1.56s**, including a regression over every workflow rejecting all automatic triggers. Only trigger expectations changed; actual historical job contracts remain tested.
- **14 existing native gateway report-validation tests passed in 0.24s** after the optional fixture-path changes.
- Shell syntax, minimal-PATH `--check`, gateway CLI help and focused Python lint pass. YAML parsing confirms all 30 definitions are manual-only and build-128 owner inputs are retained.
- A fake dependency-tool failure exercised the real runner: nonzero exit, later stages UNRUN, output paths containing spaces handled, and its scratch root removed. No dependency sync, native compilation, package, signing or full CI occurred in this lane. The coordinator will run full local CI after the clean source push.

Changed ownership handed back: `.github/workflows/`, `scripts/ci-local.sh`, optional gateway fixture paths, five workflow assertion suites and this memo. No git mutation, owner request, private read or Actions usage was performed.

## First full-run environment correction

The coordinator found three fixture failures caused by the runner context: inherited077 turned an expected0755 directory into0700 and made a0600 mutation unchanged; Darwin /tmp wheel inheritance cleared a set-group bit because the ordinary user was not in that group. Product permission checks were correct. The scratch root now takes the current primary group, and each child runs under022 while its0700 parent and0600 redirected logs stay private. The exact three failing tests pass together (3 in 31.30s); a corrected full run remains required. The live script was replaced atomically so its ongoing old run keeps its original inode and is not changed mid-execution.

The first full pytest completed with 5078 passed,5 skipped,29 failed. In the corrected environment25 further permission cases pass; one remaining packaging case correctly refuses the coordinator’s in-flight uncommitted runner edit. Commit first, then rerun that exact case. Keep the tree clean throughout the final full run, and use the final updater source for that run rather than repeating an intermediate source-only job. No production permission check was weakened.

The original run’s optimized owner UI, actual ad-hoc gateway, both architecture typechecks, desktop/browser bridges, mailbox callback, isolated launch and72-check runtime source probe pass. The shared source probe correctly refuses `/tmp` as an aliased output parent. The corrected runner uses canonical `/private/tmp/aa-ci.*` while keeping socket names short; this does not relax the probe. The remaining packaging case passes after committing the edit (1 in13.49s). Qualify the corrected full runner at final helper source.
