# Build 121 runtime fix - 31 October 2026

The installed build-120 public-example read exposed a publisher runtime defect: Apple-silicon Node crashed before reaching a website with an empty hardened-runtime JIT entitlement. The repaired image grants only `com.apple.security.cs.allow-jit` to its exact bundled Node and headless Chromium roles. Both the publisher-signed driver and sandboxed browser execute JavaScript in the image qualification; no account data was used.

- [Image execution evidence](../runtime-jit-2026-10-31/target-image.json).
- [Exact-source native release qualification](https://github.com/fainir/account-access/actions/runs/41196846462) passed: [shared full-image](full-image.json), [runtime](runtime.json), [120 compatibility](direct-compat.json), and [121 successor](direct.json).
- [Signed updater](signed-updater.json) passed notarization, stapling, Gatekeeper, independent package expansion, target signatures and finite source/payload checks. This alone does not establish installation or website success.
- The signed first-install package also passed Apple notarization, stapling and Gatekeeper: [fresh package](signed-fresh-install.json). The actual Installer matrix and owner-Mac installation/public-example read remain pending. No private account acceptance is claimed.
- Portable protected-vault backup is outside v1. The legacy per-user CLI does not reach the installed store. [Scope correction](../../docs/vault-backup.md).

Source application CI at `46d3594` passed **4,552 tests**, 112 platform skips, all native owner targets and lint ([run](https://github.com/fainir/account-access/actions/runs/41197820438)).

The installed build-120 public-example export was staged through its native warning and destination picker. The protected credential-export route requires separate macOS owner approval. The unanswered prompt ended safely at a reconnect notice; no export completion or private credential access is claimed. F8 remains an owner action.

Actual Installer run [41199648661](https://github.com/fainir/account-access/actions/runs/41199648661) failed and is **not release acceptance**. Fresh install published the exact build-121 image and passed the installed JOSE guard and live service check, then its publisher-signed Chromium child exited with SIGTRAP under the service identity. [Fresh failure](attempt1-fresh/report.json), [browser log](attempt1-fresh/install-publisher-sandboxed-browser.log). Upgrade refused at payload verification before installed context: unchanged broker/bootstrap/verifier binaries were omitted from the sparse package even though signature verification requires them. [Upgrade failure](attempt1-upgrade/report.json), [Installer refusal](attempt1-upgrade/install-daemon.log).

The source fix carries all three exact manifest-bound trust anchors as supplemental resources, preserving the verifier checks and installation delta. Python and native payload definitions now agree; missing-anchor fixtures refuse. **84 focused tests and Ruff pass**. Recompiled helper qualification and a corrected updater are required. The image and fresh package have not been rebuilt while the Chromium failure is diagnosed.
