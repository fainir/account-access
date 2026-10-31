# Build 121 runtime fix - 31 October 2026

The installed build-120 public-example read exposed a publisher runtime defect: Apple-silicon Node crashed before reaching a website with an empty hardened-runtime JIT entitlement. The repaired image grants only `com.apple.security.cs.allow-jit` to its exact bundled Node and headless Chromium roles. Both the publisher-signed driver and sandboxed browser execute JavaScript in the image qualification; no account data was used.

- [Image execution evidence](../runtime-jit-2026-10-31/target-image.json).
- [Exact-source native release qualification](https://github.com/fainir/account-access/actions/runs/41196846462) passed: [shared full-image](full-image.json), [runtime](runtime.json), [120 compatibility](direct-compat.json), and [121 successor](direct.json).
- [Signed updater](signed-updater.json) passed notarization, stapling, Gatekeeper, independent package expansion, target signatures and finite source/payload checks. This alone does not establish installation or website success.
- The actual Installer matrix and owner-Mac installation/public-example read remain pending. No private account acceptance is claimed.
- Portable protected-vault backup is outside v1. The legacy per-user CLI does not reach the installed store. [Scope correction](../../docs/vault-backup.md).
