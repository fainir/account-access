# Build 123 acceptance - 1 November 2026

Build 123 adds the reviewed Betterloop session-status connector. The only runtime
Python module changed from the qualified build-122 image is `catalog.py`.
At initial image qualification no private sign-in or new grant had been used.
[Private Betterloop acceptance passed on 2 November](../betterloop-private-2026-11-02/acceptance.md);
real MFA delivery remains separate.
Build 123 is now installed on the owner Mac, with post-reboot acceptance below.

## Completed native and package checks

[Native qualification run](https://github.com/fainir/account-access/actions/runs/41289546915)
completed successfully. All six actual result artifacts were read:

- [Shared adapter](full-image.json): source stability and six guarded-main refusals.
- [Runtime](runtime.json): 72 checks, no installed reads.
- [New exact 122-to-123 contract](direct.json): 15 units, 16 changed nodes,
  19 journal operations, two projections, eight tuple/refusal checks and nine
  retained-preparation checks.
- Earlier [110-to-120](direct-compat.json), [120-to-121](jit-compat.json) and
  [121-to-122](connection-compat.json) contracts all pass unchanged.

The [matching public image](image-qualification.json) verifies all 49 native-file
publisher signatures, unchanged dependency/JIT bytes and actual sandboxed-browser
execution. No installed path or account data was changed by assembly.

The [exact predecessor updater](updater-package.json) is signed, notarized,
stapled and Gatekeeper accepted, including its persistent published copy.
Its ordinary-user invocation refuses before any installation operation.

The full installer separately passed these actual post-notarization commands:

```
xcrun stapler validate .../fresh/Account-Access-arm64.pkg
The validate action worked!
spctl --assess --type install --verbose .../fresh/Account-Access-arm64.pkg
accepted; source=Notarized Developer ID
pkgutil --check-signature .../fresh/Account-Access-arm64.pkg
Notarization: trusted by the Apple notary service
Developer ID Installer: Nir Feinstein (WBULD6N4NQ)
```

The exact final installer bytes and immutable public predecessor are bound in
[the Installer input contract](../../artifacts/runtime123-installer-inputs.json).
The predecessor archive was checked for exact manifest membership: 27,494
public nodes/parents, no personal accounts or protected private branches.

## Regression correction

The first complete source regression found two stale account-context fixtures:
they assumed only three private providers and accidentally seeded the new
Betterloop entry as connected. The application correctly counted four private
services. Fixture setup now seeds only the three explicitly named public
examples and asserts Betterloop remains unconnected. All 32 relevant local
classification/form/connector cases pass; the Mac worker workflow now includes
Betterloop's guarded multipart/refusal cases. Runtime bytes did not change and
neither installer was rebuilt for this test-only correction.

## Completed signed Installer and source regression

Actual signed-package fresh/repair and upgrade/reapply pass on all three
Apple silicon test systems: [macOS 14.8.9](https://github.com/fainir/account-access/actions/runs/41291378897),
[macOS 15.8.2](https://github.com/fainir/account-access/actions/runs/41291108135),
and [macOS 26.6.2](https://github.com/fainir/account-access/actions/runs/41291389080).
All six report artifacts were read: 11 fresh/repair and 27 upgrade/reapply checks
on each OS, 114 checks total. Each verifies build 123, live signed browser
execution, the patched dependency guard, private sentinel/receipt preservation,
and exact retention of earlier 120/121/122 recovery histories after update/reapply.
The fixtures contain no personal account and stop their created job afterward.

The [corrected complete regression](https://github.com/fainir/account-access/actions/runs/41291108144)
passes **4,656 tests with 113 skips**, Ruff, dependency audit (no known
vulnerabilities), native owner UI, gateway and updater checks.
Source/binary code is unchanged by the fixture correction.
Real private Betterloop acceptance subsequently passed on 2 November through
the installed native Chrome import and both AI launchers; see the private
acceptance above. Signature/notarization/fixture reports alone do not establish it.
The qualified build-123 files are staged in the existing unpublished
customer draft. Earlier build-122 artifacts remain explicitly labeled legacy;
no asset deletion or publication is required for this handoff. No Android signing, upload, phone installation or publication.

Before requesting the owner update, seven existing directory/alias identities
were captured in [the owner installation log](owner-installed.log), using only
metadata. No private file or configuration was opened. The app was build 122
at that capture and is now build 123.

The [completed current-source Mac worker run](https://github.com/fainir/account-access/actions/runs/41291108214)
was read back: all 18 report files are PASSED and all 426 check values are true.
This includes [16 offline-package checks](account-access-mac-package.json) and
[23 prepared-package checks](account-access-mac-prepared-package.json), with
`prepared_runtime_executed: true`. They are controlled development fixtures;
the separate three-OS signed-package reports establish publisher Installer acceptance.

## Installed owner Mac after full OS restart

The owner reported installation and restart. Independent read-back confirms
app version 0.8.0/build 123. The kernel boot time is 1 November at 11:38:37
Asia/Jerusalem, after the pre-install log was created at 11:20:14. This verifies
an actual OS restart, not only a service restart.

All seven captured directory/alias inode identities, modes, users and groups
remain unchanged. Device numbers changed consistently after the reboot/remount.
The vault and prior recovery directories were inspected by metadata only.
The installed owner wheel and public runtime catalog match the qualified
build-123 image byte for byte, including the reviewed Betterloop connector.

Normal installed discovery reports browser READY, recovery RUNNING and zero
failures. Both installed launchers, Codex and Claude Code, completed the existing
approved public-example inventory operation: six items each, names/prices only.
The private Namecheap account remains paused and was not retried.
[Actual installed observations](owner-installed.log).

The post-restart native GUI handoff could not be observed because the configured
computer-use RPC is unavailable in this session. No UI success or staged
credential form is claimed. No private Betterloop account, credential or new
grant was used. Restore supported native UI control before staging an existing
account's local connection; browsing history alone does not establish ownership.
Private email/TOTP and physical-phone acceptance remain the ledger's owner rows.

Native UI control was restored on 2 November. The earlier unstaged handoff is
resolved by the owner-approved Chrome import and verified private results linked
above; do not repeat its credential/export/grant requests.
