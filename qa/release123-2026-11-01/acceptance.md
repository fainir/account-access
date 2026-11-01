# Build 123 acceptance - 1 November 2026

Build 123 adds the reviewed Betterloop session-status connector. The only runtime
Python module changed from the qualified build-122 image is `catalog.py`.
There is no private sign-in, MFA delivery, saved credential or new grant yet.
The installed owner Mac remains on build 122 until its separate native update.

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

## Remaining

Actual fresh/repair and upgrade/reapply on disposable Macs, corrected complete
source CI and owner-Mac installation remain open. Do not treat signature,
notarization or fixture reports as completed installation or private acceptance.
The customer 0.8.0 draft remains the older build-122 candidate until its successor
is qualified. No Android signing, upload, phone installation or publication.
