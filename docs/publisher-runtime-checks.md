# Genuine publisher checks — 18 October 2026

Application revision `b2dddbc` passed all eight push/PR workflows. The two full
regressions passed 1,445 tests with 75 platform skips, in 526.13 and 593.23
seconds. Both disposable Macs passed the original 16-check and prepared 23-check
Installer journeys, including actual process interruption and same-image retry.
Their sixteen worker reports match. The focused Mac suites passed 745 tests
with one platform skip each and no warnings.

[Exact CI and recovery evidence](../artifacts/resumable-installer-080.json).

## A production-path failure found and corrected

Staging a genuine Developer ID application exposed a defect that the ad-hoc
fixtures did not exercise. The production signature checker supplied its rule
as `codesign -R` followed by the bare requirement expression. Apple interpreted
the expression as a filename and refused the valid application.

The checker now supplies direct requirement source with `-R=`. Its Apple anchor,
identifier, publisher team and debugger-entitlement predicates are unchanged.
A native regression uses an ad-hoc synthetic binary and verifies that Apple's
actual parser rejects its untrusted publisher for the intended reason, rather
than failing to parse or locate a requirement file. It requires no publisher
certificate or account access in CI.

## Genuine staged components

The corrected checker accepts the genuinely signed universal owner app, broker,
bootstrap and installer verifier. The production payload auditor separately
checks all five executable files, including the background helper, for Developer
ID certificate purpose, secure timestamps, hardened runtime, absent debugger
entitlement and valid signatures across both native architectures.

The [ordinary-user static harness](../macos/Tests/PublisherPeerChecks.swift)
uses the production `OwnerGatewayPeer` requirement constructor. Its sixteen
checks accept the expected publisher/identifier/code hashes and reject wrong
teams, identifiers and hashes for each of the four peers. It checks static code
validity; dynamic XPC identity and genuine owner authorization remain separate.

Maintainers can compile the harness without administrator privileges:

```sh
xcrun swiftc -parse-as-library -warnings-as-errors \
  -framework Foundation -framework Security \
  macos/OwnerGateway.swift macos/Tests/PublisherPeerChecks.swift \
  -o /tmp/account-access-publisher-checks
/tmp/account-access-publisher-checks public-signatures.json
```

The input JSON has exactly `owner`, `broker`, `bootstrap` and `installerverify`
entries. Each supplies the local public code `path`, validated `team`,
`identifier` and architecture-specific `hashes` from the read-only
`account_access.system_provision.signature` check. The harness refuses root
invocation. It reads signed code and emits boolean results; it does not launch
the components or request setup authorization.

## Genuine runtime compatibility

A separate ordinary-user build copied the public inputs into the builder's
guarded private temporary directory. The existing signing code prepared 41
native files and ten bundle seals with the genuine Developer ID identity.
The reviewed plan binds sixteen executable hashes and permits JIT for fourteen
of them. Library validation stays enabled; unsigned executable memory is not
allowed. These permissions apply to the selected runtime executables, not to
the native owner app or broker. Readback from 22 signed executable locations
matches the reviewed permissions exactly; installed wheel executables also
match their preparation hashes.

The complete image passed the production native audit: 64 native files,
23 executables, eleven bundles and 33 wheels. Its CPython 3.12.15 runtime passed
the same callback/crypto/validation probe used in prepared-package CI, including
CFFI and ctypes callbacks, SSL/SQLite, greenlet, pydantic and TOTP generation.
A fresh headless browser rendered a synthetic page successfully. Its observed
launch retained sandboxing and explicitly requested a mock keychain and basic
password store. An empty home and private temporary profile kept this check
separate from the owner's browser and accounts.

The source Python download, all 32 original dependency wheels and the dependency
lock were rechecked unchanged. Preparation receipts bind the transformed copies;
the app-pinned project wheel remains unchanged. No owner app was installed or
launched, and no System Keychain, AuthDB policy or service identity was changed.

[Exact component, permission-plan and runtime evidence](../artifacts/publisher-runtime-080.json).

## Remaining production gates

These checks establish genuine signatures and ordinary-user runtime
compatibility. A publisher-signed installed deployment, genuine owner setup and
the complete protected Chrome/native/XPC/worker journey remain unverified.
The local signing identities include no Developer ID Installer identity, and
live Apple notarization/stapling is still pending. Private factor delivery,
physical phones, installed isolated agent sessions, interrupted positive
provisioning, updates/migration and power-loss/reboot acceptance remain open.
Chrome CSV imports remain snapshots. The candidate remains a preview.
