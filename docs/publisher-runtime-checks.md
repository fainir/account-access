# Genuine publisher checks — 18 October 2026

## Current import and unattended-login candidate

Application source `972b800`, Mac build **62**, has fresh genuinely signed
universal owner/background, broker, bootstrap and native Installer components.
All five executables pass publisher purpose, timestamp, hardened-runtime and
architecture audits. Sixteen static peer checks pass; the pinned wheel matches
all **58** current Python modules and the source extension/installer resources.

The isolated ordinary-user runtime preparation signed 25 native files with a
four-executable hash-bound plan; three reviewed entries receive JIT. Library
validation stays enabled and unsigned executable memory is not allowed. The
complete original-plus-assembled audit passes 49 native files, eleven executables,
one bundle and 34 wheels. Crypto, native callbacks, SSL/SQLite, TOTP, the SDK
native constructor/isolated child and a sandboxed synthetic browser render pass.
The SDK input is invalid synthetic data, with no private account request.
Pinned inputs contain only headless shell and FFmpeg; this is distinct from the
full-browser CI package variant. Original public inputs remain unchanged.

The [fresh production transport review](https://github.com/fainir/account-access/actions/runs/39122546678) passes **28 checks** at
controller `97af5c6` against the source-972 archive, with a fresh Chrome
profile and the exact production extension/native-host registration. Both reads
reach the publisher-pinned service and receive the exact pre-enrollment denial.
The disposable profile, registration, children, service, policy and image are
removed; the runner identity is unchanged. The public QA archive is a draft
input, not a consumer installer or release. No owner app was installed or
launched on the owner's Mac, and no private sign-in or genuine owner approval
was performed. [Exact current evidence](../artifacts/unattended-import-080.json).

## Earlier connected-setup candidate at `57e7702`

Application source `57e7702` has fresh genuinely signed universal owner,
background, broker, bootstrap and native Installer components. All five
executables pass Developer ID purpose, secure-timestamp, hardened-runtime and
architecture checks. Sixteen static peer checks pass. The pinned wheel matches
all 57 Python modules, extension resources, installer resources and locked
runtime dependencies from that same source.

The current runtime includes the official pinned `onepassword-sdk==0.4.1`.
An ordinary-user private build signed 25 native files with permissions bound to
four executable hashes; only three reviewed runtime executables receive JIT.
Library validation remains enabled and unsigned executable memory is refused.
The complete audit includes 49 native files, eleven executables, one bundle and
34 wheels. Those counts include both original and assembled runtime inputs;
they are not counts for the smaller transport archive.

Prepared callbacks, crypto, SSL/SQLite, validation, TOTP and the SDK's native
constructor and isolated child pass. The SDK child uses an invalid synthetic
token and performs no private account request. A sandboxed headless browser
renders a synthetic page using a mock keychain and basic ephemeral password
store. This build contains only pinned headless shell 153.0.8010.12 and FFmpeg,
not the full-browser input used by the separate package CI. Original Python,
all 33 dependency wheels and the dependency lock remain unchanged.

A genuine clean-Mac probe exposed a deployment bug: the default group-writable
Applications directory cannot be an ancestor of protected executable code.
The canonical owner app and resources now live inside the protected support
tree; Applications contains only a fixed relative navigation alias. Generic
protected-path checks remain strict, and global Applications permissions are
preserved. Python image verification, native Installer verification and
production desktop/browser entrypoints agree on this layout.

A separate [genuine publisher transport
review](https://github.com/fainir/account-access/actions/runs/39118694398) passes **28
checks** at QA controller `84452a4`, with unchanged application source `57e7702`. Signed
stable Chrome loads the unchanged production extension and launches the production
native host, which reaches the publisher-pinned desktop/XPC service and returns the
exact pre-enrollment denial twice. A fresh browser profile receives an exact copy of the
production-created host registration so Chrome can discover it in the selected data
directory. The runner identity is preserved; the temporary profile, exact registrations,
children, service, policy and public image are removed. No owner approval, vault
enrollment or website sign-in occurs.

No review app was installed or launched on the owner's Mac. The unfinished
mailbox form was preserved. Private sign-ins, genuine positive owner approval,
physical delivery, consumer installation and notarization are still unverified.
[Evidence for source 57e7702](../artifacts/connected-setup-080.json).

## Earlier full-browser runtime at `b2dddbc`

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

## Earlier full-browser runtime compatibility at `b2dddbc`

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
compatibility. The separate hosted review also proves genuine production native/desktop/XPC transport before enrollment, using the existing disposable runner and a fresh browser profile. It does not prove consumer package installation or owner approval.
Genuine owner setup and a complete authenticated protected-worker website
journey remain unverified.
The local signing identities include no Developer ID Installer identity, and
live Apple notarization/stapling is still pending. Private factor delivery,
physical phones, installed isolated agent sessions, interrupted positive
provisioning, updates/migration and power-loss/reboot acceptance remain open.
Chrome CSV imports remain snapshots. The candidate remains a preview.
