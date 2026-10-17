# Mac system key custody

`RootVaultKeyStore.swift` is the durable-key provider for a future trusted root
supervisor. It requires both real/effective UID 0 and the startup/system security
session before any Keychain operation. A sudo process in a user login session
is insufficient. This component is not enabled in the consumer installer.

The provider uses `SecItem` in the System file-based keychain and requests no
authentication UI. It does not select the owner's login keychain or a data
protection access group. Apple's [TN3137](https://developer.apple.com/documentation/technotes/tn3137-on-mac-keychains)
requires a file-based keychain for system daemons; the data protection keychain
requires a user login context. The OS manages the backing format and protected
entropy. The application does not copy keychain databases, handle entropy files,
depend on those implementation details or disable system protections.

Each canonical vault UUID identifies one 32-byte random key. The returned object
has a redacted description and gives bytes only to a root system-context caller.
The provider disables core dumps before any key operation. This does not prevent
trusted root/OS access or guarantee erasure of library memory.
Reading never enrolls a missing item. Fresh enrollment is a separate operation;
duplicates cannot replace an existing key. The supervisor must authorize that
operation and verify absence of enrolled encrypted state first. There is no
plaintext key-file, owner-keyring or environment fallback. Noninteractive access
failure is an error, not another password dialog. Temporary buffer clearing does
not guarantee erasure of all OS/library copies.

## Acceptance scope

The Mac worker workflow compiles the provider for both architectures and tests
it in temporary system launchd processes in a disposable Mac VM. A separate
fixture service namespace and newly allocated UUID isolate it from personal or
production entries. An encrypted canary checks key recovery after process exit;
missing/duplicate enrollment, invalid identity, root-context guards and direct
unprivileged access have separate assertions. Cleanup removes the fixture item.
Each daemon phase verifies zero soft/hard core-dump limits; a different valid
vault identity must not resolve the enrolled key.
No key bytes are printed, passed on a command line or stored in a report/file.

Recovery first resolves one opaque record reference, then reads that exact
record. Identical persistent references repeated by a search list count as one
item; different references remain ambiguous and are refused. Pure metadata
tests check that distinction without accessing a Keychain. The file-based shim
rejects all-password-data queries. A narrow C bridge
uses its documented, deprecated interaction control to disable prompts in the
daemon; data-protection authentication contexts do not control this keychain.
The remaining storage operations use `SecItem`. The unprivileged probe uses a
test-only `SecKeychainOpen` call to target System explicitly, avoiding a false
miss in its own default search list. Production Swift and the C bridge compile
with warnings as errors; only that specific compatibility call is annotated.
An invalid query or unavailable service is not accepted as access-denial proof.
Nor is a missing item: the root fixture independently confirms the key through
an explicit System query, before and after restart. The separate-user probe must
receive an authentication/interaction denial from that same explicit query.
Actual workflow success and its complete report must be verified before counting
this component as passed.

Revision `1aacc8a` passed **20 system-context checks** in a
[disposable Mac VM](https://github.com/fainir/account-access/actions/runs/38998814664/job/117297184139),
alongside the worker's 25 and root owner's 24 checks. The direct separate-user
read returned `errSecAuthFailed`, not a missing-item or invalid-query status.
Eleven pure reference-selection checks passed locally and in that workflow.
The [sanitized report](../artifacts/mac-key-custody-080.json) records the scope.
The test confirms process restart, not a machine reboot or a different signed
binary recovering the item after an update.

This is not production supervision, consumer installation, migration or genuine
owner authorization. Integrating the provider with the isolated worker, native
setup/source collectors and secure client issuance remains necessary, alongside
private email/SMS/TOTP, physical-device and notarized-install acceptance.
