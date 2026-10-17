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
No key bytes are printed, passed on a command line or stored in a report/file.

Recovery first resolves one opaque record reference, then reads that exact
record. The file-based shim rejects all-password-data queries. A narrow C bridge
uses its documented, deprecated interaction control to disable prompts in the
daemon; data-protection authentication contexts do not control this keychain.
The remaining storage operations use `SecItem`. The unprivileged probe uses a
test-only `SecKeychainOpen` call to target System explicitly, avoiding a false
miss in its own default search list. Production Swift and the C bridge compile
with warnings as errors; only that specific compatibility call is annotated.
An invalid query or unavailable service is not accepted as access-denial proof.
Actual workflow success and its complete report must be verified before counting
this component as passed.

This is not production supervision, consumer installation, migration or genuine
owner authorization. Integrating the provider with the isolated worker, native
setup/source collectors and secure client issuance remains necessary, alongside
private email/SMS/TOTP, physical-device and notarized-install acceptance.
