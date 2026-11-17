# First Android identity with Mac Keychain - completed after owner approval

Completed: the owner selected the first-release option and the managed operation
created one identity and signed one candidate. Independent artifact checks pass.
See [actual acceptance](android-publisher-acceptance-2026-10-31.md). The remainder
records the reviewed preparation and safeguards, not a new pending approval.

The owner asked the agent to finish production readiness after the manual
publisher handoff. A prepared first-release option now requires one named owner
decision rather than choosing and typing a new signing password in Terminal.

Proposed operation: create **one first Android publisher identity** on this Mac
for Nir Fainshtein and sign **one local Account Access Phone 0.8.0/version-code-2
APK**. Fee: $0; no upload or phone installation is part of this signing operation.
The existing publisher directory and candidate output are absent. This route
refuses either existing destination and must not be used instead of an existing
production identity. The owner can choose the existing-key path instead.

The password is generated inside the child process, added as a new native Mac
Keychain item and read back internally before key generation. The private
PKCS12 key remains outside the checkout in the private publisher directory.
Only the Keychain service reference and public certificate/fingerprint are
saved beside it. Existing Keychain items are never deleted or updated: the
adapter calls native `SecItemAdd` directly instead of the backend's replace
operation. No plaintext password, password argument, model-visible value,
transcript or fallback file is produced. Native Keychain access remains subject
to macOS permission/lock state.

The code does not open or control Terminal. It is a publishing CLI that can be
run only after the owner explicitly approves this named first-identity action.
The unapproved preparation mode and tests made no Keychain call and generated
no publisher identity or APK. The older manual route remains available.

```text
uv run --no-sync pytest -q tests/test_android_keychain_publisher.py tests/test_android_publisher_setup.py tests/test_android_release.py
47 passed, 1 skipped in 2.58s
uv run --no-sync ruff check scripts/android_keychain_publisher.py tests/test_android_keychain_publisher.py
All checks passed!
```

Coverage includes approval/TTY refusal before credential access, no replacement
of existing destinations, exclusive native-add dispatch without delete/update,
Keychain storage/read-back failure before key generation, secret exclusion from
arguments/files/output/errors, child environment cleanup, and preparation with
no side effects. The earlier real disposable JDK certificate test also passes.
Actual native bindings were loaded and checked for availability without issuing
a Keychain operation. End-to-end Mac Keychain storage and actual publisher
signing remain unverified until the owner approves and the operation completes.

The actual unapproved preparation command printed:

```text
PREPARED PLAN: create one first Android publisher identity and sign one local APK candidate.
Password destination: native Mac Keychain; private key remains on this Mac.
Owner approval required. No identity, Keychain item or APK has been created.
```

After explicit first-release approval, run `python -m scripts.android_keychain_publisher`
with `--approve-first-identity`, the staged publisher directory
`~/Library/Application Support/Account Access Publisher/android-phone-1`, output
`dist/android-publisher-2`, publisher name `Nir Fainshtein`, version code `2` and
version name `0.8.0`, in an interactive PTY. Read the actual APK signature,
package/version/hash and `release-review.json` before installation. The report
must record `signing_key_created: true` and `password_custody: native-macos-keychain`.
If it fails, retain the identity and its reference; never create a replacement.

The native backend follows the installed `keyring.backends.macOS` implementation
and [keyring's Mac Keychain documentation](https://keyring.readthedocs.io/en/stable/).
OS custody is not an approval of a public release or evidence of physical SMS
delivery. No existing account credential or Account Access vault was accessed.
