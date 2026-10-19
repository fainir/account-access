# Chrome password sync: source review

Reviewed 17 October 2026 against Chromium revision
`5926523bcfedb77ba2533ace1dd93b477673f72a`. This review used public source files;
no personal Chrome database, password, Keychain item or browser setting was read.
It is research, not an implemented or privately validated sync connection.

## What the source establishes

Chrome's `passwordsPrivate` extension permission is restricted to component
extensions. The API also has a Password Manager WebUI context. It is not a
permission this project's ordinary extension can request from the user.
See [permission restrictions](https://github.com/chromium/chromium/blob/5926523bcfedb77ba2533ace1dd93b477673f72a/chrome/common/extensions/api/_permission_features.json#L768)
and [API contexts](https://github.com/chromium/chromium/blob/5926523bcfedb77ba2533ace1dd93b477673f72a/chrome/common/extensions/api/_api_features.json#L718).
These internal interfaces must not be enabled through browser privilege tricks.

The Mac key provider obtains Chrome's Safe Storage secret from Keychain. Its
`v10` provider derives a 16-byte AES-CBC key using PBKDF2-HMAC-SHA1, the fixed
salt and iteration count defined in the implementation. User denial or another
Keychain error can leave the provider temporarily unavailable.
See [key provider](https://github.com/chromium/chromium/blob/5926523bcfedb77ba2533ace1dd93b477673f72a/components/os_crypt/async/browser/keychain_key_provider.mm)
and [Keychain item lookup](https://github.com/chromium/chromium/blob/5926523bcfedb77ba2533ace1dd93b477673f72a/components/os_crypt/common/keychain_password_mac.mm).

The login database passes the encrypted password string to the decryptor
without an origin or username argument. The database binds username, realm and
encrypted password as separate columns. The shared CBC decryptor does not take
that row metadata as associated data. Current database schema version is 43.
See [Mac password decryption](https://github.com/chromium/chromium/blob/5926523bcfedb77ba2533ace1dd93b477673f72a/components/password_manager/core/browser/password_store/login_database_mac.cc),
[row storage](https://github.com/chromium/chromium/blob/5926523bcfedb77ba2533ace1dd93b477673f72a/components/password_manager/core/browser/password_store/login_database.cc)
and [encryption implementation](https://github.com/chromium/chromium/blob/5926523bcfedb77ba2533ace1dd93b477673f72a/components/os_crypt/async/common/encryptor.cc).

## Implications for this product

A Keychain-backed local reader may be technically possible after genuine owner
approval. That alone would not establish a safe, supported continuous-sync API.
It would hold authority over a shared browser encryption key, depend on internal
formats, and need to handle locked/denied Keychain access without repeatedly
prompting the owner. It must never create, replace or reset Chrome's Keychain
item when lookup fails.

There is also a source-integrity problem to resolve under our unrestricted
same-user agent threat model. **Inference from the implementations above:**
successful decryption alone does not authenticate which website/username a
password belongs to. A privileged reader must not trust an agent-writable row's
metadata merely because the ciphertext decrypts. Selected-row filtering and
checking the same identifier on every poll do not prove that a change originated
from Chrome. This review did not execute a private-data substitution test.

A shipping connection would need a trusted change authority and a binding to the
owner-approved account, as well as bounded reads, unsupported-version refusal,
revocation, update continuity and real owner-consent QA. This review has not
identified such an authenticated external change feed. Adding raw database
decryption now would bypass unresolved requirements rather than finish them.

## Current behavior

Chrome CSV imports remain owner-reviewed snapshots. This project does not use
Chrome's internal password API, extract its Safe Storage secret, monitor arbitrary
password fields or claim live Chrome sync. The supported ongoing-sync contract
uses exact approved items through a separately consented Bitwarden CLI source,
a read-only 1Password service account or a
configured Connect service; the SDK service-account option removes the Connect
server requirement, but its live private deployment still needs acceptance
testing. See [1Password setup](onepassword-sync.md),
[password sync behavior](security-and-password-sync.md) and
[production gates](production-gates.md).

The candidate also supports reviewed Bitwarden unencrypted JSON imports through
the same owner-only import flow. That documented export format improves transfer
compatibility; it is another snapshot, not an ongoing password-manager feed or a
solution to the unresolved Chrome change-authority requirements.
[Supported import formats](password-import.md).

## Interface recheck — 19 October 2026

The [current public extension API catalog](https://developer.chrome.com/docs/extensions/reference/api)
and Chromium's [permission rules](https://github.com/chromium/chromium/blob/main/chrome/common/extensions/api/_permission_features.json)
and [API contexts](https://chromium.googlesource.com/chromium/src/+/refs/heads/main/chrome/common/extensions/api/_api_features.json)
still provide no supported ordinary-extension password-vault feed. This is a
conclusion about the documented interfaces, not a claim about Google's private
integrations. The supported manager connections above remain the ongoing-update
options implemented by Account Access.

Android now documents a supported **same-device credential transfer** between
providers. Its importer opens a system selector and waits for the selected
provider's export. Google's Password Manager instructions require account
selection, screen-lock verification and export approval. These are one-time
transfer operations, not a background subscription to later Chrome edits.
[Android transfer API](https://developer.android.com/identity/sign-in/credential-transfer),
[Google's transfer instructions](https://support.google.com/chrome/answer/13068232?co=GENIE.Platform%3DAndroid&hl=en).

An Android transfer integration could reduce plaintext-file handling during
initial enrollment, but Account Access has not implemented or physically tested
it. It would still require owner approval and would not close continuous Chrome
sync. Moving logins once to a connected manager and saving later changes there
can use that manager's existing update path; it must be described as migration,
not Chrome synchronization. No private browser store, key or credential was read
for this recheck.
