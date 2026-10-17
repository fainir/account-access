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
uses exact approved items from a configured 1Password Connect service; its live
private deployment still needs acceptance testing. See
[password sync behavior](security-and-password-sync.md) and
[production gates](production-gates.md).
