# Automatic sign-ins, bounded access

Connect once, approve the supported accounts and reads, then ask your AI normally.
The security changes do not introduce an approval prompt for each routine login.
Passwords, sessions and verification-source secrets are encrypted in the local vault.
The agent interface returns approved results, never passwords or verification codes.

Version 0.7 adds:

- The signed Mac app pins the exact Python package checksum inside its signed bundle. A replaced package is rejected even if a replaced download manifest claims it is valid. The standalone shell installer still relies on HTTPS and the downloaded manifest; dependency installation also relies on the configured package registry.
- Private file replacements publish a new 0600 inode instead of truncating an existing file. Replacing a hard link cannot overwrite its other target. Vault database sidecar and lock symlinks are refused.
- Every code resolver requires the matching, unexpired pending login window and unchanged verification-source configuration. A code cannot be requested outside that window.
- Before entering a code, the service checks the page again for the expected factor. Changed pages and payment, passkey, device or administrator challenges stop the login.
- Native login forms must POST to an exact reviewed destination. A changed form cannot put a password or code into a GET URL.
- Password imports default to moving the plaintext export to Trash. This is not secure deletion; Trash and backups can still contain it.
- Optional 1Password Connect links update only the password of the exact approved item. Username, website, connector, authenticator keys and operation permissions cannot change through sync.

The 0.8 candidate also checks the verification window and its enrollment again
immediately before entering a delivered code. Disabling, replacing or cancelling
a source while delivery is pending stops submission. Mac SMS reads record a
message-row boundary before the password can trigger delivery; only newly
inserted rows are eligible, with a bounded allowance for phone-clock rounding.

Email codes now share a bounded MIME parser for IMAP and Gmail. Plain text takes
priority over an HTML alternative. HTML-only messages are converted to text
without execution or network access; attachments and forwarded messages cannot
supply codes. The entire text must match the reviewed login template. Duplicate
identity headers, multiple candidate bodies, unsupported active markup, excessive
nesting and messages over 256 KB are rejected. Header matching is a filter, not
cryptographic sender authentication.

Gmail access is checked before password submission, and a baseline excludes
existing matching message IDs even when an imported message has a future date.
Pagination stops instead of choosing from an incomplete set. A rejected access
token can renew once per resolver call with a fresh scope check. An uncertain
rotating-token response is never replayed. These checks add no routine owner
prompt; genuine consent or revoked access still requires local repair.

Authenticator generation leaves at least five seconds for submission or waits
briefly for the next code interval. Missing Android pairing, SMS gateway
configuration and disabled sources stop before sending the website password.

Message delivery is serialized by channel as well as enrollment name. Two
different account connections may still share the same physical inbox or phone;
their email/SMS login windows cannot compete for a message. Contention returns a
temporary retry, so the existing task waits without a new owner approval. Owner
setup that can request an SMS before enrollment uses the same channel lock.

The candidate installer ships the tested dependency versions and their SHA-256
hashes inside the verified wheel. It requires those hashes and prohibits source
builds. It prepares a separate environment and browser before switching the
launcher, restores the previous launcher after a failed startup, and prevents
concurrent repairs. The previous environment is retained. Python and Chromium
downloads still rely on their vendor distribution mechanisms; this does not
claim an independently reproducible or fully offline installation.

## Password-source updates

**Chrome, Apple Passwords and CSV exports are snapshots.** Import a fresh export when a password changes. A file export is not a live connection to the original manager. Account Access does not keep a plaintext CSV watcher or extract Chrome's encrypted password database.

Chrome's [public extension API reference](https://developer.chrome.com/docs/extensions/reference/api) does not offer a password-vault synchronization API. Automatic Chrome password updates are therefore not shipped. Keeping routine logins automatic is supported while the imported credentials or saved sessions remain valid.

**1Password Connect supports background updates.** This is an optional integration for an existing Connect deployment, not a one-click connection to any personal 1Password account. An administrator first provisions a dedicated vault and a token with read access only. See the [official Connect requirements and API](https://developer.1password.com/docs/connect/api-reference/).

1. Import the login and approve its supported reads.
2. Open **Password sync** in Account Access.
3. Select that account. Enter the Connect server's HTTPS origin, vault ID, item ID and read-only token locally. Do not send the token in chat.
4. Click **Connect automatic updates**.

The service checks the selected item every five minutes while running, and checks again before a password login. Updates are encrypted and replace the password and cached session together. New accounts and new permissions are never imported silently. A fresh explicit CSV import removes any previous manager link for the selected account.

Network failures retry with backoff. A deleted item, removed access, changed username or changed website blocks use until repaired. An unavailable source cannot supply a stale password for a new login. Disconnecting a source erases its local token, cached password and session; existing operation grants alone do not restore a credential.

Sync does not rotate passwords at the website. It follows changes the owner makes in the source. It never updates a TOTP seed silently. 1Password Connect contract and browser recovery tests use fictional items; a private 1Password deployment has not been validated.

## What still needs genuine owner presence

Initial Chrome export authorization, Google consent or app-password enrollment, OS privacy permissions, phone pairing and authenticator-key enrollment belong to the owner. Once connected, supported password, email, SMS and TOTP login recovery can run without repeated input. A provider can still demand a genuine device, passkey, biometric, CAPTCHA or administrator approval. The service does not bypass that requirement or treat payment-approval codes as login codes.

Gmail access and phone permissions can be broader than the app's matching-code filter. Google Authenticator requires the website's original supported QR/key; this app does not read the phone app or its cloud storage. See the [verification guide](gmail-authenticator-and-sms.md).

Enrolling the TOTP key on the same computer as the password trades factor separation for unattended recovery: compromise of that device can expose both. Keeping the second factor exclusively on the phone preserves that separation but may require an owner approval. The preview does not claim both guarantees at once.

## Isolation limit

The local preview is for a trusted-agent pilot. An unrestricted agent running under the same OS user can potentially access owner files, alter local code or use that user's keychain. Encryption, a CLI and a separate process do not establish an OS isolation boundary. These changes reduce specific attack paths; they do not make the local app safe against a compromised process with all of the owner's privileges.

Protecting credentials from that threat requires a broker under a separate OS identity or on a separate host, with a trusted owner enrollment channel. General isolated consumer installation and an independent security assessment remain production work. The video describes encryption, approved reads and automatic supported sign-ins; it does not claim protection against every local process or unattended access to every website.
