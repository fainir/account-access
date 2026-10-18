# Automatic sign-ins, bounded access

Connect once, approve the supported accounts and reads, then ask your AI normally.
The security changes do not introduce an approval prompt for each routine login.
Passwords, sessions and verification-source secrets are encrypted in the local vault.
The agent interface returns approved results, never passwords or verification codes.

The current [Chrome sync source review](chrome-password-sync-research.md) explains
why a raw browser-database reader is not a shipped continuous-sync connection.
Chrome imports remain reviewed snapshots; the configured 1Password Connect
contract is the existing ongoing-sync option. Private deployment QA remains open.

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

The candidate also rejects excessive or partial IMAP results and verifies each
fetched message's UID. The SMS gateway checks its approved sender/recipient,
remembers existing message IDs before password submission, and rejects
pagination, duplicate identities and future-dated texts. Gateway pagination
links are never followed with credentials. These behaviors are protocol-tested;
they do not establish delivery from a personal carrier.

An owner can check saved mailbox access without fetching messages or starting a
website login. The result is bound to the source configuration and enrollment.
It does not clear a website challenge or claim code delivery. Editing a browser
credential invalidates the old saved session when the value changes; it cannot
clear CAPTCHA, unknown-page, device, passkey, administrator, recovery or action
challenges. Only a verified sign-in can clear those login gates.

Reusable mailbox connections keep one encrypted IMAP credential. A website can
link only its existing reviewed source's exact recipient, server and port;
linking changes neither message filters nor account grants. The agent interface
cannot list mailboxes or retrieve credentials. Changing or disconnecting the
mailbox invalidates pending code reads, while a connection recheck alone does
not. Temporary IMAP outages use ordinary task retry; invalid certificates and
rejected credentials still require repair. No unverified TLS fallback exists.

The newest candidate can resume the original task after a verified mailbox
repair. It retains private source/configuration context when a recognized
mailbox-access problem occurs, requires a fresh successful check and active
standing grants, and clears only that specific prerequisite. It does not mark
website authentication successful, change permissions or clear delivery,
ambiguity, device, browser or action challenges. Old challenges without proven
source context stay pending. A bounded rotating scan prevents other blocked
accounts from starving a repaired task.

OAuth mailbox checks bind to their provider configuration and authorization
identity. Token refresh preserves that identity; a new owner connection, changed
provider settings, revocation or uncertain refresh invalidates the cached check.
Reusable mailbox passwords also participate in the broker's result redaction.

The candidate installer ships the tested dependency versions and their SHA-256
hashes inside the verified wheel. It requires those hashes and prohibits source
builds. It prepares a separate environment and browser before switching the
launcher, restores the previous launcher after a failed startup, and prevents
concurrent repairs. The previous environment is retained. Python and Chromium
downloads still rely on their vendor distribution mechanisms; this does not
claim an independently reproducible or fully offline installation.

Managed activation also binds the wheel to the interpreter, launcher digest and
fixed isolated command. A matching wheel digest alone cannot select another
managed environment. Updated clients use the activated launcher for cold starts,
and invalid activation requires repair instead of starting a retained runtime.
Before executing an old launcher, installer preflight checks the runtime's
ownership and permissions and rejects unsafe, linked or non-regular files.
This provides update/preflight checks, not independent attestation of installed
code or protection from an unrestricted same-user process. Known integrations
are refreshed by installation; unchanged old client processes need restarting.

## Password-source updates

**Chrome, Apple Passwords and CSV exports are snapshots.** Import a fresh export when a password changes. A file export is not a live connection to the original manager. Account Access does not keep a plaintext CSV watcher or extract Chrome's encrypted password database.

Chrome's [public extension API reference](https://developer.chrome.com/docs/extensions/reference/api) does not offer a password-vault synchronization API. Automatic Chrome password updates are therefore not shipped. Keeping routine logins automatic is supported while the imported credentials or saved sessions remain valid.

Rechecked against primary sources on 17 October 2026: Google's documented
[Data Portability scopes](https://developers.google.com/data-portability/user-guide/scopes)
and [Chrome export schema](https://developers.google.com/data-portability/schema-reference/chrome)
include Chrome contact/autofill data, bookmarks, history and settings, with no
saved-password resource group. The autofill schema describes contact information.
This provides no documented password-sync path for Account Access.

Chromium's `passwordsPrivate` permission is restricted to browser component
extensions in its [permission feature rules](https://chromium.googlesource.com/chromium/src/+/main/chrome/common/extensions/api/_permission_features.json).
The [API context rules](https://chromium.googlesource.com/chromium/src/+/refs/heads/main/chrome/common/extensions/api/_api_features.json)
also expose it to Chrome's own password-manager WebUI. An ordinary installed
extension cannot obtain that access by declaring a normal permission. This is
why the Messages helper does not imply a Chrome vault connection. Continuous
Chrome synchronization remains an unmet requirement; CSV import is not its
replacement or proof of completion.

**1Password Connect supports background updates.** This is an optional integration for an existing Connect deployment, not a one-click connection to any personal 1Password account. An administrator first provisions a dedicated vault and a token with read access only. See the [official Connect requirements and API](https://developer.1password.com/docs/connect/api-reference/).

1. Import the login and approve its supported reads.
2. Open **Password sync** in Account Access.
3. Select that account. Enter the Connect server's HTTPS origin, vault ID, item ID and read-only token locally. Do not send the token in chat.
4. Click **Connect automatic updates**.

The service checks the selected item every five minutes while running, and checks again before a password login. Updates are encrypted and replace the password and cached session together. New accounts and new permissions are never imported silently. A fresh explicit CSV import removes any previous manager link for the selected account. Editing a saved browser username or password also disconnects its old manager link, so a later sync cannot undo your edit. Saving unchanged values keeps that connection.

A password update repairs only a missing-credential prerequisite or the exact password-source problem. It cannot dismiss a website's failed login, browser check or required verification. Busy accounts do not prevent other linked accounts from receiving their updates; background scans rotate through a bounded set of links.

Network failures retry with backoff. A deleted item, removed access, changed username or changed website blocks use until repaired. An unavailable source cannot supply a stale password for a new login. Disconnecting a source erases its local token, cached password and session; existing operation grants alone do not restore a credential.

Sync does not rotate passwords at the website. It follows changes the owner makes in the source. It never updates a TOTP seed silently. 1Password Connect contract and browser recovery tests use fictional items; a private 1Password deployment has not been validated.

## What still needs genuine owner presence

Initial Chrome export authorization, Google consent or app-password enrollment, OS privacy permissions, phone pairing and authenticator-key enrollment belong to the owner. Once connected, supported password, email, SMS and TOTP login recovery can run without repeated input. A provider can still demand a genuine device, passkey, biometric, CAPTCHA or administrator approval. The service does not bypass that requirement or treat payment-approval codes as login codes.

Gmail access and phone permissions can be broader than the app's matching-code filter. Google Authenticator requires the website's original supported QR/key; this app does not read the phone app or its cloud storage. See the [verification guide](gmail-authenticator-and-sms.md).

Enrolling the TOTP key on the same computer as the password trades factor separation for unattended recovery: compromise of that device can expose both. Keeping the second factor exclusively on the phone preserves that separation but may require an owner approval. The preview does not claim both guarantees at once.

## Isolation limit

The local preview is for a trusted-agent pilot. An unrestricted agent running under the same OS user can potentially access owner files, alter local code or use that user's keychain. Encryption, a CLI and a separate process do not establish an OS isolation boundary. These changes reduce specific attack paths; they do not make the local app safe against a compromised process with all of the owner's privileges.

Protecting credentials from that threat requires a broker under a separate OS identity or on a separate host, with a trusted owner enrollment channel. General isolated consumer installation and an independent security assessment remain production work. The video describes encryption, approved reads and automatic supported sign-ins; it does not claim protection against every local process or unattended access to every website.

The candidate's internal [separate-user worker](isolated-worker.md) passed
[24 Linux cross-user checks](../artifacts/worker-boundary-080.json), including
fictional password/email/SMS/TOTP recovery and denied vault, process and owner
access. Its root-managed runtime, inherited private pipe and separate Unix
listeners are a component for a trusted supervisor. It is not enabled by the
consumer installer and does not change the installed Mac app's same-user limit.

### Verified Mac service prerequisites

Apple's [SMAppService registration](https://developer.apple.com/documentation/servicemanagement/smappservice/register%28%29)
requires an administrator to approve a LaunchDaemon before it can run. The
installed Xcode SDK's `SMAppService.h` additionally requires apps containing
these daemons to be notarized and recommends `/Applications` for availability
before login. The current user-space preview does not satisfy that deployment
gate. Legacy service installation is not an approval workaround.

The installed SDK exposes both
[connection peer requirements](https://developer.apple.com/documentation/foundation/nsxpcconnection/setcodesigningrequirement%28_%3A%29)
and [incoming listener requirements](https://developer.apple.com/documentation/foundation/nsxpclistener/setconnectioncodesigningrequirement%28_%3A%29)
on macOS 13. These can authenticate native enrollment IPC peers without relying
only on a process ID. They do not move the Python broker or vault to another
identity automatically.

The engineering consequence is that isolation needs the complete broker runtime,
vault and trusted owner-enrollment channel behind the boundary. Keeping only a
key in a helper while an unrestricted same-user process can replace broker code
or read an owner capability is insufficient. No privileged service, owner
credential migration or broader OS permission was installed during this review.
