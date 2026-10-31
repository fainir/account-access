# Account Access privacy notice

Publisher-approved for version 0.8.0 on 1 November 2026.
This notice takes effect when version 0.8.0 is publicly released.

## Publisher and contact

Account Access is published by **Nir Fainshtein**, **עוסק פטור**.
Contact for support and privacy requests:
[welcometothebestplace@gmail.com](mailto:welcometothebestplace@gmail.com).
Do not send passwords, verification codes, recovery keys, session cookies or a
copy of your vault by email.

## Your choices and the purpose of processing

Account Access helps you complete reviewed sign-ins and lets enrolled local AI
tools perform only the account operations you approve. You choose whether to
import a login, connect a verification source, pair a phone or grant an agent
access. Account Access does not require you to provide this information by law.
If you decline a connection or its necessary permission, the corresponding
sign-in or verification feature will not work; other independent features can
still be used.

## Information on your Mac

Depending on your choices, the app processes saved login details, approved
website session state, email connection material, authenticator seeds, phone
pairing material, permitted operation results and local activity metadata.
Secret records are encrypted locally. Configuration, record identifiers,
permission metadata, challenge status, task scheduling metadata and audit
categories are protected by local file permissions but are not all encrypted
database fields. The installed protected worker uses a separate Mac service
identity. The publisher does not automatically receive your local vault.

The app has no configured publisher analytics, advertising or remote crash
collector in its application code. Local installation/recovery logs and operating
system diagnostics are separate. No cloud Account Access account database or
cloud SMS relay is required by this release.

## Connections and recipients

The selected website receives information needed for its approved sign-in and
operation. Its own pages and service providers have their own data practices.
Your selected email provider receives connection and mailbox requests. TLS IMAP
uses bounded read-only queries; configured Gmail OAuth requests the mailbox-wide
`gmail.readonly` scope, with narrower login-message filters applied by Account
Access. A mailbox connection alone does not give an AI agent inbox access.

Optional password-manager connections contact Bitwarden, 1Password or your
configured 1Password Connect server. The approved item's username/password are
checked for the selected website. Bitwarden also synchronizes a provider-encrypted
CLI profile that may include encrypted entries beyond the selected item; that
profile and its unlock session are saved inside encrypted local records. Its
master password is not saved.

Enrolled local AI tools receive discovery, status and the operation result you
approved. Credentials, cookies and verification codes are excluded and redacted.
The AI tool may send the approved result to its own provider according to its
settings. Your website, mail, password-manager and AI providers may process data
in other countries under their own terms. GitHub handles downloads, and macOS may
contact Apple for signing/notarization trust checks.

## Optional Android companion

The companion uses camera permission to decode the Mac's pairing QR locally;
scanner images are not saved or uploaded by the scanner code. Android
notification access gives a listener broad visibility. Account Access filters by
the selected SMS application, freshness, exact sender and configured message
template before forwarding a matching login notification. It requests no SMS
inbox, contacts or microphone permission.

The phone sends matching sender, recipient, message body, message identifier and
receipt time directly to the paired Mac over certificate-pinned HTTPS on private
Wi-Fi. Android 15+ requires a computer association; Bluetooth discovers the Mac,
while messages use Wi-Fi. The manifest also requests Internet and companion
background execution/data permissions. Pairing is encrypted with an Android
Keystore key, app backup is disabled, and message payloads are queued in memory
rather than saved as a message archive. Local settings keep the selected SMS app,
association metadata and last delivery time/status. The manual six-digit code
option uses the same delivery restrictions.

## Retention, access, correction and removal

Saved credentials and reusable connections remain until replaced or removed.
There is no general automatic retention period for local configuration, audit
history, task history or recovery logs in v1. Login-code authority expires after
two minutes, and the normal completion/cancellation path clears its window.
Structural sign-in diagnostics are displayed only for a matching pending
challenge that is at most 24 hours old. These expiry/display limits are not
promises of physical erasure or background disk purging after a crash.

Use the owner app to review supported saved login details, edit them, explicitly
export a login or forget it. Forget removes its saved credential, connection,
password-source binding and pending browser-session request, and resolves pending
challenges. It keeps the reviewed connector, shared verification sources and
audit/task records. Disconnect a shared mailbox or phone separately, and use a
provider's own controls to revoke server-side access where needed.

You may contact the publisher to request access to or correction of personal
information handled by the publisher, and removal where applicable. Local vault
controls operate on your device; the publisher cannot remotely inspect or erase
that vault. Support mail you choose to send is handled in the contact mailbox,
outside the local vault; this release adds no ticketing or automated support-mail
retention service. Send the minimum non-secret information needed for your
request. Ownership checks must not require a password, login code or vault key.

Login CSV exports contain a plaintext password. Import files, exports and
backups you retain are separate copies. Forget/disconnect do not erase provider
copies, original SMS messages, AI results already delivered, exports, SQLite
recovery media or system backups. Uninstall is not a verified erase-all-data
operation. Portable protected-vault backup/restore is outside v1; no secure
erasure claim is made.

## Changes and further detail

The [data-handling disclosure](data-handling.md) provides the technical details
and review evidence for this release. Changes to recipients, permissions or
processing need an updated notice with the corresponding release. A new
connection or broader operation still requires its own owner authorization.
