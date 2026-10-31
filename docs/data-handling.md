# Account Access 0.8 data handling

Reviewed 31 October 2026 for the qualified Mac build 122 and the current Android
companion source. This factual disclosure supports the release privacy notice;
it is not a claim that the Android companion has passed physical-phone acceptance
or that the candidate has been publicly released.

## What stays on your devices

Saved passwords, website sessions, verification-source secrets and task results
are encrypted as records in the local Mac store. The protected installation runs
the worker under a separate service identity. Account configuration, record IDs,
permission metadata, challenge status and audit metadata are protected by local
file permissions but are not all encrypted database fields. Account identifiers,
operation names, timestamps and fixed result categories can appear in this
metadata. Do not describe the entire database or every local file as encrypted.

The app has no configured publisher analytics, advertising or remote crash-report
collector in its application code. This does not cover your operating system's
diagnostics, a connected provider's logging, or information you choose to send to
support. Installation and recovery can create local diagnostic logs.

## When information leaves your Mac

| Feature you enable | Recipient and information |
|---|---|
| A reviewed website sign-in | The selected website receives the login information and session traffic needed for that sign-in. Its pages may contact their own service providers. |
| Local AI access | The enrolled local agent receives account discovery, status and the operation result you approved. Credentials, cookies, verification codes and source secrets are excluded and redacted. The agent may send the approved result to its own AI provider under that tool's settings. |
| TLS IMAP | Your chosen mail server receives authentication and bounded, read-only mailbox queries. Matching fresh message bodies are parsed locally to find the reviewed login code. The reader uses read-only selection and `BODY.PEEK`; it does not send mail. |
| Configured Gmail OAuth | Google receives OAuth and Gmail API requests. The configured permission is `https://www.googleapis.com/auth/gmail.readonly`; it is broader than a single login-message filter. Account Access applies its own sender, recipient, freshness and message-template checks. The distributed preview has no ready-to-use consumer Gmail OAuth registration. |
| An enrolled password manager | An approved Bitwarden or 1Password connection contacts that provider or the configured 1Password Connect server. It retrieves credentials for the exact approved item. These optional connections are not automatic access to an existing desktop password-manager session. |
| Paired Android login delivery | The phone sends a matching sender, recipient, message body, message identifier and receipt time directly to the paired Mac over certificate-pinned HTTPS on private Wi-Fi. There is no Account Access cloud SMS relay. |
| Download or Apple security checks | GitHub handles release downloads. macOS may contact Apple for its signing, notarization and trust checks. These providers operate under their own policies. |

An enrolled Bitwarden connection also synchronizes its provider-encrypted CLI
profile, which may contain encrypted vault entries beyond the one selected
login. Account Access saves that source profile and unlock session inside its
encrypted records; it does not save the master password. Exact-item output
filtering is not a claim that the provider downloaded only one encrypted item.

## Android permissions and local storage

The manifest requests Internet, camera, companion background execution and
companion background data permissions. The camera scans the Mac's pairing QR
locally; scanner frames are not saved or uploaded by the scanner code.

Notification access is a separate Android setting. Android grants a notification
listener broad visibility; the app filters first by the selected SMS application,
then freshness, exact sender and the configured message template before delivery.
It does not request `READ_SMS`, `RECEIVE_SMS`, contacts or microphone permission.
Manual entry of a six-digit login code uses the same bounded delivery path.

On Android 15 and later, the app requires an ordinary Android companion-device
association with the Mac before either delivery path. Bluetooth discovers the
Mac selected by the QR; login messages use private Wi-Fi. The Mac app requests
Bluetooth permission for this pairing step.

The phone saves its pairing payload encrypted with AES-GCM using an Android
Keystore key. Local settings also retain the selected SMS app, association
metadata, last delivery time and a fixed delivery-status category. Message
payloads are queued in memory for delivery, not saved as a message archive.
Android app backup is disabled in the manifest. **Disconnect phone** removes the
saved pairing and this app's computer association; settings and prior SMS in the
original messaging app are separate.

## Retention and removal

Saved credentials and reusable connections remain until replaced or removed
through their owner controls. There is no general automatic retention period
for local configuration, audit history, task history or recovery logs in v1.

A login-code window expires after two minutes and is cleared by the normal
completion/cancellation path. Expiry prevents reuse; it is not a promise of
physical erasure on disk or a background purge after an abrupt shutdown.
The stopped-sign-in structural diagnostic is shown only while it matches the
pending challenge and is at most 24 hours old. That display limit is not a
24-hour storage deletion policy. It contains fixed structural categories and
sanitized route hints, not page text or input values.

**Forget saved login** removes that account's local saved credential, connection,
password-source binding and pending browser-session request, and resolves its
pending sign-in challenges. It keeps the reviewed connector, shared verification
sources, audit history and task records. Disconnect a shared mailbox or phone
separately. Disconnecting locally does not promise server-side OAuth revocation;
use the provider's own security controls to revoke its authorization as needed.

An explicit login CSV export contains a plaintext password. Import files and
exports you keep remain your responsibility. Portable backup/restore of the
installed protected vault is outside v1. Uninstalling the software is not a
verified erase-all-data operation. Forget/disconnect do not remove copies in
SQLite recovery media, system backups, exported files, the original messaging
app, a website, a mail provider or an AI tool that already received an approved
result. No secure-erasure claim is made.

## Evidence and release approval

The [technical disclosure review](../qa/gates/release-disclosures-2026-10-31.md)
maps these statements to the shipped source and behavioral checks. Actual
[installed Mac acceptance](../qa/release122-2026-10-31/acceptance.md) covers the
public example and local owner controls, not private MFA acceptance.

Publisher: **Nir Fainshtein**, **עוסק פטור** (owner supplied). The public
support/privacy email still needs the owner's choice. Final public release text
and any store declaration remain subject to owner approval in
[READINESS.md](../READINESS.md); no store review has been submitted.
