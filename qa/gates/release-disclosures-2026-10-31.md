# Release data-disclosure review - 31 October 2026

Outcome: the [candidate disclosure](../../docs/data-handling.md) and
[privacy draft](../../docs/release-copy-draft.md) now state the actual storage,
recipient, permission and removal limits. This closes the technical disclosure
work; it does not approve legal text, publish the release or qualify private MFA.

The application and permission sources under `account_access`, `android/app`,
`macos/AccountAccess.swift` and `macos/build.sh` have no changes between installed
image source `26b30499a2da40d66e239563a03289f8066c694e` and this review. The later
updater-helper correction does not change these behaviors. Existing signed-image
and actual owner-app evidence remains in [build-122 acceptance](../release122-2026-10-31/acceptance.md).

| Statement checked | Implementation evidence |
|---|---|
| Secret records encrypted; configuration and audit metadata not all encrypted | `account_access/storage.py`: AES-GCM `seal`/`unseal`, private SQLite files, separately readable metadata tables and private configuration JSON. No live vault was opened. |
| Agent receives approved results rather than raw credentials/codes | `account_access/broker.py` permission and result boundaries; `account_access/providers.py` secret-key/value redaction; installed Codex/Claude public-read acceptance above. |
| No configured publisher analytics/advertising/crash collector in application code | Reviewed application imports, HTTP destinations and runtime dependencies. An OpenTelemetry API dependency is present transitively; no publisher collector/exporter configuration was found in application code. This is a source finding, not a packet-capture or a claim about OS/provider logging. |
| Gmail scope and IMAP read limits stated accurately | `account_access/mailbox_oauth.py`: exact `gmail.readonly` permission; `account_access/codes.py`: bounded Gmail queries, TLS IMAP read-only selection and `BODY.PEEK`; `email_codes.py`: bounded local parsing, no rendering or remote-content fetch. No owner's messages were accessed. |
| Optional password managers and Bitwarden cache disclosed | `account_access/password_sync.py`, `onepassword_source.py`, `bitwarden_source.py`: approved item checks, configured provider/Connect destinations, Bitwarden profile sync and encrypted source-profile persistence. Exact-item output does not mean a one-item encrypted download. |
| Android sends matching message information directly to the Mac | `LoginNotifications.java`, `PhoneCodeDelivery.java`, `LoginDelivery.java`, `account_access/phone.py`: app/sender/template/freshness filters, bounded in-memory queue, pinned HTTPS, exact payload fields, no Account Access cloud relay. |
| Android access permissions and storage stated accurately | Manifest parsed: Internet, camera, companion background execution/data; service permission `BIND_NOTIFICATION_LISTENER_SERVICE`; `allowBackup=false`. No `READ_SMS`, `RECEIVE_SMS`, contacts or microphone permission. `Pairing.java` uses Android Keystore AES-GCM. `ScanActivity.java` decodes frames locally. |
| Android 15+ association and Mac Bluetooth explained | `ComputerAssociation.java`: ordinary scanned BLE association bound to pairing; `macos/build.sh`: matching Bluetooth usage string. Physical phone acceptance remains owner work. |
| Expiry distinguished from deletion | `Codes.begin`/`finish`: two-minute authority and normal cleanup; no general background audit/history purge. `browser_diagnostics.owner_view`: 24-hour display eligibility only. |
| Forget/export and shared-source limits described | `account_access/account_data.py`: exact five record removals, challenge resolution, connector/grants/shared sources retained, plaintext CSV. `mailboxes.remove` clears the profile without a provider revocation promise. Phone Disconnect clears pairing/association. No secure-erasure/uninstall claim. |

Behavioral verification, run in this review:

```text
uv run --no-sync pytest -q tests/test_account_data.py tests/test_mailboxes.py tests/test_mailbox_oauth.py tests/test_phone_connection_test.py tests/test_browser_diagnostics.py tests/test_navigation.py
129 passed in 75.55s (0:01:15)
```

These exercise explicit export/forget boundaries, mailbox connection without
agent access, invalid/replaced OAuth grants, phone-window cleanup and refusal,
and diagnostic value exclusion/age/binding. They use isolated fixtures; no
private account, message, credential, pairing token or code was read.

Public support/privacy contact and owner approval of final release terms remain
the legal/store gate. Legal publisher name and business status are already saved.
The existing daily follow-up retains the unchanged packages for the 1 November
12:00 Asia/Jerusalem macOS 14 runner check; no new package was assembled.
