# Import saved passwords

Choose **Import saved passwords** in Account Access and select a local export.
The candidate accepts Chrome, Apple Passwords, compatible 1Password and Bitwarden
CSV files. It also accepts Bitwarden's **unencrypted JSON** export. You review the
supported website accounts and their permitted reads before enrollment.
Passwords stay hidden and encrypted during local review; only selected accounts
are enrolled. The review expires after ten minutes.

## Bitwarden JSON

In Bitwarden, open **Export vault**, choose the vault you want to export, and
select the plain **.json** format. Complete Bitwarden's own export authorization,
then choose that file in Account Access. Do not choose **.json (Encrypted)** or a
ZIP archive. Account Access does not ask for your Bitwarden master password or
attempt to decrypt a protected backup.
[Bitwarden's export instructions](https://bitwarden.com/help/export-your-data/).

One login can contain several website URIs. Account Access shows each distinct
literal web URI for local review, matching it only against existing reviewed
connectors. You choose the account when several connectors match the same origin.
Nothing is visited or imported during preview. Unsupported websites are excluded
from encrypted staging, and an import cannot add a new website connector.

Only active login items can provide a username and password. Notes, payment
cards, identities, SSH keys, passkeys, password history, attachments and custom
fields are not retained. App-only URIs and URI entries configured as **Never** or
**Regular expression** are skipped. Other URI matching settings do not broaden
the connector's reviewed origins or destinations. This follows the public
[Bitwarden JSON structure](https://sdk-api-docs.bitwarden.com/src/bitwarden_exporters/json.rs.html)
and [URI setting values](https://sdk-api-docs.bitwarden.com/bitwarden_vault/enum.UriMatchType.html).
Login items without website URIs are skipped, including the omitted collection
allowed by Bitwarden's [client export model](https://github.com/bitwarden/clients/blob/main/libs/common/src/models/export/login.export.ts).

Included authenticator secrets require the separate **Also enroll included
authenticator keys** checkbox and a matching supported login factor. The import
accepts supported six-digit, 30-second SHA1 TOTP settings; unsupported keys are
reported without retaining their value. There is no silent authenticator import.
Changing or disabling the saved authenticator while a review is open invalidates
its authenticator selection; choose a fresh preview before replacing that key.
Password-only import does not depend on the authenticator enrollment.

Exports are limited to 4,000,000 UTF-8 bytes, 10,000 items and expanded login rows,
and 64 URIs per Bitwarden item. Duplicate JSON keys, encrypted exports, malformed
login values and incomplete JSON are refused before credentials are saved.

## Keep the export local

Plain CSV and JSON exports contain passwords and may contain authenticator keys.
Never upload them or paste their contents into chat. The native app can move the
chosen export to Trash after a successful import. That does not securely erase
the file or remove copies and backups; the browser setup page cannot delete it.

Saving a selected login replaces its previous saved login and session and removes
an older password-manager source for that account. A later background read cannot
overwrite that explicit import. Account grants remain limited to the reads you
approve, and importing does not dismiss independent website challenges.

## Password changes

CSV and Bitwarden JSON imports are snapshots. Re-export and review a changed
password when needed. Account Access does not watch a plaintext export or claim
continuous Chrome or Bitwarden synchronization. For ongoing exact-item updates,
the separate [1Password service-account or Connect source](onepassword-sync.md)
uses a configured read-only connection.

The JSON import tests use fictional exports and local websites. Real private
Bitwarden export and sign-in acceptance remain unverified.
