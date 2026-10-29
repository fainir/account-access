# Encrypted vault backup and restore

Account Access can create a password-protected backup containing the encrypted
vault, approved account configuration and the vault key wrapped inside the
backup encryption. The backup uses scrypt and AES-GCM, is written with owner-only
file permissions, and never replaces an existing destination file. Use a unique
passphrase with at least 12 characters and keep it somewhere separate from the
backup. The app never prints or saves that passphrase.

Before backing up or restoring, stop Account Access so no sign-in or background
task can change the vault:

```sh
account-access stop
account-access backup --file ~/Documents/account-access.aabackup
```

Restore the backup on this or another Mac user account with Account Access
installed. The encrypted archive includes the vault key only inside its
passphrase-protected payload, so the original Mac Keychain is not required:

```sh
account-access restore --file ~/Documents/account-access.aabackup
account-access start
```

Restore asks you to type `RESTORE` before replacing the current vault, then asks
for the backup passphrase without displaying it. It validates the archive,
configuration, database and encrypted records before publishing anything. If
publication is interrupted, the next app start rolls back the partial restore;
after a complete restore it finishes cleanup. Keep the Mac awake until the
command reports success.

The backup does not include installed Codex or Claude Code files, the Android
app, or third-party provider state. Reconnect agent integrations or pair the
phone again if the restored installation asks. The archive is a recovery copy,
not secure deletion: delete old backup files using the storage provider's
normal controls when they are no longer needed.
