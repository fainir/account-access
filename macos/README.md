# Graphical Mac app

This is a genuine native installer and owner interface for macOS 13 or later, on Apple silicon or Intel. It runs the published, checksum-verified bootstrap, shows installation progress, automatically installs one portable skill and CLI, and connects supported accounts through the authenticated local owner API. Reopening it starts the saved local service; no terminal window is required.

The candidate account catalog contains a limited Namecheap password pilot as well as public SauceDemo and The Internet examples. The Namecheap operation confirms only the signed-in username. A private Chrome credential was imported, but sign-in stopped at browser verification/HTTP 429; password and email/TOTP acceptance remain open. See [other-service validation](../docs/other-service-validation.md). The app includes reviewed password-export import, explicit authenticator enrollment, TLS IMAP/Gmail source setup, an iPhone Messages reader and Android pairing. Imports do not add support for arbitrary websites. Real provider delivery and physical-phone validation remain outstanding.

Build with Xcode's command-line tools:

```sh
uv build
sh macos/build.sh
```

For Developer ID signing, set `ACCOUNT_ACCESS_SIGNING_IDENTITY` to your own certificate name before building. The app and ZIP are written to `dist/macos/`.

Build the wheel first: the wheel and its SHA-256 are embedded in the app's signed bundle. Installation verifies that pin before installing the bundled package. The standalone shell path downloads the package and checks its manifest; when a signed-app pin is supplied, it checks that too. Rebuild the app if the wheel changes.

The candidate wheel also contains `account_access/runtime-requirements.txt`,
exported from `uv.lock`. CI and the Mac build check that it matches the tested
graph. Installation enforces every package's hash and refuses source builds,
including when using a configured alternate registry. When intentionally updating
dependencies, regenerate that file before building:

```sh
uv export --locked --no-dev --no-emit-project --no-annotate --no-header --format requirements.txt --output-file account_access/runtime-requirements.txt
```

Repairs prepare a separate runtime under `runtime/environments/`, install its
browser, and check imports before stopping the saved service. Only an owned
launcher is replaced. Startup failure restores it and attempts to restart the
previous service. Previous environments remain available for rollback and
existing agent launchers; no automatic pruning is shipped. Python and Chromium
can still require vendor downloads. Notarization and clean-Mac installation
remain separate acceptance gates.

The 0.8 candidate adds **Repair installation…** to the app menu. Installation explicitly stops and restarts the background service after replacing the package, including a repair with an unchanged version number. Credentials, grants and task checkpoints are preserved. The candidate also includes local Authenticator transfer-QR selection for browser verification. These are not evidence of completed physical-device or private mailbox QA; see [production acceptance](../docs/production-gates.md).

Public Mac distribution needs Apple notarization as well as signing. The current recorded build is Developer ID signed and works locally; notarization remains pending because the configured Xcode account could not authenticate. A public preview download can therefore be blocked by Gatekeeper. The recording demonstrates the actual graphical build, rather than the older `.command` launcher.

The app hides saved passwords and owner/client tokens. Authenticator setup keys and Android pairing are intentionally visible only during owner enrollment; never record private enrollment secrets. Owner metadata is checked for file ownership and private permissions, the local server identity is verified with a fresh HMAC challenge, and HTTP redirects are refused. Connection retries retain the service's login throttle and stop for genuine owner-presence challenges.

The signed Messages helper reads only configured incoming, recent login messages. Its private IPC is bound to owner enrollment and authenticated with an owner-only key. macOS Full Disk Access remains a broad OS permission; the application filter is narrower. Do not grant broad disk access to Python for this reader. Same-user unrestricted shell access remains outside the local custody boundary.

Candidate GitHub SMS setup has a separate owner-only discovery step: after its
reviewed login requests one SMS, the app checks at most 20 fresh incoming texts
for a recognized GitHub login template. A local review shows the sender suffix
and the pattern with the code removed. Subsequent reads use that exact filter.
The native text decoder supports a constrained typedstream string prefix without
instantiating archived classes. The committed fictional fixtures were generated
with Apple Foundation by `Tests/GenerateMessageFixtures.m`; the reader tests
cover Unicode, formatting metadata, unsupported roots and malformed data.

Version 0.6 adds an account dashboard, persistent navigation, connection/approval badges, password-export guidance, friendly verification labels and ordinary-language examples. The installer adds a small managed instruction block to Codex and Claude Code profiles for new sessions, refreshes owned skill resources without rotating valid client tokens, and starts the saved local service on demand. Codex receives an allow rule for only the installed client's supported commands. Personal instructions, general approval modes, other command rules and Claude permission settings are preserved. See [automatic session setup](../docs/automatic-sessions.md).

Version 0.7 adds **Password sync** for exact approved items on an existing 1Password Connect server, defaults password-export cleanup to Trash, and adds clearer security copy. Chrome/CSV imports remain snapshots. New backend checks bind code resolution to an active unchanged source, recheck the verification page, validate native form destinations, and harden private file writes. These preserve automatic routine logins; they do not establish isolation from an unrestricted same-user process. See [security and sync](../docs/security-and-password-sync.md).

Version 0.7.1 fixes the sync screen's field constraints. The native owner-screen regression check runs the actual screen construction, checks the four inputs and masked token, and verifies the narrow window layout:

Version 0.7.2 also verifies the import summary: a saved password with an unfinished sign-in shows a repair action, while a successful verification shows Connected. **Show sign-in problem** runs a bounded visible check through the authenticated owner session; it never expands the account's grants or exports page HTML to the agent API.

```sh
xcrun swiftc -O -parse-as-library -D ACCOUNT_ACCESS_UI_CHECKS \
  -framework AppKit -framework CryptoKit -lsqlite3 \
  macos/AccountAccess.swift macos/MessageText.swift macos/MessagesReader.swift macos/Tests/OwnerScreenChecks.swift \
  -o /tmp/account-access-owner-checks
/tmp/account-access-owner-checks
```
