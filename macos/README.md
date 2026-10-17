# Graphical Mac app

This is a genuine native installer and owner interface for macOS 14 (Sonoma) or later, on Apple silicon or Intel. The pinned Playwright browser runtime requires macOS 14; the candidate's app metadata and installer preflight enforce this requirement before downloads or runtime changes. It runs the published, checksum-verified bootstrap, shows installation progress, automatically installs one portable skill and CLI, and connects supported accounts through the authenticated local owner API. Reopening it starts the saved local service; no terminal window is required.

The candidate account catalog contains a limited Namecheap password pilot as well as public SauceDemo and The Internet examples. The Namecheap operation confirms only the signed-in username. A private Chrome credential was imported, but sign-in stopped at browser verification/HTTP 429; password and email/TOTP acceptance remain open. See [other-service validation](../docs/other-service-validation.md). The app includes reviewed password-export import, explicit authenticator enrollment, TLS IMAP/Gmail source setup, an iPhone Messages reader and Android pairing. Imports do not add support for arbitrary websites. Real provider delivery and physical-phone validation remain outstanding.

Candidate build **52** separates saved verification setup from a checked mailbox
connection and completed website login. **Check email connection** fetches no
messages and starts no website sign-in. Saving verification setup cannot retry
an unrelated browser or owner-presence gate; editing a browser credential drops
the old saved session when changed and preserves unrelated challenges. All 17
native owner checks passed, and graphical repair preserved the existing accounts
and original blocked task. See [validation](../docs/validation.md).

Candidate build **53** adds **Verification → Connect Gmail or email**, available
before a website is connected. Gmail requires only an email address and masked
Google app password; other providers expose their TLS IMAP server and port.
One encrypted mailbox can be selected by exact matching approved website
sources. The owner can check, update or disconnect it without initiating a
website login. All nineteen native owner checks passed, and the signed build
was installed and visually checked locally. Private Google app-password
enrollment and code delivery remain separate acceptance gates.

Candidate build **54** resumes recognized mailbox-access interruptions after a
fresh successful owner check, with active permissions and unchanged connection
configuration. Completed steps survive a service restart. Gmail OAuth health
is bound to the authorization identity, so a new authorization or uncertain
renewal needs a new check. This signed universal build is staged separately;
build 53 remains installed while the owner Gmail form is awaiting enrollment.
No private mailbox or physical-device acceptance is implied.

Candidate build **55** adds background recovery health on **Your accounts**.
Internal worker errors retry automatically with backoff; the banner clears on
the next successful check. Messages are fixed text, with no exception or provider
details. All twenty native owner checks pass. The signed candidate is prepared
separately while installed build 53 remains open for owner Gmail enrollment.

Candidate build **56** identifies public example accounts in the catalog,
import review and Accounts screen. Example readiness is counted separately, and
an example-only setup offers a test prompt. Import summaries require the saved
connection to be ready before showing Connected; an empty error list alone is
insufficient. The change derives presentation metadata without changing account
fingerprints, grants or saved task steps. All twenty-one native checks pass.

Candidate build **57** adds a separate local supervisor. A crashed service
restarts and continues saved tasks without another agent command; Pause and
updates stop its current generation. Locked-keyring/setup failures stop retries
instead of repeating prompts. The native window verifies the restarted endpoint
before sending setup data, preserving idle forms and never replaying a request
after a lost response. This remains user-space process recovery, with the same
pending notarization and private-account gates. Installed build 53 is preserved.

Candidate build **58** adds an embedded, signed LaunchAgent registered through
Apple's ServiceManagement API. Its guardian waits for the active supervisor and
can take over after process loss. A disabled item stays disabled; Login Items is
the owner action when macOS requires approval. Pause is available in the native
app menu and stops recovery across subsequent job launches. A real QA app
verified registered-job crash recovery and Pause, then removed its fixture job
and Keychain item. A private payload record enforces the signed wheel digest
for same-version updates; stale records are rejected and failed repairs preserve
the old digest. All 633 regression tests passed. Actual logout/reboot, the
installed owner upgrade, notarization and private account acceptance remain open.
This adds no separate-OS-identity credential boundary.

Candidate build **59** fixes failed-update rollback. The stop command waits for
the supervisor and service leases, and the supervisor holds its lease until its
owned child is reaped. If stopping a replacement fails, its runtime is retained
and the previous service is not restarted concurrently. Failed payload
publication restores the preceding desktop launcher as well as the runtime
launcher. Four new regressions reproduced the previous failures; all 49 focused
installation/supervision/setup cases pass. Final CI passed 637 tests, native
checks and the Android emulator journey. A separately signed QA app again passed
actual registered-job recovery/Pause and removed its job and fixture key. The
installed owner app and enrollment form were not changed; private authentication
and notarized distribution acceptance remain open.

Candidate build **60** binds the signed wheel record to its activated interpreter,
launcher digest and exact isolated command. Native reopening and the background
helper reject an uncommitted environment or changed launcher. Updated clients
running from a retained environment start the activated service, and Pause still
prevents startup. A real Mac fixture verified this cold start alongside OS-job
recovery, then removed its job and fixture key and confirmed process shutdown.
Preflight rejects unsafe existing runtime directories, launchers and lock files
before executing an old installation. Forty-nine bootstrap/automatic-startup
cases pass under a restrictive umask; final CI passed 661 tests plus native
checks and the Android emulator journey. Eight background checks cover actual
Mac path aliases as well as spaces and apostrophes. Unchanged legacy clients need a host
integration refresh/restart. These are controlled checks; private-authentication,
installed owner upgrade, distribution and separate-identity gates remain open.

Build with Xcode's command-line tools:

Staged signed build **61** aligns the app's minimum OS version with
the pinned browser runtime and stops unsupported installations before runtime
changes. Both universal executables, their Developer ID signatures, hardened
runtime/timestamps and the wheel's source contents were checked locally.
Fifty-nine focused installer/rollback cases passed; matching source CI passed
724 tests, native owner/UI/background checks and the Android emulator journey.
The separate cross-user Mac browser workflow failed and is excluded from that
acceptance. This does not replace the
installed build 53 and does not enable the separate-user worker component.
Apple notarization was prepared locally but not submitted. See the
[packaging evidence](../artifacts/mac-platform-061.json); clean-Mac installation
and private sign-in acceptance remain open.

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
launcher is replaced. Startup failure restores it and restarts the
previous service only after replacement shutdown is confirmed. An uncertain stop
keeps the replacement environment for a later repair. Failed publication also
restores the desktop launcher's previous data-directory arguments. Previous environments remain available for rollback and
existing agent launchers; no automatic pruning is shipped. Python and Chromium
can still require vendor downloads. Notarization and clean-Mac installation
remain separate acceptance gates.

The 0.8 candidate adds **Repair installation…** to the app menu. Installation explicitly stops and restarts the background service after replacing the package, including a repair with an unchanged version number. Credentials, grants and task checkpoints are preserved. The candidate also includes local Authenticator transfer-QR selection for browser verification. These are not evidence of completed physical-device or private mailbox QA; see [production acceptance](../docs/production-gates.md).

Public Mac distribution needs Apple notarization as well as signing. The current recorded build is Developer ID signed and works locally; notarization remains pending because the configured Xcode account could not authenticate. A public preview download can therefore be blocked by Gatekeeper. The recording demonstrates the actual graphical build, rather than the older `.command` launcher.

## Maintainer notarization

This is release engineering, not an end-user installation step. Users still
download, unzip and open the app. The maintainer uses a Mac running macOS 14 or
later with Xcode tools, a Developer ID certificate and a valid Notary service
Keychain profile. This helper requires `syspolicy_check`; it never disables
Gatekeeper or removes quarantine to obtain a passing result.

Create the Keychain profile interactively if one does not already exist:

```sh
xcrun notarytool store-credentials AccountAccessPublisher
```

The account owner completes Apple's credential creation and the local prompts.
Leave credentials out of command arguments, chat, source files and ordinary
logs. The helper accepts only the existing profile **label**, not a password or
API key. Apple's tool validates credentials before storing them by default.

After building and signing, use a new private work directory outside the app:

```sh
uv run python macos/notarize.py prepare \
  --app 'dist/macos/Account Access.app' \
  --workdir dist/notarization-current --team-id YOURTEAMID
uv run python macos/notarize.py submit \
  --workdir dist/notarization-current --profile AccountAccessPublisher
uv run python macos/notarize.py check \
  --workdir dist/notarization-current --profile AccountAccessPublisher
uv run python macos/notarize.py finalize \
  --workdir dist/notarization-current --profile AccountAccessPublisher
```

`prepare` is local-only. It validates the Apple-anchored Developer ID signature,
expected team, hardened runtime, timestamp, executable permissions, both CPU
architectures and bundled-wheel pin. It copies the app, so the input app is
preserved. Unknown nonempty work directories, symlinks and conflicting release
processes are refused. Work files and tool diagnostics are private; do not
publish the work directory.

`submit` records the upload boundary before contacting Apple and saves its job
ID and an archive-bound receipt. Repeating it checks the same job instead of
uploading again. A captured receipt can recover an interrupted state write.
If an upload's outcome is unknown and no receipt exists, inspect Apple's
submission history through the authenticated tool; do not blindly resubmit.
For a known job use `adopt --submission-id UUID --workdir ... --profile ...`.
Final acceptance still requires its log's job ID, archive name and SHA-256 to
match this prepared archive. If no job exists after a credential failure, repair
the profile and explicitly start a new work directory after that review.

`check` makes one status request; an observation failure preserves the existing
handle. `status` reports cached state only. `finalize` rechecks Apple's acceptance
and archive digest, staples and validates the ticket, revalidates signatures and
the wheel pin, and runs the system distribution check. It then unpacks the ZIP
in a private temporary directory and repeats the signature, wheel, ticket and
distribution checks on the extracted app. Unexpected archive paths, symlinks,
oversized archives and changed executable permissions are refused. Only then
can it finalize `Account-Access-Mac-notarized.zip` and report `READY_FOR_RELEASE_REVIEW` with its
checksum. It does not publish a release or certify private-account production
coverage. A rejected, unknown or mismatched result cannot produce that artifact.

The protocol/interruption tests use simulated Apple responses. Real build 56
passes the local preparation and extracted signature checks, while the actual
distribution and extracted-ticket checks correctly reject its missing ticket.
Live submission, stapling, acceptance and
clean downloaded installation remain unverified until the publisher connects
valid Notary service credentials. See [validation](../docs/validation.md).

Apple documents [notarization](https://developer.apple.com/documentation/security/notarizing-macos-software-before-distribution)
and [system distribution checks](https://developer.apple.com/forums/thread/706442).

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
  -framework AppKit -framework CryptoKit -framework ServiceManagement -lsqlite3 -lbsm \
  macos/AccountAccess.swift macos/OwnerGateway.swift macos/DesktopOwnerConnection.swift \
  macos/BrowserNativeHost.swift macos/ManagedAgentSetup.swift macos/WorkerBootstrap.swift \
  macos/BackgroundRecovery.swift macos/MessageText.swift macos/MessagesReader.swift \
  macos/SystemMessagesReader.swift macos/Tests/OwnerScreenChecks.swift \
  -o /tmp/account-access-owner-checks
/tmp/account-access-owner-checks
```
