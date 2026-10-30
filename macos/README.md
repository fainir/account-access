# Graphical Mac app

This is a native installer and owner interface for macOS 14 (Sonoma) or later.

**Current owner-Mac status (30 October):** `/Applications/Account Access.app`
still reports version 0.8.0 build 110; there is no build-119 install receipt.
The source-current build 119 app and public target image are qualified from the
pinned build-118 base, and all shared/runtime/direct native updater probes pass.
The signed, notarized direct-update package is still being assembled. The
previous build-118 installer is superseded and should not be used because it
does not contain the current agent setup fix. Build 119 must pass package
signature, notarization, Gatekeeper and independent expansion checks before it
is opened in Installer. After installation, verify the app version, protected
service restart and fresh Codex/Claude Code access before enabling real account
acceptance. Harel/Phoenix SMS, Lemon Squeezy authenticator, real website email
verification and physical-phone delivery also remain unverified. See
[current acceptance](../docs/production-gates.md).

The complete build 116 package was then opened over this existing installation.
Installer returned error 112 because its protected install journal belongs to a
different image. The full package supports a first install and an identical
retry, not updates over an installed image. The attempt preserved the existing
app and service. Its build report incorrectly said `fresh_install_only: false`;
the source now marks these packages as first-install only and returns a fixed
`existing_installation_requires_update` diagnostic for this journal mismatch.
The current source checks the protected install journal before hashing the
bundled runtime, so a mismatched image refuses before the expensive payload
walk. That check preserves same-image retry recovery but does not add update
support. Use a separately qualified successor package to update an existing
installation; build 116 is not that package.

The owner app's managed-client setup now turns known protected-store response
codes into fixed, actionable messages without displaying response details,
paths or client tokens. Its native regression cases are in
`macos/Tests/OwnerScreenChecks.swift`. On this build Mac, Swift type-checking is
not available because the installed compiler (6.4.0.34.1) does not match the
available macOS 27 SDK (6.4.0.31.4); only syntax parsing ran. The system app is
still build 110 and has not received this source change.
The focused installer/package/transaction suite passes 125 cases with one
host-specific volume-query skip, and the 45-case browser-session module passes.
The local full-suite attempt was incomplete because the default sandbox denied
loopback sockets and its permitted retry was interrupted during a storage lock
wait. The same source commit passed the full Python suite in GitHub CI, along
with native owner UI/gateway/upgrade checks, Android 11/15 journeys, cross-user
password/email/SMS/authenticator recovery and an offline development-package
smoke install ([CI](https://github.com/fainir/account-access/actions/runs/40866251182),
[Mac acceptance](https://github.com/fainir/account-access/actions/runs/40866251306)).
That VM package was a development fixture; it does not qualify a signed update
on the owner's installed Mac.

Consumer package builds also require the pinned Bitwarden OSS npm CLI and its
reviewed corresponding-source release asset. Add these maintainer arguments to
`python -m macos.system_package`:

```sh
--bitwarden-archive /absolute/path/to/cli-2026.10.0.tgz \
--bitwarden-sources /absolute/path/to/account-access-bitwarden-2026.10.0-corresponding-source.tar.gz \
--bitwarden-source-sha256 REVIEWED_SOURCE_SHA256
```

For both runtime inspection and final assembly, also supply
`--pip-wheel /absolute/path/to/pip-26.2.2-py3-none-any.whl`. Its exact upstream
SHA256 is `fd7f4dfa8190e014013b9f08f3e973f4e4c26ffd179a204895533a7254813a70`.
Use the reviewed Python 3.12.16 Apple-silicon archive from python-build-standalone
release `20261026` as the `--python` input:
`cpython-3.12.16+20261026-aarch64-apple-darwin-install_only.tar.gz`,
SHA256 `fbf4afef53c2a6b72bb741bc06d5671a9dfaf87bd84e5aa73ac9b3d0d589f14e`.
The assembler pins the extracted Python tree and refuses any other source
profile. It re-installs the same hash-pinned pip wheel into private copies so
entry points target the protected runtime path, then checks the active pip,
ensurepip seed and bundled CA certificates as data. It never runs pip or
ensurepip. Source inputs remain unchanged. This is not an installed-runtime
repair or an audit of OS or embedded native trust stores.

Prepare the source asset with `python -m macos.bitwarden_sources --output NEW_DIRECTORY`.
Both assets are verified and staged before runtime inspection/signing. The
provider uses the existing protected Playwright Node 24.21.0 and fixed
JavaScript/WASM program with native addons disabled. No standalone executable,
npm install, shell launcher or extra native signing exception is introduced.
The Python tree digest changes and requires normal signing-plan review.

Every binary release containing this GPL program must provide its matching
source archive alongside the installer, at no additional charge, with clear
download directions. The source archive is a separate release asset; it is not
copied into the installed runtime. See [runtime/source packaging](../docs/bitwarden-packaging.md)
for exact validation and source-scope limits. Consumer assembly fails if the
pinned runtime or reviewed source materials are missing.
The full offline payload is archived by Apple's `pkgbuild` with a 30-minute
bounded timeout; it contains over 25,000 files, so a complete signed package can
take substantially longer than the small owner-app build.
The current 0.8 runtime candidate uses Python 3.12.16 and requires **Apple silicon
(M-series)**, running natively. Its cryptography dependency no longer publishes Intel Mac wheels;
Intel and Rosetta bootstrap sessions stop before downloads or runtime changes.
Universal native executables alone do not establish Intel runtime support.
See the [upstream platform change](https://cryptography.io/en/50.0.2/changelog/#v49-0-0).
The pinned Playwright browser runtime also requires macOS 14. Setup shows
installation progress, installs one portable skill and CLI automatically, and
connects supported accounts through the local owner API. Reopening starts the
saved local service; no terminal window is required.

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
ACCOUNT_ACCESS_MAC_BUILD=77 sh macos/build.sh
```

That command creates a development app. Signed system installs must also set
`ACCOUNT_ACCESS_SYSTEM_INSTALL=1`; the direct-update builder refuses a bundle
without this marker before copying it into the qualified image.

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

Public Mac distribution needs a signed installer package and Apple
notarization. The local Keychain now contains a valid Developer ID Installer
identity as well as the application identity, and the existing Notary profile
passed a read-only Apple history check on 27 October. This only confirms the
local signing credentials; package 101's outer package remains unsigned and no
specific Account Access package hash has been correlated with an Apple ticket.
Apple uses Developer ID Application to sign apps and Developer ID Installer to sign
packages distributed outside the Mac App Store
([certificate overview](https://developer.apple.com/help/account/certificates/certificates-overview/)).
A public download is not ready for release. The recording demonstrates the
graphical app build, not a notarized consumer installer.

## Maintainer notarization

This is release engineering, not an end-user installation step. The current
protected distribution is the complete **flat installer package**, which users
download and open in Installer. It needs both the Developer ID Application
identity used for the payload and a separate **Developer ID Installer** identity
with its private key. A valid Notary service Keychain profile is also required;
the existing `AccountAccessPublisher` profile is now confirmed usable for a
read-only status query. These Apple-issued identities and credentials cannot be created by the helper.
Use a Mac running macOS 14 or later with Xcode tools. The helper never disables
Gatekeeper, changes policy rules or removes quarantine to obtain a passing result.

Create the Keychain profile interactively if one does not already exist:

```sh
xcrun notarytool store-credentials AccountAccessPublisher
```

The account owner completes Apple's credential creation and the local prompts.
Leave credentials out of command arguments, chat, source files and ordinary
logs. The helper accepts only the existing profile **label**, not a password or
API key. Apple's tool validates credentials before storing them by default.

After assembling the complete package with `macos.system_package` and
`--installer-identity`, use a new private work directory. The unsigned review
packages in `dist/release-080-review-build*/` deliberately fail this preparation
step. Passing an application-signing identity in place of an Installer identity
does not satisfy the package check.

```sh
uv run python macos/notarize.py prepare \
  --package 'dist/system-package/Account-Access-arm64.pkg' \
  --workdir dist/notarization-package-current --team-id YOURTEAMID
uv run python macos/notarize.py submit \
  --workdir dist/notarization-package-current --profile AccountAccessPublisher
uv run python macos/notarize.py check \
  --workdir dist/notarization-package-current --profile AccountAccessPublisher
uv run python macos/notarize.py finalize \
  --workdir dist/notarization-package-current --profile AccountAccessPublisher
```

Package `prepare` is local-only. It accepts an owned, non-writable-by-others
regular flat package, verifies the trusted Developer ID Installer signature,
expected team, trusted timestamp and leaf-certificate fingerprint, and copies
the input to a private `submission.pkg`. It does not run the installer or inspect
the signing Keychain. The input remains unchanged. Package mode is remembered
in private state for subsequent commands.

The submitted archive remains immutable through Apple status and log checks.
After exact archive acceptance, `finalize` staples a separate copy, rechecks its
Installer signature and certificate, validates the ticket and requires
`spctl --assess --type install` with assessment caches ignored. The accepted
archive's bytes must remain unchanged; only a bounded appended ticket is
permitted, with exact Apple terminator/ticket framing and lengths. A failed
policy check cannot produce a release artifact. The output
is `Account-Access-arm64-notarized.pkg` with its final SHA-256. This protocol is
covered with fictional Apple responses; live Apple acceptance and a downloaded
installation on another Mac remain separate release gates.

The suffix guard is based on Apple's
[package-trailer definition](https://github.com/apple-oss-distributions/Security/blob/db15acbe6a7f257a859ad9a3bb86097bfe0679d9/OSX/libsecurity_codesigning/lib/notarization.cpp#L27-L41)
and [ticket reader](https://github.com/apple-oss-distributions/Security/blob/db15acbe6a7f257a859ad9a3bb86097bfe0679d9/OSX/libsecurity_codesigning/lib/notarization.cpp#L132-L222).
A copy-only compatibility check with the official
[Homebrew 7.0.9 package](https://github.com/Homebrew/brew/releases/tag/7.0.9)
on macOS 27.0.1/Xcode 27.0 added a fresh 1,685-byte ticket suffix, preserved the
original package and XAR table of contents, and passed the actual helper's
signature, ticket and install-policy checks. That checks the current tool path;
it is not notarization or installation acceptance for Account Access. A separate
padding experiment passed the native checks but was rejected by the helper's
strict framing check; native ticket validation alone does not establish that
only ticket bytes were appended.
[Native tool evidence and scope](../artifacts/flat-pkg-notarization-20261019.json).

Keep the Bitwarden corresponding-source archive and notices beside any
distributed package as described in [Bitwarden packaging](../docs/bitwarden-packaging.md).
Notarizing an app ZIP alone does not notarize the complete protected installer.

The earlier standalone-app ZIP mode is retained for its own distribution. It
does not provision the current protected service. For that app mode, after
building and signing, use a new private work directory outside the app:

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
architectures and bundled-wheel pin. Current bundles declare browser-extension
format 1 and contain exactly the six reviewed SMS-helper files. Missing or extra
files, unsupported formats and changed prepared helper content stop before
upload; helper hashes are checked again after the final archive is unpacked.
Legacy bundles without that marker retain their original resource layout.
It copies the app, so the input app is preserved. Unknown nonempty work directories, symlinks and conflicting release
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
  macos/AccountAccess.swift macos/MailboxOAuthLoopback.swift macos/OwnerGateway.swift macos/DesktopOwnerConnection.swift \
  macos/BrowserNativeHost.swift macos/ManagedAgentSetup.swift macos/WorkerBootstrap.swift macos/WorkerListenerBindings.swift \
  macos/BackgroundRecovery.swift macos/MessageText.swift macos/MessagesReader.swift \
  macos/SystemMessagesReader.swift macos/Tests/OwnerScreenChecks.swift \
  -o /tmp/account-access-owner-checks
/tmp/account-access-owner-checks
```
