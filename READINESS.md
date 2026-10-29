# Account Access - Readiness

Definition of done: every row below is `verified`, `cut`, `owner` or `waiting`, and every gate passes.
Statuses: todo | building (who) | verified | owner | waiting | cut (reason)

## Scope

| Surface | Production URL / store / channel | Run | Test | Deploy |
|---|---|---|---|---|
| macOS owner app, protected service and installer | GitHub release; latest public build is 0.7.4 preview | `uv run account-access --help`; macOS app via `macos/build.sh` | `uv run pytest -q`; native probes under `scripts/` and `macos/Tests/` | Signed, notarized package; release process in `macos/README.md` |
| Existing local AI agents | Codex and Claude Code local sessions | Start a fresh local agent session after app setup | Installed Account Access skill and launcher; agent protected-operation acceptance | Installed app manages shared agent integration |
| Chrome password import | Local Chrome profile and local Account Access app | App > Import saved passwords | `tests/` import tests plus owner-selected Chrome export | Bundled in macOS app |
| Email / SMS / authenticator verification | Gmail or TLS IMAP; Android companion; TOTP | App > Verification; `android/README.md` | MFA tests plus real mailbox, physical phone and supported site | macOS app and signed Android distribution |

## Flows

| ID | Flow (user words) | Surfaces | Status | Evidence | Verified on |
|---|---|---|---|---|---|
| F1 | Install or update the Mac app, connect its protected service and reopen it after restart; interrupted updates retain the prior usable app | macOS Installer, app, protected service | owner | [Build 114 owner-Mac installer result](qa/owner-upgrade114-installed-2026-10-29.log): first attempt returned generic error 112; same signed package then installed successfully in 391.96 seconds. It is script-only, so no receipt is expected. The current `/Applications` app launches, but still prompts to upgrade its AI connection; reboot/reopen acceptance remains. A separate stale user app copy is 0.6.0 build 7 | 2026-10-29 |
| F2 | Import a Chrome export, review matches and save only selected accounts; malformed or cancelled imports save nothing | Chrome, macOS app, vault | verified | [password import regression suite](qa/password-import-source-qa-2026-10-28.log): 63 passed; [owner UI acceptance](docs/other-service-validation.md#namecheap-password-pilot) is historical, with no export-file secrets accessed in this run | 2026-10-28 |
| F3 | Connect Gmail or TLS IMAP and use a fresh matching code; permission, expiry or ambiguous-mail errors stop safely | macOS app, Gmail / IMAP, connector | owner | [154 Gmail, IMAP, OAuth and verification tests](qa/email-verification-source-qa-2026-10-28.log); [24 reusable-mailbox tests, including deterministic uncertain-refresh coverage](qa/gmail-refresh-timeout-2026-10-28.log); [138-case email/SMS/authenticator setup regression suite](qa/verification-source-qa-2026-10-28.log) | 2026-10-28 |
| F4 | Pair Android and deliver a fresh approved SMS; denied permissions, redaction or a stale code refuse delivery | macOS app, Android 15+, supported connector | owner | [Current Android build and signature check](qa/android-current-build-2026-10-29.log) passed. [GitHub emulator journey](https://github.com/fainir/account-access/actions/runs/40797912092) passed Android 11 automatic/owner-entered login and Android 15 refusal without pairing. Local emulator/phone is unavailable; physical Android 15+ pairing and real SMS acceptance remain; [Android setup](android/README.md) | 2026-10-29 |
| F5 | Enroll an authenticator and finish a Lemon Squeezy TOTP login; invalid codes preserve the enrollment and reveal no secret | macOS app, Lemon Squeezy | owner | [95-case local suite: 93 passed in the concurrent run; the 2 timing-sensitive cases passed alone](qa/totp-source-qa-2026-10-28.log); [138-case authenticator setup/import regression suite](qa/verification-source-qa-2026-10-28.log); [provider acceptance](docs/other-service-validation.md#lemon-squeezy-authenticator-acceptance) shows the private challenge is unqualified | 2026-10-28 |
| F6 | Use local Codex or Claude Code for an approved read; unsupported sites and operations refuse without returning secrets | Codex / Claude Code, local launcher, connector | owner | [agent setup, policy and client source QA](qa/agent-local-qa-2026-10-28.log): 156 passed. [Launcher/account acceptance](qa/agent-launcher-connection-2026-10-29.log) shows the service returns only synthetic demo grants on 0.6.0; [fresh smoke](qa/agent-owner-access-2026-10-29.log) returned `RETRYABLE browser_execution_failed` and no account data. The live-CLI harness refuses when effective tool permissions cannot be proved. The current `/Applications/Account Access.app` still needs its owner-approved AI connection upgrade before I can retry the live smoke; no end-to-end agent use is verified | 2026-10-29 |
| F7 | Refuse expired, ambiguous or unauthorized verification and explain the next step without exposing a code | macOS app, agent, local service | verified | [MFA refusal and expiry tests](tests/test_multifactor.py) and [identity-code boundary tests](tests/test_identity_contact_login.py) | 2026-10-28 |
| F8 | Review, edit, export or delete saved account data; invalid requests preserve the vault and exports are identified as plaintext | macOS app, encrypted local store | building (Codex) | [saved-login source checks](qa/account-data-qa-2026-10-29.log): owner-only export/removal endpoints and explicit macOS controls; [build 116 app compile/sign QA](qa/macos-app-build116-2026-10-29.md) passes. Fresh runtime inspection passed with current-source native helpers. The package-only timeout fix passed [45 focused checks](qa/macos-system-package-timeout-2026-10-29.md); corrected full package assembly is running | 2026-10-29 |
| F9 | Sign in to Harel or Phoenix using approved Android SMS and return only session status; changed pages or unsupported challenges stop safely | macOS app, Android, insurer connector | building (Codex) | [Provider-specific flow gaps](docs/insurer-login-acceptance.md); [fresh public login form observation](qa/insurer-public-login-2026-10-29.md). Neither provider has an approved narrow network flow or physical-phone acceptance yet | 2026-10-29 |

## Gates

| Gate | Status | Evidence |
|---|---|---|
| Security: endpoint authorization, secret handling, input validation, auth rate limits, dependency audit | todo | [Pinned Python dependency audit](qa/security-dependency-audit-2026-10-29.log) found no known vulnerabilities. Endpoint, native runtime and release security review remain incomplete. |
| Data: reversible migrations, tested backup/restore, user data export/delete | todo | No production restore acceptance recorded. |
| Reliability: health checks, alerts, structured logs, retries/idempotency, provider-down behavior | todo | Installer update/recovery currently being diagnosed; production monitoring not verified. |
| Performance: key surfaces on mobile, Lighthouse performance and accessibility at least 90 where applicable | todo | No complete release measurement recorded. |
| UX/UI: screens checked at 375px and desktop, empty/error/loading states, contrast and keyboard | todo | Native UI and phone acceptance remain open. |
| Legal/store: privacy, terms, listings and data-safety statements match behavior | todo | Public download is labeled preview; production listing review not complete. |
| Ops: CI green, one-command deploy, rollback, environment documentation, release signatures | todo | CI for the latest code is green. Build 114's signed/notarized script-only update installed on the owner Mac; rollback and the complete consumer package remain unverified. |
| Cost: recurring services and provider fees are documented with an owner-approved cap | verified | [PRODUCT.md](PRODUCT.md) keeps v1 local with no recurring cloud or SMS relay cost; later paid services require explicit approval. |

## Owner actions

1. In the open **Account Access** window launched from **/Applications**, click **Upgrade AI connection** and approve the native macOS prompt if it appears -> unblocks the protected Codex/Claude connection for F1 and lets me complete F6 acceptance. Keep any password in the macOS dialog.
2. In Account Access > Verification, connect the approved Gmail account in Chrome and select **Check Google connection**. Then use a supported account with a real email-code challenge and complete it in Account Access; this unblocks private mailbox and delivery acceptance. Keep mailbox passwords and login codes out of chat.
3. Open Account Access > Verification > Pair Android phone, scan its pairing QR, and approve the requested access on Android; this unblocks real SMS acceptance. No phone code belongs in chat.
4. Sign in to Lemon Squeezy through Account Access once with your authenticator app; this confirms its private TOTP challenge and enrollment against the real site. Keep the password and generated codes in their intended apps.

## Waiting on third parties

| What | Since | Next check | Notes |
|---|---|---|---|
No external store or provider review has been submitted, so no third-party review wait is active.

## Log (last 10)
- 2026-10-29 - Fresh build 116 runtime inspection passed with current-source Developer ID-signed helpers. The full `pkgbuild` pass exceeded its former 10-minute bound; the package-only timeout is now 30 minutes and its regression is covered by [the focused suite](qa/macos-system-package-timeout-2026-10-29.md). The first stale-helper package is not a release candidate.
- 2026-10-29 - GitHub CI passed on `d71e709`: native owner UI/gateway, tests, separate-user workers and Android journey all passed.
- 2026-10-29 - Build 114's first postinstall attempt failed with generic PackageKit error 112; retrying the same signed package succeeded in 391.96 seconds. The package is script-only, so no receipt is expected. The launched `/Applications` app still shows “Upgrade AI connection”; evidence: [owner-Mac install](qa/owner-upgrade114-installed-2026-10-29.log).
- 2026-10-29 - The installed Account Access launcher returned only controlled-demo grants; a permitted synthetic summary smoke returned `RETRYABLE browser_execution_failed` without account data. The owner connection upgrade is still required; evidence: [agent launcher smoke](qa/agent-owner-access-2026-10-29.log).
- 2026-10-29 - `uv run pytest -q` after the restrictive-umask fixture fix passed 4,530 tests; 4 skipped. Evidence: [full suite](qa/full-suite-after-fixture-fix-2026-10-29.log).
- 2026-10-29 - The system app is 0.8.0 build 110; a separate per-user app is stale at 0.6.0 build 7. The local Codex/Claude connection is not yet upgraded, and the live agent harness correctly refuses to proceed without an effective permission boundary.
- 2026-10-29 - Android companion preview and instrumentation APKs compiled from current source and passed APK signature verification. No local emulator or phone is available; physical Android 15+ acceptance remains an owner action.
- 2026-10-29 - GitHub Android emulator journey passed: Android 11 automatic and owner-entered SMS login, plus Android 15 refusal of notifications/manual codes without computer association. This does not prove a positive Android 15 paired-phone flow; physical acceptance remains open.
- 2026-10-29 - Saved-login export and forget flows have 11 passing source integration tests and 74 owner-gateway checks; native screen check and packaged app acceptance are in progress.
- 2026-10-29 - A prior full-suite run exposed a fixture mismatch: recreated 0755 test directories inherited a restrictive umask. The fixture now chmods them explicitly; the owner-upgrade110 and cost modules passed 12/12 under umask 077. The post-fix full run is recorded above.
- 2026-10-29 - Public Chrome inspection found Harel's identity/mobile dialog with SMS selected and email as an alternative, and Phoenix's state-bound identity/contact form with SMS/email and voice-call controls. No values were entered or codes requested; details are in `qa/insurer-public-login-2026-10-29.md`.
- 2026-10-29 - Build 114 passed whole-module compile, ordinary-entrypoint refusal, exact 27,532-row predecessor projection, notarization/stapling, Developer ID signature, Gatekeeper and Installer parser/payload checks; pending actual Mac installation.
