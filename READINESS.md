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
| F1 | Install or update the Mac app, connect its protected service and reopen it after restart; interrupted updates retain the prior usable app | macOS Installer, app, protected service | building (Codex) | [Build 113 Installer log and spindump](qa/owner-upgrade113-install-2026-10-29.log) identify the generic failure: PackageKit killed postinstall at 1,800 seconds during repeated full-tree verification. [Build 114](qa/owner-upgrade114-build-2026-10-29.log) includes the read-only verification optimization and passes signature, notarization, Gatekeeper and payload checks. [Installed-adapter source probe](qa/installed-adapter-source-probe-2026-10-29.log) passes with ordinary-user refusal checks. Current package receipt check finds no build 114 receipt, so installation, service upgrade and restart smoke remain unverified; Installer is open. Installed service remains 0.6.0 | 2026-10-29 |
| F2 | Import a Chrome export, review matches and save only selected accounts; malformed or cancelled imports save nothing | Chrome, macOS app, vault | verified | [password import regression suite](qa/password-import-source-qa-2026-10-28.log): 63 passed; [owner UI acceptance](docs/other-service-validation.md#namecheap-password-pilot) is historical, with no export-file secrets accessed in this run | 2026-10-28 |
| F3 | Connect Gmail or TLS IMAP and use a fresh matching code; permission, expiry or ambiguous-mail errors stop safely | macOS app, Gmail / IMAP, connector | owner | [154 Gmail, IMAP, OAuth and verification tests](qa/email-verification-source-qa-2026-10-28.log); [24 reusable-mailbox tests, including deterministic uncertain-refresh coverage](qa/gmail-refresh-timeout-2026-10-28.log); [138-case email/SMS/authenticator setup regression suite](qa/verification-source-qa-2026-10-28.log) | 2026-10-28 |
| F4 | Pair Android and deliver a fresh approved SMS; denied permissions, redaction or a stale code refuse delivery | macOS app, Android 15+, supported connector | owner | [Current Android build and signature check](qa/android-current-build-2026-10-29.log) passed. [GitHub emulator journey](https://github.com/fainir/account-access/actions/runs/40797912092) passed Android 11 automatic/owner-entered login and Android 15 refusal without pairing. Local emulator/phone is unavailable; physical Android 15+ pairing and real SMS acceptance remain; [Android setup](android/README.md) | 2026-10-29 |
| F5 | Enroll an authenticator and finish a Lemon Squeezy TOTP login; invalid codes preserve the enrollment and reveal no secret | macOS app, Lemon Squeezy | owner | [95-case local suite: 93 passed in the concurrent run; the 2 timing-sensitive cases passed alone](qa/totp-source-qa-2026-10-28.log); [138-case authenticator setup/import regression suite](qa/verification-source-qa-2026-10-28.log); [provider acceptance](docs/other-service-validation.md#lemon-squeezy-authenticator-acceptance) shows the private challenge is unqualified | 2026-10-28 |
| F6 | Use local Codex or Claude Code for an approved read; unsupported sites and operations refuse without returning secrets | Codex / Claude Code, local launcher, connector | building (Codex) | [agent setup, policy and client source QA](qa/agent-local-qa-2026-10-28.log): 156 passed. [Installed launcher check](qa/agent-launcher-connection-2026-10-29.log) reaches the protected service and reports three permitted synthetic demo operations on service 0.6.0. [Installed agent smoke](qa/owner-agent-smoke-2026-10-28.log) returned `browser_execution_failed` twice. The current live-CLI harness refuses to start when the effective tool boundary cannot be proved; [post-fix full test suite](qa/full-suite-after-fixture-fix-2026-10-29.log) passed, while end-to-end agent use on the updated service remains unverified | 2026-10-29 |
| F7 | Refuse expired, ambiguous or unauthorized verification and explain the next step without exposing a code | macOS app, agent, local service | verified | [MFA refusal and expiry tests](tests/test_multifactor.py) and [identity-code boundary tests](tests/test_identity_contact_login.py) | 2026-10-28 |
| F8 | Review, edit, export or delete saved account data; invalid requests preserve the vault and exports are identified as plaintext | macOS app, encrypted local store | building (Codex) | [saved-login source checks](qa/account-data-qa-2026-10-29.log): owner-only export/removal endpoints and explicit macOS controls; [build 115 app compile/sign QA](qa/macos-app-build115-2026-10-29.log) passes and pins the current wheel, but the complete system package and owner acceptance remain | 2026-10-29 |
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
| Ops: CI green, one-command deploy, rollback, environment documentation, release signatures | todo | Signed/notarized packages exist; owner-Mac install and rollback are not verified. |
| Cost: recurring services and provider fees are documented with an owner-approved cap | verified | [PRODUCT.md](PRODUCT.md) keeps v1 local with no recurring cloud or SMS relay cost; later paid services require explicit approval. |

## Owner actions

1. In the open **Installer** window for **Account-Access-Owner-Upgrade-114**, click **Install** / **Install Software** and approve the native macOS prompt with Touch ID or your Mac login password; leave Installer open until it reports success -> unblocks F1 and lets me retest F6 on the updated service. Keep any password in the macOS dialog.
2. In Account Access > Verification, connect the approved Gmail account in Chrome and select **Check Google connection**. Then use a supported account with a real email-code challenge and complete it in Account Access; this unblocks private mailbox and delivery acceptance. Keep mailbox passwords and login codes out of chat.
3. Open Account Access > Verification > Pair Android phone, scan its pairing QR, and approve the requested access on Android; this unblocks real SMS acceptance. No phone code belongs in chat.
4. Sign in to Lemon Squeezy through Account Access once with your authenticator app; this confirms its private TOTP challenge and enrollment against the real site. Keep the password and generated codes in their intended apps.

## Waiting on third parties

| What | Since | Next check | Notes |
|---|---|---|---|
No current third-party wait is confirmed. Build 110 notarization completed; its Installer run failed under F1.

## Log (last 10)
- 2026-10-29 - The native gateway CI run found a stale exact-source pin after `InstallerPayload.swift` moved its ACL checks into the standalone verifier. Updated the pin; the same installed-adapter probe passes locally; CI rerun pending.
- 2026-10-29 - `uv run pytest -q` after the restrictive-umask fixture fix passed 4,530 tests; 4 skipped. Evidence: [full suite](qa/full-suite-after-fixture-fix-2026-10-29.log).
- 2026-10-29 - Build 114 still has no package receipt; Installer remains open and installed service remains 0.6.0. The agent harness safely refuses its live smoke when effective tool permissions cannot be proved.
- 2026-10-29 - Android companion preview and instrumentation APKs compiled from current source and passed APK signature verification. No local emulator or phone is available; the CI emulator journey is still running. Physical Android 15+ acceptance remains an owner action.
- 2026-10-29 - GitHub Android emulator journey passed: Android 11 automatic and owner-entered SMS login, plus Android 15 refusal of notifications/manual codes without computer association. This does not prove a positive Android 15 paired-phone flow; physical acceptance remains open.
- 2026-10-29 - Saved-login export and forget flows have 11 passing source integration tests and 74 owner-gateway checks; native screen check and packaged app acceptance are in progress.
- 2026-10-29 - A prior full-suite run exposed a fixture mismatch: recreated 0755 test directories inherited a restrictive umask. The fixture now chmods them explicitly; the owner-upgrade110 and cost modules passed 12/12 under umask 077. The post-fix full run is recorded above.
- 2026-10-29 - Public Chrome inspection found Harel's identity/mobile dialog with SMS selected and email as an alternative, and Phoenix's state-bound identity/contact form with SMS/email and voice-call controls. No values were entered or codes requested; details are in `qa/insurer-public-login-2026-10-29.md`.
- 2026-10-29 - Build 114 passed whole-module compile, ordinary-entrypoint refusal, exact 27,532-row predecessor projection, notarization/stapling, Developer ID signature, Gatekeeper and Installer parser/payload checks; pending actual Mac installation.
- 2026-10-29 - Build 114 optimization passed fresh native owner probes (79/26/21/482/324), runtime planner and refusal checks (69), and complete installed-image compile/runtime/guard probe; package build and owner-Mac acceptance remain.
