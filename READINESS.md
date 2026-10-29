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
| F1 | Install or update the Mac app, connect its protected service and reopen it after restart; interrupted updates retain the prior usable app | macOS Installer, app, protected service | building (Codex) | [Build 114 owner-Mac installer result](qa/owner-upgrade114-installed-2026-10-29.log) shows the signed app update installed. [Build 116 attempt](qa/macos-package116-existing-install-refusal-2026-10-29.md) failed safely because it is a first-install package and its image does not match the existing install journal. The report metadata and fixed refusal diagnostic are corrected in source; a qualified successor update package and restart acceptance remain | 2026-10-29 |
| F2 | Import a Chrome export, review matches and save only selected accounts; malformed or cancelled imports save nothing | Chrome, macOS app, vault | verified | [password import regression suite](qa/password-import-source-qa-2026-10-28.log): 63 passed; [owner UI acceptance](docs/other-service-validation.md#namecheap-password-pilot) is historical, with no export-file secrets accessed in this run | 2026-10-28 |
| F3 | Connect Gmail or TLS IMAP and use a fresh matching code; permission, expiry or ambiguous-mail errors stop safely | macOS app, Gmail / IMAP, connector | owner | [154 Gmail, IMAP, OAuth and verification tests](qa/email-verification-source-qa-2026-10-28.log); [24 reusable-mailbox tests, including deterministic uncertain-refresh coverage](qa/gmail-refresh-timeout-2026-10-28.log); [138-case email/SMS/authenticator setup regression suite](qa/verification-source-qa-2026-10-28.log) | 2026-10-28 |
| F4 | Pair Android and deliver a fresh approved SMS; denied permissions, redaction or a stale code refuse delivery | macOS app, Android 15+, supported connector | owner | [Current Android build and signature check](qa/android-current-build-2026-10-29.log) passed. [GitHub emulator journey](https://github.com/fainir/account-access/actions/runs/40797912092) passed Android 11 automatic/owner-entered login and Android 15 refusal without pairing. Local emulator/phone is unavailable; physical Android 15+ pairing and real SMS acceptance remain; [Android setup](android/README.md) | 2026-10-29 |
| F5 | Enroll an authenticator and finish a Lemon Squeezy TOTP login; invalid codes preserve the enrollment and reveal no secret | macOS app, Lemon Squeezy | owner | [95-case local suite: 93 passed in the concurrent run; the 2 timing-sensitive cases passed alone](qa/totp-source-qa-2026-10-28.log); [138-case authenticator setup/import regression suite](qa/verification-source-qa-2026-10-28.log); [provider acceptance](docs/other-service-validation.md#lemon-squeezy-authenticator-acceptance) shows the private challenge is unqualified | 2026-10-28 |
| F6 | Use local Codex or Claude Code for an approved read; unsupported sites and operations refuse without returning secrets | Codex / Claude Code, local launcher, connector | building (Codex) | [Agent integration check](qa/macos-package116-existing-install-refusal-2026-10-29.md): the launcher found only three controlled-demo accounts on service 0.6.0; the allowed sample read returned `RETRYABLE browser_execution_failed` with no account data. Source now maps known managed-client enrollment failures to fixed, safe explanations, but the updated native app could not be type-checked on this Mac because the installed Swift compiler does not match the available SDK. The installed system app remains on its **Upgrade your existing connection** screen; no agent connection is confirmed | 2026-10-29 |
| F7 | Refuse expired, ambiguous or unauthorized verification and explain the next step without exposing a code | macOS app, agent, local service | verified | [MFA refusal and expiry tests](tests/test_multifactor.py) and [identity-code boundary tests](tests/test_identity_contact_login.py) | 2026-10-28 |
| F8 | Review, edit, export or delete saved account data; invalid requests preserve the vault and exports are identified as plaintext | macOS app, encrypted local store | owner | [saved-login source checks](qa/account-data-qa-2026-10-29.log); [build 116 app compile/sign QA](qa/macos-app-build116-2026-10-29.md); [72 security/data boundary tests](qa/gates/security-data-boundaries-2026-10-29.md). The signed/notarized package passed payload-signature audit and Gatekeeper checks but is not an update package for this installed image. Owner UI data-operation acceptance remains open | 2026-10-29 |
| F9 | Sign in to Harel or Phoenix using approved Android SMS and return only session status; changed pages or unsupported challenges stop safely | macOS app, Android, insurer connector | building (Codex) | [Provider-specific flow gaps](docs/insurer-login-acceptance.md); [fresh public login form observation](qa/insurer-public-login-2026-10-29.md). Neither provider has an approved narrow network flow or physical-phone acceptance yet | 2026-10-29 |

## Gates

| Gate | Status | Evidence |
|---|---|---|
| Security: endpoint authorization, secret handling, input validation, auth rate limits, dependency audit | todo | [Pinned Python dependency audit](qa/security-dependency-audit-2026-10-29.log) found no known vulnerabilities. Endpoint, native runtime and release security review remain incomplete. |
| Data: reversible migrations, tested backup/restore, user data export/delete | todo | No production restore acceptance recorded. |
| Reliability: health checks, alerts, structured logs, retries/idempotency, provider-down behavior | todo | The first-install package correctly preserves a mismatched existing image, but an update package and restart recovery are not qualified; see [the build 116 refusal](qa/macos-package116-existing-install-refusal-2026-10-29.md). Production monitoring is also not verified. |
| Performance: key surfaces on mobile, Lighthouse performance and accessibility at least 90 where applicable | todo | No complete release measurement recorded. |
| UX/UI: screens checked at 375px and desktop, empty/error/loading states, contrast and keyboard | todo | Native UI and phone acceptance remain open. |
| Legal/store: privacy, terms, listings and data-safety statements match behavior | todo | Public download is labeled preview; production listing review not complete. |
| Ops: CI green, one-command deploy, rollback, environment documentation, release signatures | todo | CI passed on the earlier commit `d71e709`; the current native changes are not yet CI-verified. The Mac has no matching Swift compiler/SDK pair, so no updated owner app or successor updater package has been built. Rollback and the complete consumer package remain unverified. |
| Cost: recurring services and provider fees are documented with an owner-approved cap | verified | [PRODUCT.md](PRODUCT.md) keeps v1 local with no recurring cloud or SMS relay cost; later paid services require explicit approval. |

## Owner actions

1. After a qualified successor update is installed, open `/Applications/Account Access.app`, choose **Upgrade AI connection**, and approve the separate **Authorize Account Access setup** dialog if it appears. The previous Mac approval did not complete enrollment; this step unblocks live F6 acceptance. Keep any password in the macOS dialog.
2. In Account Access > Verification, connect the approved Gmail account in Chrome and select **Check Google connection**. Then use a supported account with a real email-code challenge and complete it in Account Access -> unblocks private mailbox and delivery acceptance. Keep mailbox passwords and codes out of chat.
3. Open Account Access > Verification > Pair Android phone, scan its pairing QR and approve the requested access on Android -> unblocks real SMS acceptance. No phone code belongs in chat.
4. Sign in to Lemon Squeezy through Account Access once with your authenticator app -> confirms its private TOTP challenge and enrollment against the real site. Keep the password and codes in their intended apps.

## Waiting on third parties

| What | Since | Next check | Notes |
|---|---|---|---|
No external store or provider review has been submitted, so no third-party review wait is active.

## Log (last 10)
- 2026-10-29 - The focused installer/package/transaction suite passed 125 tests with one host-specific `installer -volinfo` skip; Ruff, Swift parsing and the 45-case browser-session module passed. The full suite is incomplete: its sandboxed run could not bind loopback, and its loopback-enabled run was interrupted after 650 passes/1 skip during a storage-lock wait. Native type-check is still unavailable on this Mac because the compiler and SDK builds differ. Details: [package and follow-up QA](qa/macos-package116-existing-install-refusal-2026-10-29.md).
- 2026-10-29 - The notarized build 116 first-install package returned Installer error 112 on the existing app. The journal's image differs from the package target; the refusal preserved the installed system app and service. The package report wrongly advertised update support. Source now marks it first-install only and emits a fixed update-required reason; evidence in [the refusal and agent check](qa/macos-package116-existing-install-refusal-2026-10-29.md).
- 2026-10-29 - The system app at `/Applications/Account Access.app` returned to **Upgrade your existing connection** after a prior owner-approved setup attempt; enrollment is still unconfirmed. The single permitted sample read on the controlled-demo service returned `RETRYABLE browser_execution_failed` without data and was not repeated.
- 2026-10-29 - Build 116 full package passed payload signing, Apple notarization, stapling and local distribution/Gatekeeper checks; 72 focused security and saved-account boundary tests passed. The notarized package is open in Installer; owner-Mac runtime acceptance is pending.
- 2026-10-29 - Fresh build 116 runtime inspection passed with current-source Developer ID-signed helpers. The full `pkgbuild` pass exceeded its former 10-minute bound; the package-only timeout is now 30 minutes and its regression is covered by [the focused suite](qa/macos-system-package-timeout-2026-10-29.md). The first stale-helper package is not a release candidate.
- 2026-10-29 - GitHub CI passed on `d71e709`: native owner UI/gateway, tests, separate-user workers and Android journey all passed.
- 2026-10-29 - Build 114's first postinstall attempt failed with generic PackageKit error 112; retrying the same signed package succeeded in 391.96 seconds. The package is script-only, so no receipt is expected. The launched `/Applications` app still shows “Upgrade AI connection”; evidence: [owner-Mac install](qa/owner-upgrade114-installed-2026-10-29.log).
- 2026-10-29 - The installed Account Access launcher returned only controlled-demo grants; a permitted synthetic summary smoke returned `RETRYABLE browser_execution_failed` without account data. The owner connection upgrade is still required; evidence: [agent launcher smoke](qa/agent-owner-access-2026-10-29.log).
- 2026-10-29 - `uv run pytest -q` after the restrictive-umask fixture fix passed 4,530 tests; 4 skipped. Evidence: [full suite](qa/full-suite-after-fixture-fix-2026-10-29.log).
- 2026-10-29 - The system app is 0.8.0 build 110; a separate per-user app is stale at 0.6.0 build 7. The local Codex/Claude connection is not yet upgraded, and the live agent harness correctly refuses to proceed without an effective permission boundary.
