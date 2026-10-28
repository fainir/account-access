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
| F1 | Install or update the Mac app, connect its protected service and reopen it after restart; interrupted updates retain the prior usable app | macOS Installer, app, protected service | building (Codex) | [build 113 owner-Mac failure](qa/owner-upgrade113-install-2026-10-29.log): PackageKit killed postinstall at 1,800 seconds during duplicate full-tree/ACL scans; no receipt. [Build 114 source QA](qa/owner-upgrade114-source-qa-2026-10-29.log) passes fresh native owner, runtime and complete shared-image probes; signed candidate and owner-Mac install remain | 2026-10-29 |
| F2 | Import a Chrome export, review matches and save only selected accounts; malformed or cancelled imports save nothing | Chrome, macOS app, vault | verified | [password import regression suite](qa/password-import-source-qa-2026-10-28.log): 63 passed; [owner UI acceptance](docs/other-service-validation.md#namecheap-password-pilot) is historical, with no export-file secrets accessed in this run | 2026-10-28 |
| F3 | Connect Gmail or TLS IMAP and use a fresh matching code; permission, expiry or ambiguous-mail errors stop safely | macOS app, Gmail / IMAP, connector | owner | [154 Gmail, IMAP, OAuth and verification tests](qa/email-verification-source-qa-2026-10-28.log); [24 reusable-mailbox tests, including deterministic uncertain-refresh coverage](qa/gmail-refresh-timeout-2026-10-28.log); [138-case email/SMS/authenticator setup regression suite](qa/verification-source-qa-2026-10-28.log) | 2026-10-28 |
| F4 | Pair Android and deliver a fresh approved SMS; denied permissions, redaction or a stale code refuse delivery | macOS app, Android 15+, supported connector | owner | [138-case synthetic email/SMS/authenticator setup regression suite](qa/verification-source-qa-2026-10-28.log); physical Android pairing and real SMS acceptance remain; [Android setup](android/README.md) | 2026-10-28 |
| F5 | Enroll an authenticator and finish a Lemon Squeezy TOTP login; invalid codes preserve the enrollment and reveal no secret | macOS app, Lemon Squeezy | owner | [95-case local suite: 93 passed in the concurrent run; the 2 timing-sensitive cases passed alone](qa/totp-source-qa-2026-10-28.log); [138-case authenticator setup/import regression suite](qa/verification-source-qa-2026-10-28.log); [provider acceptance](docs/other-service-validation.md#lemon-squeezy-authenticator-acceptance) shows the private challenge is unqualified | 2026-10-28 |
| F6 | Use local Codex or Claude Code for an approved read; unsupported sites and operations refuse without returning secrets | Codex / Claude Code, local launcher, connector | building (Codex) | [agent setup, policy and client source QA](qa/agent-local-qa-2026-10-28.log): 156 passed; [installed agent smoke](qa/owner-agent-smoke-2026-10-28.log) still returned `browser_execution_failed` twice; [full-suite load attempt](qa/full-suite-load-2026-10-28.log): 201 passed before interruption, the only failure passed alone | 2026-10-28 |
| F7 | Refuse expired, ambiguous or unauthorized verification and explain the next step without exposing a code | macOS app, agent, local service | verified | [MFA refusal and expiry tests](tests/test_multifactor.py) and [identity-code boundary tests](tests/test_identity_contact_login.py) | 2026-10-28 |
| F8 | Review, edit, export or delete saved account data; invalid requests preserve the vault and exports are identified as plaintext | macOS app, encrypted local store | todo | [security and sync](docs/security-and-password-sync.md) | |
| F9 | Sign in to Harel or Phoenix using approved Android SMS and return only session status; changed pages or unsupported challenges stop safely | macOS app, Android, insurer connector | todo | [provider-specific flow gaps](docs/insurer-login-acceptance.md); neither insurer is bundled yet | |

## Gates

| Gate | Status | Evidence |
|---|---|---|
| Security: endpoint authorization, secret handling, input validation, auth rate limits, dependency audit | todo | Controlled checks pass; real service deployment and release audit not complete. |
| Data: reversible migrations, tested backup/restore, user data export/delete | todo | No production restore acceptance recorded. |
| Reliability: health checks, alerts, structured logs, retries/idempotency, provider-down behavior | todo | Installer update/recovery currently being diagnosed; production monitoring not verified. |
| Performance: key surfaces on mobile, Lighthouse performance and accessibility at least 90 where applicable | todo | No complete release measurement recorded. |
| UX/UI: screens checked at 375px and desktop, empty/error/loading states, contrast and keyboard | todo | Native UI and phone acceptance remain open. |
| Legal/store: privacy, terms, listings and data-safety statements match behavior | todo | Public download is labeled preview; production listing review not complete. |
| Ops: CI green, one-command deploy, rollback, environment documentation, release signatures | todo | Signed/notarized packages exist; owner-Mac install and rollback are not verified. |
| Cost: recurring services and provider fees are documented with an owner-approved cap | verified | [PRODUCT.md](PRODUCT.md) keeps v1 local with no recurring cloud or SMS relay cost; later paid services require explicit approval. |

## Owner actions

1. When signed build 114 is ready, install it from the visible macOS Installer and approve any native authorization prompt with Touch ID; this supplies the real owner-Mac update and protected-service check. No password needs to be shared.
2. In Account Access > Verification, connect the approved Gmail account in Chrome and select **Check Google connection**. Then use a supported account with a real email-code challenge and complete it in Account Access; this unblocks private mailbox and delivery acceptance. Keep mailbox passwords and login codes out of chat.
3. Open Account Access > Verification > Pair Android phone, scan its pairing QR, and approve the requested access on Android; this unblocks real SMS acceptance. No phone code belongs in chat.
4. Sign in to Lemon Squeezy through Account Access once with your authenticator app; this confirms its private TOTP challenge and enrollment against the real site. Keep the password and generated codes in their intended apps.

## Waiting on third parties

| What | Since | Next check | Notes |
|---|---|---|---|
No current third-party wait is confirmed. Build 110 notarization completed; its Installer run failed under F1.

## Log (last 10)
- 2026-10-29 - Build 114 optimization passed fresh native owner probes (79/26/21/482/324), runtime planner and refusal checks (69), and complete installed-image compile/runtime/guard probe; package build and owner-Mac acceptance remain.
- 2026-10-28 - Gmail uncertain-refresh regression is synchronized on receipt by the synthetic local provider; exact test passed and reusable-mailbox module passed 24/24. Full-suite rerun remains outstanding.
- 2026-10-28 - Build 113 signed package has passed notarization, stapling, Gatekeeper, Installer parser and exact payload verification; owner Mac acceptance is next.
- 2026-10-28 - Build 113 native owner probes (79/26/21/477/324 checks), APFS/runtime probe (69 checks), ordinary-user refusal, 5 diagnostic tests and notarized package gates pass.
- 2026-10-28 - Full suite last run: 4524 passed, 4 skipped, 2 failed under load. Build 110 diagnostic rerun passed 10/10; Gmail mailbox module passed 24/24 after synchronizing its timeout test on provider receipt.
- 2026-10-28 - Build 111 passed signing/notarization and package-content QA, but the authorized owner-Mac postinstall hit PackageKit's 1,800-second timeout and left no receipt.
- 2026-10-28 - Ship scaffold and product spec added; no public production release has been published.
- 2026-10-28 - Agent setup, permission guard and managed-client source QA passed 156 tests; installed synthetic browser smoke remains unresolved.
- 2026-10-28 - Email, SMS and authenticator setup/import source QA passed 138 tests; owner-device and private-provider acceptance remain open.
- 2026-10-28 - Password import source QA passed 63 tests; no private Chrome export was used.
