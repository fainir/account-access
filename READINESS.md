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
| F1 | Install or update the Mac app, connect its protected service and reopen it after restart; interrupted updates retain the prior usable app | macOS Installer, app, protected service | building (Codex) | [build 110 install failure](qa/owner-upgrade110-install-2026-10-28.log); [checkpoint fix source QA](qa/owner-upgrade-checkpoint-source-qa-2026-10-28.log); [build 111 builder QA](qa/owner-upgrade111-builder-qa-2026-10-28.log) | 2026-10-28 |
| F2 | Import a Chrome export, review matches and save only selected accounts; malformed or cancelled imports save nothing | Chrome, macOS app, vault | verified | [owner UI acceptance](docs/other-service-validation.md#namecheap-password-pilot) and [import tests](tests/test_password_import.py); historical test date not recorded | historical |
| F3 | Connect Gmail or TLS IMAP and use a fresh matching code; permission, expiry or ambiguous-mail errors stop safely | macOS app, Gmail / IMAP, connector | owner | [154 Gmail, IMAP, OAuth and verification tests](qa/email-verification-source-qa-2026-10-28.log) | 2026-10-28 |
| F4 | Pair Android and deliver a fresh approved SMS; denied permissions, redaction or a stale code refuse delivery | macOS app, Android 15+, supported connector | owner | Physical Android pairing and real SMS acceptance remain; [Android setup](android/README.md) | |
| F5 | Enroll an authenticator and finish a Lemon Squeezy TOTP login; invalid codes preserve the enrollment and reveal no secret | macOS app, Lemon Squeezy | owner | [95-case local suite: 93 passed in the concurrent run; the 2 timing-sensitive cases passed alone](qa/totp-source-qa-2026-10-28.log); [provider acceptance](docs/other-service-validation.md#lemon-squeezy-authenticator-acceptance) shows the private challenge is unqualified | 2026-10-28 |
| F6 | Use local Codex or Claude Code for an approved read; unsupported sites and operations refuse without returning secrets | Codex / Claude Code, local launcher, connector | building (Codex) | [agent smoke log](qa/owner-agent-smoke-2026-10-28.log): synthetic read returned `browser_execution_failed` twice | 2026-10-28 |
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

1. In Account Access > Verification, connect the approved Gmail account in Chrome and select **Check Google connection**. Then use a supported account with a real email-code challenge and complete it in Account Access; this unblocks private mailbox and delivery acceptance. Keep mailbox passwords and login codes out of chat.
2. Open Account Access > Verification > Pair Android phone, scan its pairing QR, and approve the requested access on Android; this unblocks real SMS acceptance. No phone code belongs in chat.
3. Sign in to Lemon Squeezy through Account Access once with your authenticator app; this confirms its private TOTP challenge and enrollment against the real site. Keep the password and generated codes in their intended apps.

## Waiting on third parties

| What | Since | Next check | Notes |
|---|---|---|---|
No current third-party wait is confirmed. Build 110 notarization completed; its Installer run failed under F1.

## Log (last 10)

- 2026-10-28 - created readiness ledger from repository docs and current acceptance evidence; production readiness remains false.
- 2026-10-28 - Initial scope and readiness rows reconciled from the README, app docs, code and existing acceptance evidence; readiness remains false.
- 2026-10-28 - Build 110 passed signing and notarization but failed in protected postinstall; its stale checkpoint was corrected and the native source probe passed.
- 2026-10-28 - The local authenticator suite collected 95 tests; 93 passed under compiler load and the two timing-sensitive tests passed alone.
- 2026-10-28 - Build 111 builder passed 13 tests; pinned build 109 and runtime package 95 inputs were verified.
- 2026-10-28 - Ship scaffold and product spec added; no public production release has been published.
