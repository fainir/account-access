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
| F1 | Install or update Account Access and see a usable app after restart | macOS Installer, app, protected service | building (Codex) | [build 110 install failure](qa/owner-upgrade110-install-2026-10-28.log); [checkpoint fix source QA](qa/owner-upgrade-checkpoint-source-qa-2026-10-28.log); [build 111 builder QA](qa/owner-upgrade111-builder-qa-2026-10-28.log) | 2026-10-28 |
| F2 | Import selected Chrome passwords and approve only the accounts I choose | Chrome, macOS app, vault | verified | [owner UI acceptance](docs/other-service-validation.md#namecheap-password-pilot) and [import tests](tests/test_password_import.py); historical test date not recorded | historical |
| F3 | Connect email and receive a fresh login code for a supported account | macOS app, Gmail / IMAP, connector | owner | [154 Gmail, IMAP, OAuth and verification tests](qa/email-verification-source-qa-2026-10-28.log) | 2026-10-28 |
| F4 | Pair my Android phone and receive an approved SMS login code | macOS app, Android 15+, supported connector | owner | Physical Android pairing and real SMS acceptance remain; [Android setup](android/README.md) | |
| F5 | Enroll an authenticator and finish a Lemon Squeezy TOTP login | macOS app, Lemon Squeezy | owner | [95-case local suite: 93 passed in the concurrent run; the 2 timing-sensitive cases passed alone](qa/totp-source-qa-2026-10-28.log); [provider acceptance](docs/other-service-validation.md#lemon-squeezy-authenticator-acceptance) shows the private challenge is unqualified | 2026-10-28 |
| F6 | Ask my existing AI agent to do an approved operation through Account Access | Codex / Claude Code, local launcher, connector | building (Codex) | [agent smoke log](qa/owner-agent-smoke-2026-10-28.log): synthetic read returned `browser_execution_failed` twice | 2026-10-28 |
| F7 | Refused, expired or ambiguous verification is explained and cannot leak a code | macOS app, agent, local service | verified | [MFA refusal and expiry tests](tests/test_multifactor.py) and [identity-code boundary tests](tests/test_identity_contact_login.py) | 2026-10-28 |
| F8 | Review, change, export or delete saved account data safely | macOS app, encrypted local store | todo | [security and sync](docs/security-and-password-sync.md) | |
| F9 | Sign in to Harel or Phoenix using Android SMS and expose only session status | macOS app, Android, insurer connector | todo | [provider-specific flow gaps](docs/insurer-login-acceptance.md); neither insurer is bundled yet | |

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
- 2026-10-28 - current source probes passed; replacement installer is building with field-level final stability checkpoints.
- 2026-10-28 - installed launcher account discovery shows controlled-demo only; one permitted retry of the synthetic agent read failed and was recorded for post-update recheck.
- 2026-10-28 - replacement package passed Developer ID signature, Apple notarization, stapling, Gatekeeper and Installer parser checks; protected postinstall is still running.
- 2026-10-28 - reconciled the prior real Chrome import acceptance and added explicit Lemon Squeezy and insurer connector gates.
- 2026-10-28 - Gmail, IMAP, OAuth and email-verification source suite passed 154 tests; private mailbox delivery remains an owner acceptance step.
- 2026-10-28 - Checkpoint-order fix passed the native owner-upgrade probe; build 110 still needs a corrected, installed successor package.
- 2026-10-28 - Authenticator suite had two timeouts under concurrent Swift compilation; both passed in a serial rerun. Provider acceptance remains an owner action.
- 2026-10-28 - Build 111 candidate builder passed 13 tests and pinned-input checks; signed build and owner installation are next.
