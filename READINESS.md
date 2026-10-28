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
| F1 | Install or update Account Access and see a usable app after restart | macOS Installer, app, protected service | building (Codex) | [installer log and QA](qa/owner-upgrade110-install-2026-10-28.log); [previous refusal](artifacts/owner-upgrade110-proof-boundary-install-20261028.json) | 2026-10-28 |
| F2 | Import selected Chrome passwords and approve only the accounts I choose | Chrome, macOS app, vault | todo | [import flow docs](docs/password-import.md) | |
| F3 | Connect email and receive a fresh login code for a supported account | macOS app, Gmail / IMAP, connector | todo | [production gates](docs/production-gates.md) | |
| F4 | Pair my Android phone and receive an approved SMS login code | macOS app, Android 15+, supported connector | owner | Physical Android pairing and real SMS acceptance remain; [Android setup](android/README.md) | |
| F5 | Enroll an authenticator and finish a supported TOTP login | macOS app, supported website | owner | Real Lemon Squeezy enrollment and login have not been verified; [MFA guide](docs/gmail-authenticator-and-sms.md) | |
| F6 | Ask my existing AI agent to do an approved operation through Account Access | Codex / Claude Code, local launcher, connector | building (Codex) | [agent smoke log](qa/owner-agent-smoke-2026-10-28.log): synthetic read returned `browser_execution_failed` twice | 2026-10-28 |
| F7 | Refused, expired or ambiguous verification is explained and cannot leak a code | macOS app, agent, local service | verified | MFA suite and refusal tests recorded in [production gates](docs/production-gates.md) | 2026-10-28 |
| F8 | Review, change, export or delete saved account data safely | macOS app, encrypted local store | todo | [security and sync](docs/security-and-password-sync.md) | |

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

1. Pair the physical Android 15+ phone to Account Access and approve its notification-access permission when F4 reaches that step; this unblocks real SMS acceptance.
2. Complete the owner-authenticated Chrome export/import and the selected personal website sign-in locally if the app requests browser or system authorization; this unblocks F2 and private-account acceptance. Do not put exported passwords or codes in chat.

## Waiting on third parties

| What | Since | Next check | Notes |
|---|---|---|---|
| Apple notarization for the current diagnostic package | 2026-10-28 | When the active builder returns | Active package build submits and polls automatically; not a product approval. |

## Log (last 10)

- 2026-10-28 - created readiness ledger from repository docs and current acceptance evidence; production readiness remains false.
- 2026-10-28 - current source probes passed; replacement installer is building with field-level final stability checkpoints.
- 2026-10-28 - installed launcher account discovery shows controlled-demo only; one permitted retry of the synthetic agent read failed and was recorded for post-update recheck.
- 2026-10-28 - replacement package passed Developer ID signature, Apple notarization, stapling, Gatekeeper and Installer parser checks; protected postinstall is still running.
