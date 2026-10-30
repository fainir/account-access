# Account Access

**One line:** Account Access helps a person and their local AI agents complete approved sign-ins without sharing passwords or verification codes with the agent.

## Who

The first user is the owner of a Mac and Android phone who uses local Codex or Claude Code agents and needs help with supported personal account sign-ins.

## Core job

Complete a reviewed sign-in step locally, using only the credentials and verification sources the owner approved, then return the permitted account result or session status to the agent. Passwords, cookies and verification codes stay inside Account Access.

## Flows

| Flow | Happy path | Unhappy path |
|---|---|---|
| Install and first run | Install the signed macOS app, connect its protected service and local agent launcher, then reopen after restart. | A failed or interrupted update retains the prior usable app and gives a specific recovery step. |
| Chrome password import | Select a Chrome export, review matching accounts and save only selected entries. | Malformed files, ambiguous matches or cancellation save nothing and explain what to do next. |
| Email verification | Connect a checked Gmail or TLS IMAP source and use a fresh matching code during a supported login. | Permission, mailbox, expired-code or ambiguous-message errors stop safely without exposing the code. |
| Android SMS verification | Pair Android, approve the source and deliver a fresh matching SMS to a supported login. | Missing permissions, Android notification redaction, stale codes or a changed pairing refuse delivery and identify the next action. |
| Authenticator verification | Enroll an original setup key or supported QR and use a current TOTP code for a supported login. | Invalid, expired or mismatched codes fail without changing enrollment or revealing the secret. |
| AI agent access | A fresh local Codex or Claude Code session discovers approved operations and requests a permitted read in ordinary language. | Unsupported sites, unapproved operations, unavailable service or expired owner permission are refused without returning secrets. |
| Account data controls | Review, edit, export or delete saved account data, and create or restore a password-protected encrypted vault backup. | Invalid export requests preserve the vault; a wrong backup passphrase or interrupted restore leaves the prior vault intact; deletion does not claim secure erasure of external copies. |
| Recovery and privacy | Revoke access, expire a session and recover from a provider outage without sharing secrets. | Replayed, stale or ambiguous verification and unauthorized callers are refused and logged without secret values. |

## Non-goals

- Arbitrary websites are not automatically supported. Each site needs a reviewed, narrow connector.
- Direct Harel and Phoenix sign-in automation is excluded from v1. Their provider-specific request and challenge contracts have not passed private acceptance; Account Access must refuse these flows until each connector is separately qualified.
- The agent cannot make payments, change policy details, approve account recovery or bypass a site's own owner challenge.
- Cloud agents cannot reach the local service unless a separately reviewed secure relay is added.
- Chrome live password sync is not shipped; Chrome import is a reviewed snapshot.

## Success metric

Every supported synthetic sign-in and refusal case passes in the release QA run; private provider acceptance is tracked separately in READINESS.md.

## Stack and hosting

| Run | Test | Deploy |
|---|---|---|
| `uv run account-access --help`; native app via `macos/build.sh` | `uv run pytest -q`; native probes in `scripts/` and `macos/Tests/`; Android emulator journey in CI | Signed and notarized macOS package; Android publisher build; public channel is not production-ready yet |

The product is local-first. The owner app and protected service run on Apple silicon Macs with macOS 14 or later; Android is a paired notification companion. Account data does not require a hosted database. Production distribution still needs a verified installer, agent smoke test, release channel and real provider acceptance.

## Data model

| Entity | Important fields | Storage and privacy |
|---|---|---|
| Account | provider, username, login URL, approved operations | Encrypted local vault; only reviewed provider metadata is sent to the local agent. |
| Credential | password or manager reference, source version | Encrypted at rest; never logged or returned to an agent. |
| Session | provider, opaque browser state, expiry | Local protected store; revoked or expired sessions are not reused. |
| Verification source | Gmail/IMAP connection, Android pairing, TOTP secret, sender/template | Encrypted local storage; codes are consumed only for a matching active sign-in. |
| Approval and event | account, operation, decision, time, fixed result category | Sanitized local audit data; no password, cookie, message body or code. |

## Decisions

- 2026-10-28 - Keep Account Access local-first and support only reviewed connectors.
- 2026-10-28 - Treat Harel and Phoenix as requested provider targets, not as supported until their real sign-in flows pass QA.
- 2026-10-28 - Do not publish a production release until the signed installer, protected service and agent path pass on the owner Mac.
- 2026-10-30 - Keep Harel and Phoenix out of v1's supported-provider list until their exact login, SMS delivery and authenticated-session contracts pass review and owner acceptance. The generic login engine must continue to refuse unqualified insurer flows.
- 2026-10-28 - No cloud hosting or paid SMS relay is assumed for v1; recurring provider cost remains $0 unless the owner approves a later service.

## Open questions

- None for v1. Harel and Phoenix remain future provider targets and require separate connector implementation and acceptance before being listed as supported.
