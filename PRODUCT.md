# Account Access

**One line:** Account Access helps a person and their local AI agents complete approved sign-ins without sharing passwords or verification codes with the agent.

## Who

The first user is the owner of a Mac and Android phone who uses local Codex or Claude Code agents and needs help with supported personal account sign-ins.

## Core job

Complete a reviewed sign-in step locally, using only the credentials and verification sources the owner approved, then return the permitted account result or session status to the agent. Passwords, cookies and verification codes stay inside Account Access.

The owner clarified on 3 November: import passwords once, connect the existing authenticator, SMS and Gmail sources once, then let local agents complete later supported logins automatically. Do not replace this with repeated website-by-website password entry. Password changes, new account grants and owner-presence challenges are separate. Passkeys must keep their platform-required presence/verification and cannot be advertised as unattended.

## Flows

| Flow | Happy path | Unhappy path |
|---|---|---|
| Install and first run | Install the signed macOS app, connect its protected service and local agent launcher, then reopen after restart. | A failed or interrupted update retains the prior usable app and gives a specific recovery step. |
| Chrome password import | Select a Chrome export, review matching accounts and save only selected entries. | Malformed files, ambiguous matches or cancellation save nothing and explain what to do next. |
| Email verification | Connect a checked Gmail or TLS IMAP source and use a fresh matching code during a supported login. | Permission, mailbox, expired-code or ambiguous-message errors stop safely without exposing the code. |
| Android SMS verification | Pair Android, approve the source and deliver a fresh matching SMS to a supported login. | Missing permissions, Android notification redaction, stale codes or a changed pairing refuse delivery and identify the next action. |
| Authenticator verification | Select a complete existing transfer export once, review explicit key-to-website mappings together, enroll selected keys atomically and generate later TOTP codes locally. | Incomplete exports, duplicate mappings, stale reviews or changed source/account bindings save nothing and reveal no secret. |
| AI agent access | A fresh local Codex or Claude Code session discovers approved operations and requests a permitted read in ordinary language. | Unsupported sites, unapproved operations, unavailable service or expired owner permission are refused without returning secrets. |
| Account data controls | Review, edit, export or forget saved account logins through the native owner app. | Invalid export requests preserve the vault; plaintext exports are identified; forgetting a login preserves its reviewed connector and does not claim secure erasure of external copies. |
| Recovery and privacy | Revoke access, expire a session and recover from a provider outage without sharing secrets. | Replayed, stale or ambiguous verification and unauthorized callers are refused and logged without secret values. |

## Non-goals

- Arbitrary websites are not automatically supported. Each site needs a reviewed, narrow connector.
- Phoenix sign-in automation is excluded from v1. Harel was reopened on 4 November for email verification first, then SMS. Harel remains unavailable until its fixed provider protocol, local setup and real status-only acceptance pass; the generic engine must continue to refuse its unsafe native GET form.
- The agent cannot make payments, change policy details, approve account recovery or bypass a site's own owner challenge.
- Cloud agents cannot reach the local service unless a separately reviewed secure relay is added.
- Chrome live password sync is not shipped; Chrome import is a reviewed snapshot.
- Portable backup and restore of the installed protected service vault is excluded from v1. The legacy per-user CLI backup cannot reach that store. A future owner maintenance flow must coordinate worker shutdown, supervisor-owned key custody and restore recovery before this can be advertised.

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

- 2026-11-04 - Follow the owner's acceptance order: existing Chrome import and email/password, then Harel email, then Harel SMS, then Google Authenticator. Preserve completed imports, mailbox setup and paused challenges. Harel requires its own local identity/mobile enrollment, not a Chrome password. Return only authenticated-session status; stronger identity, declarations and insurance data stay outside the connector.

- 2026-11-03 - Use one setup path for reusable passwords, authenticator, Gmail and SMS sources; preserve existing completed setup. Add batch authenticator review with explicit mappings rather than fuzzy website matching or repeated transfer imports. Google documents local transfer QR exports ([guide](https://support.google.com/accounts/answer/1066447)). Password CSV does not carry passkeys; [Apple](https://developer.apple.com/documentation/authenticationservices/supporting-passkeys) and [WebAuthn](https://www.w3.org/TR/webauthn/) retain owner presence/verification. No virtual authenticator, weakened verification or cross-site credential authority is introduced.

- 2026-10-31 - Remove the unsupported protected-vault backup promise from v1. Preserve the tested legacy CLI separately; do not request a passphrase, access its protected key or bypass the service boundary to make that CLI target the installed vault. Installer rollback and per-account owner data controls remain in scope.
- 2026-10-31 - Make Android pairing reachable without a website through an owner-only connection test. It accepts only the chosen sender and fixed test template in a two-minute window, creates no account grants, and does not establish private-provider sign-in acceptance.

- 2026-10-28 - Keep Account Access local-first and support only reviewed connectors.
- 2026-10-28 - Treat Harel and Phoenix as requested provider targets, not as supported until their real sign-in flows pass QA.
- 2026-10-28 - Do not publish a production release until the signed installer, protected service and agent path pass on the owner Mac.
- 2026-10-30 - Keep Harel and Phoenix out of v1's supported-provider list until their exact login, SMS delivery and authenticated-session contracts pass review and owner acceptance. The generic login engine must continue to refuse unqualified insurer flows.
- 2026-10-28 - No cloud hosting or paid SMS relay is assumed for v1; recurring provider cost remains $0 unless the owner approves a later service.

## Open questions

- Harel's email/SMS protocol and local source binding are active implementation work. Phoenix stays excluded. No new owner decision is needed before the Harel candidate is concrete and qualified.

## Publisher identity

The owner supplied the legal publisher name **Nir Fainshtein**, business status **עוסק פטור** and public support/privacy contact **welcometothebestplace@gmail.com** on 31 October 2026. Preserve the issued Apple certificate name as credential metadata; it is separate from release-copy publisher details.
