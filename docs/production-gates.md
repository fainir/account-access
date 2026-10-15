# Production acceptance

Account Access remains a preview. This checklist separates tested behavior from
the remaining work required to ship the requested consumer experience. Public
source, passing tests and an edited recording do not establish private-account
or physical-device coverage.

## Candidate 0.8 changes

- The signed Mac app includes the Python wheel and pins its SHA-256. A repair
  reinstalls the package and restarts the background service even when the
  version number is unchanged. Python, dependencies and Chromium can still
  require network downloads.
- Google Authenticator transfer QR images can be imported locally. The owner
  selects one entry for an existing authenticator source; other entries are
  discarded. Previews are encrypted, expire after ten minutes, and do not return
  keys. One complete export batch with six-digit, SHA-1 TOTP is supported. This
  is interoperability with a reverse-engineered format, not a Google API or a
  connection to Authenticator cloud sync.
- Verification setup reports the result of the website sign-in check. Saving a
  password or key alone does not mark the website connected.
- An optional GitHub connection reuses the installed, already signed-in GitHub
  CLI for one fixed identity read. The owner reviews the account and read before
  connecting. The adapter checks the executable checksum and expected GitHub
  identity on use, drops inherited token/debug/host settings, bounds execution
  time and output, and never invokes a token-export command. A changed binary
  or identity requires review. This does not establish a browser session or
  support arbitrary GitHub operations.
- Owner troubleshooting records fixed public route words and masks every other
  path segment. It does not record hostnames, query values, credentials or page
  contents, and it does not broaden network allowlists.

## Acceptance matrix

| Requirement | Verified evidence | Remaining gate |
| --- | --- | --- |
| Simple Mac installation | Signed universal app, local update/repair flow, checksum-tamper rejection | Apple notarization and a clean downloaded-install test on a separate Mac |
| Chrome/password-manager import | Reviewed CSV imports; one selected personal entry imported in the native app | More real export formats and representative private website connectors |
| Continuous password updates | Exact-item 1Password Connect contract and password-rotation recovery tests | Private Connect deployment QA; Chrome exports remain snapshots |
| Gmail and other email codes | TLS IMAP browser recovery and Gmail API contract tests | Registered consumer OAuth application, owner consent, real mailbox delivery QA |
| iPhone SMS | Narrow signed Messages helper and message-selection fixtures | Owner-granted Mac privacy permission and real forwarded SMS delivery QA |
| Android SMS | Emulator notification → pinned relay → browser verification | Physical Android pairing, notification delivery and reconnect QA |
| Authenticator app | Setup-key and transfer-import browser recovery tests | Owner-approved real authenticator export and provider login QA |
| Passkey/security key | Real private browser sign-in identified the WebAuthn route; existing GitHub CLI authorization works independently | Trusted browser-session path or approved provider authorization for the requested operation; genuine device presence when required |
| Automatic agent discovery | Installed skill/CLI used in Codex and Claude Code sessions | Re-run both against each completed private connection; broader host matrix |
| Credential isolation | Separate owner/agent APIs, encryption, scoped operations and fail-closed routing | Broker under a separate OS identity/host with a trusted enrollment channel; unrestricted same-user agents are not isolated |
| Open-source trust | Public MIT repository, CI, contribution guide, private vulnerability reporting enabled | Independent security review, release provenance and published production acceptance results |

## Private QA rules

Keep account identifiers, raw agent traces, exports, QR images, messages and
cookies out of public artifacts. Publish sanitized coverage and failure classes.
Use read-only account checks. Preserve blocked task IDs rather than repeatedly
creating new sign-ins. Test revocation, session expiry, account switching and
recovery as well as the successful path.

A provider-requested passkey, phone unlock, biometric or administrator approval
must be completed through its genuine owner flow. Initial enrollment can require
the owner; supported later sign-ins should reuse the approved access. No test may
replace an unavailable private source with fictional data and claim it passed.
