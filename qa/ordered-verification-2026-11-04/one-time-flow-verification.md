# One import and reusable verification - 5 November 2026

Requested acceptance: import passwords once, connect verification once, then complete later supported sign-ins automatically. This record distinguishes controlled browser/service verification from the owner's still-unfinished personal enrollment.

## Checks and results

| Check | Actual exercised path | Result |
|---|---|---|
| Import once and finish password, email, SMS and TOTP logins | Owner HTTP import/approval routes, real local provider HTTP, TLS IMAP and synthetic Messages database | Four approved accounts connect; each factor is used once. No password, seed or code is returned to the caller. |
| Reuse setup after expiry in a new worker process | Site sessions are cleared; a separate Python PID loads the same encrypted fixture store and runs the four-step task | Each email/SMS/TOTP count and IMAP fetch count reaches two; grants, enrollment records and import/enrollment audit events remain unchanged. No second import or enrollment occurs. |
| Reuse checked Gmail after reopening saved state | Actual bounded local HTTP profile/message APIs, TOTP and device-email confirmation; a fresh Broker/Store | Old mail stays present. Only the new fresh-2 message is fetched for the later login; profile checking/source setup are not repeated. Revoked Gmail authority still refuses further message access. |
| Reuse native SMS collector | Private fixture Unix transport and browser, then expired site session and a fresh message | A new baseline and message ID are used; source enrollment is retained. Both first and later codes are excluded from results/audit. This is not native UID or physical-phone proof. |
| Reuse Google Messages transport | Owned synthetic browser page, shipped reader/native-host code and ordinary/protected fixture bridges | Two distinct code windows are armed before password submission; old DOM messages remain excluded. Each code is checked for output leaks; worker cleanup is bounded even on test failure. |
| Import/setup UI and refusal regression | Owned local page at375/1440px; authenticator setup, polling/late replies, mailbox binding, cancellation and revocation | Existing UI and security cases pass. No owner data or private website is used. |

The separate worker opens only its temporary fixture root, fixture demo.key and synthetic Messages database. It does not use the owner's keychain, installed service, Chrome store, real mailbox or phone. Reopening a Python fixture worker is not an OS reboot or signed installed-worker MFA acceptance.

## Fresh execution

- Baseline selection:216 passed in258.65 seconds.
- Expanded regression selection:217 passed in293.05 seconds. This includes the stronger Gmail-source assertion and all unchanged UI/refusal cases.
- After final process-isolation, per-login redaction and bounded-cleanup changes, all four changed journey files were rerun:31 passed in64.42 seconds.
- Ruff on all four changed files passes. Local CI input checks pass all30 disabled-automatic workflow restrictions. No GitHub Actions, package rebuild, private sign-in or new grant occurred.
- No production runtime defect was reproduced. Changes are regression tests and evidence only; the installed128 program/package is unchanged.

Changed-file command:
```sh
uv run --locked --no-sync pytest -q \
  tests/test_verification_journey.py \
  tests/test_gmail_reusable_mailbox.py \
  tests/test_native_messages_journey.py \
  tests/test_google_messages_journey.py
```

The broader217-case selection also includes test_authenticator_setup_ui.py, test_multifactor.py, test_gmail_mailbox_binding.py, test_gmail_mailbox_ui.py, test_sms_setup.py, test_harel_setup.py, test_password_import.py and test_authenticator_import.py.

## Independent check and verify loop

The independent checker first found that existing reuse tests retained an active session or the same service objects. It then identified a stale Gmail source assertion and missing per-login code-redaction assertions in the new tests; these were corrected without weakening the original revocation/refusal checks. Final fresh review finds no blocking issue in the separate-PID variant, source/grant snapshots, fresh-message baselines, per-login redaction or bounded teardown. Final31-case execution passes after those corrections.

## Actual installed boundary and owner handoff

[Installed128 acceptance](installed128-acceptance.md) already verifies the real installation/new kernel boot, all73 Python source matches, preserved identities/grants, healthy worker/browser and both agents' approved Betterloop/private-status and separate public-example reads.

Real Harel email, physical carrier SMS and Google Authenticator transfer/login remain unverified. At the final native UI check, Harel still has the saved checked mailbox selected, empty secure identity/mobile fields, unchecked setup consent and a disabled Send button. Existing action22 is unchanged; no private Harel request, code, source or grant was created. A password export cannot supply that passwordless provider's missing identity/mobile.

No completed Chrome import, mailbox password, installation or grant approval is requested again. Complete the existing native Harel enrollment first, then qualify email, SMS and authenticator in the owner's order. The completed installation monitor remains deleted; no personal-enrollment polling is scheduled.

