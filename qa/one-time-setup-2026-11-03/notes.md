# One-time setup candidate - 3 November 2026

The owner clarified the core job: one password import, reusable authenticator,
SMS and Gmail connections, then approved automatic sign-ins. The owner identified
**Google Authenticator** through the in-app question. The old manual Lemon
password handoff is superseded; existing completed mailbox/Betterloop setup stays done.

The best implementation keeps credentials and codes in the local protected
service, reuses existing grants, and imports a complete authenticator export
with explicit account/source mappings. [Google's transfer guide](https://support.google.com/accounts/answer/1066447)
describes the owner-unlocked local export. [Apple passkeys](https://developer.apple.com/documentation/authenticationservices/supporting-passkeys)
and [WebAuthn](https://www.w3.org/TR/webauthn/) retain owner presence/verification.
No passkey import or unattended platform-presence bypass is implemented.

## Implemented source

- Native Automatic sign-in setup links the existing password import/sync,
  authenticator transfer, email setup and Android pairing surfaces. It explains
  exactly what is reused and when owner approval is required.
- One complete Google Authenticator export is decoded once. The native review
  offers explicit mappings to existing configured TOTP sources. Every mapping
  starts unselected. Duplicate key mappings disable the import control.
- Owner-only batch endpoints bind every selected source to its configuration,
  linked account fingerprints and enrollment generation. All selected keys and
  preview consumption commit in one SQLite transaction. Stale, revoked,
  duplicate or invalid selections make no changes. Unselected sources are kept;
  no website credentials, account definitions or AI grants are added.
- Leaving the review discards its encrypted preview. Late preview/apply replies
  cannot replace a navigated screen. The existing single-site setup path stays.
- Zero-match password exports now have a clear recovery screen and no enabled
  no-op Import action or file-deletion control. The local web setup also offers
  a new file and clears its file input so selecting the same file works again.

## Current evidence and limits

The compiled native fixture passes all 61 PASS groups, including new setup,
no-match recovery, duplicate selection and required native setup authorization:
[native check output](native-checks.log). It uses only a temporary home,
intercepted owner requests and blocked managed helpers, never the installed vault.

Actual native UI was opened with CUA and inspected: [setup top](setup-top.jpg),
[SMS/passkey guidance](setup-bottom.jpg), [empty import](empty-import.jpg) and
[batch review](authenticator-review.jpg). Choose another file opens the native
picker; Cancel returns to the same unchanged no-match screen. The batch page
starts with Do not import for both fictional websites and a disabled submit.
Native selection-state transitions are also exercised by the compiled fixture.
CUA's menu-selection control reported a changed-app guard and then
noWindowsAvailable; this is a control failure, not a successful user selection.
No CUA-driven completed native batch import or installed acceptance is claimed.
The earlier modal prototype also produced a blank modal capture; a full review
page now provides readable screenshot evidence and more room for many accounts.

Actual localhost web UI at [375px](web-empty-375.png) and
[1440px](web-empty-1440.png) shows safe no-match recovery with no horizontal
overflow or page errors. Only fictional exports and isolated browser profiles
were used. Browser cache was initially absent, affecting an unchanged original
browser test too; the pinned project's official headless browser install fixed
that environment issue.

[Final focused source regression](source-tests.log) passes 206 tests, including actual local browser/MFA, native-route API, import and web-UI behavior. The [16-case batch security subset](batch-security.log) and earlier [97-case local web/import regression](ui-regression.log) overlap that set; they are not added to its total. All [16 image/predecessor/CLI safety checks](image-builder-tests.log) pass separately. Ruff passes.
The controlled batch engine test imports two sources together, then completes a
real local password/TOTP browser login without owner code entry. No real Google
Authenticator export, private MFA, physical SMS, passkey ceremony or new grant
was performed. Installed build 125 and its qualified release assets are unchanged.
A signed matching owner/broker/runtime update and installed acceptance remain
necessary before this candidate can be called shipped.

The build-126 native compilation workflow retains choices 121–125 and uses 126 for this new source. Its public image builder is bound to the actual qualified build-125 manifest. The updater, signed packages and installed acceptance have not been created or claimed yet.


## Build and existing CI

Program source 2ca9de3 is pushed. [Native owner build 126](https://github.com/fainir/account-access/actions/runs/41614265465)
completed successfully and its actual runtime126-owner-image archive is
present locally. The [main source checks](https://github.com/fainir/account-access/actions/runs/41614265449)
and [Mac worker checks](https://github.com/fainir/account-access/actions/runs/41614265385)
completed successfully. The main run reports 4,731 passing tests and 114 skips,
with lint and dependency audit passing; [read-back](source-ci-summary.log). The existing [separate-user run](https://github.com/fainir/account-access/actions/runs/41614265397)
and [component run](https://github.com/fainir/account-access/actions/runs/41614265387) pass.
Automatic pull-request duplicates were cancelled and read back as completed/
cancelled; the primary push runs remain. No manual duplicate was dispatched.

Inspection of the real image CLI found its separate hard-coded version choices
excluded 126 despite the new profile. Choices now come from the profile table;
actual child-process CLI tests accept both retained 125 and new 126 before
requesting image inputs. Program source is unchanged by this publisher-only fix.
Use the current builder and retain the compiled 2ca9de3 owner/broker/wheel bytes.

## Qualified image and updater contract

The matching build-126 [image qualification](target126-qualification.json)
reports TARGET_IMAGE_QUALIFIED: 49 native files, 11 executables, one bundle,
34 wheels, publisher signatures and actual sandboxed browser execution pass.
Dependencies and required JIT roles are unchanged. No installed paths or account
data were used. Image qualification alone does not claim notarization.

The exact 125-to-126 plan has 15 units and 17 changed nodes. A separate Automatic
Setup recovery namespace retains every prior history. All 140 [focused updater
checks](update-source-tests.log) pass, including current image/source refusals,
retained profile CLIs and refusal before any owner-Mac Installer probe inputs.
The public five-file [qualification archive](https://github.com/fainir/account-access/releases/tag/qa-automatic-setup126-20261103)
was independently read back with the expected size/digest and uploaded state.
It contains no credentials or customer installer. The native qualification
workflow now checks all retained 120-125 plans and the new 126 plan and compiles
the exact updater. Signed packages and installed acceptance remain pending.

The existing worker and Android runs also completed successfully; no duplicate
was dispatched. Technical continuation is scheduled hourly as
account-access-one-time-setup-release and stays quiet on unchanged state.
