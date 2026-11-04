# Owner-requested verification order - 4 November 2026

Order: Chrome import and email/password sign-in, then email verification, then
SMS, then authenticator transfer. Existing approvals/data are preserved.

## Step 1: actual Chrome-import/password baseline

The real native Chrome import and initial Betterloop email/password sign-in
were observed on 2 November: [native journey](../betterloop-private-2026-11-02/acceptance.md).
Only the owner-selected account/status grant was saved; no credential file was
opened by the agent. The installed 127 login code for this password-only
connector retains that path. Current normal installed [Codex](codex-password-status.json)
and [Claude](claude-password-status.json) operations each return
COMPLETED/environment live and only authenticated=true. These two current reads
confirm the existing session; they are not fresh password submissions. No
session/credential was erased, no new import/grant or duplicate login challenge.

## Step 2: Harel email, then Step 3: Harel SMS

The owner explicitly selected Harel and identified its email/SMS choice.
This reopens Harel's earlier v1 exclusion; Phoenix stays excluded. Public review
already identified identity/mobile fields and a native GET form wrapped by
JavaScript. The generic GET refusal must remain; IDs/phone/codes must never enter
URLs, agent output or logs. Review the exact provider-owned API sequence before
an installed connector or local personal enrollment is requested. Only boolean
session status is in scope; no insurance policies/medical/payment data.

Best way: use Harel's official public entry/application assets as primary
implementation evidence and enforce a closed, attempt-bound request/response
state machine. Stop on declarations, document-issue-date, card or stronger identity
branches. Reuse the already checked mailbox through native owner binding;
request no saved mailbox password again. Provider and controlled fixture proof
remain distinct from a real email/SMS login. Existing insurer observations:
[review](../../docs/insurer-login-acceptance.md),
[official entry](https://www.harel-group.co.il/Pages/login-page/Login.aspx).

Authenticator action 18 is deferred by the owner until the preceding stages are
accepted. Preserve the existing paused Lemon task/challenge and Namecheap pause;
request no further QR, authenticator setup or manual login codes now.

## Implemented source candidate; installed 127 is unchanged

Fresh anonymous HTTP inspection retrieved the current official entry and
[microfrontend configuration](https://digital.harel-group.co.il/portal-config-backend/api/v1/micro-frontends/get-config/cus).
The public customer-header and Scanovate ver61 bundles match the previously
reviewed bytes. The selected radio is passed into ContextConfig: email is 1,
SMS is 0. This corrects the earlier description of an unconditional SMS request.
No identity, phone, code request, private profile or insurance data was used.

The new fixed client itself reached the real entry, anonymous GetCurrentDetails
(authenticated=false), then email ContextConfig successfully:
[actual anonymous client result](harel-anonymous-client.json). This does not
establish private-account acceptance. CurrentProcess is an integer discriminator,
not an attempt nonce; the private cookie context and enrolled local code window
bind the attempt.

The source adapter uses only the exact reviewed POST endpoints. It selects the
channel before identity submission, refuses native GET submission, resends,
channel changes, redirects, uncertain replay and stronger identity branches.
After code verification it requires UserLoggedIn plus the current-user marker
and a separate cookie-authenticated status response. Only a boolean leaves it.
The inferred success contract still needs live native qualification.

- [158 component cases](harel-component-tests.log): protocol state/response
  guards, source-backed TLS test-mailbox delivery, reuse/expiry, revocation,
  scope mutations, cookie restoration and redacted first-use pattern proposals.
- [191 focused regressions](source-tests.log): existing password/identity,
  catalog, grants, security, metadata and Chrome import boundaries. These overlap
  the component cases; do not add the counts as distinct cases.
- [63 MIME/pattern cases](email-pattern-tests.log): no automatic adoption of a
  sender or message; one local owner-reviewed code proposes an exact filter.
  No actual email was fetched or sender/template invented.
- [Owned UI checks](owner-ui-tests.log) pass at 375 and 1200 pixels, with no app
  console errors or horizontal overflow. Email identity/mobile stay masked and
  are cleared before changing to password fields. [375](harel-owner-375.png),
  [1200](harel-owner-1200.png). The catalog was a controlled fixture, not an
  installed Harel entry. Native screen checks are recorded separately.
- [61 native screen groups](native-ui.log) pass in the locally compiled controlled
  app, including distinct masked identity/mobile fields for email and SMS,
  password-kind switching, cleared values and no credential export/sync choice.

The first UI fixture omitted the install mock and correctly hit the existing
protected-skill guard. No installation occurred; normal installed discovery
still returns exactly the four prior grants. The fixture now isolates install.
An eval-based QA wait was also replaced with an attached-element wait under
the unchanged CSP. These were fixture failures, not private provider verdicts.

Remaining buildable work: add the native Harel email setup entry, reuse the
checked mailbox, bind UID/arrival/profile/attempt state, review the actual email
pattern locally, then save only the selected identity/status/source grant.
The first email code, if required for that one-time review, must be entered only
in the native app. The pattern helper alone grants and reads nothing. Qualify
matching signed delivery and installed acceptance before an owner setup ask.
No new installer, live code request, grant, import or personal enrollment has
occurred in this source-candidate phase. Harel email and SMS remain unverified.
