# Lemon Squeezy MFA qualification - 2 November 2026

The owner selected Lemon Squeezy for the real MFA test. This completes the
website-choice decision; it does not create an Account Access grant or establish
that the site's authenticated challenge is implemented.

## Best way and reviewed sources

Use the vendor's documented authenticator-based two-factor flow and inspect the
actual challenge before declaring a connector supported. Keep credentials,
setup QR/seed, recovery codes and current codes in the owner's local tools.
The existing protected connector model supports explicit password/TOTP forms,
fixed destinations and narrow status results; do not infer routes or selectors
from a generic Laravel/TOTP fixture.

Lemon Squeezy's [official 2FA documentation](https://docs.lemonsqueezy.com/help/getting-started/two-factor-authentication)
describes an authenticator app after the account password. Recovery codes and
new enrollment are separate; neither is part of this test. Its
[official sign-up/login guide](https://docs.lemonsqueezy.com/guides/getting-started)
distinguishes the merchant account from customer magic-link access. No new
account, store, payout, identity or security-setting action is requested.

## Current public observations

Opened https://auth.lemonsqueezy.com/login in the owner's existing Chrome,
using the supported browser tool. The page visibly offers Google, Twitter and
email/password sign-in. [Empty public form](public-login.png) was saved and
visually inspected; it contains no account identity or secret.

Read only DOM structure/attributes, never field values or hidden token values:

- One form: POST https://auth.lemonsqueezy.com/login, URL-encoded.
- Hidden _token field present; its value was neither read nor retained.
- Email input: id=email, name=email, type=email, autocomplete=email.
- Password input: id=password, name=password, type=password,
  autocomplete=current-password.
- One submit button, Sign in; no form action or method override.
- Remember-me checkbox remains off. No authenticator challenge is shown yet.

This is the observed public password-form shape, not completed guarded-browser
or private MFA qualification. No credential, password POST, code request,
authenticator enrollment or private account operation was performed.

## Required owner presence

The exact sign-in tab is open and marked for handoff. The owner should use the
normal saved sign-in locally and stop when Lemon Squeezy asks for its
authenticator code. Leave that field blank and reply “prompt ready”. No password,
code, QR/seed or recovery code should be sent in chat, and no new 2FA enrollment,
reset, signup or permanent account change is requested.

The agent cannot inspect Chrome's saved password or the exported credential
file. Account Access currently has no Lemon Squeezy catalog entry/grant. The
native import cannot select that provider yet. The owner-controlled challenge
is needed only to review its origin, fields and submit destinations before
implementing support; completing a manual Chrome login will not count as
Account Access MFA acceptance.

After the prompt is available: inspect only form structure and reviewed public
labels/destinations; exclude code values and private page data. Build and test
the fixed status-only connector, then qualify its installed successor before
requesting local credential/grant and authenticator enrollment. Do not add an
unreviewed route or broaden an existing provider's grants. Existing Betterloop
acceptance stays complete and Namecheap stays paused.


## Actual authenticator challenge observed

After the owner replied “i did”, the same staged Chrome tab was at
https://auth.lemonsqueezy.com/2fa-challenge with heading “Enter your 2FA code”.
Only DOM structure and attributes were inspected; no input or token value,
password, current code, recovery code, cookie or storage value was read.

The observed challenge contract is:

- POST https://auth.lemonsqueezy.com/2fa-challenge,
  application/x-www-form-urlencoded.
- Hidden _token input present; value excluded.
- Exactly one visible required code field: id=code, name=code, type=text,
  autocomplete empty. Select it only within that exact challenge form.
- One Sign in submit button; no formaction/formmethod overrides.
- A separate POST https://auth.lemonsqueezy.com/logout form is already present
  before MFA completes. A logout form alone must never establish readiness.

The real MFA contract is now observed. Its post-login destination and reliable
signed-in marker are still unknown and must be observed before adding a
status-only connector. The page's logout form is explicitly insufficient.
No incomplete connector was added to the installed catalog.

The unique visible code field is focused for the owner. The next exact owner
action is to enter the current authenticator code in this Chrome prompt and
click Sign in, then reply “signed in”. Values remain unread by the agent. This
completes the owner's normal manual sign-in only; it will not be recorded as
Account Access's automated MFA acceptance. No QR/seed export, factor reset,
new enrollment or recovery-code use is requested.

After that action, inspect only the authenticated destination and structural
ready marker, excluding account/financial content. Complete the guarded
connector and test its known challenge and refusal paths, then qualify the
installed successor and local owner enrollment before product MFA acceptance.
