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
