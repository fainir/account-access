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


## Signed-in destination observed; implementation method

The owner replied “i signed in”. In the same Chrome tab, the location is now
https://app.lemonsqueezy.com/dashboard and the code form is absent. No password,
code, cookie, browser storage or private dashboard text/value was read.

The page uses Inertia: its existing #app DOM data-page attribute reports only
the selected component field App/Dashboard and URL path /dashboard. Dashboard
props, account identities, financials and API keys were excluded from output.
The exact escaped-slash JSON CSS match was checked and occurs once. The initial
#app can be empty/invisible with JavaScript off, so use html:has(the exact #app
marker), not visibility of the empty app element or a pre-MFA logout form.

Inertia's [official protocol](https://v1.inertiajs.com/the-protocol) documents
that the initial full HTML carries the page object in data-page, without
rendering the client components. Therefore keep JavaScript disabled, read only
this server component/route marker and return authenticated=true. Do not
whitelist the dashboard's payment/analytics scripts or expose any props.

Before implementation: use fixed native POST password and /2fa-challenge forms,
a separate owner-enrolled TOTP source, exact auth/app destinations and one
status-only operation. Test successful password/TOTP and session reuse, expired
sessions, absent/revoked factors, malformed forms/overrides/redirects, pre-MFA
logout decoys, wrong component/route and private-data canaries. Preserve all
existing catalog entries/fingerprints. Then qualify the exact signed successor
before a new local credential/grant and authenticator setup. The manual Chrome
MFA observation alone is not Account Access acceptance.


## Guarded implementation and focused verification

Implemented a separate Lemon Squeezy catalog entry with fixed password and TOTP
POST destinations, JavaScript off, a distinct initially unenrolled source and
one session-status operation. Password import uses exact HTTPS origin aliases;
no payment, API-key, settings, logout or account-change operation is granted.

Testing exposed that CSS substring checks can match nested dashboard-like props
inside the wrong page. Replaced that prototype with a typed ServerPageMarker:
exact current browser URL, exactly one #app, bounded JSON parsed inside the
browser, and exact own top-level component/url fields. Only a boolean leaves
that predicate. The feature permits only script-free session-status operations;
its active definition is permission-bound, while absence preserves every old
connector fingerprint. A legacy fixture needed the new absent field removed
from its historical expected schema, without changing runtime fingerprints.

Twenty dedicated server-marker tests pass, including nested decoys, wrong
component/route/destination, malformed/oversized JSON, duplicate roots, result
scope restrictions and legacy fingerprints. The initial provider/catalog run
passed 60 cases with one stale count expectation; both counts now reflect five
private catalog services. The later Lemon/multifactor run passed 70 runtime
cases with only the historical schema fixture mismatch described above.
The corrected marker/legacy/spec run passes separately. Sets overlap; do not
add these as unique totals. Ruff passes. Complete source CI and matching
build-124 owner/broker compilation are next, followed by the exact 123-to-124
image/update and actual signed Installer qualification. No installed upgrade,
new private grant, seed enrollment or automated live MFA success is claimed.

## Build 124 qualification in progress

The corrected local provider, marker, MFA and prior-provider regression passes
110 tests. All 164 exact-update, manifest, sparse-payload and source-freeze tests
pass; Ruff passes. Matching source-276207e owner/broker compilation completed in
[run 41435565761](https://github.com/fainir/account-access/actions/runs/41435565761).
The owner app reports build 124 and its embedded project wheel exactly matches
the source wheel. The [signed target image](../release124-2026-11-02/image-qualification.json)
passes the 49-file native audit, unchanged dependency/JIT verification and actual
sandboxed browser execution. No installed path or personal account was accessed.

The exact 123-to-124 public plan contains 15 units and 18 changed nodes. Its
public five-file native fixture archive was read back from the QA prerelease
with matching digest/size. The predecessor archive contains exactly 27,494
manifest nodes/parents and no private branches. Earlier 120/121/122/123 histories
remain separate. Native updater compilation, signed packages and actual Installer
acceptance remain pending. This does not establish installed Lemon access or MFA.
