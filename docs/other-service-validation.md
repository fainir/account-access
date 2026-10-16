# Validation on other services

Further GitHub account testing stopped at the owner's request on 16 October
2026. Its historical results remain in the validation report; they do not count
as coverage of the services below.

## Namecheap password pilot

The 0.8 candidate adds **Namecheap** to the native account picker and password
import review. Its sole operation, `personal-namecheap:status`, confirms the
signed-in username displayed by Namecheap's login page. There are no domain,
DNS, billing, checkout or account-setting operations.

The connector uses the actual server-rendered username/password form, with
JavaScript disabled. The only permitted login POST is
`https://www.namecheap.com/myaccount/login/`. The reviewed successful landing
page is `https://ap.www.namecheap.com/`; other destinations stop. Header sign-in
inputs and newsletter inputs cannot be selected as the password form.

Chrome exports can store the login under either the main website or the
account subdomain. An explicit `password_import_origins` alias covers that
case. Aliases match exact HTTPS origins, are included in the permission
fingerprint, and do not grant any browser network access. An empty alias list
preserves older grants and saved connections. Lookalike domains, child
subdomains and HTTP downgrade exports do not match.

[The anonymous preflight](../artifacts/namecheap-preflight-080.json) passed
through Account Access's sandboxed browser and network guard. It verified one
visible username field, password field and submit control, the exact form POST,
and the absence of a signed-in marker. It used a fresh browser context with no
personal profile, submitted no credential and requested no code.

Provider-shaped fixtures exercise password submission, cookie retention,
repeated session use, selected encrypted import and rejection of an unrecognized
verification step. These are fictional local fixtures, not private acceptance.

Signed universal Mac build **50** was installed through graphical repair. The
native picker shows Namecheap and its exact proposed read permission. Existing
connections remain present. In a subsequent owner-approved private test, one
selected Namecheap credential was imported from a real Chrome export through
the native UI. Other entries were not imported; the app moved the plaintext
export to Trash through its normal cleanup flow.

The private sign-in did **not complete**. The visible review reached a browser
verification page saying to enable JavaScript and cookies; the owner console
also recorded HTTP 429. The connector has JavaScript disabled, and this gate
does not establish password validity or email/SMS/TOTP coverage. Further
Namecheap requests were stopped. Its original task is retained, not resubmitted.

The next candidate identifies Cloudflare Challenge Page responses using the
documented `cf-mitigated: challenge` header. It keeps a per-page boolean for
main-document responses, stops before password/code entry or retry, and ignores
challenge headers from scripts and child frames. A normal later navigation can
clear the signal; authentication must still pass the usual readiness checks.
The app gives a specific explanation and an accessible review-finish action.
An earlier unknown challenge can be refined without changing its ID, granting
access, clearing it or retrying the website. These changes are fixture-tested;
they do not solve a CAPTCHA or make Namecheap unattended login pass.

[Cloudflare's detection documentation](https://developers.cloudflare.com/cloudflare-challenges/challenge-types/challenge-pages/detect-response/)
defines the response header. Its [supported-browser guidance](https://developers.cloudflare.com/cloudflare-challenges/reference/supported-browsers/)
states that production challenges do not support automated browsers. Do not
label an anonymous form preflight or challenge detection as successful private
authentication.

The final functional revision passed **405 tests**, fourteen native owner UI
checks, Messages/startup checks, lint, audit and build in
[CI](https://github.com/fainir/account-access/actions/runs/38941709228).
Its [Android emulator journey](https://github.com/fainir/account-access/actions/runs/38941709131)
also passed. See the [sanitized validation record](../artifacts/other-services-080.json).

Namecheap documents [email verification for a new device](https://www.namecheap.com/support/knowledgebase/article.aspx/10333/45/marking-a-device-as-trusted/)
and [TOTP authentication](https://www.namecheap.com/support/knowledgebase/article.aspx/10073/45/how-can-i-use-the-totp-method-for-twofactor-authentication/).
Those provider-specific verification routes are **not implemented or validated
by this password pilot**. A required challenge must stop for local review;
do not disable 2FA, consume recovery codes, or substitute a browser-session
transfer and label that a completed password/code test.

## Railway discovery

An anonymous inspection of Railway's current login page confirmed an email
sign-in option alongside federated sign-in. Its email flow is not a bundled
connector: the current password-form engine cannot treat an email-first login
as a completed password login. No personal address was entered, no email was
requested, and no Railway account was connected. This is discovery, not a
successful account test.

## Running the anonymous check

Developers can explicitly run:

```sh
uv run python scripts/service_preflight.py
```

This contacts Namecheap's public login page. It does not use the installed vault,
the owner's Chrome profile, a password export, mailbox or phone. The ordinary
regression suite remains local and uses fictional accounts.
