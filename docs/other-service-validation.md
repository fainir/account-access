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

## PyPI password and authenticator pilot

The development candidate adds an optional **PyPI** connector. Its only operation,
`personal-pypi:status`, returns the signed-in username from PyPI's authenticated
navigation fragment. It does not read account settings, projects, email addresses,
tokens or publishing permissions. Adding the connector creates an **unenrolled**
TOTP source; it does not install a seed, enable a factor or grant an agent access.
See the [complete configuration](../examples/pypi-browser.json).

The [anonymous preflight](../artifacts/pypi-preflight-080.json) uses a fresh sandboxed
browser and the product's network guard. It verifies the real login form, exact
POST destination and reviewed deployment revision. It enters no username,
password or code, and uses no personal browser profile. This proves form
compatibility, not private authentication or delivery.

The reviewed [deployed Warehouse revision](https://github.com/pypi/warehouse/tree/f9ce83647318089c485c3d66378d559f0e7cdeed)
uses a response-generated opaque query token for its
[TOTP page](https://github.com/pypi/warehouse/blob/f9ce83647318089c485c3d66378d559f0e7cdeed/warehouse/accounts/views.py#L298).
The connector accepts one exact URL only from the attached main document's armed
password POST and its first 302/303 response. The private CDP request chain,
origin, path, bounded token grammar and 120-second lifetime must match. The
capability permits that redirect's GET and one separately armed native TOTP POST.
Iframes, scripts, HEAD requests, new navigations, duplicate Location headers and
redirect replays cannot acquire or reuse it. It is never saved as a URL pattern;
tokens remain in memory and are redacted from returned data.

The [TOTP template](https://github.com/pypi/warehouse/blob/f9ce83647318089c485c3d66378d559f0e7cdeed/warehouse/templates/accounts/two-factor.html)
can offer a security key and a recovery link alongside the authenticator form.
The connector can use an enrolled authenticator when that form is present. A
required security key or actual recovery-code form stops. It never consumes
recovery codes. PyPI's
[new-device confirmation](https://github.com/pypi/warehouse/blob/f9ce83647318089c485c3d66378d559f0e7cdeed/warehouse/templates/accounts/unrecognized-device.html)
stops unless the owner explicitly binds the optional device-email source
described below. The bundled picker does not silently choose a mailbox.

The development candidate offers an in-app connection under **Verification**:
choose an already checked saved TLS IMAP mailbox, review its address and the
existing account reads, then confirm. Gmail app-password mailboxes work through
this picker. A broken configured binding can be disconnected or replaced without
editing configuration. Setup fetches no messages and starts no website login;
delivery remains separate from saved setup. [Consumer steps](device-email-setup.md).

The engine also accepts a
[complete operator configuration](../examples/pypi-device-email.json); replace its
recipient and mail server with the owner's actual mailbox configuration, enroll
that source through the local owner flow, and separately approve the connector's
changed permission fingerprint. This example contains no credential or grant.
The source can use IMAP or an explicitly configured, consented Gmail account.
Gmail OAuth-only connections still require that advanced configuration; automatic
selection of them is not implemented by the consumer picker.

The [deployed confirmation view](https://github.com/pypi/warehouse/blob/f9ce83647318089c485c3d66378d559f0e7cdeed/warehouse/accounts/views.py#L950)
uses an emailed GET link, not a six-digit code or a form. Only an observed,
guarded TOTP response to the bare device page can start this step. The resolver
requires fresh mail beyond the existing Gmail-ID or IMAP-UID baseline, exact
recipient/sender/subject, the reviewed plain-text MIME template, unchanged source
generation and current mailbox authority. It requires the fixed login-confirmation
action, checks the unique login identifier for canonical UUID syntax, and compares the
confirmation token's user UUID to the user in PyPI's trusted password response.
The unique login UUID is not derived from that response, and structural inspection
does not validate a signature: PyPI verifies its signed token and the device's IP
when the link is used. Other users, actions, links,
ambiguous messages and stale tokens cannot be selected.

The resulting URL is a one-use, attached-main-frame capability within the
original 120-second login lifetime. The original successful 303 and Set-Cookie
are preserved. Its exact projects-page redirect is intercepted at CDP Request
stage before dispatch, then a fresh guarded page in the same cookie context
checks only the approved username fragment. No projects page is fetched or
granted. A different redirect, frame, chain, session, HTTP method, duplicate
Location header or replay stops. Tokens remain in memory and never become a
saved URL allowlist or agent-visible result.

PyPI may throttle confirmation email for fifteen minutes. A fresh matching mail
that does not arrive within this login window remains a stop; the engine does
not select an older inbox message or repeatedly submit the password to force a
resend. Required security-device and recovery challenges remain owner actions.

Local fictional fixtures exercise password/TOTP sign-in, saved-session reuse,
remembered-factor sign-in, changed forms, missing sources, code rejection,
presence challenges, redirect provenance and secret-free results. Additional
fictional Gmail/IMAP journeys cover device-link confirmation, cookie retention,
saved-session reuse, zero projects requests, token/user binding, freshness,
revocation and ambiguous mail. They do not
establish a successful login to a real PyPI account. This pilot supports the
guarded automatic path; generic manual browser setup is rejected before opening
a window (`pypi_manual_setup_unavailable`). No private PyPI account has been
enrolled or validated.

Developers can rerun the anonymous PyPI-only check explicitly:

```sh
uv run python scripts/pypi_preflight.py
```

## Railway discovery

An anonymous inspection of Railway's current login page confirmed an email
sign-in option alongside federated sign-in. Its email flow is not a bundled
connector. The newer engine supports a reviewed username/email step followed by
a password, but that does not implement a passwordless email-code flow.
No personal address was entered, no email was
requested, and no Railway account was connected. This is discovery, not a
successful account test.

## Two-page password engine

The development candidate adds an optional identity step with exact identity
POST, password-page and password-POST URLs. It works with reviewed native forms
or an explicit JavaScript identity request. Source preparation precedes all
credential fills, and a changed page/form or presence challenge stops before
the password. Controlled tests cover all four existing verification variants
and saved-session reuse. This does not enroll or validate another private
provider. See [the configuration and limits](username-password-pages.md).

## Running the anonymous check

Developers can explicitly run:

```sh
uv run python scripts/service_preflight.py
```

This contacts Namecheap's public login page. It does not use the installed vault,
the owner's Chrome profile, a password export, mailbox or phone. The ordinary
regression suite remains local and uses fictional accounts.
