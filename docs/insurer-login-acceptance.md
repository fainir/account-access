# Harel and Phoenix login acceptance

Owner-selected targets: Harel and Phoenix. The owner receives SMS on Android.
Neither provider is currently a bundled supported connector. Public-page
inspection on 22 October 2026 did not submit an identity number, contact detail,
password or code, and did not access an insurance account.

| Provider | Official entry | Public login observed | Remaining provider evidence |
| --- | --- | --- | --- |
| Harel | [Personal area](https://www.harel-group.co.il/Pages/login-page/Login.aspx) | Header controls `#idUser` / `#phone`; the direct login dialog uses `#uid` / `#phone` and defaults to SMS. | Bound request sequence, live code screen, sender/template, authenticated marker, session expiry and session-status scope. |
| Phoenix | [Personal area](https://my.fnx.co.il/policies) | Redirect to `auth.fnx.co.il/u/login` with a per-attempt state. Identity type and number, then phone or email, followed by Send code. | Bound redirect/state handling, exact send-code endpoint, code screen, sender/template, authenticated marker, session expiry and read scope. |

Harel's [official FAQ](https://www.harel-group.co.il/long-term-savings/independent-and-employees/information/faq)
describes identity/phone verification and possible first-login identity-issuance
date verification. Phoenix's [security information](https://www.fnx.co.il/customer-service/terms-of-use/security/)
describes personal-area login using an identity number and an SMS code.

These are identity-and-contact flows followed by a code. They must not be
represented as imported Chrome passwords. The login engine now has a separate identity/phone credential shape, masked
local enrollment, and a required SMS factor. Existing password connector
fingerprints are preserved; password imports and synchronization cannot populate
identity/phone accounts. These accounts can grant only session status. The
initial request has one explicit same-origin POST destination, which is armed
only for submission and must return a successful HTTP response; POST redirects
and a ready marker without SMS verification are refused. Synthetic browser tests
cover these boundaries, session reuse/expiry and source revocation. This does
not yet implement the insurers' complete JavaScript flows or establish a
physical-phone login. Identity/contact values must stay out of agent results,
diagnostics, logs and chat.

The request to support these sites does not specify permission to read policies,
medical details or make changes. Initial personal acceptance should prove only
authenticated-session status. No insurance purchase, claim, policy change or
other transaction is part of login QA.

Acceptance must include:

1. Local owner enrollment and selection of the exact permitted operation.
2. Android companion pairing through the native app, with its certificate pin
   and sender/template binding checked locally.
3. A fresh code request made by the service for the current attempt, followed
   by delivery from the physical phone and a successful authenticated marker.
4. Refusal of stale/replayed codes, unrelated senders, modified destinations,
   unrecognized challenge pages and codes approving a transaction.
5. A later agent task that encounters an expired session, signs in through the
   service and resumes without exposing identity, contact details or codes.
6. Owner revocation stopping subsequent access and an owner-presence challenge
   remaining pending until the owner completes it locally.

Synthetic tests and public form inspection cannot satisfy items 2, 3 or 5.
Do not ship a provider as supported until its exact flow and personal acceptance
have both passed. Do not persist Phoenix's ephemeral anonymous state URL as a
connector destination or treat its broad auth host as an unrestricted allowlist.

## Public implementation observations

The Harel page's import map identifies its customer-header component at
`https://d1oqsep8o8n0bq.cloudfront.net/apps-customer-portal-frontend/customer-main-header.js?ver=61`.
The anonymous download was 3,150,247 bytes with SHA-256
`bbad9c6180acdfbdd7af09e3538f6dc94e1c7b63e47a1ff5bfe35be2c15bf0de`.
Source inspection, without executing the downloaded code or submitting a login,
shows that Continue performs several ordered POST requests below
`/_vti_bin/webapi/CustomersAuthentication/PostAuthenticate/`: `ContextConfig`,
two `ElasticLogger` calls, `PortalLogger`, then `StartProcess`. The last call
includes the locally entered identity and phone. A separate page-start call to
`GetCurrentDetails` also exists. These are observations, not an approved network
allowlist, and do not establish the next challenge or authenticated marker.
Blocking the prerequisite requests while allowing only `StartProcess` would not
reproduce the reviewed page's flow. Broadly allowing every POST on this host is
not an acceptable replacement.

The [direct login dialog](https://www.harel-group.co.il/Pages/login-page/Login.aspx?isshowlogin=true)
was also observed anonymously. A fresh browser check on 25 October found its
visible `#uid` and `#phone` inputs inside a native form whose default method is
**GET**; the earlier observation of no associated form was incomplete. No field
was filled, no submit button was clicked, and all non-GET/HEAD requests were
aborted. Opening the page attempted `ContextConfig` and `GetCurrentDetails`
POST requests. The existing generic identity/phone engine correctly refuses
this GET form. A provider implementation must bind the reviewed JavaScript
request sequence and prevent native credential-bearing GET submission; simply
loosening the form check would not provide that protection.
The SMS radio `#otp-channel-sms` is selected initially;
`#otp-channel-email` is a separate choice. No input was filled and Continue was
not pressed. These controls belong to the Scanovate component identified by
Harel's [public portal configuration](https://digital.harel-group.co.il/portal-config-backend/api/v1/micro-frontends/get-config/cus):
`https://d1oqsep8o8n0bq.cloudfront.net/apps-scanovate-frontend/scanovate.js?ver=61`.
The anonymous component download was 1,633,635 bytes with SHA-256
`20f9366c8dbce751cb0d78fe2a82c3b9c97fedfe4a0c43a8824c70e3046a7117`.

Static review distinguishes two phases of this direct route. Opening it calls
`ContextConfig`, followed by two `ElasticLogger` calls and `PortalLogger`.
Those three logging calls are launched from the configuration promise's success
callback without awaiting one another; their response order is not established.
The login dialog is also displayed without awaiting all logging responses. A
connector must account for this overlap rather than assume four sequential
completed requests. The separate `CustomerRouting` entry has different promise
handling and is not interchangeable with the reviewed direct entry.
The dialog's submission handler separately calls `ContextConfig` with an SMS
channel value of zero, then `StartProcess` with the entered identity and phone.
Thus the direct route does not remove the need to review preparatory requests.
The source defines an OTP control `#otp` and `SCValidateOTP` with an `OTP` field;
`CreateOTP` and `UpdateOtpChannel` are separate resend/change-channel operations.
These are source observations, not a captured successful login or a network
permission grant. No request bodies containing owner data were produced.

The same component branches to identity-issuance-date checks, credit-card
verification, stronger identity checks, password changes, declarations,
representative access and open-service-request handling. A connector must stop
for unqualified branches; a generic Continue action could exceed login QA.
The header's logout link and personal-area destination are only candidate
authenticated markers until verified after an actual, service-owned SMS attempt.
Raw page HTML and vendor bundles are not committed: the page contains transient
anonymous form tokens, and public source alone cannot prove account acceptance.
[Bound public evidence](../artifacts/harel-public-login-review-20261022.json).

The Phoenix login page observed on 22 October had no native form element. It loads a component
from `auth0-login.fnx-public.com/index.js`; a separate anonymous source download
returned HTTP 403, so that source was not reviewed. The current identity/phone
engine's one initial POST does not qualify either insurer's full JavaScript
flow. No personal login attempt was made during this review.

A fresh anonymous request on 25 October returned HTTP 403 at the Phoenix
personal-area entry itself, so that check did not reach or qualify the login
form. In the same fresh-browser check, Lemon Squeezy's email/password form
loaded with a native POST to `/login`; its authenticator challenge and a
successful session remain unreviewed. No credential was entered, code requested
or private browser profile used for any of the three sites.
[Sanitized current discovery](../artifacts/selected-provider-anonymous-discovery-20261025.json).
