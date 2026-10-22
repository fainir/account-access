# Harel and Phoenix login acceptance

Owner-selected targets: Harel and Phoenix. The owner receives SMS on Android.
Neither provider is currently a bundled supported connector. Public-page
inspection on 22 October 2026 did not submit an identity number, contact detail,
password or code, and did not access an insurance account.

| Provider | Official entry | Public login observed | Remaining provider evidence |
| --- | --- | --- | --- |
| Harel | [Personal area](https://www.harel-group.co.il/Pages/login-page/Login.aspx) | Identity number and phone; SMS/email choice. Visible identity input `#idUser` and phone input `#phone`. | Exact send-code endpoint, code screen, sender/template, authenticated marker, session expiry and read scope. |
| Phoenix | [Personal area](https://my.fnx.co.il/policies) | Redirect to `auth.fnx.co.il/u/login` with a per-attempt state. Identity type and number, then phone or email, followed by Send code. | Bound redirect/state handling, exact send-code endpoint, code screen, sender/template, authenticated marker, session expiry and read scope. |

Harel's [official FAQ](https://www.harel-group.co.il/long-term-savings/independent-and-employees/information/faq)
describes identity/phone verification and possible first-login identity-issuance
date verification. Phoenix's [security information](https://www.fnx.co.il/customer-service/terms-of-use/security/)
describes personal-area login using an identity number and an SMS code.

These are identity-and-contact flows followed by a code. They must not be
represented as imported Chrome passwords. The current browser-login model
requires a username and password. A reviewed extension must support locally
encrypted identity/contact inputs, preserve existing password connectors and
their grant fingerprints, and exclude identity/contact values from agent
results, diagnostics and logs. Native enrollment must label these fields
accurately and never ask for them in a chat.

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

Phoenix's anonymous login page has no native form element. It loads a component
from `auth0-login.fnx-public.com/index.js`; a separate anonymous source download
returned HTTP 403, so that source was not reviewed. The current browser adapter's
native username/password-form checks do not qualify either insurer's JavaScript
flow. No personal login attempt was made during this review.
