# Email or username followed by a password

Some websites show the email or username first, then a separate password page.
The development candidate supports a reviewed two-step password flow without
adding an end-user command or another routine approval. The imported login is
used by the same scoped account operation as a single-page password form.

This adds an engine capability, not automatic support for an arbitrary website.
A connector still needs reviewed pages, selectors, destinations and permitted
reads. No new private account or Google/Meta/financial service is validated by
this change. Passwordless email-code flows and federated sign-in require their
own reviewed flow; this is not a Railway email-code connector.

## Connector configuration

See the complete [two-page example](../examples/browser-username-first.json).
The existing `username_selector` selects the first page's input. The password
and final submit selectors select the second page. Add:

```json
"identity_step": {
  "submit_selector": "#continue",
  "post_url": "https://account.example/identify",
  "password_url": "https://account.example/password",
  "password_post_url": "https://account.example/authenticate",
  "scripted": false
}
```

All three URLs must be explicit login resources on the login origin. Both POST
destinations must also be in `login_post_urls`. They do not grant read operations
or access to other hosts. The new configuration changes the account fingerprint
and requires its permissions to be reviewed again. An absent step preserves the
existing account fingerprint, grants and saved sessions.

The default uses a native POST form. The username field and Continue control
must belong to the same form and its effective method/action must match the
reviewed identity endpoint, including submit-button overrides. A reviewed
JavaScript identity request can use `scripted: true` only when JavaScript is
enabled. It still needs the exact POST endpoint and a real accepted HTTP
response; changing the DOM alone does not establish a completed first step.

## Runtime behavior

The service prepares the enrolled verification sources before entering either
credential. This also protects single-page JavaScript forms that may submit on
input. It then rechecks page location and priority challenges after preflight.
If no enrolled alternative is usable, ordinary sign-in stops before the identity
request and does not consume the login cooldown. An unavailable alternative does
not prevent another enrolled method from completing. Page/form checks also run
after a single-page username fill, since its input handler can change the page.

The first stage permits one POST to the identity endpoint. An unexpected POST,
an early request before preflight, or a redirect that replays the POST stops the
flow. The password is entered only after an accepted identity response and the
expected password URL/input. In that phase, POSTs are limited to the password
endpoint. Native password controls must share the matching POST form. The
ordinary verification-method handling resumes after password submission.

A first-stage request consumes the existing login cooldown. Known temporary
HTTP failures return `RETRYABLE`, letting durable tasks wait with backoff.
Changed forms/pages and unconfirmed submissions require review. CAPTCHA,
passkey, device, administrator and transaction challenges retain priority; the
service does not fill a password or reinterpret them as another login code.

## Verification scope

Controlled tests cover native and JavaScript identity requests followed by
password-only, TLS IMAP email, Messages-fixture SMS and authenticator sign-in,
then saved-session reuse. They also cover changed forms/URLs, missing sources,
inert controls, early/duplicate/wrong-endpoint POSTs, replay redirects, temporary
failures, late presence challenges and permission invalidation.

The [protected Mac composition](../artifacts/username-password-pages-080.json)
also completes two identity/password/SMS logins through the product CLI,
production system host, System key, isolated worker and native owner-UID reader,
with session reuse and durable cooldown recovery after a cold restart. Two
disposable Macs produced identical 18-check system-host reports. This uses a CI
entrypoint, synthetic enrollment and ad-hoc hash-pinned peers.

These tests use fictional accounts, messages and seeds. They do not establish
private provider compatibility, physical delivery or consumer installation.
Those remain in [production acceptance](production-gates.md).
