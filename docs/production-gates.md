# Production acceptance

Account Access remains a preview. This checklist separates tested behavior from
the remaining work required to ship the requested consumer experience. Public
source, passing tests and an edited recording do not establish private-account
or physical-device coverage.

## Candidate 0.8 changes

- A verified mailbox repair can resume an original blocked task without a
  separate website-check click. The service stores internal source/fingerprint
  context on recognized mailbox-access challenges and requires a fresh verified
  check, unchanged account/mailbox configuration and active standing grants.
  It clears only that prerequisite; ordinary website authentication still runs.
  Delivery failures, ambiguous codes, historical unbound challenges, browser
  checks and independent presence/action requirements remain pending.
- Configured OAuth mailbox checks are bound to their authorization identity,
  provider configuration and revocation/uncertain-refresh state. Normal token
  refresh preserves that identity; a new owner authorization invalidates the
  old check. Reusable mailbox passwords join the service's output-redaction set.
- Reusable TLS IMAP mailbox setup is available before a website is added. Gmail
  supplies its server/port preset; other providers require their TLS settings.
  Approved website sources can reuse only an exact matching server, port and
  recipient. Stored secrets are not returned to the agent or owner state API.
  Changing/removing a mailbox invalidates pending code reads; a health recheck
  alone does not interrupt them. Existing website permissions are unchanged.
- Owner email setup has a separate connection check. It authenticates to a
  read-only IMAP inbox and checks its UID tracking, or verifies the approved
  Gmail address through the configured OAuth account's profile. It does not
  fetch messages, start a website sign-in, resolve challenges or prove delivery.
  Changing enrollment/filter settings invalidates its result. Saved setup is
  distinguished from a checked mailbox and from completed website login.
- IMAP retrieval searches from its pre-password UID boundary, validates returned
  identifiers and fetched message identity, and stops on excessive/partial
  results rather than inspecting only the last twenty. SMS gateway retrieval
  establishes a pre-password message-ID baseline and rejects incomplete result
  pages, duplicate identities, future dates and changed enrollment. These are
  controlled protocol tests; private provider/carrier QA remains open.
- Saving verification details does not automatically retry a linked website
  blocked by an unknown page, browser verification or mandatory presence.
- Editing a browser credential invalidates the previous saved session when the
  value changes. It cannot clear independent presence, browser-verification,
  unknown-page, recovery or transaction challenges or resume their blocked task.
- Email recovery parses bounded plain-text and HTML MIME messages through the
  same exact sender, recipient, subject and login-template check. It does not
  render HTML, fetch images/links, read attached or forwarded messages, or scan
  arbitrary text for six-digit numbers. Duplicate identity headers, ambiguous
  bodies, malformed MIME and oversized messages cannot supply a code.
- Gmail checks its approved OAuth access and records existing matching message
  IDs before the password is submitted. Existing messages cannot become fresh
  codes through a future import timestamp. Incomplete/paginated result sets stop
  instead of hiding ambiguity. Rejected access can renew once per resolver call;
  removed scope and uncertain refresh rotation stop safely. This is contract and
  browser-fixture coverage, not a completed consumer Google connection.
- Authenticator recovery waits for the next interval when a code has less than
  five seconds remaining. Unpaired Android relays, missing SMS gateway details
  and disabled sources stop before password submission. These checks do not
  prove a phone is online or a carrier delivered a message.
- Distinct enrollment names cannot start competing email/SMS login windows.
  Each message channel is serialized; temporary contention waits through normal
  task retry without a new owner approval. Browser tests cover two accounts
  sharing TLS IMAP or the Messages fixture, followed by successful later reuse.
- The signed Mac app includes the Python wheel and pins its SHA-256. A repair
  reinstalls the package and restarts the background service even when the
  version number is unchanged. Python, dependencies and Chromium can still
  require network downloads.
- The wheel includes the runtime dependency export from the tested lockfile.
  Installation requires matching SHA-256 hashes for every dependency and refuses
  source builds. A replacement environment and browser are prepared before the
  old service is stopped. A failed startup restores the previous launcher;
  concurrent repairs stop before changing installed files. Previous environments
  are retained for rollback and existing client launchers. Python and Chromium
  still use their vendors' download mechanisms.
- Google Authenticator transfer QR images can be imported locally. The owner
  selects one entry for an existing authenticator source; other entries are
  discarded. Previews are encrypted, expire after ten minutes, and do not return
  keys. One complete export batch with six-digit, SHA-1 TOTP is supported. This
  is interoperability with a reverse-engineered format, not a Google API or a
  connection to Authenticator cloud sync.
- Verification setup reports the result of the website sign-in check. Saving a
  password or key alone does not mark the website connected.
- Browser connectors can bind separate email, SMS and authenticator sources to
  the same account. A browser regression completes all three after one password
  submission, checks session reuse, and confirms that a repeated code challenge
  or payment approval stops safely. Those message sources are fictional TLS
  IMAP and Messages fixtures; real delivery remains a separate gate.
- Optional verification-method pickers use exact reviewed GET links to enrolled
  sources. Changed links, missing enrollment and mandatory presence stop safely.
  A connector can also declare an offered method before its source is configured;
  that choice requests local setup and never reads a different method's code.
  The owner can review a GitHub sign-in-routing repair without importing its
  password again or expanding the approved operations or login POST destinations.
- Owner troubleshooting records fixed public route words and masks every other
  path segment. It does not record hostnames, query values, credentials or page
  contents, and it does not broaden network allowlists. A new check retires the
  previous check's routing error so a later verification stop is not mislabeled.
- Native iPhone SMS enrollment checks the Messages schema without reading message
  rows before starting a website sign-in. Missing Mac privacy permission is
  explained locally with exact Touch ID/password instructions.
- A reviewed code-request step checks the form POST destination and requests a
  code once. Repeated requests, changed forms, unusable sources and mandatory
  presence stop safely. Owner-only GitHub SMS setup can request one text before
  sender enrollment, without retrieving or submitting a code. Native setup shows
  a code-free sender review before enabling its exact filter.
- Code-request diagnostics require an actual reviewed POST response. An inert
  button or HTTP rejection cannot start the delivery wait. An HTTP-accepted
  request is still separate from a delivered SMS: the latest private attempt
  reached that request boundary but no new Mac message, and the owner reported
  no phone delivery for the preceding attempt.
- SMS enrollment and code reads support constrained typedstream bodies,
  plaintext and keyed archives. Native tests use fictional archives generated by
  Apple Foundation, including Unicode, formatting metadata and malformed data.
  SMS setup also takes a pre-request row boundary, excluding all existing texts
  while allowing a small phone-clock offset for a newly inserted message.
- Normal Mac SMS sign-ins establish that same boundary before password
  submission. A code arriving after its window expires, is cancelled, or its
  verification source/enrollment changes cannot be submitted to the website.
- Finder-launched repair reuses the cached installer. Owner-visible browser
  checks stay visible after transient retries.

## Acceptance matrix

| Requirement | Verified evidence | Remaining gate |
| --- | --- | --- |
| Simple Mac installation | Signed universal app, local update/repair flow, checksum-tamper rejection | Apple notarization and a clean downloaded-install test on a separate Mac |
| Chrome/password-manager import | Reviewed CSV imports; one selected personal entry imported in the native app | More real export formats and representative private website connectors |
| Other website providers | Namecheap username-only pilot and exact export aliases; one selected real Chrome credential imported locally; anonymous preflight and local import/session fixtures passed | Private Namecheap login stopped at browser verification/HTTP 429; password/email/TOTP acceptance remains open. Railway email-first login is not implemented. See [provider scope](other-service-validation.md) |
| Continuous password updates | Exact-item 1Password Connect contract and password-rotation recovery tests | Private Connect deployment QA; Chrome exports remain snapshots |
| Gmail and other email codes | Separate owner mailbox check; plain-text/HTML TLS IMAP browser recovery; Gmail API → browser contract, freshness, bounded renewal and complete-result checks | Registered consumer OAuth application, owner consent, real mailbox delivery QA |
| iPhone SMS | Narrow signed Messages helper, message-selection fixtures and owner-granted Mac privacy permission | Real forwarded SMS delivery and completed private sign-in QA; the latest bounded attempt detected no new incoming text |
| Android SMS | Emulator notification → pinned relay → browser verification | Physical Android pairing, notification delivery and reconnect QA |
| Google Messages Web | Owner-approved local extension installed and GitHub SMS source enabled; exact native origin, pre-password baseline and synthetic password → reader → native host → browser verification | Completed private sign-in, broader language coverage and Chrome Web Store distribution |
| Authenticator app | Setup-key and transfer-import browser recovery tests | Owner-approved real authenticator export and provider login QA |
| Passkey/security key | Real private browser sign-in identified a WebAuthn route | A reviewed browser route to an available email/SMS/authenticator method, or genuine owner presence when the provider requires it |
| Existing browser sign-in | One private GitHub Chrome session verified locally; original task resumed; fresh Claude Code and Codex reads completed without authentication input. Wrong-user, expiry, cancellation, native framing and temporary-permission contracts tested | Chrome permission display remains unconfirmed; further GitHub QA was stopped at the owner's request. Private session expiry/recovery coverage and extension marketplace distribution remain open; session reuse does not validate fresh SMS delivery |
| Automatic agent discovery | Installed skill/CLI used from ordinary prompts in Codex and Claude Code; both completed the approved private GitHub profile read | Broader private connections and host matrix |
| Credential isolation | Separate owner/agent APIs, encryption, scoped operations and fail-closed routing | Broker under a separate OS identity/host with a trusted enrollment channel; unrestricted same-user agents are not isolated |
| Open-source trust | Public MIT repository, CI, contribution guide, private vulnerability reporting enabled | Independent security review, release provenance and published production acceptance results |
| Operational health | Durable tasks, bounded retries and private diagnostic classes | Owner-visible background-worker health and unexpected-failure reporting; exceptions currently retry without exposing details |

## Private QA rules

Agent CLI fixture runs must enforce their client boundary. The current harness
uses a fixture-socket permission profile for Codex and a uniquely named temporary
skill plus invocation-only tool gate for Claude. Successful trace tools are
checked against the same policy. Older unrestricted smoke entry points refuse
before making account requests. A failed Claude global-selection incident is
retained in [validation](validation.md); it is excluded from acceptance. This
test guard is not the separate-OS-identity production custody boundary.

Keep account identifiers, raw agent traces, exports, QR images, messages and
cookies out of public artifacts. Publish sanitized coverage and failure classes.
Use read-only account checks. Preserve blocked task IDs rather than repeatedly
creating new sign-ins. Test revocation, session expiry, account switching and
recovery as well as the successful path.

Use the website's email/username and password followed by its actual login
verification methods. Another application's existing authorization is not proof
that these browser authentication flows work.

A provider-requested passkey, phone unlock, biometric or administrator approval
must be completed through its genuine owner flow. Initial enrollment can require
the owner; supported later sign-ins should reuse the approved access. No test may
replace an unavailable private source with fictional data and claim it passed.
