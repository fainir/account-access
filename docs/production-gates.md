# Production acceptance

Account Access remains a preview. This checklist separates tested behavior from
the remaining work required to ship the requested consumer experience. Public
source, passing tests and an edited recording do not establish private-account
or physical-device coverage.

## Candidate 0.8 changes

- Reviewed two-page password flows can submit an email/username to one exact
  identity endpoint, verify the expected password page, and submit the password
  only to its declared endpoint. Native form controls must share the reviewed
  POST form; JavaScript identity requests need explicit configuration and an
  actual accepted response. Early/duplicate/wrong-endpoint requests and POST
  replay redirects stop. Temporary failures retain automatic task retry and the
  normal cooldown. This is controlled coverage, not a new private provider.
- Verification-source preflight now runs before any credential fill, followed by
  another page/presence check. Single-page username input handlers are rechecked
  before filling the password. Routine sign-in with no usable enrolled method
  stops without consuming a first-stage login attempt; an unavailable alternative
  does not block another usable method. Existing connector
  fingerprints remain unchanged when the optional identity step is absent.
- Staged Mac build 61 requires macOS 14 (Sonoma) or later, matching the
  pinned Playwright browser runtime. App metadata, shell preflight and the direct
  Python bootstrap enforce this before downloads/runtime changes. This corrects
  the previous macOS 13 claim; it is not clean-Mac installation acceptance.
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
- Failed updates restore both runtime and desktop launchers. Stopping waits for
  actual supervisor/service leases; if a replacement cannot confirm shutdown,
  its environment is retained and the previous service is not restarted beside
  it. Controlled failure tests cover these cases; installed owner upgrade remains
  a separate acceptance gate.
- Runtime activation records bind the wheel, managed interpreter, launcher
  digest and exact isolated command. Native reopening and the OS helper reject
  stale/unbound activation. Updated managed clients use the activated launcher
  for cold startup, preserving Pause. This does not attest every runtime file or
  protect against an unrestricted same-user process; unchanged legacy clients
  need their integration refreshed and long-running processes restarted.
- Installer preflight rejects unsafe existing runtime directories, launchers
  and lock files before executing an old installation. An ownership marker
  alone is insufficient. This does not make user-writable runtime code an
  isolated credential boundary.
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
| Simple Mac installation | Signed universal app, local update/repair flow, checksum-tamper rejection; resumable maintainer notary helper with real local preflight and protocol failure tests | Valid publisher Notary credentials, live Apple acceptance/stapling and a clean downloaded-install test on a separate Mac |
| Dedicated Mac service provisioning | [26 checks in two disposable Macs](../artifacts/mac-system-provisioning-080.json): non-login identity, private empty state, idempotent policy publication, persistent job registration, cold user-domain recreation and native pre-enrollment denials | Signed consumer deployment, migration, machine reboot, genuine positive owner approval and interrupted-install repair |
| Offline protected Mac package | [10 negative checks in two disposable Macs](../artifacts/mac-system-package-080.json): actual Installer, bundled Python, hash-locked offline dependencies, relocated sandboxed browser, unchanged shared folder permissions and refusal before unsigned credential setup | Signed/notarized positive installation, runtime publisher/notarization acceptance, first successful owner setup, updates and clean downloaded-install QA; development archive is not a consumer download |
| System-service entrypoint | Universal service/bootstrap build and signature/ordinary-user guard checks; the actual entrypoint's separate-process native owner connection passed [18 pre-enrollment checks](../artifacts/mac-desktop-connection-080.json) | Native desktop/profile integration and unsigned negative package provisioning have controlled coverage; publisher-signed positive installed deployment and genuine approval through the screens remain |
| First isolated vault setup | Initializer/key verification/publication passed [28 checks](../artifacts/mac-staged-enrollment-080.json); native setup-session authority → fresh System key → published store → worker passed [40 first-vault/client checks](../artifacts/mac-agent-setup-080.json), including initialized-vault Pause/Resume and missing-key repair | Positive setup authority is synthetic; genuine owner approval, positive separate-process native enrollment, full crash/power-loss recovery, complete isolated source/collector setup, consumer client provisioning/repair and installed migration |
| Automatic agent client setup | One portable identity, digest-only enrollment, both host launchers and preserved session instructions passed [40 first-vault/client checks and 38 transport checks](../artifacts/mac-agent-setup-080.json) | Genuine OS approval, consumer deployment, migration/revocation repair, real Codex/Claude sessions against this isolated setup and private sign-in QA |
| Chrome/password-manager import | Reviewed CSV imports; one selected personal entry imported in the native app | More real export formats and representative private website connectors |
| Other website providers | Namecheap username-only pilot and exact export aliases; one selected real Chrome credential imported locally; anonymous preflight and local import/session fixtures passed | Private Namecheap login stopped at browser verification/HTTP 429; password/email/TOTP acceptance remains open. Railway email-first login is not implemented. See [provider scope](other-service-validation.md) |
| Continuous password updates | Exact-item 1Password Connect contract and password-rotation recovery tests | Private Connect deployment QA; Chrome exports remain snapshots |
| Gmail and other email codes | Separate owner mailbox check; plain-text/HTML TLS IMAP browser recovery; Gmail API → browser contract, freshness, bounded renewal and complete-result checks | Registered consumer OAuth application, owner consent, real mailbox delivery QA |
| iPhone SMS | Narrow signed Messages helper, message-selection fixtures and owner-granted Mac privacy permission | Real forwarded SMS delivery and completed private sign-in QA; the latest bounded attempt detected no new incoming text |
| Isolated Mac SMS collector | [13 native checks](../artifacts/mac-native-messages-080.json), [10 composed checks](../artifacts/mac-native-browser-080.json) and [17 system-host recovery checks in two Macs](../artifacts/mac-native-system-browser-080.json): actual production host, System key, CLI, isolated worker and native reader complete two fresh password/SMS logins with session reuse and automatic durable cooldown recovery after a cold restart; restricted results and store/collector denials remain enforced | CI entrypoint and synthetic enrollment/messages/website; real agent sessions, genuine owner approval/Full Disk Access, physical delivery and installed consumer QA remain |
| Android SMS | Emulator notification → pinned relay → browser verification | Physical Android pairing, notification delivery and reconnect QA |
| Google Messages Web | Legacy owner-approved extension installed; exact origin, fresh-message baseline and synthetic password/SMS browser recovery. New protected-app bridge passed [18 native component checks](../artifacts/mac-browser-bridge-080.json), fixed-resource registration and a separate private-Unix/DOM/browser fixture without vault access | Complete protected Chrome/native/XPC/worker journey, positive signed-Chrome parent check, genuine approval and installed setup, private delivery, broader language coverage and Web Store distribution |
| Authenticator app | Setup-key and transfer-import browser recovery tests | Owner-approved real authenticator export and provider login QA |
| Passkey/security key | Real private browser sign-in identified a WebAuthn route | A reviewed browser route to an available email/SMS/authenticator method, or genuine owner presence when the provider requires it |
| Existing browser sign-in | One private GitHub Chrome session verified locally; original task resumed; fresh Claude Code and Codex reads completed without authentication input. Wrong-user, expiry, cancellation, native framing and temporary-permission contracts tested | Chrome permission display remains unconfirmed; further GitHub QA was stopped at the owner's request. Private session expiry/recovery coverage and extension marketplace distribution remain open; session reuse does not validate fresh SMS delivery |
| Automatic agent discovery | Installed skill/CLI used from ordinary prompts in Codex and Claude Code; both completed the approved private GitHub profile read | Broader private connections and host matrix |
| Credential isolation | Linux worker passed 24 and Mac worker passed 25 real cross-user checks with fictional password/email/SMS/TOTP ([Linux evidence](../artifacts/worker-boundary-080.json), [Mac worker evidence](../artifacts/mac-worker-boundary-080.json)); native Mac owner channel passed [58 separate-process checks](../artifacts/mac-owner-gateway-080.json) and [24 root host integration checks](../artifacts/mac-root-owner-080.json); the separate System key provider passed [20 daemon checks](../artifacts/mac-key-custody-080.json) and setup-policy provisioning passed [16 checks](../artifacts/mac-owner-policy-080.json). System key → production storage → worker start/stop/crash recovery passed [33 native checks](../artifacts/mac-key-handoff-080.json); native bounded supervision passed [21 checks](../artifacts/mac-root-supervisor-080.json). The composed system host passed [31 parent-crash/cold-service checks](../artifacts/mac-root-coordinator-080.json) | Consumer deployment, machine reboot and active-operation/browser-descendant recovery, genuine owner authorization, trusted enrollment/client issuance and consumer integration; the installed same-user Mac app is not isolated. Root host deployment was tested only in a disposable VM with ad-hoc hash-pinned peers |
| Open-source trust | Public MIT repository, CI, contribution guide, private vulnerability reporting enabled | Independent security review, release provenance and published production acceptance results |
| Operational health | Worker health and bounded retries; process leases, native reconnection and same-version payload handshake; signed Apple-registered per-user guardian with real synthetic-job crash/Pause/cleanup acceptance | Actual logout/reboot and installed owner upgrade, external monitoring/alerting and separate-identity custody remain open |

## Private QA rules

Classify each account and result from its recorded source environment. Known
public examples and local fixtures do not count as personal/work account
acceptance, including in a mixed list. Legacy task results without recorded
classification are unclassified. Configuration labels and a test-mode flag alone
are not evidence of private ownership, a fresh sign-in or completed delivery.

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
