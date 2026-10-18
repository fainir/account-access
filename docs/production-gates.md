# Production acceptance

Account Access remains a preview. This checklist separates tested behavior from
the remaining work required to ship the requested consumer experience. Public
source, passing tests and an edited recording do not establish private-account
or physical-device coverage.

## Candidate 0.8 changes

- Revision `972b800` passes all eight workflows: both **2,130-test**
  regressions with 92 platform skips and zero warnings, both **1,037-case**
  focused Macs with one skip, and **35** executed native UI scenarios per Main
  run. All eighteen Mac reports and paired native/Linux/Android reports match;
  strict validators, package contracts and actual Installer-context checks pass.
  Fresh signed build **62**, its runtime and a separate **28-check** genuine
  production Chrome/native-host review at controller `97af5c6` pass.
  The candidate adds reviewed Bitwarden JSON snapshots, locked import authority
  rechecks, bounded UTF-8 file reads, renewable least-scope Gmail authorization
  and a guarded PyPI password/TOTP pilot. Private sign-ins remain zero; owner
  setup, real consent/delivery, physical phones, continuous Chrome/Bitwarden sync
  and consumer installation/notarization remain open. The owner's installed app
  and unfinished mailbox form were preserved. Production readiness is false.
  [Exact current evidence](../artifacts/unattended-import-080.json).
- Revision `57e7702` passes both Main regressions: **1,797 tests, 92 platform
  skips, zero warnings**, in 677.48 and 603.99 seconds. Lint, locked exports,
  sandboxing, dependency audits and package builds pass. Native reports pass
  **67 gateway, 38 desktop, 18 framing and 23 Gmail callback checks**; Linux
  isolation passes **24**, and Android emulator delivery passes **6**. These
  push/PR report pairs match. Both focused Macs pass 1,018 cases with one skip,
  with all eighteen reports matching across sixteen strict validators and the
  original 16-check/prepared 23-check package contracts. Actual Installer
  sandbox and eight native handoff checks preserve shared-parent permissions.
  A separate genuine publisher production-entrypoint review passes **28 checks** at QA controller `84452a4` using a fresh browser profile with the exact production registration; both pending requests reach the pre-enrollment service. The existing runner identity is unchanged; the review image, service, temporary profile and registration files are removed. Owner approval and enrollment are not exercised.
  The canonical owner app and resources now reside in protected
  `/Library/Application Support/Account Access/owner.app`; the public
  `/Applications` entry is a fixed launcher symlink. Source-image recovery
  preserves existing names, verifies the canonical tree and publishes the
  inode-bound alias exclusively without changing shared directory permissions.
  Signed-desktop Gmail PKCE, complete multi-QR authenticator import and exact-item
  1Password SDK sync have controlled coverage. No new private sign-in or owner
  installation occurred; the unfinished owner mailbox form was preserved.
  Consumer deployment and production readiness remain false.
  [Earlier connected-setup evidence](../artifacts/connected-setup-080.json).
- Application revision `585412e` passes all eight workflows: two **1,605-test**
  regressions with 79 platform skips and two **889-case** focused Mac suites
  with one skip. All eighteen worker reports match. A new 17-check journey uses
  genuine signed stable Chrome and the unchanged extension for native
  framing/desktop/XPC/isolated-worker pending reads, native-port reuse and reload
  reconnection. Its fixture entrypoint does not join Google Messages DOM or
  password/SMS login to this path. Provisioning passes 37 checks, including seven
  actual subprocess kill boundaries. Enrollment revisions and live mailbox
  authorization checks reject revoked/replaced sources and stale in-flight
  phone requests without another routine approval. A fresh signed review app
  pins all 55 current Python modules and passes five executable audits and
  sixteen static peer checks. No owner app was installed or new private sign-in
  requested. [Exact current evidence](../artifacts/verification-authority-080.json).
- Revision `304df4c` passes all eight workflows, two 1,517-test regressions with
  77 platform skips and two 799-case focused Mac suites with one skip. All
  seventeen worker reports match. A new 18-check native framing/desktop/XPC/worker
  composition completes fictional password/SMS recovery and session reuse;
  signed Chrome parentage, extension/DOM, genuine approval and physical delivery
  remain separate. Provisioning now passes 34 checks, including five actual
  SIGKILL boundaries for empty private-directory staging and exclusive
  publication. Password-source updates retain unrelated login gates, serialize
  with owner edits, scan fairly and let repaired-source tasks continue without
  another polling interval. A fresh signed review app pins the changed code and
  passes five executable audits and sixteen static peer checks. No owner app
  was installed or new private sign-in requested.
  [Evidence for that revision](../artifacts/protected-recovery-080.json).
- Genuine Developer ID staging exposed a production signature-check argument
  defect: a bare `codesign -R` requirement was interpreted as a filename. The
  corrected `-R=` invocation preserves the rule and has an actual native parser
  regression. Revision `b2dddbc` passes all eight workflows, both 1,445-case
  regressions with 75 platform skips, and two warning-free 745-case focused Mac
  suites with one skip. All four genuine universal peers and five executable
  files pass publisher/purpose/timestamp/runtime checks. A separate genuine
  runtime passes its complete native audit and callback/browser probes with
  library validation enabled and hash-bound JIT permissions only. This is
  ordinary-user compatibility, not publisher-signed installed deployment or
  genuine owner setup. [Method and evidence](publisher-runtime-checks.md).
- Same-image/same-owner installation recovery passed actual Installer journeys
  on two disposable Macs. A script-only package verifies its complete public
  source before isolated privileged Python, copies under an exclusive journal
  lease, publishes complete directories exclusively and rechecks the installed
  image natively before provisioning. CI kills the actual coordinator after its
  protected intent, reinstalls the package and retries again without replacing
  the public roots or receipt. Original 16-check and prepared 23-check package
  reports match across both Macs. Revision `a777168` passed all eight workflows
  and two 1,445-case regressions with 74 platform skips each. Unsigned setup
  deliberately stops before credential enrollment or registration: completed
  consumer setup, interrupted positive provisioning, physical power loss,
  different-image updates and migration remain unverified.
  [Exact recovery evidence for that revision](../artifacts/resumable-installer-080-a777168.json).
- Native public-image verification now runs before privileged Python during
  fresh installation. It binds the complete bounded inventory, checks root
  ownership/modes/ACLs and stable hashes through non-following descriptors, and
  requires exact directory children and confined aliases. The builder preflights
  inventories through metadata-only stdin; acceptance requires the distinct
  installed-image receipt. An actual-Installer probe isolated Apple's sticky
  `/private/tmp` resource ancestor, which receives a narrow resource-only rule;
  installed payload walks retain strict protection. Both disposable Macs passed
  original 13-check and prepared 20-check package acceptance; both regressions
  passed 1,380 tests with 66 platform skips. These earlier fixtures did not
  exercise the subsequent recovery implementation above. Positive consumer
  setup remains unverified.
  [Exact native-verification evidence](../artifacts/native-install-verification-080.json).
- The current Mac runtime requires Apple silicon, running natively. Intel and
  Rosetta bootstrap sessions stop before downloads/runtime changes; the package
  assembler also refuses Intel before opening payload inputs. The pinned
  cryptography release no longer publishes Intel Mac wheels. Universal native
  binaries alone do not establish Intel installation support. Source compilation
  or an older cryptography release is not used as an automatic fallback.
  [Upstream platform change](https://cryptography.io/en/50.0.2/changelog/#v49-0-0).
- Mac package assembly checks its private native payload before running the
  supplied Python. Production builds require Developer ID signatures and secure
  timestamps throughout runtime folders and dependency wheels, hardened runtime
  for executables, compatible architecture slices and valid bundle seals. Wheel
  traversal/collision/symlink and native-container bounds are checked in both
  modes. Development inventory never claims publisher verification. Optional
  maintainer preparation now binds exact runtime input trees/executables, signs
  private copies, rebuilds native wheel checksum records and derives installer
  hashes from the original locked artifacts. The source lock remains unchanged.
  The complete development-package check additionally binds installed native
  bytes/signatures, package receipts and locks, native callbacks and sandboxed
  browsing. Its explicit ad-hoc library-validation exceptions are fixture-only.
  Complete runtime assembly now installs the exact approved wheels during the
  ordinary-user build without executing package code or compiling bytecode. The
  administrator-level installer uses that image without pip/venv or recursive
  permission changes. Original artifact filenames/hashes, wheel records and the
  dependency graph are checked; the final copied image receives another native
  audit and complete file/mode/alias inventory.
  [Twenty prepared-install checks passed on two disposable Macs](../artifacts/native-install-verification-080.json).
  Publisher-signed installed runtime compatibility, Apple acceptance and positive consumer
  installation remain open. CodeDirectory runtime flags are checked separately
  from executable-segment flags; missing or duplicate directory metadata stops.
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
  fingerprints remain unchanged when the optional identity step is absent. The
  [18-check protected Mac composition](../artifacts/username-password-pages-080.json)
  also requires two identity/password/SMS logins, session reuse and durable
  recovery after a cold restart; its accounts/messages are synthetic.
- Staged Mac build 62 requires macOS 14 (Sonoma) or later, matching the
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
| Simple Mac installation | Signed universal app, local update/repair flow, checksum-tamper rejection; resumable maintainer notary helper with real local preflight and protocol failure tests | Developer ID Installer identity for the protected package, valid Notary credentials, live Apple acceptance/stapling and a clean downloaded-install test on a separate Mac |
| Dedicated Mac service provisioning | [37 checks in two disposable Macs](../artifacts/verification-authority-080.json): non-login identity, private empty state, five private-directory and two immediate public-directory SIGKILL/retry boundaries, exact modes under a restrictive inherited mask, idempotent policy publication, persistent job registration, cold user-domain recreation and native pre-enrollment denials | Signed consumer deployment, migration, machine reboot, genuine positive owner approval and complete interrupted positive provisioning |
| Offline protected Mac package | [Current candidate](../artifacts/connected-setup-080.json) inventories the canonical `owner.app` under protected Library support, treats the public Applications entry as one literal launcher symlink, and checks exclusive publication, inode-bound recovery and unchanged shared-parent permissions. Current matching actual Installer journeys pass 16 original and 23 prepared checks, and both native script-sandbox handoffs pass. | The separate genuine-publisher review passes 28 pre-enrollment transport checks after production prepare/activate; it does not install a signed consumer package. Apple silicon only; signed/notarized consumer installation, genuine owner setup, positive provisioning interruption, power loss/reboot, different-image updates/migration and clean downloaded-install QA remain open. |
| System-service entrypoint | [Current native reports](../artifacts/connected-setup-080.json) pass 67 gateway, 38 desktop and 18 framing checks. The owner app binds its executable, resources and Info to the protected canonical bundle and checks static/running code identity independently of the public launcher. | Genuine publisher Chrome → production native host → pinned desktop/XPC → initial-enrollment denial passes twice in the separate 28-check review. Genuine owner approval, account enrollment and consumer deployment remain open. |
| First isolated vault setup | Initializer/key verification/publication passed [28 checks](../artifacts/mac-staged-enrollment-080.json); native setup-session authority → fresh System key → published store → worker passed [40 first-vault/client checks](../artifacts/mac-agent-setup-080.json), including initialized-vault Pause/Resume and missing-key repair | Positive setup authority is synthetic; genuine owner approval, positive separate-process native enrollment, full crash/power-loss recovery, complete isolated source/collector setup, consumer client provisioning/repair and installed migration |
| Automatic agent client setup | One portable identity, digest-only enrollment, both host launchers and preserved session instructions passed [40 first-vault/client checks and 38 transport checks](../artifacts/mac-agent-setup-080.json) | Genuine OS approval, consumer deployment, migration/revocation repair, real Codex/Claude sessions against this isolated setup and private sign-in QA |
| Chrome/password-manager import | Reviewed CSV and candidate Bitwarden JSON imports; one selected personal Chrome entry imported using an earlier native preview | More real export formats and representative private website connectors |
| Other website providers | Namecheap username-only pilot and exact export aliases; one selected real Chrome credential imported locally; anonymous preflight and local import/session fixtures passed | Private Namecheap login stopped at browser verification/HTTP 429; password/email/TOTP acceptance remains open. Railway email-first login is not implemented. See [provider scope](other-service-validation.md) |
| Continuous password updates | [Exact-item 1Password service-account SDK and Connect](onepassword-sync.md) contracts; encrypted local tokens, approved username/origin binding, bounded isolated reads, serialized edits, preserved website gates and retry after repaired sources. | Private service-account/Connect enrollment, real rotation and revocation QA. CSV/JSON exports remain snapshots; continuous Chrome and Bitwarden sync is unimplemented. |
| Gmail and other email codes | [Signed-desktop Gmail browser/PKCE setup](gmail-authenticator-and-sms.md), with 23 native callback/lifetime checks and controlled browser/token/cancellation tests. Separate mailbox checks, bounded Gmail freshness/renewal and plain-text/HTML TLS IMAP recovery remain covered. | Publisher-registered and verified consumer Google application, genuine owner consent and real mailbox/code-delivery QA. Arbitrary webmail is unsupported. |
| iPhone SMS | Narrow signed Messages helper, message-selection fixtures and owner-granted Mac privacy permission | Real forwarded SMS delivery and completed private sign-in QA; the latest bounded attempt detected no new incoming text |
| Isolated Mac SMS collector | [13 native checks](../artifacts/mac-native-messages-080.json), [10 composed checks](../artifacts/mac-native-browser-080.json) and [18 current system-host recovery checks in two Macs](../artifacts/protected-recovery-080.json): actual production host, System key, CLI, isolated worker and native reader complete two fresh password/SMS logins with session reuse and automatic durable cooldown recovery after a cold restart; restricted results and store/collector denials remain enforced | CI entrypoint and synthetic enrollment/messages/website; real agent sessions, genuine owner approval/Full Disk Access, physical delivery and installed consumer QA remain |
| Android SMS | [Current matching six-check emulator journeys](../artifacts/connected-setup-080.json): encrypted pairing, actual notification listener, private destination checks, pinned HTTPS ingress, browser code submission and no code in the agent result. | Physical Android pairing, carrier/notification delivery and reconnect QA. |
| Google Messages Web | [Current stable-Chrome checks](../artifacts/connected-setup-080.json) separate the unchanged production-manifest transport (17 checks) from a nested synthetic DOM/password/SMS/session composition (17 checks; unchanged script/UI files, test-only pre-enrolled Messages origin). Both use native framing, desktop/XPC and the isolated worker. The separate 28-check genuine-publisher review reaches initial enrollment twice through the actual production entrypoint, with a fresh profile and exact production host registration; it grants no Messages permission and performs no website login. | Genuine positive owner approval, complete genuine signed-worker website login, private/physical SMS delivery, broader language coverage and Web Store distribution remain open. |
| Authenticator app | [Local setup-key and complete transfer-batch import](gmail-authenticator-and-sms.md): up to 16 matching QR parts/100 supported TOTP entries, one owner-selected account, encrypted expiring previews, atomic enrollment and rejection of missing, duplicate or mixed parts; controlled browser recovery. | Owner-approved real phone export and provider TOTP login QA. Push approvals, nonstandard TOTP settings and Google Authenticator cloud-sync access are unsupported. |
| Passkey/security key | Real private browser sign-in identified a WebAuthn route | A reviewed browser route to an available email/SMS/authenticator method, or genuine owner presence when the provider requires it |
| Existing browser sign-in | One private GitHub Chrome session verified locally; original task resumed; fresh Claude Code and Codex reads completed without authentication input. Wrong-user, expiry, cancellation, native framing and temporary-permission contracts tested | Chrome permission display remains unconfirmed; further GitHub QA was stopped at the owner's request. Private session expiry/recovery coverage and extension marketplace distribution remain open; session reuse does not validate fresh SMS delivery |
| Automatic agent discovery | Installed skill/CLI used from ordinary prompts in Codex and Claude Code; both completed the approved private GitHub profile read | Broader private connections and host matrix |
| Credential isolation | Linux worker passed 24 and Mac worker passed 25 real cross-user checks with fictional password/email/SMS/TOTP ([Linux evidence](../artifacts/worker-boundary-080.json), [Mac worker evidence](../artifacts/mac-worker-boundary-080.json)); current native Mac owner channel passes [67 checks](../artifacts/connected-setup-080.json) and [24 root host integration checks](../artifacts/mac-root-owner-080.json); the separate System key provider passed [20 daemon checks](../artifacts/mac-key-custody-080.json) and setup-policy provisioning passed [16 checks](../artifacts/mac-owner-policy-080.json). System key → production storage → worker start/stop/crash recovery passed [33 native checks](../artifacts/mac-key-handoff-080.json); native bounded supervision passed [21 checks](../artifacts/mac-root-supervisor-080.json). The composed system host passed [31 parent-crash/cold-service checks](../artifacts/mac-root-coordinator-080.json) | Consumer deployment, machine reboot and active-operation/browser-descendant recovery, genuine owner authorization, trusted enrollment/client issuance and consumer integration; the installed same-user Mac app is not isolated. Controlled cross-user/key/worker recovery uses fixture peers in disposable VMs; the separate genuine publisher review proves only the production entrypoint and pinned dynamic XPC before enrollment, with no owner authorization, key creation or authenticated worker website journey. |
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
