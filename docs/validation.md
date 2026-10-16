# Validation of Account Access

## Browser verification and repair candidate — 16 October 2026, version 0.8

Follow-up `6db076d` fixes the reviewed SMS-request guard for a connected Google
Messages source and adds nine exact public GitHub assets used by the passkey
page's alternative-method control. An owner-reviewed connector update preserves
the enrolled SMS source and read grants. All **235 tests**, nine native
owner-screen checks, native Messages checks, Ruff, dependency audit and build
passed in [CI](https://github.com/fainir/account-access/actions/runs/38899053403).
The [Android emulator journey](https://github.com/fainir/account-access/actions/runs/38899053946)
also passed. The preceding local full suite passed 234 tests; the asset-refresh
grant-preservation test and eight related cases then passed locally.

The latest follow-up preserves Chromium's native main-frame transport and final
redirect URL while checking every redirect response before it is followed. Tests
cover credential-bearing 307/308 redirects and requests from pages, fetches,
iframes, workers and popups. Candidate `81e3ec7` passed all **233 tests**, eight
native owner-screen checks, native Messages checks, Ruff, dependency audit and
package build in [CI](https://github.com/fainir/account-access/actions/runs/38895850906).
Its [Android emulator journey](https://github.com/fainir/account-access/actions/runs/38895850882)
also passed. The local full run passed 229 tests before four additional targeted
cases covered extension identity/permissions, revocation and an offline paired tab.

The optional [Google Messages connection](google-messages.md) has 26 passing
synthetic tests, including password → paired-page DOM reader → framed native host
→ browser SMS verification. A real extension load used a separate temporary
Chromium profile and verified that message-site access was absent initially.
Only structural metadata and fresh-message indicators were inspected on the
owner's paired Google Messages tab; no code was returned to the agent. The owner
loaded the extension and its approved GitHub SMS connection is enabled. Private
sign-in validation is still in progress; connection enrollment is not completed
SMS-delivery or website-login QA.

Native checks now also distinguish a timeout before confirmed SMS dispatch from
unconfirmed delivery after dispatch. A provider-required owner action or unknown
sign-in page is reported before the owner review window ends. Graphical repair
to signed build 30 preserved saved accounts and permissions. The owner view now
exposes closed route/control diagnostics and exact public vendor asset names,
excluding credentials, code values, arbitrary page text and URL queries. Chrome
Web Store distribution remains outstanding.

After the build 30 live attempt, desktop control could reach Chrome but could
not attach to Account Access while two app instances were running. The owner was
asked to close and reopen the app. A build 31 source follow-up now asks the prior
canonical owner window to terminate normally before replacing its bundle, waits
up to eight seconds, and refuses replacement if that window remains open. It
does not force-terminate an active owner step or stop the independent account
service. Compilation and all nine native screen checks passed locally; the
guard's real update recovery remains to be verified.

The functional candidate at `9fbcad0` passed 173 tests, native owner/reader checks,
Ruff, dependency audit and build in [CI](https://github.com/fainir/account-access/actions/runs/38886257072).
Its [Android emulator journey](https://github.com/fainir/account-access/actions/runs/38886257119)
also passed. Eighteen additional evidence-checker cases cover successful absolute
and relative launcher execution and reject merely echoed/read paths, failed
commands and unrelated launchers.

Native build 21 was installed through graphical repair on the pilot Mac. Its
bundled wheel matched the signed checksum, its installed dependency lock matched
the tested source, and existing account/grant state was preserved. The installed
skill then completed a public SauceDemo inventory read. This is local repair
evidence, not a clean notarized installation on a separate Mac.

Fresh ordinary-language Codex and Claude Code sessions each completed one durable
task across four fictional browser accounts, with four password submissions and
one email, SMS and authenticator verification. Independent provider counters and
task results confirm completion. Claude used `cd` into the project skill followed
by `scripts/access`; the checker was corrected to recognize that successful form
and the actual trace was rechecked. These fixtures do not establish private
mailbox or physical-phone delivery. Evidence: [Codex](../artifacts/agent-tests/codex-verification-080.json),
[Claude](../artifacts/agent-tests/claude-verification-080.json).

The personal browser pilot used its imported website password and reached the SMS
request form. An instrumented reviewed POST received an HTTP-accepted response,
but no new incoming text appeared on the Mac in the bounded window. The owner
reported no phone delivery for the preceding attempt. No SMS source was enabled,
no private verification code was submitted, and the original blocked task was
preserved. Real mailbox/authenticator enrollment and private sign-in completion
remain outstanding. [Production acceptance](production-gates.md) records the
remaining isolation, distribution and service-coverage gates.

## Automatic sessions and revised UX — 14 October 2026, version 0.6

The native Mac app and responsive local console now show account status, actual approved reads, verification setup and password-import guidance separately. Desktop and 390-pixel mobile console layouts were rendered and checked; the native dashboard, verification empty state and password-import navigation were inspected on the Mac.

Fresh CLI sessions received an ordinary-language comparison request with no skill name, slash command or launcher command in the prompt. Codex automatically selected the integration and completed a saved three-account task. Claude Code automatically selected it, completed all three reads and saved a comparison file. The service audit independently confirmed each completion. Both used only the configured public SauceDemo and The Internet accounts, with existing host hooks and general approval modes retained. Codex's installed rule permits only the exact client launcher and supported client commands; it does not allow general Python or shell commands.

The installed Codex CLI rejected the profile's default model before any work. The successful isolated test used the CLI's bundled `gpt-6-astra` model without changing the user's default. Claude's unrelated stop hook attempted four blocked writes to its sensitive session-log path after the requested account work had finished. Those denials are retained in the report; Account Access had zero permission denials. These results do not establish compatibility with every host policy.

A cold local service was then restarted by the installed client without opening owner setup. All three accounts were discovered and the client token and grants remained unchanged. Deliberate pause and response-timeout replay behavior are covered by regression tests. The full local suite passed 75 tests, and the universal Mac build is Developer ID signed. Apple notarization and real private account / physical-phone validation remain outstanding.

Evidence: [Codex session](../artifacts/agent-tests/codex-implicit-06.json), [Claude session](../artifacts/agent-tests/claude-implicit-06.json), [automatic startup](../artifacts/automatic-start-06.json), [dashboard](account-dashboard.png). Raw traces, personal instructions and owner metadata remain excluded from Git.

## Earlier 0.3.1 checks

Observed on 12 October 2026 on macOS, Python 3.13 and Chromium installed through Playwright. This is a **working release candidate**, not a certification of production financial access. No private bank, insurance, Google, Meta or other personal account was connected or tested. No phone inbox was accessed.

## Public release verification — 13 October 2026

The public GitHub repository was verified as readable without authentication. A clean checkout was synchronized, built and installed in an isolated tool directory, then completed all three local demo reads as one durable task. Existing host skill directories were not modified by that verification. Gitleaks reported zero findings in the publication tree and public history; runtime vaults, keys and raw agent traces are excluded. The original local development history was preserved locally, and only the fresh public history with GitHub's no-reply commit email was pushed.

[Linux CI](https://github.com/fainir/account-access/actions/runs/38374863318) passed **43 regression tests**, lint, dependency auditing and distribution building for code revision `0cc7863ea9f1cb478e9da641933926a10ca7acc0`. The first Linux run exposed Ubuntu's restrictions on sandbox namespaces for the downloaded browser. CI now loads an AppArmor policy scoped to the exact installed browser executables and verifies launch with Chromium's sandbox enabled. An initial helper assumed the older headless executable filename; it was corrected for the current and older names before the successful run. The application sandbox setting was not weakened.

Machine-readable publication results are in `artifacts/public-release.json`. These publication checks add Linux and installation evidence to the earlier experiment; they do not add private-account, mobile or thirty-day reliability validation.

## Measured checks

| Check | Result | Evidence |
| --- | --- | --- |
| Regression suite | 43 passed, 93.75 seconds | `uv run pytest -q`; tests in `tests/` |
| Source lint | Passed | `uv run ruff check account_access tests scripts` |
| Known dependency vulnerabilities | None reported at test time | `artifacts/dependency-audit.json`; `pip-audit --local` |
| Portable skill schema | Passed | Bundled skill-creator `quick_validate.py` |
| Distribution | Wheel and source archive built; UI and skill resources present; runtime keys/databases/raw agent traces absent | `dist/account_access-0.3.1-py3-none-any.whl`, `dist/account_access-0.3.1.tar.gz` |
| Owner console | Rendered in Chromium and visually inspected | `artifacts/owner-console.png`; fake UI data |
| Codex CLI 0.155.1 | Five-account task completed; exit 0; 46.633 seconds | `artifacts/agent-tests/codex-summary.json` |
| Claude Code CLI 2.1.112 | Five-account task completed; exit 0; 51.730 seconds; zero permission denials | `artifacts/agent-tests/claude-summary.json` |

An earlier full-suite run had one ten-second subprocess timeout while other workloads were active. The isolated retry passed in 1.92 seconds. The CLI integration test now allows thirty seconds, and the final full suite passed. The dependency audit originally found advisories in the older cryptography dependency; the implementation now requires cryptography 50.x, and the final audit reported none. These are observed checks, not a comprehensive security audit.

## Controlled repeated access

The benchmark creates real HTTP OAuth and website fixtures, runs a real Chromium browser, reopens the encrypted store/broker for every run, and checkpoints each read as a durable task. Enrollment is programmatic with fictional credentials; human onboarding effort is **not measured**.

| Account route | Runs | Unattended completions | Post-setup challenges | Automatic recovery |
| --- | ---: | ---: | ---: | --- |
| OAuth API | 30 | 30 | 0 | 30 refreshes; local expiry forced before each read |
| Password website | 30 | 30 | 0 | One password login, then session reuse |
| Password + TOTP website | 30 | 30 | 0 | One password login and one TOTP submission, then session reuse |

The final accelerated experiment took 85.023 seconds. This is 90/90 unattended completions under controlled conditions, **not thirty days of uninterrupted access**. After invalidating refresh access, five blocked jobs shared one challenge. One simulated owner reconnection resumed all five jobs automatically. The exact recovery timing is in `artifacts/benchmark.json`; it depends on execution and polling rather than a guaranteed SLA.

Regression tests separately cover rotating refresh tokens across threads and processes, lost refresh responses, interrupted work, grant expiry/revocation, configuration drift, denied operations, provider outages, session expiry, code ambiguity and action-authorization challenges.

## External public demo integrations

Only identities deliberately published for testing were used. The experiment enrolled seven identity cases across **three external testing services**. Each of the five positive identities completed five reads with a freshly constructed broker on every run.

| Service and case | Successful reads | Automatic password attempts | Automatic OAuth refreshes | Unique authentication challenges |
| --- | ---: | ---: | ---: | ---: |
| SauceDemo standard user | 5/5 | 1 | 0 | 0 |
| SauceDemo problem user | 5/5 | 1 | 0 | 0 |
| The Internet valid account | 5/5 | 1 | 0 | 0 |
| Duende Alice | 5/5 | 0 | 5 | 0 |
| Duende Bob | 5/5 | 0 | 5 | 0 |

Both Duende identities renewed access using the real external token endpoint, and all ten refreshes returned a different refresh token. Local expiry was accelerated; no access or refresh token was forged. The provider publishes a seventy-five-second client and a `https://notused` redirect. The owner test harness intercepts that redirect in memory before requesting the host, then uses the application's PKCE/state-bound exchange. This validates the provider protocol integration, **not** that provider's compatibility with the application's ordinary loopback owner enrollment UI.

Clearing saved sessions for SauceDemo and The Internet caused one automatic password attempt each and successful recovery. The locked SauceDemo identity and deliberately incorrect The Internet password each stopped after one login attempt. A second request reused the same durable challenge without another login. Client revocation returned `DENIED`.

The complete external experiment took 101.685 seconds. The report contains outcomes, rotation counts, recovery results, limits and source links in `artifacts/public-demos.json`. Public JavaScript demonstration login does not establish server-side session security, and demo behavior does not establish bank or SaaS compatibility.

Initial external runs exposed an unapproved SPA fallback redirect and asynchronous navigation/state timing. Those adapters and bounded marker waits were corrected before the final run. Investigation also found that normal Playwright routing checks only the first request in a redirect chain. The implementation now fetches and validates every hop with automatic redirects disabled. Tests prove that a 307 cannot forward a password to an unapproved destination and that an unapproved read redirect is blocked.

Sources establishing intentional demo use: [Sauce Labs demonstration scripts](https://docs.saucelabs.com/web-apps/automated-testing/selenium/sample-scripts/), [The Internet login page](https://the-internet.herokuapp.com/login), [Duende demo](https://demo.duendesoftware.com/), [Duende published client configuration](https://github.com/DuendeSoftware/demo.duendesoftware.com/blob/main/src/Config.cs). Another examined practice site used a public success URL and client-side credential comparisons; it was excluded as evidence of authenticated session reuse.

## Actual agent execution

The installed wheel runs the service; the skills point at its stable interpreter and private client configuration. Distinct Codex and Claude principals use the same service. Both CLI agents discovered all five accounts, selected their permitted operations, submitted one durable task and obtained five completed results. Completion was independently read through the authenticated service API; an agent's final claim alone was not counted as success.

The account set was `demo-api`, `demo-web`, `demo-mfa`, `sauce-standard`, `internet-valid`. The first three are local fixtures; the last two use public testing sites. Outputs are demo data. The service version returned by discovery was 0.3.1.

Codex ran in an ephemeral workspace sandbox with network access. Claude ran with only Read, Skill and the installed client-command Bash pattern; no MCP servers were loaded. Existing Claude hooks remained enabled. An earlier smoke run completed its service task but could not finish its report because the user's stop hook required project records. The isolated test workspace was given truthful records of that completed experiment, and subsequent runs finished normally. No global hook was removed or modified.

Raw traces can contain unrelated host metadata, so they are private and ignored by Git. The checked-in summaries contain only the test result, service task evidence and demo report. These are **CLI integration tests**; the user still needs to try skill discovery in a fresh Codex desktop chat. No additional named agent host has been executed. The portable client path and installed-script-to-private-service integration are regression-tested.

## Reproduce

```sh
uv sync --locked
uv run playwright install chromium
uv run pytest -q
uv run ruff check account_access tests scripts
uv run pip-audit --local
uv run python scripts/benchmark.py
# Network calls only to published testing identities:
uv run python scripts/public_demos.py --runs 5
uv build
uv tool install ./dist/account_access-0.3.1-py3-none-any.whl
account-access --root "$HOME/.local/share/account-access-demo" demo --install --public-sites
```

Keep the final process running. In separate terminals, after choosing an isolated workspace and satisfying any existing host instructions/hooks, the opt-in CLI tests are:

```sh
uv run python scripts/agent_smoke.py codex --workspace /absolute/path/to/test-workspace
uv run python scripts/agent_smoke.py claude --workspace /absolute/path/to/test-workspace
```

These use the user's existing CLI login and can consume agent usage. They create no API keys. For normal user testing, use the short prompts in README.md; no test harness is necessary.

## Remaining production work

| Area | Current evidence | Required before claiming production coverage |
| --- | --- | --- |
| Private service coverage | Public demos and controlled fixtures; Google Drive configuration example | Named authorized service adapters, approved operator OAuth apps, real account pilots and provider conditions |
| Long-term interruptions | Accelerated measurements | At least thirty-day per-service observations with real onboarding and notification counts |
| Gmail and SMS codes | Contract tests for precise filtering | Live provider/source enrollment and code-delivery tests; support for the intended phone number |
| iPhone and Android | Ordinary provider owner handoff; no native companions | Platform-specific enrollment, live SMS/device handoff validation, native companion implementation where feasible |
| Passkeys/biometrics/admin | Challenge classification and genuine owner handoff | Real platform/provider tests; mandatory presence remains a user gesture |
| Chrome convenience | Native bridge and origin-filter unit tests | Extension installation/live Chrome session adoption, compatibility testing and signed distribution |
| Credential isolation | Private files, encrypted records and API boundaries | Broker under a separate OS identity/host for unrestricted agents; deployed TLS and operational validation |
| Notifications | Durable shared challenges | Real delivery, cross-chat deduplication and wake/resume integration |
| Packaging/operations | Wheel, portable skill, TLS example, macOS tests and passing Linux CI | Signed installer/updater, service lifecycle management, recovery/backup procedures and broader platform coverage |

Payments, tax filings and account-changing writes are unsupported. No test result in this report authorizes or validates those operations. The goal of a broad production consumer product remains open; this release establishes a tested, usable foundation and the measurements needed for a real pilot.
