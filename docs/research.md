# Authentication and delegated access research

Research date: 12 October 2026. This is repository documentation for the implementation in this workspace. Product capabilities below come from official documentation; comparative judgments and architecture choices are engineering assessments, not measured product benchmarks.

## Problem and success criteria

The user delegates work across several accounts, but repeated login, verification and approval steps make the user the authentication coordinator. The objective is to reduce **total human interruptions across repeated useful tasks**, not simply automate password entry. A broker should preserve legitimate access, enforce standing permissions, distinguish login from action authorization, and resume progress after unavoidable intervention.

Count an interruption when a person must do something: consent, unlock a vault, enter a code, approve a device, supply a passkey gesture or authorize an action. Several reminders for one unresolved challenge are one unique challenge but multiple notification interruptions; record both. Initial enrollment is reported separately. Machine retries and silent token refreshes are not human interruptions. A denied operation is not a completed task.

For each service, measure over at least 30 daily runs:

| Metric | Definition | Pilot target, not a claim |
| --- | --- | --- |
| Authentication interruptions | Unique login interventions / post-enrollment service runs | OAuth: 0 while the provider grant remains valid; browser: at most 1/30 on selected sites |
| Notification interruptions | Prompts actually delivered / unresolved challenge | At most 1 until the challenge changes |
| Unattended task completion | Tasks completed without post-submission human action / submitted tasks | At least 95% for selected read operations |
| Eventual completion | Completed tasks, including recovered tasks / submitted tasks | 100% in controlled recoverable cases |
| Recovery latency | Credential repair to next successful continuation | Within one worker polling interval plus execution time |
| Progress preservation | Successful steps repeated after a checkpoint | 0 after persisted checkpoints; read replay allowed after a crash before checkpoint |
| Boundary enforcement | Out-of-grant attempts that reached the provider | 0 |
| Secret disclosure | Credential values in agent output, ordinary logs or plaintext database | 0 in tested scenarios |

Report denominators, initial setup gestures, active-provider failures, and elapsed observation time. Accelerated token expiry cannot establish month-long real-site reliability. A six-service aggregate can conceal one service that demands authentication every day, so retain per-service results.

## Authentication choices

| Route | Initial setup | Ongoing intervention expectation | Compatibility and reliability | Security and deployment | Effort |
| --- | --- | --- | --- | --- | --- |
| OAuth with renewable delegated scopes | Register or reuse an approved app; user consent | Usually none during a valid renewable grant; new consent after revocation, expiry or policy change | Strong for supported APIs; scope and refresh behavior vary | Keep refresh credentials server-side; local and hosted execution | Low with managed connectors, medium for direct adapters |
| Provider service account, application identity, API key or formal proxy role | Owner/admin provisioning and least privilege configuration | Usually none until rotation/revocation or policy change | Excellent where the provider explicitly supports the task; often unavailable for personal accounts | Represents a distinct principal where supported; secret store and audits required | Low to medium |
| Licensed financial aggregator or open banking | Provider, institution and jurisdiction coverage; consent | Reduced login burden, but repair and consent renewal remain possible | Better for covered account information than arbitrary financial administration | Data-access permission does not imply payment authority | Medium; commercial onboarding may dominate |
| Saved browser session | Interactive login in a dedicated browser | None while the site accepts the session; site controls expiry and step-up | Covers sites without APIs; fragile selectors, risk checks and device binding | Cookies are bearer-like secrets; prefer a stable local device for device-bound sites | Medium per site, high maintenance |
| Password manager autofill | Explicit vault access, account setup | Removes typing, but does not remove MFA, consent or device presence | Broad login support, no universal unattended guarantee | Keep vault material and filling outside the model; use a separate scoped automation vault | Medium |
| Login-only TOTP with an exportable seed | Explicit supported enrollment for automation | Can eliminate that login code interaction | Only services permitting such a flow; clock and challenge binding matter | Seed is a long-lived secret; storing both factors together changes the threat model | Medium per adapter |
| Email or SMS login code collection | Narrow authorized inbox/phone integration plus account-specific matching | Can reduce intervention for permitted login-only codes | Delivery delay, expiry, rate limits and ambiguous messages limit reliability | Must bind service, active challenge, recipient and purpose; no generic code harvesting | High |
| Passkey, hardware key or device approval | Enroll and retain the supported authenticator | User presence/verification when demanded by the provider | Good interactive security; no universal unattended substitute | Local authenticator often cannot move to a cloud browser | High or unsupported for unattended use |

These are expected characteristics, not measured interruption rates. A supported API is the first choice, but lack of an API is not a reason to ignore session reuse.

OAuth refresh permits renewed access without repeating consent; it is still subject to server policy and revocation. RFC 9700 recommends restricted privileges and protects public-client refresh tokens through rotation or sender constraints. Use authorization code with PKCE, not password grants. [OAuth Security BCP](https://datatracker.ietf.org/doc/html/rfc9700)

Provider setup matters materially: Google's external OAuth apps in Testing generally receive seven-day refresh tokens, except its documented basic identity scope exception. Microsoft documents scenario-dependent lifetimes and revocation, and replacement tokens do not necessarily invalidate earlier tokens. A generic assumption that every refresh token lasts forever, or rotates identically, is wrong. [Google OAuth](https://developers.google.com/identity/protocols/oauth2), [Microsoft refresh tokens](https://learn.microsoft.com/en-us/entra/identity-platform/refresh-tokens)

For a desktop owner connection, use an external browser and a loopback callback with PKCE. Do not put authorization codes or token responses in chat. Google documents an installed-app flow; actual app registration, consent configuration and API enablement remain owner setup. [Native app OAuth RFC](https://datatracker.ietf.org/doc/html/rfc8252), [Google desktop flow](https://developers.google.com/identity/protocols/oauth2/native-app)

TOTP is generated from a shared seed and time. A trusted component could generate it when a provider permits automated **login** and the user explicitly enrolled that factor for that purpose. This does not authorize using the same mechanism for payments or other transaction-specific confirmations. The MVP does not store passwords or TOTP seeds. [TOTP RFC](https://datatracker.ietf.org/doc/html/rfc6238)

Email/SMS access can technically support some login flows, but a code's availability does not establish its purpose or permission. An adapter would need an active, service-bound login challenge, a narrowly scoped source and a fixed matching rule. Unknown purpose must stop. NIST treats PSTN authentication as restricted, rejects email for its out-of-band authentication assurance model, and distinguishes address-confirmation/recovery codes from authentication. These are assurance guidelines, not a claim that every existing email login is illegal. [NIST authentication guidance](https://pages.nist.gov/800-63-4/sp800-63b.html)

WebAuthn ceremonies involve user presence and sometimes verification; an agent must not fabricate these with a virtual authenticator on a real account. Session reuse after a legitimate passkey login is different from satisfying a later passkey ceremony. Device push, biometric presence and transaction signing should use the provider's genuine owner interaction when required. [WebAuthn Level 3](https://www.w3.org/TR/webauthn-3/)

Saved browser state can preserve cookies, local storage and IndexedDB. Playwright does not automatically preserve sessionStorage; storage state is sensitive. A session export is not a complete Chrome profile and cannot reproduce every hardware/device binding. [Playwright authentication](https://playwright.dev/python/docs/auth)

Finance needs separate data and action permissions. Plaid documents login repair using update mode and a minimum necessary reauthentication flow; successful aggregation is not permanent access. The FCA distinguishes account access and payment initiation and documents a UK account-information reauthentication exemption conditional on provider adoption. This is an illustration of supported delegation, not a coverage or legal claim for the user's unnamed institutions or jurisdiction. [Plaid update mode](https://plaid.com/docs/link/update-mode/), [FCA SCA](https://www.fca.org.uk/firms/strong-customer-authentication)

## Products and open source to reuse

| Component | What the official documentation establishes | Reuse decision and remaining gap |
| --- | --- | --- |
| Nango | Auth, refresh, credential custody, API integrations, action functions and MCP; open-source deployment described | Leading production candidate for API credential lifecycle; inspect license/deployment requirements for the selected release. Does not promise arbitrary-site login persistence. [Docs](https://nango.dev/docs/getting-started/intro-to-nango), [repository](https://github.com/NangoHQ/nango) |
| Composio | Per-user connected accounts, hosted connection links, managed refresh, scopes and agent tools | Fast agent integration; assess custody, retention, pricing and operation granularity in a pilot. API/toolkit coverage is not arbitrary-site coverage. [Authentication](https://docs.composio.dev/docs/authentication), [expiry behavior](https://docs.composio.dev/docs/tools-direct/authenticating-tools) |
| Pipedream Connect | Managed account auth, approved or custom OAuth clients, credential-hiding proxy, tools and MCP | Useful managed alternative with existing workflows. Do not expose unrestricted proxy requests through an agent-facing tool. [Connect](https://pipedream.com/docs/connect) |
| Browserbase | Persisted contexts across browser sessions; sites can still log users out; concurrency cautions | Optional cloud browser custody/runtime, after evaluating data residency and device/IP checks. Persistence does not defeat provider expiry. [Contexts](https://docs.browserbase.com/platform/browser/core-features/contexts) |
| browser-use | Open-source browser agent, stored state and user profiles | Reuse a browser runtime when expanding coverage; an unrestricted browser agent alone does not enforce action grants. [Parameters](https://docs.browser-use.com/open-source/customize/browser/all-parameters), [repository](https://github.com/browser-use/browser-use) |
| 1Password SDK | Desktop authorization and service-account access; automation service accounts have vault limitations | Potential scoped password/TOTP source. Desktop prompts can recreate interruptions; a supported automation vault is a distinct choice. [SDK](https://www.1password.dev/sdks) |
| Authlib | PKCE-capable OAuth HTTP client | Reuse protocol code, add durable refresh coordination and scoped execution. [HTTP clients](https://docs.authlib.org/en/stable/oauth2/client/http/index.html) |
| Agent Skills and host CLI support | Portable instructions and executable resources, supported by Codex and Claude Code | Chosen agent interface. Instructions route calls; the independent service enforces authority. [Specification](https://agentskills.io/specification), [Codex skills](https://developers.openai.com/codex/skills), [Claude skills](https://code.claude.com/docs/en/skills) |
| agent-browser | Browser automation, saved authentication and opt-in policy features | Evaluated as a future runtime. Reused Playwright directly for bounded operations; unrestricted browser commands and credential retrieval are not exposed. [Repository](https://github.com/vercel-labs/agent-browser) |
| Official MCP Python SDK | Server/client tooling, stdio and HTTP transports | Evaluated but not used. The user selected an agent-independent Skill/CLI/service architecture. MCP authentication does not authenticate downstream websites. [SDK](https://github.com/modelcontextprotocol/python-sdk) |

This is documentation and public-source inspection, not a hands-on vendor benchmark, procurement recommendation or security certification. Vendor marketing coverage counts are deliberately not used as compatibility evidence.

## Standards and interoperability

The accepted interface is **Agent Skill + CLI + independently authenticated service API**. Agent Skills package instructions and scripts, not a credential security boundary. The service issues distinct scoped identities to Codex, Claude and a portable client; operation payloads cannot select an identity. MCP remains an optional interface adapter, with no dependency in this build. HTTP MCP authorization, if added, would remain separate from downstream provider authorization. [Agent Skills](https://agentskills.io/specification), [MCP authorization](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization)

OAuth token exchange and rich authorization requests can represent delegated actors or fine-grained authorization where a provider supports them. They do not retrofit arbitrary services. The newer delegated AI agent authorization profile is an Internet-Draft, not a deployed universal standard or a dependency of this MVP. [Token exchange RFC](https://datatracker.ietf.org/doc/html/rfc8693), [Rich authorization RFC](https://datatracker.ietf.org/doc/html/rfc9396), [agent authorization draft](https://datatracker.ietf.org/doc/draft-mishra-oauth-agent-grants/)

Codex and Claude Code support skills with scripts and command execution. Their host tool permissions remain separate from account grants. Actual CLI agent runs are recorded in validation.md; this does not establish that every host automatically discovers the package. Agents without a skills loader can use the thin CLI or authenticated API. [Codex skills](https://developers.openai.com/codex/skills), [Claude Code skills](https://code.claude.com/docs/en/skills)

A2A coordinates tasks and can represent an authentication-required task state, but is not a universal downstream login solution. WebMCP exposes website tools through supporting browser surfaces and depends on website adoption; it is not a replacement for persistent credential custody across arbitrary services. Neither is required for this MVP. [A2A specification](https://a2a-protocol.org/latest/specification/), [Chrome WebMCP](https://developer.chrome.com/docs/ai/webmcp)

## Recommended architecture and focused MVP

Use a broker with stable account handles, a provider adapter registry, encrypted custody, owner-controlled operation grants, a durable challenge queue, checkpoints and audit metadata. Prefer managed API integration infrastructure in production rather than building a universal OAuth vendor catalog. A narrow direct adapter in the MVP makes refresh rotation, concurrency and failure recovery reproducible without a vendor subscription or access to the user's accounts.

The MVP implements two routes: an Authlib OAuth API connector with named GET operations, and a Playwright connector with owner setup, encrypted storage state, optional saved-password recovery and named extraction operations. Enrolled login-only TOTP, Gmail and Twilio sources can supply a configured factor; Gmail/Twilio are contract-tested, not live-validated. A Google Drive metadata example remains unvalidated without an operator-provided OAuth app. Controlled providers exercise failure mechanics; public demo sites exercise external integrations. Neither route exposes credentials, arbitrary URLs, JavaScript, headers, cookies or code retrieval to agents.

Owner setup and permission changes use the CLI or separate local owner console. Existing agents receive discovery, status, execution and durable task inspection. Identity comes from authenticated service credentials. Routine permitted work proceeds. A durable challenge describes the account, login/action/presence category and required owner step; repeated tasks share it. Reconnection resolves login challenges and the worker resumes persisted jobs. Resuming service steps does not automatically restart a terminated AI conversation.

Local custody is appropriate for the trusted-agent experiment: no mandatory hosted account, stable browser environment and direct owner repair. The CLI supports a private Unix socket or HTTPS broker URL. A TLS deployment example is supplied but not deployed. Cloud agents cannot directly reach a laptop's localhost. Device-bound sessions should remain where the provider accepts them; the laptop must be awake for local tasks.

The hardest tests are repeated access across process restarts, rotating refresh tokens shared across agent processes, a 401 with one bounded recovery attempt, revoked refresh tokens, transient network errors, session expiry, a challenge shared by several jobs, recovery without repeating completed steps, wrong OAuth state, redirect exfiltration attempts, configuration drift and grant revocation. Synthetic measurements establish these mechanics, not real bank reliability.

Supported release-candidate scope: portable Skill/CLI, private service, approved reads, owner connection/grants/revocation, encrypted state, OAuth renewal, password and enrolled TOTP recovery, checkpoints, schedules and worker resumption. Experimental: per-site browser adapters, Chrome session adoption, Gmail/Twilio code sources. Unsupported: payments, tax filings, arbitrary browser control, transaction-code consumption, extracting Chrome passwords, native iPhone/Android inbox capture, fabricated presence and multi-tenant hosting. Strong isolated custody is a deployment requirement, not established by a same-user skill.

Before expanding, validate selected real services for 30 days, separately test a cloud API connector and a device-bound browser connector, verify provider automation conditions, decide credential custody, and test owner notifications end to end. A same-user local process is not a sandbox against an agent with unrestricted shell access; stronger deployments require a separate OS identity or a remote broker whose secrets and owner controls the agent cannot reach. More detail is in architecture.md.
