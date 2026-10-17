# Security policy

Account Access is a preview. Private financial-account coverage, isolated deployment, physical-phone delivery and notarized consumer distribution are not established by the demo tests.

## Reporting a vulnerability

Use this repository's **Security → Report a vulnerability** feature for private reports. If that feature is unavailable, open an issue requesting a private reporting channel without including vulnerability details, credentials or private account data.

Describe the affected version, trust boundary, expected behavior and minimal reproduction using fictional credentials. Do not attach live tokens, cookies, vault files, OAuth callback URLs, inbox content or unsanitized agent traces. There is no promised response-time SLA or bounty program.

## Relevant boundaries

- The agent API supports named operations and status/task inspection. It does not support arbitrary URLs, credential export or permission changes.
- The owner console and owner CLI are privileged interfaces.
- A skill and file permissions do not isolate credentials from an agent with unrestricted shell access under the same OS user. Use a separate OS identity or host for that threat model.
- Demo file-key custody is for fictional data. Real vaults use supported OS keyrings.
- The 0.8 candidate installer requires the dependency hashes shipped in its
  verified wheel and refuses source builds. Staged repairs and launcher rollback
  preserve the previous installation on failure. Python/Chromium vendor downloads,
  trusted local bootstrap tooling and the same-user isolation limit remain part
  of the trust model.
- Provider-required presence and transaction approval are not automated as login codes.
- After enrollment, the Mac SMS reader uses an active login window, an exact
  sender and a literal template. Candidate GitHub SMS setup checks at most 20
  fresh incoming texts to discover that filter. It accepts only recognized login
  templates, removes the code from its preview and requires local sender review.
  The agent API exposes neither message discovery nor message contents. Full Disk
  Access itself is a broad OS permission.
- The isolated Mac candidate keeps Messages under its owner's UID. Its native
  reader verifies the root broker using a kernel-issued socket audit token; the
  broker verifies the reader's code and identity before sending bounded active-login
  metadata. The queue and replies are private and unavailable through agent routes.
  A system-host journey exercises the production host, System key, isolated
  worker and native reader through a CI entrypoint with synthetic enrollment,
  Messages and website data. Cold restart and durable cooldown recovery pass in
  that environment. Consumer installation, genuine owner approval/Full Disk Access,
  physical SMS and private-account acceptance remain separate. See the [collector boundary](docs/mac-isolated-sms.md).
- The isolated Chrome SMS bridge uses the native app and pinned owner channel,
  not a same-user vault-opening Python host. A new source requires setup approval;
  active-window polling/delivery does not. Methods, framing and reply limits are
  fixed. The signed stable-Chrome parent is checked around each request. Component
  and worker/browser tests are separate; complete installed acceptance remains
  unverified. Root-controlled app/resources do not prevent an unrestricted owner
  process from changing Chrome registration or controlling the browser itself.
  See [browser bridge scope](docs/google-messages.md#protected-mac-candidate).
- The native typedstream reader extracts the first string of a constrained
  attributed-string archive. It does not instantiate archived classes or search
  formatting metadata for codes. Unsupported formats stop setup.
- Redaction is defense in depth, not a universal proof against encoded or unknown secret disclosure.

See the [architecture](docs/architecture.md) and [validation report](docs/validation.md) for implementation details and measured limits.
