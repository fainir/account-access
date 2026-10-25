# Portable client setup for the isolated Mac service

The native owner app now connects a fresh isolated store to the portable skill.
There is one `generic` client identity and no Claude/Codex selector. This is part
of the development candidate; the published preview does not provision the
system runtime or enable this path.

## First connection

After first-vault setup, the desktop can continue automatically into agent setup.
If the owner opens a store without a completed connection, it offers **Connect
automatically**. Opening an already connected store checks its local installation
and the broker's public client ID without enrolling again or requesting setup
approval. A manual reopen after a lost response checks state; it does not repeat
a write automatically.

The native app invokes the immutable system runtime as the ordinary owner user:

`/Library/Application Support/Account Access/runtime/bin/python`

Only the fixed `account_access.agent_setup` module and `prepare`, `install`,
`status`, `prepare-upgrade` or `install-upgrade` action can be selected. Python runs with isolated imports and a sanitized
environment. The app verifies the protected runtime before execution. The helper
uses the OS account's home, not an inherited `HOME`, and refuses root execution.
Production has no arguments or environment override for the home, client location,
interpreter or service endpoint.

Both installers honor a custom `CODEX_HOME` inherited by the app when it is a
validated private namespace beneath the actual owner's home. Personal Codex
settings and authentication files are not read or changed. Instructions and the
narrow client rule use that namespace; the shared skill remains in `.agents`.

## Upgrade a preview connection

A recognized preview skill shows **Upgrade AI connection**. Choose it once to
connect both detected agents to the new protected store. The helper first
prepares a separate capability, the native app obtains owner approval, and the
new broker confirms that capability before any launcher changes. Unknown or
modified skills remain preserved for review.

The upgrade replaces only known managed skill files and instruction blocks.
Recognized owner-local preview roots may use the default `account-access` name
or a bounded `account-access-` suffix beneath `.local/share`. The old client
descriptor and runtime must belong to that same root. Exact reviewed templates,
launcher bytes, private file metadata and no-follow directory checks still apply;
the old runtime is never executed and its credentials are never imported.
Publication failures restore the old launchers; an interrupted upgrade can be
retried. Existing personal instructions, hooks, settings and unrelated command
rules are preserved. The preview vault, website passwords, old tokens and old
grants are not copied. Import and approve the accounts intended for the protected
store through its local setup flow.

The next source candidate identifies a failed connection's stage using fixed
messages: preparation, local identity validation, enrollment, agent-file
installation, confirmation, or final verification. Known connection conflicts
and revocation receive separate review messages. It never includes an exception,
response, filesystem path or capability in the explanation, and does not retry
an operation automatically. This diagnostic improvement is not installed in
package 95 and does not resolve or identify the owner's current failure by itself.

Source `6736a20` passed all 55 optimized native UI checks locally, including
injected exceptions and malformed results at each connection stage. Both hosted
native jobs also passed. The installed runtime and templates passed two isolated
preview migrations with fictional discovery; no owner service was contacted.
Diagnostic app build 96 compiles for both Mac architectures and passes strict
Developer ID signature verification. Its public delta changes only the app
executable, bundle version and derived package identity. It has no qualified
successor installer yet: the existing package 95 controller accepts only its
frozen predecessor and target. Updating the installed app requires a new
controller that verifies the completed predecessor and preserves its history;
copying this candidate over the installed app would invalidate that state.
[Source checks](../artifacts/agent-connection-diagnostics-source-20261025.json) ·
[App build](../artifacts/owner-diagnostics96-build-20261025.json) ·
[Public delta](../artifacts/owner-diagnostics96-public-delta-20261025.json).

## Client publication

1. The helper checks the destination skill folders and instructions before
   creating an unregistered random capability. It preserves that same capability
   across interrupted setup. Its files live separately from the legacy store, in
   `~/Library/Application Support/Account Access/client-v1`.
2. The app checks the local capability's public digest against the helper result
   and sends it over the pinned native connection with setup authorization. The
   broker enrolls only `generic`, stores only the digest and grants no account
   permissions. Its response contains no token. An existing different connection,
   revoked capability or orphaned principal history requires repair/migration;
   enrollment cannot silently replace it or inherit old access.
3. The helper verifies that exact capability with an account-discovery read on
   the isolated service. It then installs the shared launcher, the Claude alias
   when that host is detected, and the existing automatic-session guidance for
   detected Codex/Claude installations. It preserves unrelated preferences and
   restricts the Codex execution rule to the client-only launcher.
4. The app confirms the completed installation to the broker using the public
   client ID and known host names. This is an assertion by the trusted owner app
   after local writes; the broker does not inspect the owner's filesystem.

The portable skill is installed at `~/.agents/skills/account-access`. Its shared
identity applies the same owner-approved account operations in different agents.
The installed launcher uses the protected interpreter rather than a Python
command from PATH. An installed instruction block makes relevant plain-language
requests use the skill in new sessions; no per-session command is required.
Existing conversations may have cached their instructions. Other agents must
support the portable skill/CLI convention; this does not intercept arbitrary
browser tools or resume an entire stopped AI conversation.

An unsuccessful or unknown local discovery result stops setup with a review
message. It cannot be treated as a missing connection or trigger enrollment.

## Files, interruption and revocation

The capability is private owner-user client material, not a vault key or website
credential. It authorizes only the broker's existing standing grants. It is not
returned in helper stdout, setup responses, owner state, instructions or skill
installation metadata. Passwords, cookies and verification codes stay inside the
credential service and its supported trusted-source paths.

Preflight rejects symbolic paths, hard-linked files, unsafe owners/modes and ACLs
that grant access. Restrictive Darwin deny entries, such as the standard home
folder delete restriction, are allowed. A recognized legacy skill uses the
explicit upgrade path; an unknown or modified skill is preserved.
Installation success is recorded only after the service read and file writes.
Status checks compare skill resources, launcher metadata and session guidance,
including the narrow Codex execution rule, so stale files cannot claim readiness.

Native enrollment and confirmation require a live setup lease. Repeated enrollment
of the same valid client is idempotent; it does not rotate tokens or alter grants.
A lost reply is surfaced and reopening only checks progress. A deliberate retry
can finish setup with the same local capability. Revoked or missing/conflicting
client material is not recreated automatically. Its repair/migration UX remains a
release gate. The agent client cannot call the owner enrollment endpoint.

## Verification and remaining work

Focused tests use temporary owner homes and fictional accounts. They exercise
private capability preparation, one broker identity shared by both launchers,
preserved preferences, denial after revocation, refusal to inherit orphaned
permissions, altered/missing files, symlinked destinations and Darwin ACLs.
Native screen checks use a synthetic helper/channel to exercise setup and
reopening without another enrollment or approval. Transport tests reject malformed
client requests and unauthenticated setup sessions.

Disposable Mac CI adds an ordinary-owner process that prepares and installs the
skill against a real newly enrolled worker. A native owner setup session enrolls
the capability and confirms installation; positive authorization remains synthetic
and in-process. Both launchers must discover an empty permitted-account set, omit
the capability from output, preserve both hosts' instructions and receive an actual
permission error when opening the broker store. Client state must survive worker
reopening. This is client-bootstrap acceptance, not a private website sign-in or a
run of the real Claude/Codex products. The matching revision passed [40 first-vault/client assertions and 38 transport
checks](../artifacts/mac-agent-setup-080.json) in two complete repeats. See
[validation](validation.md) for source, results and limitations.

Consumer provisioning must create the immutable runtime and the fixed agent socket
at `/Library/Application Support/Account Access/run/agent.sock`, with the listener
ownership and group policy described in [system supervision](mac-supervision.md).
It must also publish the [native desktop registration](mac-desktop-connection.md).
A complete consumer package, genuine OS approval through these screens, trusted
email/SMS/browser collectors, migration/revocation repair, publisher continuity,
notarization and private/physical-device QA remain required. No installed owner
app, credential file or existing skill is changed during development tests.
