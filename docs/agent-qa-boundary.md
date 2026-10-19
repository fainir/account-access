# Controlled agent acceptance boundary

`scripts/agent_verification_smoke.py` tests ordinary-language requests against
four fictional website accounts. It does not validate personal accounts, a
physical phone, carrier delivery, Google consent, or a consumer installation.
Existing success artifacts describe their recorded source and host conditions;
they are not evidence that a later revision or stronger isolation boundary has
passed.

## Codex currently stops before setup

The Codex entry point now fails closed with
`codex_effective_permissions_unverifiable` before creating the requested
workspace, fixture credentials, mailbox, service, or model session. It preserves
the positional agent, workspace, optional model, and report-suffix arguments.
`--codex-cli /absolute/path/to/codex` selects an explicit executable; otherwise it
checks the bundled macOS CLI. It never falls back to a potentially older `codex`
on `PATH`. Only bounded public version/help commands run. Their sanitized output
contains the numeric version and selection category, not configuration, auth,
paths, command errors, or raw CLI output. The probe sets its home and agent
configuration paths to non-directory placeholders under `/dev/null`, preventing
an absent home variable from falling back to the owner's home. This does not
prove that the installed CLI cannot read machine-managed configuration.

The refusal is intentional. Official OpenAI documentation establishes that:

- A legacy `sandbox_mode` in any loaded layer overrides a named
  `default_permissions` profile. A socket allowlist alone also does not restrict
  filesystem reads; the intended profile needs a deny-root filesystem policy.
  [Permissions](https://learn.chatgpt.com/docs/permissions)
- `exec --ignore-user-config` skips `$CODEX_HOME/config.toml` and preserves
  authentication. It does not establish that all remaining configuration layers
  select the intended sandbox. `--ignore-rules` would discard user/project
  execution rules and is not used.
  [CLI reference](https://learn.chatgpt.com/docs/cli/reference)
- A `PreToolUse` hook can block supported calls, but some tool paths are outside
  its coverage and hook failures can allow execution. It cannot be the sole
  boundary. [Hooks](https://learn.chatgpt.com/docs/hooks)

An explicit `codex sandbox -P` sentinel test proves that sandbox invocation,
not that a subsequent `codex exec` selected the same effective policy. The
harness does not present that weaker test as an attestation or weaken the
requested sandbox to make acceptance proceed.

### App-server profile provenance is not a complete tool boundary

The official app-server API provides a stronger selection mechanism for a future
QA client: experimental `thread/start.permissions` selects a named profile, and
`command/exec` can test that profile without creating a thread or model turn.
However, `thread/start` can initialize configured MCP servers. App runtime status
and MCP server status are separate snapshots, rather than a complete callable
tool inventory bound to the selected permission profile.
[App-server documentation](https://learn.chatgpt.com/docs/app-server)

Static schema generation from the bundled CLI 0.163.0 exposes
`activePermissionProfile` with only `id` and optional `extends`; this identifies
profile provenance, not the complete resolved filesystem/network policy. The
thread-start response also describes `disabledPluginIds` as a saved list that
does not yet filter plugin capabilities. These schema observations do not prove
that an app-server model turn has the fixture-only boundary required here.

Permission profiles govern local sandboxed commands. Hosted search, apps, MCP,
browser actions, and client service traffic have separate controls; a command
socket allowlist does not constrain them. Consequently this investigation used
official documentation and static CLI schema generation only. It did not start
an app server, thread, model, or fixture, and it does not unblock acceptance.
[Permission scope](https://learn.chatgpt.com/docs/permissions#scope-and-enforcement)

The next live Codex run needs a disposable environment with a dedicated QA
login and controlled configuration, or a supported way to attest the exact
effective `exec` permissions before model startup. The intended policy must
deny unrelated file reads and all unrelated sockets/network destinations while
allowing only the fixture client, required public runtime/package files, and
the fixture service socket. Managed restrictions and execution rules must
remain effective. Any invocation that intentionally skips inline user
configuration/hooks must disclose that scope; it must not claim to preserve
them. No owner authentication/configuration is copied to provision such an
environment.

A blocked run writes `codex-verification-080[-suffix].blocked.json` separately
from historical success reports. It records `passed: false`,
`fixture_started: false`, `model_started: false`, and zero private sign-ins.
There is no override flag that turns this refusal into an acceptance result.

## Claude now stops before setup

The Claude entry point now fails closed with
`claude_pretool_boundary_unverifiable` before creating the requested workspace,
fixture credentials, mailbox, guard, service, or model session. Its prior
invocation hook and trace checks were incomplete as a pre-execution boundary:
the harness generated the guard but did not establish that Claude would load
and enforce it. Historical successful fixture runs retain their recorded scope;
they do not attest a current run's effective policy.

`--claude-cli /absolute/path/to/claude` selects an explicit executable;
otherwise the harness checks `/usr/local/bin/claude`. It never falls back to a
CLI on `PATH`. Only bounded public version/help commands run with a scrubbed
environment with home and agent configuration paths set to non-directory
placeholders under `/dev/null`. Sanitized diagnostics retain the numeric
version and selection category, without paths, raw output, errors, owner
configuration, or auth data. These placeholders prevent owner-home fallback;
they do not attest or suppress machine-managed configuration.

Claude's managed settings take precedence over `--settings`. Managed
`allowManagedHooksOnly` can exclude ordinary hooks, and `disableAllHooks` can
disable the invocation hook. Settings can also reload during a session.
[Settings precedence](https://code.claude.com/docs/en/settings#settings-precedence),
[hook policy](https://code.claude.com/docs/en/hooks#hook-lifecycle).
The installed CLI's public help does not offer a model-free resolved-hook
attestation. Running our hook directly or observing a startup canary proves
only that execution, not subsequent `PreToolUse` enforcement. `--bare` skips
hooks and existing OAuth and cannot supply this boundary.
[CLI reference](https://code.claude.com/docs/en/cli-reference).

A live run requires a disposable environment with a dedicated QA login and
controlled configuration, or a supported effective-hook attestation before
fixture/model startup. This requirement is not yet met. No owner settings or
authentication are inspected or copied to provision it, and there is no
override that converts refusal into acceptance. The blocked report is saved as
`claude-verification-080[-suffix].blocked.json`, separately from prior success
reports, with `passed: false`, `fixture_started: false`, `model_started: false`,
and zero private sign-ins.

The historical fixture invocation set `CLAUDE_CODE_SUBPROCESS_ENV_SCRUB=1`,
reducing credential inheritance in tool subprocesses while retaining Claude's
own authentication. That is a partial reduction: the documented scrub can
retain GitHub tokens, proxy credentials, and unrecognized secrets. It is not an
OS sandbox or a complete secret boundary.
[Claude environment documentation](https://code.claude.com/docs/en/env-vars)

The retained fixture code removes inherited shell/Python startup injection
variables without changing persistent settings. Historical raw traces remain
in ignored local artifact storage, and successful reports remain qualified to
fictional accounts.

## Installed-preview checks on 19 October 2026

The existing installed launcher completed three previously approved public-example
reads from Codex in this chat. Saved sessions may have been reused; fresh password
entry was not measured. The installed source revision was not attested, so this
does not validate a newer protected candidate or a private account.
[Sanitized task evidence](../artifacts/agent-tests/installed-public-reads-20261019.json).

A separate preflight for Claude Code 2.1.112 did not start a model. Its public
executable supports excluding user/project settings, Chrome and MCP servers,
but mandatory managed policy remains and can suppress an invocation tool guard.
The effective guard was not attested before startup. No owner authentication
or account configuration was inspected to resolve that uncertainty.
[Preflight evidence](../artifacts/agent-tests/claude-installed-preflight-20261019.json).
This limits that optional QA run; it does not establish a failure of normal
Claude Code use through the installed skill.
