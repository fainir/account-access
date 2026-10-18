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
paths, command errors, or raw CLI output.

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

## Claude remains a guarded fixture run

The Claude entry point retains its invocation-only tool guard, pinned fixture
files, existing authentication, and inherited hook configuration. Successful
tools must resolve to the fixture policy in both hook audit and trace checks.
The harness sets `CLAUDE_CODE_SUBPROCESS_ENV_SCRUB=1` for that invocation, so
Claude retains credentials for its own API calls while reducing credentials in
its tool subprocess environments. This is a partial reduction: the documented
scrub can retain GitHub tokens, proxy credentials, and unrecognized secrets.
It is not an OS sandbox or a complete secret boundary.
[Claude environment documentation](https://code.claude.com/docs/en/env-vars)

The harness removes inherited shell/Python startup injection variables without
changing persistent settings. Raw traces stay in ignored local artifact storage;
the sanitized acceptance report must remain qualified to fictional accounts.
