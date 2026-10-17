# Automatic account access in new sessions

Install once, connect supported accounts, approve their reads, then ask your AI in ordinary language. For example: “Compare prices in my shopping accounts and show my membership welcome message.” You do not need to type a skill name or a command in each session.

The installer keeps one portable skill and CLI in `~/.agents/skills/account-access`, with a discovery copy for Claude Code. It explicitly allows implicit skill invocation. It also writes a short managed instruction block into the supported hosts' persistent user instructions:

| Host | Persistent instructions |
| --- | --- |
| Codex | `AGENTS.md` in `CODEX_HOME`, normally `~/.codex`; an existing `AGENTS.override.md` also receives the block |
| Claude Code | `~/.claude/CLAUDE.md` |
| Other compatible local agents | Load the portable skill from the host's skills directory and reference it in persistent instructions once |

These are the documented startup mechanisms for [Codex global guidance](https://learn.chatgpt.com/docs/agent-configuration/agents-md) and [Claude Code user instructions](https://code.claude.com/docs/en/memory). Skills are also eligible for automatic selection based on their descriptions: [OpenAI skill guidance](https://learn.chatgpt.com/docs/build-skills), [Claude Code skill invocation](https://code.claude.com/docs/en/skills#control-who-invokes-a-skill).

Only the marked Account Access block is updated. Other instructions and file permissions are preserved. Existing valid client tokens and standing grants stay in place. The installer does not alter approval modes, disable hooks or create new account permissions. Start a fresh conversation after first-time installation so the host loads the updated instructions.

For Codex, the installer also creates an owned `rules/account-access.rules` file next to the user configuration. Its allow rule matches only the exact installed launcher and its client commands: discovery, status, approved reads, tasks, audit and diagnostics. This permits that client to connect to the local service outside the command sandbox without opening general shell or network access. Owner setup commands are excluded. Existing restrictive rules and managed policies continue to apply; an unrelated file at that name is preserved and setup stops for review. This uses Codex's documented [persistent command rules](https://learn.chatgpt.com/docs/agent-configuration/rules). Claude Code's permission settings are preserved.

When a relevant request arrives, the agent discovers the accounts and operations it may use and performs the requested work through the installed launcher. Ordinary coding conversations do not fetch unrelated account information at startup. The CLI is internal plumbing; the user does not run it.

For an existing secure local installation, a connection failure can start its registered background service once. This does not replay an operation after a response timeout. A deliberate pause is respected until the owner reopens the app. The computer must be awake and its secure keyring available. Remote clients do not use this local startup path. Controlled fixtures disable it by default; the opt-in Mac QA runner enables it only inside its synthetic store.

Build 60 binds managed startup to the activated interpreter, wheel and exact
launcher command. A client running the updated logic from a retained environment
uses the current launcher; it cannot start its older runtime when activation is
missing or invalid. The native app and OS helper use the same binding, while
equivalent Mac system-folder aliases remain valid. Unsafe existing runtime or
launcher files stop before execution and need owner maintenance. Installation
refreshes the known host integration folders. Unmodified pre-60 client processes
need a refresh/restart; the new behavior cannot be added to an already-running
old binary remotely. A real Mac fixture verified cold startup from a separate
managed environment and that Pause prevents it.

The 0.8 candidate also supervises the desktop service in a separate local
process. Generated skill launchers, client startup and supervised subprocesses
use isolated Python imports, excluding the working directory, `PYTHONPATH` and
user site packages. If its child crashes, it restarts with a one-to-thirty-second backoff
and continues saved tasks without waiting for another agent request. Completed
steps stay completed; existing browser and owner-presence challenges still
require their recorded resolution. Pause stops supervision, and a repair stops
the old generation before starting its replacement. A locked keyring or invalid
setup ends automatic startup attempts rather than repeating owner prompts.

A held process lock establishes supervisor attachment; a saved marker or PID
alone is insufficient. The supervisor loads no vault key and signals only a
child it created. The host also exits if its API/recovery thread stops, so the
owner endpoint cannot keep advertising a dead service. Native setup requests
verify the current local endpoint before sending data, preserving idle forms
when its port changes; a lost response is never replayed. An already-open web
setup tab needs reopening after a host restart. This user-space supervisor does
not survive every simultaneous process failure or computer shutdown: the next
client/app launch restores it. It adds no privileged service or separate-OS-
identity credential boundary.

Build 58 adds a signed, embedded Mac LaunchAgent through Apple's
[SMAppService API](https://developer.apple.com/documentation/servicemanagement/smappservice).
The service runs after user login, waits for an existing supervisor lease and
takes over if that supervisor exits. macOS owns abnormal-exit restart. The native
app registers the saved Applications copy, respects revoked approval, and offers
Login Items when approval is required. Native Pause removes the active generation
and remains effective on a fresh job launch; Resume prepares a new generation.
Registration means eligible to run, not proof that account authentication works.
A uniquely identified QA app verified registered-job recovery and Pause, then
removed its job and fixture Keychain item. Actual logout/reboot acceptance
remains open. The native app and helper also compare the installed payload
record against the signed bundle wheel, so same-version candidates require the
current runtime rather than reusing an older package. This remains
a per-user process, with the same separate-identity security gate.

Automatic invocation depends on a host that loads local skills/instructions and permits the client to run. Project overrides, host permissions and isolated cloud sessions still apply. There is no interception of arbitrary browser tools, and an unsupported website still needs a reviewed connector. Genuine owner-presence authentication remains a human step.

Ordinary-language model fixtures were last checked on revision `321d143` with Claude Code 2.1.112 and the desktop app's
bundled Codex CLI 0.162.0-alpha.17.2. A separate older CLI 0.155.1 on PATH rejected
its configured model before reaching Account Access. A host-model error needs
that host's supported client/model setup; reinstalling Account Access cannot
grant model access. See the official [Codex model availability guidance](https://learn.chatgpt.com/docs/models)
and [invocation-only CLI overrides](https://learn.chatgpt.com/docs/cli/reference).
The compatibility test used the bundled CLI for one invocation and preserved
the user's global settings. These two host versions are tested coverage, not a
minimum-version guarantee for every other version or agent.
Subsequent managed-startup changes have focused bootstrap/native tests and
actual Mac CLI cold-start acceptance; see [validation](validation.md).
