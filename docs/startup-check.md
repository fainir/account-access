# Local startup check

Build 76 installed successfully on the owner Mac, but its protected service exits
with `EX_CONFIG` before enrollment. That installed version discards its startup
response. This check captures the existing service's fixed error code so the
failure can be diagnosed. It does not repair the service or establish readiness.

The check is a separate, explicitly unsigned local Installer package. Review and
approve it before opening it. macOS may ask for administrator authentication.
There are no terminal commands for the owner to enter.

It accepts only the exact build 76 broker, interpreter, package identity, app
metadata and launchdaemon configuration. It temporarily redirects only the next
invocation's stdout to a root-only capture and requests `kickstart -p`, without
the option that kills an existing process. It then requests the original
`/dev/null` stdout setting. No program, arguments, environment, persistent job,
code, permissions, account grants or authentication rules are changed.

Only a recognized failure code and fixed status fields appear in a public
report under `/Library/Logs/AccountAccessStartupChecks`. Unknown output is never
published. If capture consumption or cleanup cannot be established, its private
target is retained so a pending invocation cannot reference a missing path.
The report says `default_stdout_requested`; command acceptance does not prove a
debug-setting readback that Apple does not expose.

The helper never opens credentials, account stores, journals, Keychain items,
mailboxes, texts or user configuration. The new broker source also reports a
closed startup phase and reason through OSLog for future builds. Those source
changes have not replaced the installed build 76 broker.
