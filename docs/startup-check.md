# Local startup check

Build 76 installed successfully on the owner Mac, but its protected service exits
with `EX_CONFIG` before enrollment. That installed version discards its startup
response. This check captures the existing service's fixed error code so the
failure can be diagnosed. It does not repair the service or establish readiness.

The first owner-approved check ran through Installer but returned
`diagnostic_tool_unavailable`, without a broker reason. Its stdout-reset request
and capture consumption were not confirmed, so its protected capture target was
retained. Installer completion did not establish diagnostic success.

The current builder produces a separate, explicitly unsigned local
**Startup Capture Inspect** package. Its fixed `--inspect-retained` entrypoint
accepts only the exact build 76 broker, interpreter, package identity, app
metadata and launchdaemon configuration. It opens one existing root-only
diagnostic capture through checked descriptors and publishes only a recognized
broker failure code. It refuses missing, ambiguous, oversized or changed
targets. It cannot create a replacement capture, redirect stdout, start or stop
the service, or reset its debug settings. Review and approve this new package
before opening it; macOS may ask for administrator authentication.

Only a recognized failure code and fixed status fields appear in a new public
report under `/Library/Logs/AccountAccessStartupChecks`. Unknown output is never
published. Recovered output is marked historical, with
`fresh_startup_verified: false` and `cleanup_pending: true`. Inspection does not
prove current service health, restored stdout or permission to delete the
retained target. There are no terminal commands for the owner to enter.

The helper never opens credentials, account stores, journals, Keychain items,
mailboxes, texts or user configuration. Source-level capture operations now
report closed command stages/outcomes and bound command output in memory.
Their privileged ordering is checked in a disposable CI Installer fixture;
they are not used by the inspection package. The new broker source also reports
a closed startup phase and reason through OSLog for future builds. Those source
changes have not replaced the installed build 76 broker.
