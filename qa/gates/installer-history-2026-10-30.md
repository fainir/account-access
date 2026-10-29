# Installer failure diagnosis - 2026-10-30

Read only the matching Account Access postinstall outcomes from the local macOS Installer log; no unrelated log lines or account data are retained.

| Package | Installer outcome | Helper refusal | Meaning |
|---|---|---|---|
| Owner Upgrade 104 | PackageKit script error 112 | `component_owner_app_close_required` at `context` | The canonical Account Access owner app was running during installation. |
| Owner Upgrade 109 | PackageKit script error 112 | `owner_upgrade_source_not_verified` at `predecessor_repair_history` | The legacy updater could not prove its expected predecessor transition history. |

Installer displayed the same generic failure screen for both. These were explicit safety refusals from each package's postinstall helper, not a signing, notarization, Touch ID or password failure.

The current build-118 package is a distinct direct update pinned to the observed installed build 110 and its exact target manifest. It passes Developer ID signing, Apple notarization, stapling, Gatekeeper assessment and independent payload checks ([candidate qualification](../direct-runtime-notarized-candidate-2026-10-30.md)). Its runtime helper also requires the canonical owner app process to be closed before it transitions the installed files. The two owner UI processes were gracefully quit; the protected broker remains running for the helper's managed service barrier. Build 118 was reopened with Installer, but the package has not been installed.

Next acceptance: install the exact build-118 package from Downloads, authenticate in the native macOS dialog, restart if Installer requests it, then verify the app reports build 118 and the protected service/agent reconnects. Any failure from build 118 must be diagnosed from that package's own sanitized helper outcome; do not infer it from the older 104/109 results.
