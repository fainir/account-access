# Installer failure diagnosis - 2026-10-30

Read only the matching Account Access postinstall outcomes from the local macOS Installer log; no unrelated log lines or account data are retained.

| Package | Installer outcome | Helper refusal | Meaning |
|---|---|---|---|
| Owner Upgrade 104 | PackageKit script error 112 | `component_owner_app_close_required` at `context` | The canonical Account Access owner app was running during installation. |
| Owner Upgrade 109 | PackageKit script error 112 | `owner_upgrade_source_not_verified` at `predecessor_repair_history` | The legacy updater could not prove its expected predecessor transition history. |

Installer displayed the same generic failure screen for both. These were explicit safety refusals from each package's postinstall helper, not a signing, notarization, Touch ID or password failure.

The current build-118 package is a distinct direct update pinned to the observed installed build 110 and its exact target manifest. It passes Developer ID signing, Apple notarization, stapling, Gatekeeper assessment and independent payload checks ([candidate qualification](../direct-runtime-notarized-candidate-2026-10-30.md)). Its runtime helper also requires the canonical owner app process to be closed before it transitions the installed files. The stale per-user owner UI was gracefully quit; the protected broker remains running for the helper's managed service barrier.

At 01:39:53 local time on 30 October, the exact Downloads package was opened in a fresh Installer process. The UI reached the native macOS authorization dialog asking for Touch ID or **Use Password**. No password or Touch ID was entered by the automation. No PackageKit install plan, package receipt or successful result exists, and `/Applications/Account Access.app` still reports build 110. The previous build-118 Installer process had no install plan and was closed before this clean attempt. The new authorization dialog is the owner action; after approval, verify build 118 and the protected service/agent restart. If the attempt fails, diagnose build 118 from its own sanitized helper reason/checkpoint rather than inferring from older packages.
