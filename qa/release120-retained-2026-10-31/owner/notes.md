# Build 120 on the owner Mac - 31 October 2026

The AI connection was subsequently repaired and upgraded successfully; see
[the later connection acceptance](connection-repair.md). The installation
observations below describe the earlier state and remain useful evidence.

The corrected signed updater completed successfully at 00:49 local time. The
owner's earlier install approval was already given; no repeat approval was
requested. The installed app is version 0.8.0, build 120.

The installation wrapper verified that the support-root and application-alias
identities, private home/vault-root identities and all 98 metadata records in
the older unpublished preparation stayed unchanged. Its final service check
failed, after Installer itself returned zero. [Installer log](install.log).

The protected service's fixed diagnostic was
`phase=settings reason=unsafe_worker_launcher_runtime`. Both socket parent
directories were absent. The cause of their earlier removal is unproven.
Using the existing root authorization, stopped only the registered broker,
restored its missing `run` (root, 0755) and `control` (root, 0700) directories
with the installed `system_provision.root_directory` checks, then bootstrapped
the existing signed service plist. No existing directory, policy, account
grant or credential was replaced.

A subsequent controlled service restart succeeded. Three running-state
samples retained the same positive PID. The app reopened to **Upgrade AI
connection**. [Health result](service-health.json),
[visible screen](upgrade-ai-connection.png). A full Mac reboot was not performed.

The installed Account Access skill's `accounts` discovery returned
`RETRYABLE/service_unavailable`, including one retry. The legacy launcher has
not been enrolled into the protected store. No unrelated account data,
password, cookie, verification code or vault key was read.

The next owner step is the visible **Upgrade AI connection** button, followed
by the separate **Authorize Account Access setup** macOS approval. This grants
the local AI connection and must be completed by the owner. Then repeat
installed launcher discovery and an already-approved read; label any synthetic
account result as a demo. No new installer is needed for this step.

The actual Installer probe now waits through bounded startup transitions,
requires three stable running PID samples, and rejects a loaded but crashing
job or a nested endpoint that merely says running. Nineteen focused tests and
Ruff pass. The two saved upgrade/reapply service logs also pass the stronger
running-state parser; no new package bytes were generated.
