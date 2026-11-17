# Installed AI connection repair - 31 October 2026

The app's **Upgrade AI connection** advanced through enrollment, then refused
the install stage with `client_upgrade_needs_repair`. Both active preview
skills had an occupied `.account-access-preview-backup-v1` slot containing an
exact duplicate of that same preview, rather than a staged current skill.
The source's refusal was correct; an unknown slot must not be overwritten.
[Visible stopped setup](connection-upgrade-blocked.png).

The new maintenance tool `scripts/retain_duplicate_preview_skills.py` verifies
the bounded public-only tree, private modes, ownership, no grant ACLs or links,
exact equality with the active skill, recognized shipped template hashes and
coherent generated launcher paths. It never opens a client credential file,
enrolls a connection, changes grants, or changes the active skill. It exclusively
renames each verified duplicate to
`~/.local/share/account-access-retained-skills/`, preserving its inode and bytes.
Unknown, changed or additional files are refused before moving either host.

The dry run found exactly two duplicates; both were more than 30 minutes old.
The applied repair retained both. The normal app's **Reopen and check status**
and **Upgrade AI connection** then completed. No new installer, password entry,
credential-file inspection or manual grant change was needed.

Both installed launchers now return `OK`, service version 0.8.0 and the approved
Namecheap status operation. [Installed discovery](installed-client-discovery.json).
The owner app says **Ready in every new session** for Claude Code and Codex.
This verifies the local connection, not private provider authentication.

The approved Namecheap operation stopped on its existing challenge without
sending another website request. The preserved challenge is
`b56217f0353d484add171f6bc78b5239`, `browser_state_unrecognized`; required action:
review the unrecognized authentication page. The app describes an unreviewed
sign-in destination. Do not resubmit the operation or claim successful login.
[Status result](approved-status-result.json).

The public SauceDemo testing account is prepared in the native connection form
for a separate installed happy-path test. Its credentials were verified on
the site's public login page, and the proposed permission is limited to product
names and prices. Saving this example connection awaits the user's explicit
approval. It must remain labeled `public-example` and cannot establish private
account acceptance. [Prepared native form](public-example-prepared.png).

Validation: [56 passing maintenance and agent-upgrade tests, plus Ruff](duplicate-backup-tests.log).
The maintenance tests cover preserved active/retained inodes and bytes, no
credential reads, unknown templates, extra files, symlinks, hard links, unsafe
modes, foreign bindings, existing destinations and changes during validation.
