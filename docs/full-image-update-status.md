# Full-image update development status

## Latest status — 24 October 2026

Package91 repaired the owner installation and the app opens. AI connection setup
then failed because its older upgrade checker rejects a named preview root.
Runtime92 contains the tested source fix and is undergoing fresh-install QA.
A completed-repair verifier is undergoing hosted qualification before work can
bind a successor update to this repaired image. No runtime92 owner upgrade is
qualified yet. See [current production gates](production-gates.md) for the live
status; the sections below preserve the earlier development history.

## Current status — 23 October 2026

The controller described below has since been implemented. The current
reviewed application image is source `d30fda7`, with controller `d5cd6b7`.
Its exact package passed installation/reapplication and both interrupted-update
scenarios on disposable Macs. The original package did not complete on the owner's Mac: two
attempts reached the package-script deadline, leaving five owner-app files at
the target version and the remaining changed entries at the predecessor.
Those incomplete public files have now been repaired by package 85.

A reviewed derivative changes only the native package script deadline from
600 to 1,800 seconds. Its compressed script archive, including the application
and updater, is byte-identical. The native deadline experiment passed, and
actual installation/reapplication and both interruption scenarios in run
`39945206041` passed all 18 checks each. Native Installer then completed on the
owner Mac. An independent read-only check matched all 25,165 files, 2,297
directories and 21 aliases and confirmed removal of all 237 obsolete paths.
The public image is qualified. The native app still reports that the protected
account store cannot be opened safely; one Check again returned the same result.
The discovered agent launcher connects to a legacy controlled demo, not the
protected personal installation. GUI startup and personal end-to-end use remain
unqualified. No private store, key or client capability was inspected.
[Exact installation results](../artifacts/full-image-installer85-acceptance-20261023.json).
[Owner result](../artifacts/owner-mac-update85-result-20261023.json).

The source diagnostic changes passed hosted Mac acceptance, including all 43
initial-store/restart checks. They have not been installed on the owner Mac.
A corrected read-only registration diagnostic completed in native Installer and
confirmed a changed device number with the original directory inode pair. It did
not repair or reset the store. Persistent-volume binding source passed all 46 hosted initial-store/restart
checks. New atomic publication, migration authority and read-only predecessor
verification passed local native fixtures. The successor update controller and
installed legacy migration still require integration and qualification. [Repair scope](store-volume-repair.md).
[Diagnostic scope](store-registration-diagnostic.md).

See [current production gates](production-gates.md),
[owner failure evidence](../artifacts/owner-mac-update84-result-20261023.json),
and [exact derivative identity](../artifacts/full-image85-deadline-package-20261023.json).

## Historical primitive proposal

The remainder records the initial proposal before controller integration; its
statements about missing integration describe that historical source only.

The repository contains an in-development directory-storage primitive in `macos/FullImageTreeStorage.swift` and its ordinary-user fixture in `macos/Tests/FullImageTreeStorageChecks.swift`. A full-image updater does not yet exist. The primitive is not connected to installation or an update controller.

The primitive accepts held parent descriptors, one of four fixed public subtree units, complete before/after inventories, an exact plan digest, and an injected quiescence callback. The units are the owner application, the project package, its dist-info, and the provider tree. It verifies exact member sets, file bytes and modes, owner/group metadata, directory metadata, symlink targets, device membership, and no-follow descriptor/path identity. It writes an immutable intent and bounded event journal before an atomic directory exchange, retains the old directory, and supports same-intent observation and rollback. These are properties of this one-unit primitive.

Production integration still requires:

- A controller coordinating every unit with metadata, policy, head publication, and complete-image rollback.
- A trusted loader binding descriptors and inventories to the qualified fixed public roots and a verified signed plan, including publisher/trust-path validation, root ownership authority, and installation receipts.
- Repeated proof that held parent descriptors remain attached to their canonical trusted ancestors, before and after exchange and during outer whole-image verification. A pinned descriptor alone does not establish attachment.
- A policy and verification mechanism for symlink ACLs; the primitive does not inspect them.
- Real quiescence of owner-user runtime clients, background operations, and reserved-broker processes. The fixture Boolean does not establish this or prove race freedom.
- Testing of physical power loss, cross-volume behavior, hostile concurrent mutation, genuine signatures, and installed/root operation.

The primitive performs no service-enable action or old-tree deletion. It has no installed-path loader, account/Keychain access, or production update entrypoint. The fixture accepts no path arguments, refuses root and changed effective UID, and operates below a fresh exclusive `/private/tmp/account-access-public-tree-XXXXXX` directory with the caller's real UID/GID. Its manifests and executable-named application member are synthetic plain data.

The source proposal passed an ordinary-user temp-only native validation with 39 assertions: four-unit roundtrips and idempotence; interruption after an actual exchange followed by same-intent reopen, retry, and rollback; refusal of extra members, symlink substitution, a hardlink, changed alias, wrong mode, wrong bytes, a failed quiescence callback, and a wrong owner. Compilation exited 0 in 27.958 seconds and fixture execution exited 0 in 1.193 seconds. The result explicitly reports `production_ready: false`, no installed reads, no root execution, and no service actions.

The proposal result SHA256 is `7dcdb45721837a8d60fcc246f1021dc22f1255a00a53f112a686fe0f1f2bcfa7`. The source bodies were copied byte-for-byte into the repository, with only their introductory comment blocks changed. No separate compilation or fixture execution was performed during that mechanical promotion. Frozen source hashes, body-equality checks, and copies of the proposal bindings, source review, boundary statement, and validation result are recorded in the ignored `dist/qa-full-image-tree-promotion-213509c/` evidence directory.
