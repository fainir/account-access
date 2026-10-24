Package 94 is built from controller `b5ea8a2`, with the same frozen runtime92 application payload. Its package SHA-256 is `1086e6eac90083489c7b85578f5267eaee77bdd6b3844b1b4a4579d89c731c3e`. All seven draft assets match their sizes and hashes. Local native core checks (377), shared-controller checks and 68 runtime checks pass. Hosted run `40127602745` verified both live Apple code identities and rejected incorrect identities. A second isolated run exercised a dedicated-UID Apple process surviving user-domain removal successfully, but artifact export failed because the fixture omitted publishing its evidence directory; that fixture-only export is fixed and must be rerun. Full package94 Installer/recovery acceptance and owner recovery remain pending.

## Owner Mac refusal after hosted acceptance, 24 October 2026

Package 93 failed on the owner Mac at `component_service_quiescence_not_confirmed`. Read-only checks confirm the previous 25,166 public files and all five public trees remain intact. The broker job is absent and disabled. Two Apple system process paths remain under its dedicated UID: `distnoted` and `lsd`. Recovery and a verified process classifier are pending. The three hosted Installer passes did not cover this owner condition. See `artifacts/runtime93-owner-quiescence-refusal-20261024.json`.

Runtime successor candidate (2026-10-24): package93 is built from controller `f9c0a80` and application `7051ef2`. Its signed helper, final package inventory and all seven frozen draft assets are verified. Ordinary native checks pass (68 successor checks, 459 tree-storage checks, plus existing adapter regressions). A hosted-only temporary-buffer fixture failure was fixed without changing the production controller; source `32dc10e` passed native checks and 4,169 Python tests. The fixed group mapping matches 27,472 public installed nodes, including the earlier three cache repairs. The corrected harness at `c2bd304` reached the production helper in run `40120185620`; one scenario refused at tree capture before publication. The rerun at `bd933a8` confirmed exactly those three historical cache-group differences and passed all three actual Installer scenarios with the unchanged package. Its three archive hashes and 155 referenced log hashes were independently verified; see `artifacts/runtime-upgrade93-installer-acceptance-20261024.json`. The owner Mac still has package91. This does not qualify real account login or Android delivery.

Latest validation (2026-10-24): runtime92 fresh Installer and exact reapplication passed all 13 checks in hosted run 40113282658. Completed package91 predecessor validation passed all four scenarios in run 40113010696, including interruption recovery and refusal of a foreign volume binding. Downloaded reports and referenced logs were hash-verified; see `artifacts/runtime92-fresh-installer-20261024.json` and `artifacts/completed-repair-hosted-20261024.json`. The owner successor upgrade controller and real-account acceptance remain unqualified.

# Full-image update development status

## Latest status — 24 October 2026

Package91 repaired the owner installation and the app opens. AI connection setup
then failed because its older upgrade checker rejects a named preview root.
Runtime92 contains the tested source fix and passed fresh-install/reapply QA.
The completed-repair verifier passed all four hosted predecessor scenarios.
Package93 binds that runtime to the repaired image and has passed actual successor
Installer/recovery acceptance. The owner installation attempt remains pending. See [current production gates](production-gates.md) for the live
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
