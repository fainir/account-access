# Full-image update development status

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
