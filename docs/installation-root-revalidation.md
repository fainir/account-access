# Installation root revalidation

This development recovery path passed actual disposable-Mac Installer
qualification at package source `93fc906`, using the corrected controller
`abe6e02`. All 26 recovery-route checks passed, including repeat installation and
an interrupted-write fixture. On the affected personal Mac, native Installer
failed and the protected public result reports `REFUSED` at checkpoint
`publish`. The specific failed operation is not established, and the component
update was not attempted. Personal repair, account sign-in and production
readiness remain unverified.
[Qualification record](../artifacts/installation-root-revalidation-93fc906-20261020.json).

A later signed read-only diagnostic published a refusal at `first_service_job`
and observed that the supplementary binding directory was absent. The initial
service check had passed; the repeated check still combines command success,
individual process attestation and identity equality. Separate public metadata
observations showed the service changing from running to stopped. This supports
correcting the cross-observation lifecycle requirement, while leaving the exact
failed predicate unconfirmed. Publication of this diagnostic result does not
attest completion of its Installer transaction.
[Read-only diagnostic record](../artifacts/installation-root-revalidation-diagnostic-93fc906-20261021.json).

An installation receipt must keep identifying the installed software after a
restart. The original protected Mac installer recorded each installation root's
device number and inode. A device number is a mount-time identifier; it is not
a persistent volume identity. Apple documents that these identifiers can change
across restarts and recommends comparing a volume UUID instead.
[Apple's device-stream guidance](https://developer.apple.com/library/archive/documentation/Darwin/Conceptual/FSEvents_ProgGuide/UsingtheFSEventsFramework/UsingtheFSEventsFramework.html).
The component updater refuses an unexpected
binding instead of modifying an installation it cannot verify.

The explicit native revalidation package can establish a new current-volume
binding when the original inodes still match. This is a new administrator
authorized attestation of the current installation. The old receipt does not
contain a volume UUID, so this operation cannot prove historical volume
continuity.

## What it checks

The package must run through the native root Installer path with the expected
Developer ID publisher and its compiled component-plan pin. Before creating
the supplemental receipt, it checks:

- All four original immutable receipt files, their schema, original owner,
  base manifest and completed publication state.
- Both fixed installation roots, their original inodes, protected ownership,
  literal application alias and a nonempty persistent volume UUID. Both roots
  must identify the same current volume. An inode replacement is refused.
- The complete pinned public installation image and installed owner, broker
  and bootstrap signatures. Private account directories remain opaque.
- The typed protected policies, reserved operating-system service identity,
  fixed system job and matching service process identity.
- The same receipts, roots, public image and policies again, and a fresh
  independent attestation of the current fixed service job,
  immediately before and after publication, while installation leases remain
  held and the owner app is closed.

The development correction permits an authentic service to stop or restart
between complete observations. Every running observation still requires the
exact approved broker signature and its individual process-identity checks.
Revalidation does not store, adopt or signal a process identity. The component
updater's separate process-ownership and quiescence rules remain unchanged.
This correction still needs its own exact-source and Installer qualification.

The native code queries volume metadata from pinned directory descriptors. It
does not follow the application alias to discover its volume or read account
credentials, codes, browser sessions, mailbox messages or vault keys.

## What it saves

The four original receipts stay byte-for-byte unchanged. One supplementary
receipt is published in a separate root-owned directory with mode `0700`; its
file has mode `0600`, one link and no ACL. It binds the original receipt hashes,
owner and base generation to both unchanged inodes and the current volume UUID.
The issuing source, plan, publisher and policy hashes record creation evidence.
Policy hashes are not permanent equality requirements: a legitimate component
update changes some policy values.

Publication uses a fixed pending file, an exclusive rename and filesystem
synchronization. A retry can finish an interrupted pending file only when its
protected metadata and every existing byte match the newly verified expected
receipt. Unknown entries and conflicting contents are refused. The process
does not overwrite an existing receipt or create an unlimited set of temporary
files.

After publication, the supplemental binding remains authoritative even if a
later mount reuses the original numeric device number. The updater checks the
persisted UUID, both inodes and original receipt hashes on each use. A changed
UUID, changed inode, missing or incomplete proof, or altered original receipt
causes refusal. Ordinary legacy installations without a supplemental namespace
keep their existing validation path.

The package also attempts to publish a small public result containing only a
fixed status and, on refusal, a fixed checkpoint. It retains at most eight
completed or interrupted report slots per plan. Reports contain no account,
policy, inode or volume-UUID values, and a reporting failure cannot turn a
refused operation into success.

## Limits

- Creating a new binding is allowed only for a valid device-number mismatch
  with both original inodes still matching. A changed inode requires a separate
  reviewed recovery procedure; this package does not adopt it.
- An existing valid binding can be checked again against the exact base image
  or the exact corresponding component-updated image. Revalidation does not
  start, stop or reconfigure the service.
- The frozen original base installer does not understand the new supplemental
  binding. Reapplying that installer after revalidation remains unsupported;
  a future base installer needs its own native authenticated consumer.
- This does not import passwords, grant agent permissions, enroll a store or
  bypass owner authentication. Existing personal password, email, SMS and
  authenticator acceptance gates remain open.
- The package is a development recovery component. Consumer Installer signing,
  notarization and release qualification remain separate requirements.

## CI qualification

The package builder requires successful checks for its exact source. Normally
every required workflow passes its first attempt. One failed-jobs-only retry is
allowed when GitHub's authenticated job and check records prove that a hosted
Mac job never acquired a runner or executed a step, and carry its exact runner
capacity cancellation annotations. The only permitted skipped job is that
cancelled context job's declared dependent.

Both attempts, original annotations and their hashes remain in the build
evidence. Already successful jobs must retain their original identities; every
retried required job must actually succeed. Native artifacts must identify the
selected context job's real source and attempt. A test failure, executed failed
step, assigned runner, unknown cancellation, unrelated skip, repeated successful
job, missing history or third attempt is refused. Retrying infrastructure never
turns the original attempt into a first-attempt pass.

The implementation is in `macos/InstallationRootBinding.swift`,
`macos/InstallationRootRevalidation.swift` and `macos/ComponentUpdate.swift`.
See [production gates](production-gates.md) for the broader release status.
