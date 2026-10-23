# Persistent store volume identity

The corrected read-only owner diagnostic completed with `device_number_changed`.
The two directory inode values match their registration, but the current device
number differs. No credential contents, keys, or raw metadata were exported, and
the diagnostic changed no store files. This confirms a registration mismatch;
it does not establish that all later startup stages will succeed.

New broker source keeps the original publication record unchanged and adds a
small root-owned `volume-v1.json` binding. It binds the exact record bytes to a
persistent volume UUID and the parent directory inode. It can create this binding
for a fresh registration or an existing registration only while both original
directory identities and their device number still match. Existing legacy data
with a changed device number remains refused until a separate migration supplies
independent persistent-volume evidence.

Reopening validates canonical bounded binding bytes, the original record hash,
the current volume UUID, parent identity, protected path attachment, and both
directory identities. A device number may change within that bound volume.
Changed volumes, changed parents, substituted directories, changed records and
ambiguous binding data remain refusals. No original record or credential is
rewritten and no missing key is recreated.

Thirty ordinary-user native checks passed, including actual volume-UUID reads
from a new temporary directory and simulated device-number changes. Production
broker typechecking passed. The disposable root fixture now requires 46 checks,
including worker reopening with a simulated old device number, immutable
registration preservation and refusal of a different persistent volume. Hosted
execution of this new fixture is still required; it is not physical reboot QA.

This source is not installed on the owner Mac. The next delivery work must bind
the legacy store registration to the existing independently verified installation
volume receipt, qualify a successor update from the repaired public image, and
test installation, recovery and owner startup. Directly editing the owner's
publication record, replacing keys, resetting the store, or manually swapping
native binaries is not a repair path.

The migration authority validator now checks the exact original installation
receipts, the already published volume receipt, the fixed component plan/source,
unchanged worker/service policies, and both currently attached installation roots.
The publication record must use the original installation's device epoch and both
store directory inodes must be present in the completed, reversed order. It also
requires the existing owner authorization and ready marker. A different volume,
changed policies, substituted directories, ambiguous records, paused enrollment,
or unrelated historical device epoch is refused. The validator is data-only;
its installed adapter and successor broker delivery are still unfinished.

Binding publication now stages a bounded, root-owned pending file, syncs it, and
publishes through exclusive rename. An interrupted matching prefix can resume;
existing or foreign files are never overwritten. The broker rechecks the journal,
lock, original record, volume and directory identities before publication. Local
ordinary-user tests passed 61 binding/interruption assertions, including failures
after creation, partial write, sync and publication. The component fixture passed
330 assertions including the migration authority checks; 223 focused Python tests
also passed. Hosted verification is required for these exact new bytes. None of
this new source has repaired the owner's installed store yet.

Hosted Mac run 39964787681 at source 07d4c73 passed all 46 initial-store/restart
checks, including real fixture-worker reopening with simulated device renumbering,
preservation of the original registration, and refusal of another volume UUID.
This run predates the atomic writer and migration adapter. It is not an owner
installation, a physical remount test, or a positive legacy migration test.

The installed metadata migration adapter now typechecks and rejects ordinary-user
calls before reading metadata or invoking its service-barrier callback. It has no
entrypoint. Its successor controller still needs to supply verified update
authority and prove the broker is disabled and quiescent. The adapter retains the
enrollment lock, reads protected receipt metadata, stats both store directories,
and revalidates before atomically publishing the binding.

A separate read-only completed-full-image verifier reuses the full-image checks.
Verification cannot create a missing namespace, intent or per-tree journal, and
cannot stage an update or call its service transition. It emits an opaque proof
only for an already completed, verified image. Ordinary native fixtures passed:
namespace checks 24, durable journal checks 153, and tree storage checks 221.
The combined full-image fixtures and ordinary entrypoint refusal passed. Root
execution of the successor and migration adapter still requires disposable-Mac
acceptance before an owner installation is offered.

The broker-repair source contract passed 54 native checks and its immutable
recovery intent passed 49 checks in the combined ordinary-user suite. The suite
also passed all six argument-refusal guards and the ordinary full-image updater
refusal. The report is bound in
`artifacts/broker-repair-source-contracts-20261023.json`. Two earlier runtime
attempts failed and are retained; they are not counted as acceptance.

The successor controller and Installer entrypoint are now implemented as
unqualified candidate source. Its public delta is exactly the broker executable,
package signature metadata and a new provenance file. It derives only owner and
installation policies, preserves the bootstrap policy, and retains before/after
objects in a separate protected namespace. Initial acceptance requires the
opaque completed-full-image proof. Recovery checks the exact saved history,
head, policies, persistent volume UUID and root inodes before translating a
transient device number. This initial successor deliberately refuses predecessor
journals containing pending audit files.

The transaction uses the existing persistent launchd disable/quiescence barrier,
publishes the additive volume binding before its head, and releases the enrollment
lock before restoring the service. Exact completed retry verifies the public image
without claiming GUI health. New history/audit and ordinary-root-refusal fixtures
have been added but have not yet qualified this controller. The local controller
compile hit its deadline during severe host load; the runner now bounds compiler
parallelism and allows a longer bounded deadline. No repair package has been
built or installed from this source.

Hosted run 39971114599 passed Python tests and owner UI checks, but its gateway
job found a standalone tree-test compile dependency introduced by the read-only
fixture. That test now uses its existing payload reader directly; the original
failure remains part of the evidence. Hosted run 39971114489 passed Installer
context checks and was still running cross-user acceptance at this checkpoint.
