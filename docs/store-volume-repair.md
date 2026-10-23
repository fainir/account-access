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
