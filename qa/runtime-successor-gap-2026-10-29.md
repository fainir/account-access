# Runtime successor update gap - 2026-10-29

The owner Mac has the build 95 public image (`03fb35…`). The exact build 95 installer asset was downloaded from its draft QA release and matched the recorded SHA-256. The current signed build 116 fresh-install image targets `78113e…`; its installer correctly refuses to overwrite the existing install journal.

The public image delta contains 207 changed entries. It changes the owner app, broker and installer helpers, browser/runtime trees, wheels, and package identity. The current `FullImageSource` contract requires the old and new broker code-identity records to match and its installed adapter loads a `ComponentSource` predecessor. Build 116 changes the broker code-identity record, and the installed predecessor is the completed runtime 95 transition. The existing adapter therefore cannot safely qualify this successor package.

The required buildable work is a fixed runtime-successor source and adapter that validates the completed runtime 95 proof, permits only the target's Developer ID identities, preserves the private store, and reuses the existing atomic staging, rollback, retry and post-restart verification. Then the signed/notarized successor needs a real Installer run on this Mac. No account store or private records were read while making this comparison.
