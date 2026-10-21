These three `.bin` files are the original CPython 3.12 bytecode files shipped
in the reviewed build76 package. They are code, not account data. They were
retained from the official pinned CPython archive with SHA256
`9866e11cf2ae9caa1e671383786f248859a52dd8bfb702fb4c0dc2c65f1d36de`.
The Python Software Foundation license and notices are retained alongside these
files in `PSF-LICENSE.txt`, copied from that archive's `lib/python3.12/LICENSE.txt`.

`plan.json` binds each original file's exact size/hash to the package manifest
at `dist/release-080-review-build76/actual-package-manifest.json`, SHA256
`5618053e6f8ed0a8720a9d2f7dde317425cecda6a970abd90c499fbfe27b43a8`.
The plan also fixes three observed replaced cache files, eight extra cache
directories, and their permitted public source files. The helper rejects any
unrecognized child or cache body and validates all eleven targets before the
first installed change.

The separate nopayload package only restores those three original files and
moves the eight validated extra directories into a new private backup outside
the runtime. Existing files, staged replacements and durable per-operation
journals remain available for manual recovery. In-process rollback checks exact
inode/hash identities and preserves concurrent changes. Automatic crash recovery
is not implemented: a previous repair backup causes refusal pending review.
An exclusive empty bytecode prefix prevents the repair interpreter from reading
the installed caches it is about to inspect. Neither helper nor package starts
or stops a service, changes its stdout, or accesses account data.

The original broker failure predates these cache changes. Restoring the caches
does not establish that startup or authentication works. The fixed signed native
checker can observe public metadata afterward; its successful execution is not
a product-readiness claim.
