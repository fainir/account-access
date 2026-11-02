# Build 125 startup qualification - 2 November 2026

Installed build 124's owner-Mac restart exposed worker_start/worker_process_unavailable.
Its approximately 43-second bootstrap lifetime matches the previous 30-second
readiness allowance plus 12-second owned-child shutdown, but the old reason
does not distinguish a deadline from an early exit. No private policy, credential,
key or account data was read. [Actual 124 observations](../release124-2026-11-02/owner-installed.log).

The proposed native fix permits a finite 120-second monotonic readiness window,
keeps owned-child/health checks and bounded shutdown, and distinguishes timeout
from bootstrap exit using closed reasons. A controlled worker becoming ready at
45 seconds fails under the old window and passes under the new one. Six cases
cover delay, final deadline, child exit, ownership, transport error and late
reply refusal; all 53 focused local checks and Ruff pass.
[Before/after](../release124-2026-11-02/startup-readiness-regression.log).

Matching [owner/broker compilation](https://github.com/fainir/account-access/actions/runs/41452017204)
passes at source e0d65ce1803295d96dde96e465bd7e3ace18f32d. The
[signed image](image-qualification.json), assembled at b8aa5ef, passes all
49 native-file audits and actual sandboxed browser execution. Python wheel,
dependencies and JIT bytes are identical to build 124. Only seven public files
change; no private data or installed path was used by assembly.

The exact 124-to-125 plan has seven units: one fixed identity file and six
direct public files, with no Python/tree change. Its separate recovery namespace
retains 120/121/122/123/124 histories. The five-file public native input archive
is published only for synthetic qualification. Native updater compilation,
signed/notarized package qualification and actual Installer acceptance remain
pending. Installed worker recovery is unverified; do not claim this is the real
startup cause or a completed production fix until actual installed checks pass.
