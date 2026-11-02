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
is published only for synthetic qualification. The exact
[native qualification](https://github.com/fainir/account-access/actions/runs/41455143115)
passed all eight reports, including retained 120/121/122/123/124 transitions.
The matching [source regression](https://github.com/fainir/account-access/actions/runs/41455143143)
passed 4,712 tests with 114 platform skips, Ruff, dependency audit and native
owner/gateway checks. [Source summary](source-regression.log).

Both packages are signed, accepted by Apple, stapled and accepted by Gatekeeper.
The full package is 289 MB; the exact update changes seven public files, with
27 packaged nodes including the complete signed owner bundle. Its independent
resource/signature checks and ordinary-user refusal pass.
[Updater result](updater-qualification.json), [full-package result](fresh-qualification.json).

The first worker CI run reached the deliberate wrong-key refusal, where an
old test still expected the generic unavailable error. The new production
reason correctly identifies bootstrap exit. The test now requires that exact
reason; production code and qualified packages are unchanged. The same CI-only
change adds a separately signed bootstrap that sleeps 35 seconds, then uses
the actual key handoff, identity drop and worker protocol. Eighteen local
validator/readiness checks and Ruff pass; the actual delayed-worker run and
three-OS Installer qualification are next.

The interrupted first updater assembly stopped before packaging because the
post-reboot developer PATH omitted Homebrew's gh. Restarting assembly with the
normal publisher PATH completed; no earlier package/notary submission existed.
Installed worker recovery is still unverified. Do not claim this is the real
startup cause or a completed production fix until actual installed checks pass.
