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
validator/readiness checks and Ruff pass. The later focused
validator/readiness/Installer suite passes 55 tests; actual worker qualification
is complete below.

The interrupted first updater assembly stopped before packaging because the
post-reboot developer PATH omitted Homebrew's gh. Restarting assembly with the
normal publisher PATH completed; no earlier package/notary submission existed.
Qualification alone did not verify owner-Mac recovery or prove the original
startup cause. The completed installed checks are recorded below; the original
timeout cause remains an inference.

## Actual signed Installer acceptance

All six final-byte reports were downloaded and read. Both journeys pass on
[macOS 14](https://github.com/fainir/account-access/actions/runs/41460717727),
[macOS 15](https://github.com/fainir/account-access/actions/runs/41460712207) and
[macOS 26](https://github.com/fainir/account-access/actions/runs/41460722560),
using test-only revision f352d39 and the
[exact published-input contract](../../artifacts/runtime125-installer-inputs.json).

| OS | Fresh / identical repair | Update / reapply |
|---|---|---|
| 14.8.9 arm64 | [11 checks](macos14-fresh/report.json) | [27 checks](macos14-upgrade/report.json) |
| 15.8.2 arm64 | [11 checks](macos15-fresh/report.json) | [27 checks](macos15-upgrade/report.json) |
| 26.6.2 arm64 | [11 checks](macos26-fresh/report.json) | [27 checks](macos26-upgrade/report.json) |

All 114 checks pass. The actual installed public image/build 125, publisher-signed
sandboxed browser, dependency guard, synthetic private/root inodes, receipts,
policies and reapplication pass. Every upgrade/reapply preserves recovery
histories 120/121/122/123/124 and earlier incomplete public preparation. Every
created fixture job is stopped or absent. Zero personal accounts were used.

Customer-named package copies match these final tested bytes and were added to
the existing unpublished draft. Server digest, size and complete upload state
match both local files; the draft now has nine assets with no replacement or
deletion. Exact 125 notes, current/legacy labels, tested source target and unpublished
state were read back. [Customer handoff](../gates/customer-release-handoff-2026-11-02.md). The owner
Mac was still build 124 at that qualification checkpoint. Subsequent build-125
installation and recovered private reads are recorded below.

## Actual worker and package acceptance

[Mac worker run 41460707153](https://github.com/fainir/account-access/actions/runs/41460707153)
completed successfully at test-only revision f352d39. All 18 actual reports
were downloaded and read; their 427 check values pass. All 16 dedicated evidence
validators pass against those files. The [22-check supervisor report](worker/account-access-mac-root-supervisor.json)
includes slow_live_worker_ready_after_old_deadline=true from the real signed
35-second delayed-bootstrap fixture. The [staged-enrollment report](worker/account-access-mac-staged-enrollment.json)
also passes the precise wrong-key bootstrap-exit refusal and subsequent correct-key
recovery. These checks use synthetic data and disposable System keychain entries.

The [16-check offline package](worker/account-access-mac-package.json) and
[23-check prepared package](worker/account-access-mac-prepared-package.json)
include actual execution. Native framing, desktop XPC, private sockets,
password/email/SMS/TOTP, browser identity and initial-enrollment boundaries pass.
These fixtures do not establish real owner approval, private MFA, physical SMS
or current owner-Mac recovery. No production package was rebuilt for test-only
changes. The subsequent owner-Mac installation and acceptance follow below.

## D16 connector and signed-update completion

The existing completed worker CI contains 73 passing guarded-provider/form/
readiness cases. Its catalog, model, browser and relevant test sources match
the current checkout and the actual qualified build-125 wheel byte for byte.
The exact updater's source/compiler run, final digest and Apple/Gatekeeper
results match the completed native run and published Installer contract.
[Source and CI binding](d16-ci-binding.log). No job, test suite or package was
repeated. D16's connector, signed-update and subsequent installed acceptance
are complete. Personal Lemon credential/grant/TOTP enrollment and real MFA
remain F5/action 13. No new Lemon account operation or grant is claimed.

## Completed owner-Mac acceptance

The actual exact update completed at 20:07:27 Asia/Jerusalem on 2 November;
full kernel boot at 20:08:09 confirms the restart. Public metadata now reports
0.8.0/build 125 on macOS 27.2. Eleven selected native/identity/Python/wheel
files match the qualified image, all nine existing metadata identities survive,
and the new 125 recovery namespace is root-owned 0700. Private contents and
configuration were not opened. [Actual observations](owner-installed.log),
[scoped postinstall results](owner-installer-outcome.log).

The post-restart worker is RUNNING with zero failures and browser is READY.
Both installed agent launchers discover their existing narrow grants and
complete the real approved Betterloop session-status read with outer environment
live and authenticated=true. The Codex response was read directly from stdout;
the [Claude response](installed-claude-private.json) is retained. Separate
[Codex public-example](installed-codex-public.json) and
[Claude public-example](installed-claude-public.json) reads each return six
names/prices. [Final health/discovery](installed-accounts.json).
The actual native app reopens with Automatic integration and Betterloop Connected;
Namecheap remains paused. [Native screen](installed-accounts.png).

An unnecessary repeated updater invocation after tool interruption was refused
at journal. It did not disrupt the installed worker or the private/public reads
above. The recorded device changed after reboot; the native journal deliberately
rejects historical-device mutation, but the exact wrapped failure was not read
from protected state. This does not qualify successful owner-Mac reapplication.
Do not rerun a completed predecessor updater or weaken that guard.

Before the update, normal quit was requested only for the verified owner bundle
and independent process read-back confirmed exit. This follows the existing
saveApplication implementation and Apple's [normal-quit API](https://developer.apple.com/documentation/appkit/nsrunningapplication/terminate%28%29?language=objc).
The key lesson from the redundant reapply is to re-read installed build and
completed postinstall results after any interruption before taking another
Installer action.

D16's installed connector and D18's post-restart worker acceptance are complete.
Real private MFA remains unverified: Lemon still needs a local credential grant
and existing-authenticator enrollment. Its native import file chooser is staged;
the original export is absent from Downloads and Trash is uninspected. No new
export, manual Chrome MFA or completed import approval is requested. The completed
installation follow-up was deleted; remaining personal steps stay owner rows.
