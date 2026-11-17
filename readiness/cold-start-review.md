# Initial worker timeout recovery - independent safety review

Scope: source-only review of the observed post-reboot build 127 worker timeout. No installed credential, policy, enrollment, vault or key files were read; no owner command, service change, build, signing, installation or CI job was run by this reviewer.

## Evidence and limit

The coordinator observed a new kernel boot, a fixed native `worker_start` / `worker_startup_timed_out` diagnostic, a live root broker without a worker, and `RETRYABLE/service_unavailable` from both installed agent launchers. This proves unavailable service after the startup deadline. It does **not** prove why readiness was delayed or that a retry will succeed. Cold-boot load is an inference; real installed/reboot acceptance remains required.

## Reviewed design

- Retry only the final worker-start step after publication, not `perform()` or key creation/publication. Replaying the whole enrollment pipeline is unnecessary.
- Preserve the no-argument `Supervisor.start()` single-attempt contract. A new opt-in overload is used only by the already-authorized native enrollment coordinator and returns whether startup completed.
- Admit only the typed `RootWorkerProcessFailure.startupTimedOut`, after successful cleanup. `RootWorkerProcess.start()` already stops/reaps/releases before preserving its original error; `Supervisor` then discards its worker. Any cleanup error replaces the timeout and must remain terminal.
- At every retry and bounded backoff check, the enrollment callback rechecks stopped/paused state, durable authorization and the published phase. The next normal `RootWorkerProcess` repeats launcher policy/code, listener, key and identity validation. No generic failed-to-idle reset API is needed.
- Two retries with finite backoff are reasonable. A request, health read or repeated UI poll must not replenish this local attempt budget or dispatch another launch.
- Returning false for pause/cancellation must return from `perform()` before ready publication. This matters when Pause is immediately followed by a newly authorized Resume: the existing `pendingResume` handling must retain that fresh approval rather than marking a paused worker ready.
- Initial-start backoff needs an actual monotonic clock with a matching pause function. The existing supervisor fixture's externally advanced crash-budget clock cannot safely be paired with real sleeping.

This design keeps startup recovery separate from owner enrollment, post-readiness crash recovery, public update recovery and account operations. No secret/key replacement, grant change, operation replay, new owner approval or security-refusal bypass belongs in the retry path.

## Lock order and pause handling

No new lock inversion was found. The supervisor holds its recursive lock while retry validation takes the enrollment lock. The reverse calls release enrollment's lock first: `stop()` releases it before draining the queue/stopping the worker; owner Stop queues its supervisor pause and releases the lock; the post-start path releases it before pausing the worker. Journal methods release their own state lock before returning; retry validation and owner Stop use the same enrollment-to-journal order.

The first draft treated a normally returning `launch()` as success, although a `service.paused` marker makes it return without a child. That finding is fixed: the production launch closure now returns `current == .running`, and a false result cannot publish ready. The caller sets paused only while still initializing with no pending fresh Resume, preserving stopped state and the existing authorized `pendingResume` handoff.

The last validation-to-launch boundary does not make cancellation atomic. As before, Pause can overlap an already-admitted bounded readiness wait. The final journal-paused or current-paused check stops that worker and suppresses controller ready publication. The patch does not extend this existing admission window across backoff: every delay slice and the next launch boundary recheck pause/authority.

## Required checks

1. First launch succeeds once; no retry callback or delay.
2. Exact timeout is cleaned up before validation/backoff; the next launch can succeed.
3. Three consecutive timeouts exhaust the two-retry budget and preserve a terminal timeout.
4. Every other process/key/policy/listener/publication/authorization error, an error with the same text, and every cleanup error remain terminal.
5. Pause/cancel during delay and immediately before launch produce no next launch; authorization or phase drift throws without launching.
6. No-argument startup retains one-attempt behavior.
7. A real root fixture must confirm the timed-out child is reaped and inherited listener leases released before replacement, including socket/ownership changes and cleanup refusal.
8. An enrollment integration fixture must cover Pause followed immediately by authorized Resume, stopped state and one publication/key initialization across retries.
9. Installed acceptance must verify actual worker/browser readiness and the two already-approved launchers after the new package, then after a full new kernel boot. Pure helper tests and typechecking do not close this.

## Patch verdict

The current production patch has no remaining concrete review finding. It includes the paused-launch correction and preserves the old single-attempt entrypoint. The 13 pure test groups were inspected. The implementation lane's completed current-source run reports `2 passed in 9.46s` for the new 13-group recovery check and existing six-group readiness check, with clean ruff and whitespace checks; its [handoff](cold-start-recovery.md) records the command/result. This reviewer did not duplicate those runs. Root child/listener integration, Pause-to-authorized-Resume integration and actual installed/coldboot acceptance remain unrun here. This memo is not production or installed acceptance.

## Adjacent deadline review

Acceptance checks for this additional source/metadata review: identify whether update publication waits for worker readiness; compare the actual package deadline with retry time; distinguish native response waits from asynchronous startup; check whether UI polling or a close cancels startup. No compiler, CI, service or owner command was run.

No production watchdog was found that requires widening for D29:

- `ComponentUpdate.swift:771-781` restores the user domain, enables and bootstraps the job, then explicitly records `canonical_job_bootstrapped_gui_unverified`. It performs no owner-health RPC or private-vault readiness check. `ComponentTransition.run` returns after that restore (`ComponentUpdate.swift:137-140`); the direct updater follows the same transition then verifies public aliases (`source-fragments/RuntimeUpgradeInstalledAdapter.swift.inc:727-730`). `FullImageInstalledIO.swift` and the installed adapter fragments contain no later worker-readiness deadline. A slow asynchronous enrollment is therefore not a post-transition failure that triggers rollback.
- The **existing held** signed candidate's independently expanded `dist/root-recovery-release/harel128/candidate-Q/independent/PackageInfo` was read directly: its postinstall timeout is `1800`, with restart action. The builder explicitly replaces the generated 600-second value with 1800 at `scripts/build_direct_runtime_upgrade_candidate.py:622-625`. The nominal retry readiness budget is `3*120+5+20=385` seconds, plus owned-child cleanup (up to 12 seconds for each attempted stop), policy/key validation and filesystem work. It is not a hard 385-second overall deadline. The corrected future package still needs its own final-byte read-back; this check does not qualify that package.
- Enrollment work is scheduled on its serial queue (`RootInitialEnrollment.swift:141-146`), and an approved enrollment request returns 202 after scheduling (`:252-262`). The broker starts its native gateway after that scheduling (`RootBrokerHost.swift:82-85`). `OwnerGatewayRoute.requestTimeout` 35 seconds (`OwnerGateway.swift:175`) and the desktop 40-second response wait (`DesktopOwnerConnection.swift:306`) therefore do not enclose all startup attempts. Closing the desktop session invalidates its authorization/session (`OwnerGateway.swift:456`), not the durable enrollment operation or worker.
- The native setup screen starts 60 read-only polling iterations (`AccountAccess.swift:1109`, `:1213-1227`). Exhaustion displays “Setup is taking longer. Choose Check progress to reconnect.” It neither cancels nor replays enrollment, so recovery can still finish. Automatic screen transition can stop before a long successful recovery; retaining the Check progress fallback is an existing UI limitation, not an updater rollback or backend cancellation. No unrelated UI change is required for D29 safety.
- The 20-second launchctl command/removal guards (`ComponentUpdate.swift:401`, `:535-553`) apply to command execution and old-job quiescence, not new-worker readiness. Updating during an already admitted startup can still require the existing stop barrier; D29 does not force that barrier to wait for all three attempts because stop is rechecked before a retry. Do not weaken ownership or quiescence checks to accommodate startup. `SystemBroker.swift:177`'s 15-second domain-command guard and `RootWorkerChannel.swift:72`'s one-second atomic pipe-write guard are separate bootstrap operations, not total readiness watchdogs.
- The offline browser probe has its own 20-second child bound (`account_access/browser_health.py`). Exhaustion marks browser health unavailable and returns; it does not cancel the worker startup/retry controller. Actual acceptance must still inspect browser READY separately from worker readiness. The root integration fixture's existing 90-second `wait(setup)` (`macos/Tests/RootInitialEnrollmentChecks.swift:45-50`) is a test bound; any future test deliberately exercising a 120-second timeout/retry must give that specific test enough time or inject a matching fake clock.

Minimal necessary deadline adjustment from this review: **none**. Existing fixed deadlines are not proof that the newly built/installed service recovers; final corrected-package and full cold-boot acceptance remain required.
