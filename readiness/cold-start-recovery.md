# Initial worker timeout recovery - 4 November 2026

Scope: source fix and ordinary synthetic checks only. No installed service,
owner command, protected key/policy/credential file, signing, package or CI job
was accessed or changed by this lane. Root owns release qualification.

`RootWorkerSupervisor.start()` retains its single-attempt default. Only the
trusted enrollment caller can opt into initial timeout recovery: at most two
additional launches, after 5 and 20 seconds. A launch failure first runs the
existing owned-child/listener cleanup. Only the preserved typed
`RootWorkerProcessFailure.startupTimedOut` can then retry. Cleanup failure,
missing keys, changed identity/socket/code, authorization/publication failures,
pause and bootstrap exit remain terminal. The existing running-worker crash
restart budget is unchanged; no failed-to-idle reset API was added.

`RootInitialEnrollment` rechecks its durable owner authorization, published
phase, journal pause and stopped state throughout bounded backoff and
immediately before each additional launch. Each actual launch retains all
existing daemon, key, code, identity, listener and policy checks. The retry
does not rerun key enrollment, initialization, publication or account writes.
Cancellation returns without a repair error; the caller preserves paused and
stopped states and any fresh authorized pending Resume. A paused launch with
no worker explicitly returns false and cannot mark enrollment ready.

Changed files:

- `macos/RootInitialEnrollment.swift`
- `macos/RootWorkerSupervisor.swift`
- `macos/Tests/InitialWorkerStartupRecoveryChecks.swift`
- `tests/test_worker_startup_recovery.py`

Actual current-source verification:

```text
/opt/homebrew/bin/uv run pytest -q tests/test_worker_startup_recovery.py tests/test_worker_startup_readiness.py
2 passed in 9.46s
/opt/homebrew/bin/uv run ruff check tests/test_worker_startup_recovery.py
All checks passed!
git diff --check
exit 0
```

The Python checks compile exact production helper prefixes with warnings as
errors, then execute 13 recovery groups plus the six existing readiness
groups using fake clocks and synthetic owned-resource state. They cover finite
budget/exact error preservation, cleanup before revalidation/relaunch,
cleanup failure, missing/changed authority and security errors, nil-callback
single-attempt behavior, pause before/during/the final backoff slice, later
security failure and the paused-without-worker result.

Independent review found the paused-launch result issue during development;
it was fixed and the additional regression group passed in the final run.
Full native broker compilation, real owned child/listener cleanup and
Pause-to-authorized-Resume integration in an isolated root fixture, and actual
installed/cold-boot acceptance remain unrun. Pure tests do not close those
release checks.
