# D22 - independent pre-release setup review

Reviewed 2026-11-04, before coordinator fixes, against the uncommitted setup/owner/native tree over `3c5520a`. Only this memo was written. No private account/mailbox, credentials, Chrome files, signing, build, CI, package, owner action or git mutation was used. Synthetic tests used the repository's temporary local TLS mailbox and fictional Harel transport.

## Findings

### [P1] Stop the first-message scan before further reads after cancellation/revocation

Location: `account_access/harel_setup.py:120` (`_pattern`), especially the FETCH loop at lines 140-143 and the caller's `_active` only after `_pattern` returns in `_run`.

The scan checks only wall-clock expiry between messages. If the owner cancels or replaces/removes the selected mailbox while the first FETCH is in flight, the next FETCH still reads another full message body using the old profile. The later `_active` correctly prevents review/publication, but does not undo the extra private mail read. The normal `Codes.imap` path already rechecks its window/authority before each FETCH.

Reproduced: two new synthetic messages; cancel the job immediately after the first FETCH returns. Recorded FETCH states were `[{number: 1, already_cancelled: false}, {number: 2, already_cancelled: true}]`; final status was CANCELLED and no account was published.

Fix: pass the attempt's `_active` callback into `_pattern`; check it before connecting/searching and before each FETCH, and after blocking network operations before consuming results. This must recheck both cancellation and the exact checked-profile authority, not only the stop event. Add a two-message cancellation and profile-replacement regression proving no second FETCH.

### [P2] Remember cancellation that arrives before the queued start

Locations: `account_access/harel_setup.py:252` (`cancel` calls `_job` and raises for unknown IDs), `macos/AccountAccess.swift:1530` (best-effort asynchronous cancel), and `:1606` (independent asynchronous start).

The owner can cancel the native starting screen before its start RPC reaches the broker. If cancel arrives first, it fails with `harel_setup_changed` and is ignored by `try?`; the delayed start subsequently creates the same job and sends the login email after the UI has abandoned it. Epoch guards hide the reply but do not cancel the broker operation.

Reproduced directly through the same manager methods: `cancel(valid_id)` returned `harel_setup_changed`; later `start` for that ID reached WAITING_CODE and sent one email. No replacement/new start was needed.

Fix: keep a bounded, expiring cancellation tombstone for a valid attempt ID and refuse a later start for that ID, or provide equally strong ordered start/cancel delivery. Native cancellation must remain effective after a lost start reply. Add the cancel-before-start ordering test and an in-flight/lost start response test.

### [P2] An older poll can unlock a pending native mutation

Locations: `macos/AccountAccess.swift:1640-1644`, `:1687`, `:1718-1739`; existing stale-reply coverage is `macos/Tests/OwnerScreenChecks.swift:261-264`.

Submitting a code or approving the pattern sets `busy = true`, but leaves the current phase and accepted revision unchanged. A check snapshot captured while the backend was still WAITING_CODE/REVIEW can arrive before the mutation response. Its revision is newer than the last UI revision, so `acceptHarel` accepts it and sets `busy = false`. The same code/approval button is enabled again while the first mutation remains pending. A second click can then receive a backend phase refusal and invoke `harelFailure`, cancelling the valid attempt. Server revision ordering protects only against a response older than a newer response the UI has already accepted.

Fix: track a pending local mutation/generation independently of server revision and keep controls locked until that mutation resolves; an earlier poll cannot clear it. Alternatively pause/invalidate polls across mutations with equivalent ordering. Add a native fixture that holds the mutation reply, delivers the pre-mutation poll, and asserts controls stay locked and only one mutation is dispatched. This finding is from source/control-flow inspection; its native timing was not executed because this lane does not build.

## Checks and preserved boundaries

- Existing suites: `PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m pytest -q -p no:cacheprovider tests/test_harel_setup.py tests/test_harel_protocol.py tests/test_harel_email_review.py` -> **171 passed in 26.70s**. `uv` was absent from this tool PATH; the existing repository virtualenv interpreter was used. No repository test/cache file was created by the review.
- Injected a normal publication failure at `connection:personal-harel` after credential/source transaction writes: result NEEDS_USER; original config restored; credential/source/code-window absent; zero Harel grants. The normal exception rollback works. Crash/power-loss atomicity was not exercised and is not claimed.
- `_EnrollmentStore` stages credentials/source/connection in memory; the automatic test starts with `state=None` and reuses real `Codes` baseline/window resolution, not the first code or session. Existing happy-path test verifies two StartProcess calls and two mailbox FETCHes, plus no standing Harel authority before approval/testing.
- Final source checks, `_active`, profile digest checks and locked publication prevent publishing a response after cancellation/profile replacement. The first scan issue above concerns additional reads before that final check.
- First-attempt monotonic expiry, protocol send/submission windows, cooldown and automatic resolver window checks are present. The second setup deadline includes its cooldown, so it can end earlier than a fresh full 120 seconds after the second send; I found no case that grants an expired code a new window. Slow-network absolute timing was not exercised.
- Native start is browser-setup authorization gated; code/check/approve consume an exact ID/candidate; legacy owner HTTP rejects these routes. No concrete gateway widening or existing-account overwrite was found in this review.

The three findings above are actionable before D22 is finalized. Retest them after the coordinator's changes; this memo does not qualify signed or installed delivery.

## D24/D25 remediation

The backend scan and cancel/restart findings above are addressed by the [setup safety implementation](harel-setup-safety.md). Final setup tests: 35 passed; lint clean. Native pending-action ordering remains the coordinator's D26 scope. The original findings and reproductions above describe the pre-fix tree.
