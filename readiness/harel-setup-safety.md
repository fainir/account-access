# D24/D25 - setup cancellation and replay protection

Implemented and verified 2026-11-04. Only `account_access/harel_setup.py`, `tests/test_harel_setup.py` and these readiness memos were changed by this lane. No signing, build/native compile, CI dispatch, package, private account/mailbox, owner request, commit or push was performed.

## Result

- The first-message baseline and scan call the complete attempt/profile authority check before and after mailbox acquisition, UID metadata, SEARCH and each FETCH. Cancelling from this or another manager, replacing the checked profile or removing the mailbox stops before another body fetch. Cleanup can finish an already in-flight operation; it does not authorize another read.
- First sends consume one encrypted product operation record before a provider request can be issued. The record contains only status, issued flag, revision and a closed failure reason. Credentials, identity, phone, code, message pattern and provider cookies are not copied into it.
- A valid cancellation can arrive before start. Its shared tombstone prevents a delayed start, including after manager recreation. Another manager's cancellation reaches a waiting worker within its one-second check and is checked around subsequent network operations.
- A recreated manager cannot resume private live cookie state. An existing active operation becomes terminal `NEEDS_USER / harel_setup_interrupted`; it never reissues that attempt. Uncertain first sends remain consumed. Completed operations remain completed without another send.
- Completion state is written in the same SQLite transaction as the new credential/source/status grant. Publication holds the shared operation lock, so cancellation cannot slip between its final authority check and publication. Injected ordinary failures restore the old configuration and roll back all new authority.
- Native polling gets a positive, increasing persisted revision. Missing/restarted operations are terminal; expired IDs return terminal `harel_setup_expired` with a revision above earlier snapshots. Polling also expires a 120-second window while a worker is blocked on a response, rather than waiting indefinitely for that response.

## Native ID contract and bounded state

Keep the existing 32-lowercase-hex wire shape, generated as **8 hex UTC seconds followed by 24 random hex characters**. The coordinator owns the matching native generation change; gateway shape validation remains unchanged.

Exported backend constants:

| Constant | Value |
|---|---|
| `ATTEMPT_MAX_AGE_SECONDS` | 600; an age of exactly 600 seconds is refused |
| `ATTEMPT_FUTURE_SKEW_SECONDS` | 5; exactly 5 seconds ahead is admitted |
| `ATTEMPT_LIMIT` | 8 operation records |

Expired operation records are pruned on admission. Their timestamp-bound IDs remain refused after pruning, including IDs whose first send was issued. Arbitrary old opaque UUIDs must not be regenerated/replayed as new attempts.

One additional encrypted scalar admission deadline handles the full-capacity cancellation case. When a ninth valid unknown ID cannot get a tombstone, new-ID admission stays closed through that ID's complete validity period, even if an older slot expires meanwhile. Existing attempts still check/cancel normally. This is deliberately conservative: capacity rejection requires waiting for that bounded period before starting a new attempt. It prevents a rejected cancellation from silently becoming sendable after pruning. There is no per-step journal or new private file.

## Verification

- Final setup suite: `PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m pytest -q -p no:cacheprovider tests/test_harel_setup.py` -> **35 passed in 39.66s**.
- Before the final polling-expiry assertion, all four Harel component suites together passed **195 tests in 53.21s**. The final setup-only run above includes that last added case; the separate provider/protocol/review/UI run passed **161 tests in 14.04s**.
- Final lint: `.venv/bin/ruff check account_access/harel_setup.py tests/test_harel_setup.py` -> **All checks passed**. `uv` was absent from this tool PATH, so the existing repository virtualenv was used.
- Added synthetic coverage: cancellation and profile removal/replacement during a first FETCH; cancellation after SEARCH; cancel-before-start across managers; simultaneous managers; lost start response and uncertain send; reserved-before-send restart; terminal unknown checks; completion replay; cross-manager cancellation without code entry; age/skew boundaries; capacity with staggered expiry; pruned issued-ID replay; first-code expiry and blocked-response polling; rollback after source writes and after grant insertion.
- Existing successful setup still requests exactly two explicitly authorized emails, uses two fresh UID-bound message reads and publishes only status access. Existing account fingerprints remain unchanged. No real email delivery or installed/signed acceptance is claimed.

D24/D25 implementation is ready for the coordinator's integration/source qualification. Native D26 and signed delivery D23 remain owned by the coordinator.
