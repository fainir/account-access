# Current Account Access agent smoke - 2026-10-29

- The live Account Access window reports **Ready in every new session / Automatic**.
- The installed Account Access launcher reports `controlled-demo`, service 0.6.0, and three synthetic accounts with approved summary operations.
- Its single `demo-web summary` smoke returned `RETRYABLE / browser_execution_failed`. The result contained no account data. The Account Access skill allows at most one retry during a turn, so this read was not repeated.
- Current-source synthetic browser-session and connected-setup UI QA: `47 passed in 57.15s` (`tests/test_connected_setup_ui.py` and `tests/test_browser_sessions.py`).

The app's readiness indicator is not proof that an approved browser read succeeds. No personal account, password, cookie, or verification code was accessed.

## Resumed live smoke - 2026-10-29

The installed launcher again reported `controlled-demo`, service 0.6.0 and three synthetic accounts. The only permitted `demo-web summary` operation returned `RETRYABLE / browser_execution_failed` on both allowed attempts in the resumed run. No account data was returned, and no personal account, password, cookie or verification code was accessed.
