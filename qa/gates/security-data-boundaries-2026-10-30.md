# Security and data boundary verification - 2026-10-30

- Focused endpoint, capability, principal isolation, worker, saved-account and owner-review suite: **92 passed in 47.96s**.
- The API exposes six private routes. Regression checks verify all routes reject missing bearer capabilities, malformed credentials refuse safely, task reads remain principal-scoped, invalid authentication is throttled with `Retry-After`, and the limiter recovers after its window. Strict request models reject extra identity, URL and password fields; middleware rejects browser origins/cookies and bodies over 64 KiB. Error responses and tests do not echo supplied secret values.
- `uv run --no-sync ruff check account_access/service.py account_access/storage.py tests/test_security.py` and `uv run --no-sync python -m compileall -q account_access`: passed.
- `uv run --no-sync pip-audit -r account_access/runtime-requirements.txt`: **No known vulnerabilities found**.
- The current source-current build-118 public image includes the Account Access Python package and signed owner app; native payload signature audit and manifest preflight pass ([image qualification](../direct-runtime-target-image-2026-10-30.json)). The image has not been installed. Installer, restart and installed-service acceptance remain under F1.
- Current-source scan has no secret findings; the separately reviewed historical Gitleaks findings were all literal `REDACTED` markers ([history triage](gitleaks-history-triage-2026-10-29.md)).
- **Gate: verified for source controls, dependency set and qualified runtime image.** Installed acceptance remains tracked by F1 and Ops.
- Re-run from the active continuation worktree: the same six-file focused boundary suite passed again, **92 passed in 47.01s**.
- Requalified after the native updater fix on source commit `f580dc4`: the same suite passed, **92 passed in 46.79s**; Ruff, Python compilation and the pinned runtime dependency audit also passed, with no known vulnerabilities.
- Revalidated the current continuation revision `29f72e1`: **92 passed in 47.11s**; Ruff, Python compilation and the pinned runtime dependency audit passed, with no known vulnerabilities.
