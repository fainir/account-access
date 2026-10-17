# Preview validation history

These results describe specific earlier revisions. Their test counts and
installation claims are historical. See [current production gates](production-gates.md)
and [validation](validation.md) for the development candidate.


Version 0.7.4 exposes those redacted navigation diagnostics in the authenticated owner app. A stopped account gets a plain-language explanation and an optional technical-details action. Only the fixed diagnostic format is returned; arbitrary audit text is excluded, and service diagnostics remain outside agent audit responses.

For 0.7.4, **93 Python tests**, native macOS UI checks and the Android emulator journey passed in CI. The signed update was installed through the graphical updater, and the actual owner diagnostic screen and detail dialog were checked. Both installed agent CLIs preserved an existing blocked private task using ordinary requests. A private provider redirect remained outside the reviewed flow; private sign-in and live mailbox/physical-phone delivery are still unvalidated. See the [sanitized installation and test evidence](../artifacts/reinstall-074.json).

Version 0.7.3 adds bounded navigation-failure diagnostics for troubleshooting. The audit identifies a transport/HTTP failure or a blocked redirect and whether it matches an already configured resource path. It records a numeric resource index and query-presence flag, with no raw URL, query value, page text, headers, cookies or credentials. The destination allowlist remains enforced.

Version 0.7.2 keeps the import result visible when a website check fails instead of silently returning to an empty connection form. It refreshes the account state after verification, distinguishes a saved password from a verified connection, and adds an owner-only visible sign-in check. Normal agent reads remain headless, and the same destination and credential-entry protections apply in the visible check.

Version 0.7.1 fixes an AppKit constraint-order error that hid the new password-sync fields. A native regression check constructs the actual owner screen, verifies all four fields and the masked token control, and checks the minimum window size. The Python authentication and sync implementation is unchanged from 0.7.

The published 0.7.1 update was installed through the graphical updater and checked on the local Mac. Existing client identity, grants and configuration were preserved, the signed package pin matched, and the four password-sync fields were visible. Native macOS, Python and Android emulator CI passed. Claude Code and Codex each completed the three approved public-account reads from an ordinary request with no Account Access command in the prompt. Codex's configured default model was rejected before invoking Account Access; the isolated compatibility run used `gpt-6-astra` without changing saved settings. See the [installation evidence](../artifacts/reinstall-071.json), [Claude Code evidence](../artifacts/agent-tests/claude-implicit-071.json), [Codex evidence](../artifacts/agent-tests/codex-implicit-071.json) and [default-model failure](../artifacts/agent-tests/codex-implicit-071-default.json). These checks do not validate private-account access or physical phone delivery.

Version 0.7 checks on 15 October 2026: **91 Python tests passed**, including automatic password rotation with unchanged grants, blocked identity/destination changes, active code-window enforcement, safe file replacement and the four-factor controlled journey. Five external public-demo reads, their negative cases and session recovery also passed. Lint, the third-party dependency audit, package builds, strict verification of the signed universal Mac app and the revised video decode passed. Private-account enrollment, live Gmail/phone delivery and protection from unrestricted same-user processes remain unvalidated. See [0.7 evidence](../artifacts/security-07.json), [public-site evidence](../artifacts/public-demos-07.json) and [security/sync limits](security-and-password-sync.md).

Version 0.6 validation on 14 October 2026: **75 Python tests passed** locally, with lint, dependency auditing and package building also covered by the [Linux CI workflow](https://github.com/fainir/account-access/actions/workflows/check.yml). Fresh ordinary-language requests activated the integration automatically: Codex completed a saved three-account task, and Claude Code completed the three approved reads and saved a comparison file. See [Codex evidence](../artifacts/agent-tests/codex-implicit-06.json), [Claude evidence](../artifacts/agent-tests/claude-implicit-06.json) and [automatic startup evidence](../artifacts/automatic-start-06.json). The Codex test used an account-compatible model for that invocation; Claude's unrelated session-log hook encountered four permission denials after the account work succeeded. General host policies and hooks were retained. The [Android emulator journey](https://github.com/fainir/account-access/actions/runs/38543728385) passed separately. The [four-factor explainer recording](../artifacts/video/gmail-authenticator-sms.json) verifies a completed Claude task at 4/4 with one plain-language request and zero password or code inputs during the task.

Earlier experiments on 12 October 2026:

- **43 regression tests passed.**
- **90/90 controlled repeated reads** completed unattended after programmatic demo enrollment.
- **25/25 external public-demo reads** completed across SauceDemo, The Internet and Duende, including ten rotating OAuth refreshes.
- **Codex and Claude Code each completed a five-account task**, independently verified through the service.

These accelerated results do not establish thirty-day reliability or private financial-account coverage. See the [full validation report](validation.md) and [machine-readable evidence](../artifacts/).

For public distribution on 13 October 2026, a clean-checkout installation completed the three-account demo, and [Linux CI passed all 43 tests, lint, dependency auditing and package building](https://github.com/fainir/account-access/actions/runs/38374863318). See [publication verification](../artifacts/public-release.json).

```sh
uv run ruff check account_access tests scripts
uv run pytest -q
uv run pip-audit --local
uv run python scripts/benchmark.py
# Optional external network experiment with published demo identities only:
uv run python scripts/public_demos.py --runs 5
uv build
```

See [CONTRIBUTING.md](../CONTRIBUTING.md) to add reviewed connectors and tests.


## Guided setup validation (0.4.0)


On 13 October 2026, **50 distinct tests passed**: a 49-test regression run followed by 11 focused installation checks, including one added symlink-preservation case. The guided setup checks cover authenticated/CSRF-protected account connection, both agents' standing grants, shared session reuse, refusing unreviewed destinations, a launcher that needs no Python on PATH, and reopening/stopping the background app. The installer rejects modified downloads before executing them, and local app startup rejects an impostor on a reused port. Dependency auditing found no known vulnerabilities in the third-party packages. A live screen recording of the guided interface is still pending.
