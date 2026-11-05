# Android publisher setup retry - 31 October 2026

The owner attempted the staged setup and reported “Setup stopped” or another
error. Read-back found no signed APK/release report and no new key in the staged
publisher directory. The private publisher parent exists; the setup is no longer
running. The exact original failure category was unavailable because the first
version exposed only a generic refusal. No Terminal contents or signing secret
were read, and no failed attempt was marked complete.

A separate clean-shell reproduction found a launcher defect:

```text
env -i HOME=/Users/nirfeinstein PATH=/usr/bin:/bin:/usr/sbin:/sbin /bin/zsh android/publisher-setup.command
android/publisher-setup.command:7: command not found: uv
exit 127 after Return
```

The launcher now finds the installed `uv` executable in its known Homebrew/local
locations without depending on shell startup configuration. This fixes the
reproduced defect; it does not establish that this was the owner's exact error.
For a first identity the alias is fixed to `phone`, removing an unnecessary
question. Explicit CREATE AND SIGN/SIGN confirmation is preserved, with harmless
surrounding whitespace normalized.

Failures now print a fixed, actionable phase. The single current diagnostic
`dist/android-publisher-setup-status.txt` contains only a known category; it never
records inputs, exception strings, passwords, key material or provider output.
Symlink/hardlink/public-file refusal occurs before truncation. No history or
per-step receipt is retained.

```text
uv run --no-sync pytest -q tests/test_android_publisher_setup.py tests/test_android_release.py
37 passed, 1 skipped in 1.57s
uv run --no-sync ruff check scripts/android_publisher_setup.py tests/test_android_publisher_setup.py
All checks passed!
zsh -n android/publisher-setup.command
exit 0
```

The actual corrected launcher was then run with the same minimal environment
in an interactive PTY. It reached the normal 1/2/Q menu, accepted Q and Return,
and exited zero. Read-back: `CURRENT cancelled`; no staged key, signed APK or
release report. That cancellation is the agent's deliberate launcher QA, not a
claim that the owner cancelled. Tests also exercise the first-release branch
without an alias prompt and ensure status logging does not follow external
links or retain arbitrary input.

Finder read-back confirms `publisher-setup.command` is still selected in the
Android folder. The owner must open the corrected local file and finish signing.
Native Terminal control remains unavailable; no attempt was made to bypass it.
Do not replace an existing or partly generated key to retry. Actual publisher
signing and physical-phone acceptance are not yet verified.
