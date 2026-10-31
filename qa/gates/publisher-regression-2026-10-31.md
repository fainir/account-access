# Publisher regression read-back - 31 October 2026

The [current-source application checks](https://github.com/fainir/account-access/actions/runs/41238775413)
completed successfully. The actual completed log reports:

```text
No known vulnerabilities found
All checks passed!
4638 passed, 113 skipped in 986.79s (0:16:26)
```

Native owner UI, updater and gateway jobs also completed successfully in that
run. [Separate-user acceptance](https://github.com/fainir/account-access/actions/runs/41238775374)
and [component review](https://github.com/fainir/account-access/actions/runs/41238775412)
are successful. The [corrected Android journeys](https://github.com/fainir/account-access/actions/runs/41238775371)
have both actual artifact reports read back in the
[offline/journey evidence](android-offline-build-2026-10-31.md).

The [Mac separate-user workflow](https://github.com/fainir/account-access/actions/runs/41238775359)
is still running at this check: its Installer-context job succeeded, and the
cross-user job is executing offline/fully prepared package-install acceptance.
Do not verify the aggregate publisher regression gate until this workflow's
actual completion has been read back. The existing 30-minute follow-up remains
active for that job; restore daily noon afterward for the dated macOS 14 wait.

Installed state was read through the normal public launcher: app build 122,
version 0.8.0, browser runtime READY, background recovery RUNNING, zero current or
total failures. The public example remains connected; private Namecheap remains
paused. No account operation, provider read or challenge resubmission occurred.
There was no installed-image change, so completed public read/export/repair
approvals were not requested or repeated.

The publisher release report is still absent. First-identity approval remains
pending; no new key, Keychain item, signed Android APK or physical install was
created. The existing owner question is unchanged and was not asked again.
