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
completed successfully at 22:51:54 Asia/Jerusalem. Both jobs report success:
Installer context and cross-user acceptance. Actual artifact read-back found:

| Artifact | Actual completed results |
|---|---|
| `mac-installer-context` | Three JSON reports: installed image VERIFIED, eight native source-handoff checks PASSED, actual Installer sandbox report PASSED. |
| `mac-component-update-native` | Five JSON reports, including 60 core and eight policy checks PASSED, ordinary main/revalidation results and the aggregate PASSED report. |
| `mac-worker-boundary-acceptance` | Eighteen reports, all PASSED; 426 reported checks cover distinct user identities, authorization/key boundaries, native messaging/browser integration, provisioning and both package modes. |

The offline package report records `actual_installer_used: true` with sixteen
checks. The prepared package records twenty-three checks and
`prepared_runtime_executed: true`. Both are controlled development fixtures;
`publisher_signed_package`, `positive_consumer_install_verified` and
`production_ready` remain false, and `private_signins` is zero. This verifies
current-source regression acceptance, not a new consumer release or private MFA.
The previously qualified publisher-signed build-122 packages remain separate.

The publisher regression gate is now verified. The existing follow-up was
restored through the automation tool to ACTIVE daily noon, with its original
prompt and chat target unchanged. Actual saved cadence was read back as
`FREQ=DAILY;BYHOUR=12;BYMINUTE=0`. Its remaining purpose is the dated macOS 14
compatibility check on 1 November; it must not repeat the pending signing ask.

Installed state was read through the normal public launcher: app build 122,
version 0.8.0, browser runtime READY, background recovery RUNNING, zero current or
total failures. The public example remains connected; private Namecheap remains
paused. No account operation, provider read or challenge resubmission occurred.
There was no installed-image change, so completed public read/export/repair
approvals were not requested or repeated.

The publisher release report is still absent. First-identity approval remains
pending; no new key, Keychain item, signed Android APK or physical install was
created. The existing owner question is unchanged and was not asked again.
