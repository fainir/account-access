# Android login-code journey - 2026-10-30

- Source revision: `4ad561ca3318a5b06581de76e8f1877f10bf53bb`.
- [Hosted Android login-code workflow](https://github.com/fainir/account-access/actions/runs/40980629809) completed successfully for both Android 11 and Android 15.
- The Android 11 job, `Android 11 automatic and owner-entered SMS login`, passed its synthetic automatic-code and owner-entered-code login journeys. The workflow built and retained the tested APK.
- The Android 15 job, `Android 15 manual and notification refusal without computer permission`, passed the refusal journey for both notification-forwarded and manually entered codes without an authorized computer association.
- This verifies the hosted emulator journeys and test-viewport fix on the pushed revision. An earlier run encountered a corrupted Android SDK image download and passed on a single-job retry; this run passed both jobs. It does not verify physical-phone pairing or delivery of a real SMS from a supported live site; those remain owner acceptance under F4.
