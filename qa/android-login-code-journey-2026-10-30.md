# Android login-code journey - 2026-10-30

- Source revision: `49456cc26e7874419f6be7ba8a6a6e1acedd8353`.
- [Hosted Android login-code workflow](https://github.com/fainir/account-access/actions/runs/40969929620) completed successfully.
- The Android 11 job, `Android 11 automatic and owner-entered SMS login`, passed its synthetic automatic-code and owner-entered-code login journeys. The workflow built and retained the tested APK.
- The Android 15 job, `Android 15 manual and notification refusal without computer permission`, passed the refusal journey for both notification-forwarded and manually entered codes without an authorized computer association.
- This verifies the hosted emulator journeys and the test-viewport fix on the pushed revision. It does not verify physical-phone pairing or delivery of a real insurer SMS; those remain owner acceptance under F4.
