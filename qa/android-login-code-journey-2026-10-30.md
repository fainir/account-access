# Android login-code journey - 2026-10-30

- Source revision: `d5f7c074a4cc1df48b743bf109cf6d99986a2ca5`.
- [Hosted Android login-code workflow](https://github.com/fainir/account-access/actions/runs/40978030874) completed successfully after rerunning only its failed Android 15 job.
- The Android 11 job, `Android 11 automatic and owner-entered SMS login`, passed its synthetic automatic-code and owner-entered-code login journeys. The workflow built and retained the tested APK.
- The Android 15 job, `Android 15 manual and notification refusal without computer permission`, passed the refusal journey for both notification-forwarded and manually entered codes without an authorized computer association.
- The first Android 15 job attempt could not unpack a corrupted downloaded system-image archive; the single-job rerun installed the image and passed the refusal journey. This verifies the hosted emulator journeys and test-viewport fix on the pushed revision. It does not verify physical-phone pairing or delivery of a real insurer SMS; those remain owner acceptance under F4.
