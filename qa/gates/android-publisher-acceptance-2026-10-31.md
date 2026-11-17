# Android publisher candidate acceptance - 31 October 2026

The owner explicitly selected “First release: create key and sign APK.” The
managed publishing CLI completed once with exit zero. One identity was created
for Nir Fainshtein and one local 0.8.0/version-code-2 APK was signed. No upload
was authorized or performed. The generated password was stored and read back
inside the child through native Mac Keychain; it was never returned to the
agent. The private identity directory is outside the checkout with mode 0700.
Do not repeat first-identity creation or replace this identity.

## Actual artifact read-back

- [Signed APK](../../dist/android-publisher-2/Account-Access-Phone.apk),
  303,601 bytes, package `com.fainir.accountaccess.phone`, version `0.8.0`/code `2`.
- Actual `apksigner verify --print-certs` exits zero; certificate subject is
  `CN=Nir Fainshtein`, SHA-256
  `8362118f0e3d3f9fed2733c12a6bedb9252eca35aee95897d46b76d0d258c4a6`.
  Its digest matches the exported public certificate and the signing report.
- APK SHA-256 independently matches the [release review](../../dist/android-publisher-2/release-review.json).
  Every recorded source input matches the current checkout. The artifact was
  built from commit `1e421bf6af33b08376ed1b06e864d63536e76d7d`; subsequent
  acceptance notes do not alter those source inputs.
- Actual `aapt2 dump badging`: min SDK 26, target SDK 36, expected launcher and
  notification listener, no direct SMS-read permission. The embedded upstream
  license matches its source byte for byte; the APK contains no keystore/key.
- Review reports `SIGNED_CANDIDATE`, `signing_key_created: true`,
  `password_custody: native-macos-keychain`, `uploaded: false`,
  `physical_phone_verified: false`, `production_ready: false`.

## Emulator acceptance - passed

The owner clarified that welcometothebestplace@gmail.com is their Play Store
account email and that no phone is connected; they asked to use an emulator.
It also remains the previously selected public support/privacy contact. No
Google sign-in, new account, Play upload or private SMS was used.

Environment: Android Emulator 37.2.13, API 35 AOSP ATD ARM64 revision 1,
750 × 1624 pixels at 320 dpi (375 dp width), fresh disposable 1 GiB ext4
userdata, two CPU cores, SwiftShader, no snapshots, camera or audio. The sole
ADB target was checked as an emulator and as this task's named AVD before
installation. Existing app/data would have stopped the fresh-install check.

Actual installed `base.apk` was read back and its SHA-256 matched the signed
candidate byte for byte. Android package-manager read-back reports code 2,
version 0.8.0, min SDK 26 and target SDK 36. `run-as` refuses with “package not
debuggable”; compiled manifest read-back has no debug/test-only flag, disallows
backup and cleartext traffic. First cold launch completed in 1,870 ms; this
single virtual-device observation is not physical performance qualification.

| Real UI check | Observed result |
|---|---|
| Fresh launch at 375 dp | Not paired; expected controls readable and reachable; [screenshot](../android-publisher-2026-10-31/fresh-375dp.png) inspected |
| Connect computer before pairing | Refused: scan the computer's QR first |
| Notification access before association | Refused: connect the paired computer with Android first |
| Invalid pasted pairing | Refused with QR recovery guidance |
| Valid synthetic pasted pairing | All 399 input characters read back before submitting; pairing saved and paste field cleared |
| Normal app restart after pairing | Saved pairing decrypted and retained; [paired screen](../android-publisher-2026-10-31/paired-375dp.png) |
| Empty manual code | Specific six-digit input guidance; no delivery |
| Synthetic six-digit manual code | Owned input is masked; keyboard Tab/Enter submits and clears it; Android computer-association refusal displayed; [screenshot](../android-publisher-2026-10-31/permission-refusal-375dp.png) inspected |
| Restart after manual attempt | Manual input empty; no code retained in the UI |
| Open source licenses | Real dialog displays bundled ZXing 3.5.3 and Apache notices; Close works; [screenshot](../android-publisher-2026-10-31/licenses-375dp.png) inspected |
| Disconnect and restart | Not paired immediately and after a normal restart |
| Crash check after all UI actions | Android crash buffer empty |

The synthetic pairing used a fake token/fingerprint, emulator-only source and
private test endpoint. No matching computer association was created. The
expected refusal is not a successful carrier/SMS delivery or a private login.
No development-key instrumentation was attached to the publisher-signed app;
the production signing password/key was not needed for emulator UI checks.

### Test setup corrections and replay

The local SDK initially contained build tools but no emulator/image/AVD. The
existing accepted SDK license covered restoring `emulator` and
`system-images;android-35;aosp_atd;arm64-v8a`. `avdmanager` created the new
`AccountAccess_Publisher35` device without replacing another AVD.

The emulator rewrote first-boot data size to 6 GiB and refused the available
space, even with `-partition-size`. A fresh explicitly sized 1 GiB ext4 data
image was created with the emulator's bundled `bin64/mkfs.ext4`; the AVD data
path/size and `-data` refer to it. No owner files or protected builds were
removed. [Upstream emulator initialization](https://android.googlesource.com/platform/external/qemu/+/emu-master-dev/android-qemu2-glue/main.cpp)
explains first-boot allocation and existing data-image handling.

ATD disables drawing by default. The first black capture was rejected;
`debug.hwui.drawing_enabled=true` and a normal app restart enabled actual
rendering, and the final screenshots were inspected. ATD removes ordinary
Settings, messaging and other phone apps, so these checks cover this app's own
UI only. [Android ATD documentation](https://developer.android.com/studio/test/managed-devices)
describes these test-device limits.

A single long `adb input text` call dropped characters in the synthetic pairing
payload. It was not accepted as a product defect or a valid pairing attempt.
Typing in 16-character chunks and reading the masked length back as 399 before
submission completed the actual flow. Page Up/Down and Tab/Enter were used to
inspect offscreen status and submit the focused manual-code form; missed touch
events were not counted as product results.

Existing hosted API 30/35 journeys passed independently on the same app source:
API 30 completes two synthetic browser SMS verifications; API 35 refuses
notification and manual codes without ordinary computer association. See the
[current-source CI read-back](android-offline-build-2026-10-31.md).

Positive Bluetooth association, physical carrier delivery, private MFA,
physical-phone performance, public Play distribution and final publisher/legal
approval remain unqualified. The signing report describes the completed build
operation, so its `installed: false` is unchanged; the later emulator
installation is evidenced above. No upload occurred. The final APK, build
report and private identity were added to this Mac's disk-cleanup keep list.
