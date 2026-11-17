# Performance qualification - 2026-10-29

## Scope

Account Access ships native macOS and Android apps; there is no production website, so Lighthouse scoring is not applicable. This checks the Android companion package and process cold-start behavior on the available API 35 virtual device.

## Evidence

- Built with `ACCOUNT_ACCESS_ANDROID_OUTPUT=/tmp/account-access-perf-20261029 sh android/build.sh` using the repository's checksum-pinned ZXing dependency and JDK 17.
- APK package: **303,605 bytes**; install succeeded on the API 35 AVD at **1080 x 2400 / 420 dpi**.
- Activity cold-launch smoke: `adb shell am start -W -n com.fainir.accountaccess.phone/com.fainir.accountaccess.MainActivity`, force-stopping the package between launches. Eight complete observations were **1,129; 1,762; 1,957; 2,170; 2,295; 2,566; 3,586; 6,389 ms**. Median: **2,233 ms**; max: **6,389 ms**.
- The emulator was saturated during this sample: Android reported 76% total guest CPU, 10% I/O wait, and active swap/reclaim. The result is too noisy to accept as a representative phone startup measurement or a reliable regression baseline.
- Source inspection shows the first screen builds a small native view locally, makes no network request, reads local preferences and only decrypts a pairing when one exists. No blocking network or large data load was found to fix from this sample.

## Result and limit

The APK is small, but the cold-launch target is **not verified**. A physical Android 15+ measurement using the owner’s installed release candidate is needed to establish the actual phone experience. The app does not have an applicable Lighthouse score. This gate remains `owner` in `READINESS.md`; do not treat emulator timing as a pass.
