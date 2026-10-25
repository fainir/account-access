# Account Access Phone for Android

This companion pairs with the Mac/local Account Access service on private Wi-Fi. It observes notifications from the selected SMS app, discards nonmatching notifications locally, and forwards matching login messages to a scoped HTTPS endpoint. The computer checks the sender, recipient, message template, active login window, freshness, duplicates, and ambiguity before submitting a code. No notification history or login-code API is exposed to agents.

Android's notification-access permission grants broader access than the app's own filter. The companion does not request SMS inbox permissions, become the default SMS app, or upload a notification archive. Messages hidden by Android, the SMS app, a work profile, or notification settings cannot be retrieved this way. Codes approving payments or account changes must never be configured as login messages.

## Setup

1. Install the signed **development preview APK** from the release. It is not a Play Store distribution or a validated production phone release.
2. In Account Access on the computer, open **Verification methods**, select the configured Android source, and click **Pair Android phone**.
3. Open the phone companion and scan that QR. Camera permission is requested for this scan. Paste pairing is also available.
4. Enable **login notification access** in the Android system screen. Both devices must stay on the same private Wi-Fi, and the SMS app must display the matching notification.

On Android 15 and newer, keep the updated Mac app's pairing screen open and turn
on Bluetooth on both devices. After scanning, choose **Connect computer with
Android** and confirm the matching discovered device in Android before enabling
notification access. The Mac advertises a fresh discovery UUID for five minutes,
or until you leave the pairing screen. The UUID contains no account or login data.
Messages still travel through certificate-pinned HTTPS on private Wi-Fi.

The app uses ordinary Bluetooth LE discovery, without privileged self-managed,
computer or watch roles. Android can redact login codes from ordinary notification
listeners. Revocation, replacement and disconnect stop forwarding. An old QR
without Bluetooth discovery information requires a new QR from the updated Mac
app. Devices without companion-device setup or supported Bluetooth discovery
cannot complete this connection. Positive Bluetooth pairing and physical-phone
delivery remain unqualified; the Android 15 emulator only checks that forwarding
stops without a confirmed association. The Android 11 emulator checks successful
notification-to-browser delivery.

References: [Android 15 notification protection](https://developer.android.com/about/versions/15/behavior-changes-all#otp-redaction)
and [ordinary companion-device pairing](https://developer.android.com/develop/connectivity/bluetooth/companion-device-pairing).

Pairing is encrypted using the Android Keystore. The phone pins the computer's TLS certificate and refuses public IP destinations, HTTP and redirects. Pairing rotation replaces the source's previous token. Closing/reopening the computer service preserves the certificate and endpoint while its Wi-Fi address remains unchanged; a changed address/certificate requires pairing again. Disconnect in the phone to remove its pairing, or disable the source in owner setup to reject further deliveries.

The development source retries the same fresh notification after temporary
socket, timeout or DNS failures. Each attempt checks that the pairing and login
message are still current. Certificate failures, server refusals and changed
pairing stop delivery; retries never switch destinations or extend freshness.
Physical-phone delivery and the updated APK still require release validation.

The preview currently uses the device's default SMS app. Some phones display a saved contact name instead of the sender number: the reviewed source must match the displayed sender. General authenticator push notifications are not supported by this companion.

## Build and verification

Requires JDK 17 and Android SDK platform/build tools 36. Override `ACCOUNT_ACCESS_JAVA_HOME` and `ANDROID_SDK_ROOT` on other machines.

```sh
sh android/build.sh
sh android/test/build.sh
```

The build downloads checksum-pinned [ZXing Core 3.5.3](https://github.com/zxing/zxing), licensed under Apache-2.0, for on-device QR decoding. No cloud scanning service is used. The APK uses a local development signing identity; replacing it with a production signing identity and validating physical phones are release work.

The APK bundles the upstream ZXing 3.5.3 license and notice text. Open **Open
source licenses** in the phone companion to read it without a network connection.

`scripts/android_journey.py` installs the app and instrumentation on a running emulator, exercises Keystore storage, posts an actual Android notification, and verifies HTTPS delivery plus a real browser verification form. Its identities, message and website are synthetic. The CI workflow runs this separately from the Python regression suite. The [Android emulator journey passed on 14 October 2026](https://github.com/fainir/account-access/actions/runs/38543728385). A passing emulator check does not establish carrier delivery or physical-device reliability.

After that journey passes, CI retains the exact preview APK and a JSON record of
its source revision, run, size and SHA-256 for seven days. These two files support
physical-phone acceptance of the tested binary. The signing keystore and test
instrumentation APK are excluded from the artifact. The preview uses a development
signing identity and is not an upgrade-stable production distribution.

## Publisher signing candidate

`scripts/build_android_release.py` builds with an existing publisher keystore
outside the checkout. It requires the independently recorded certificate
SHA-256, an explicit non-preview version, and either an initial-release choice
or the previous signed APK. Updates must use that exact certificate and a
higher version code. The tool never generates a replacement key, installs an
APK or uploads a release. The keystore must be a private, single-link file in a
private publisher directory; passwords are entered without echo in the local
terminal and passed only to the SDK signing process.

For an update, run this locally with your actual paths and public certificate
fingerprint:

```sh
python3 scripts/build_android_release.py \
  --keystore /private/publisher/phone.jks --alias phone \
  --certificate-sha256 YOUR_RECORDED_CERTIFICATE_SHA256 \
  --version-code 3 --version-name 0.6.0 \
  --previous-apk /private/publisher/previous-phone.apk \
  --output dist/android-publisher-candidate-3
```

Use `--initial-release` instead of `--previous-apk` for the first candidate.
The output includes `Account-Access-Phone.apk` and a credential-free review
record. The signed candidate is independently checked with `apksigner` and
`aapt2`; source files must match the current Git commit and remain unchanged
during the build. Development certificates are refused. The default preview
build and its signing key remain separate. Android will not accept a different
certificate as an update to an existing preview, and this tool never uninstalls
that preview or discards its pairing.

An explicit SDK-only CI fixture signs successive versions with a disposable
fixture key and checks wrong-certificate and downgrade refusals. That fixture
does not use a publisher key or install on a physical phone. Publisher-signed
distribution, physical installation, pairing preservation across a real update
and Android 15+ delivery still need acceptance.

References: [Android app signing](https://developer.android.com/studio/publish/app-signing)
and [the SDK signer](https://developer.android.com/tools/apksigner).

For iPhone on Mac, use the separate Messages reader after configuring text forwarding and granting the signed Account Access app Full Disk Access. An iPhone companion cannot be assumed to read arbitrary SMS inboxes.
