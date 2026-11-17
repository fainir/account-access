# Android offline dependency and manual-field journey - 31 October 2026

The [Android push run](https://github.com/fainir/account-access/actions/runs/41236755533)
failed before compilation because Maven Central returned HTTP 429 for ZXing
3.5.3, including both curl retries. The unchanged, previously verified JAR is now
stored in `android/vendor/` with its original SHA-256 and Apache-2.0 notice. The
build checks those bytes and copies them locally; it makes no QR-library network
request. The release builder includes this artifact in its checked source inputs.

```text
uv run --no-sync pytest -q tests/test_android_offline_dependency.py tests/test_android_keychain_publisher.py tests/test_android_publisher_setup.py tests/test_android_release.py
50 passed, 1 skipped in 2.75s
Ruff on changed Python files: All checks passed!
```

The offline cases run the actual build script with a failing fake curl, verify
that valid pinned bytes reach Java without a network call, and require modified
or linked dependency bytes to refuse before compilation.

A real JDK/Android SDK unsigned build then completed using a generated 0.8.0
release manifest and `ACCOUNT_ACCESS_ANDROID_UNSIGNED_ONLY=1`. Output:
`dist/android-offline-080/build/aligned.apk`; build log:
`dist/android-offline-080/build.log`. SDK read-back reports package
`com.fainir.accountaccess.phone`, version code `2`, version name `0.8.0`, minimum
SDK 26 and target SDK 36. The bundled license asset exactly matches the source.
This is an unsigned compiled candidate, not a publisher-signed release. No
publisher identity, Keychain item, upload or physical installation occurred.

A separate [PR emulator run](https://github.com/fainir/account-access/actions/runs/41236761152)
compiled successfully but could not find the masked manual-code input on API
35. GitHub read-back confirmed its app and instrumentation sources matched the
branch. The failure did not include a window snapshot, so its exact window state
cannot be established.

The instrumentation now brings the app forward, searches only its own window
and package, and can identify its sole masked numeric input when Android omits
password-node labels. It still requires EditText/password semantics and uses the
real input and button actions. It never searches a system PIN field, reads code
values or scrolls an unrelated window. A bounded ten-second search and a fixed
owned-window boolean provide safe failure diagnostics. Pairing/notification
authority and production app code are unchanged. Local JDK compilation of all
instrumentation sources against the actual 0.8 app classes and SDK 36 exits zero.

Completed [hosted journey](https://github.com/fainir/account-access/actions/runs/41238775371)
now passes both API 30 and API 35 on the corrected source. Read-back found exactly
two preview artifacts and read both actual journey reports from their ZIPs
without extracting the APKs:

- API 30: status `COMPLETED`, two browser SMS verifications, notification and
  owner-entered UI paths both pass, with no code in the agent result.
- API 35: status `BLOCKED_AS_EXPECTED`, zero browser verifications, manual and
  notification codes refused without association, no manual-code persistence,
  and unrelated notifications preserve the blocked status.
- Both reports explicitly leave positive Bluetooth pairing and physical-phone
  delivery unqualified. Their package remains development-signed.

This verifies the emulator locator correction and source build, not a
publisher-signed physical deployment. Publisher signing awaits the named
first-identity approval; real private MFA/physical pairing remain owner actions.
