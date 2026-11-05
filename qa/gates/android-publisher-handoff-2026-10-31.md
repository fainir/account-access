# Android publisher handoff - 31 October 2026

The physical USB inventory reports exactly one authorized target: API 37,
non-emulator, with companion-device setup and Bluetooth LE. Account Access Phone
is not installed. Only those capability/package facts were read; no phone
messages, notification content, identifiers or user files are stored here.

The [owner-present setup](../../scripts/android_publisher_setup.py), opened using
[`publisher-setup.command`](../../android/publisher-setup.command), stages one
0.8.0/version-code-2 APK under `dist/android-publisher-2`. It does not install or
upload anything. Existing publisher identities require their independently
recorded certificate; new identity creation requires an exact local owner
confirmation and refuses any existing destination. Passwords stay in the native
keytool/signer prompts. A partial identity is retained for review, never silently
replaced. The wrapper creates no password argument, pipe or transcript.

Verification:

```text
uv run --no-sync pytest -q tests/test_android_publisher_setup.py tests/test_android_release.py
34 passed, 1 skipped in 1.63s
uv run --no-sync ruff check scripts/android_publisher_setup.py tests/test_android_publisher_setup.py
All checks passed!
zsh -n android/publisher-setup.command
exit 0
```

The new tests include an actual JDK keytool run with a disposable fixture key,
export/re-export fingerprint equality, private file permissions, no replacement,
invalid/unattended refusal before prompting, and preservation after a partial
failure. No publisher identity was generated. The skipped test is the older,
explicitly enabled full Android SDK signing/update fixture; its existing hosted
qualification remains separate.

The actual CLI ran in an interactive PTY, displayed the existing-key/new-first-
identity/cancel choices, and exited successfully on `Q`. Read-back found both the
publisher key directory and APK output absent. No signing password was entered.

Native computer-use control refused the Terminal app for safety. No alternate
tool was used to control that app. Finder was opened normally to the repository's
Android folder, and a single click selected `publisher-setup.command`; the file
was not executed. The owner can open it locally. Version, output and publisher
name are filled; the owner chooses or creates the identity and enters passwords
only in their own Terminal.

Next: once `dist/android-publisher-2/release-review.json` reports a signed
candidate, independently read back APK package/version/certificate and the
report, then proceed to normal physical installation. Do not run the emulator
journey or its uninstall helpers against the physical phone. Pairing QR scanning,
Android permission approval and real matching SMS remain owner-presence actions.
No QR, token or code may be read into agent output.

Keytool's native password prompt and public-certificate export follow
[Oracle's keytool documentation](https://docs.oracle.com/en/java/javase/12/tools/keytool.html).
This handoff does not change the Android app image or the signed Mac packages.

The implementation is pushed. Its [application/native CI](https://github.com/fainir/account-access/actions/runs/41233999568),
[Mac worker CI](https://github.com/fainir/account-access/actions/runs/41233999585)
and [Android journey](https://github.com/fainir/account-access/actions/runs/41233999572)
were dispatched. Completed read-back now reports Android success, along with the
separate-user and component-review checks. Application/native and Mac-worker
checks remain in progress; do not infer their pass from dispatch. The existing follow-up is
temporarily active every 30 minutes with the same prompt to read their actual
results and any completed publisher report, then restore its daily noon cadence
for the unchanged macOS 14 wait. No new automation was created.
