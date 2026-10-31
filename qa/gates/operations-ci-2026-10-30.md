# Operations CI snapshot - 2026-10-30

Source revision under review: `f2f311b0b31d29806b89af17a17b11e2d47b40d9`.

- [Separate-user worker acceptance](https://github.com/fainir/account-access/actions/runs/40965909604) passed.
- [Android login-code journey](https://github.com/fainir/account-access/actions/runs/40965909845) passed both Android 11 login and Android 15 refusal journeys on retry.
- [Account Access checks](https://github.com/fainir/account-access/actions/runs/40965909681) has passed the native owner gateway, UI and upgrade jobs; its full Python test/build job was still running at capture time.
- [Mac separate-user worker acceptance](https://github.com/fainir/account-access/actions/runs/40965909613) failed its standalone component updater compile: `ComponentUpdate.swift` referenced `PublicTreeIO`, which is not among that builder's sources. The call now uses `InstallerPayloadIO.noACL`, which is an existing dependency of the helper. Local validation passed (`swiftc -parse`, `git diff --check`, and 143 focused component-update builder tests); a fresh Mac CI run on the fix is pending.

This snapshot does not qualify the Ops gate. The full checks and fresh Mac workflow must finish green, and release procedure and rollback still need acceptance. The Android 15 retry is green; physical-phone pairing remains an owner check.
