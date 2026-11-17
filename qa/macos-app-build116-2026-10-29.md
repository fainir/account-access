# Mac owner app build 116

- Built from the current wheel as an Apple-silicon system-installation candidate.
- `codesign --verify --deep --strict` passed for `Account Access.app`.
- Bundle metadata reports version `0.8.0`, build `116`, and `AccountAccessSystemInstallationRequired=true`.
- The embedded `account_access.whl` digest matches the exact wheel supplied to the build.
- This is build/signature evidence only; complete package installation and owner UI acceptance are still open.
