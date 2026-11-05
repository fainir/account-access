# macOS build 116 package QA - 2026-10-29

- Built the complete arm64 offline runtime package from the current build 116 app and current-source Developer ID-signed native helpers.
- The signed payload manifest records 25,167 files, 2,298 directories and 21 aliases. The runtime audit verified 49 native files and 34 hash-pinned wheels; publisher signatures passed.
- `pkgutil --check-signature` reported an Apple-issued Developer ID Installer signature with a trusted timestamp.
- Apple notarization returned Accepted. Finalization stapled the ticket and the local distribution/Gatekeeper check passed.
- Opened the finalized package in macOS Installer and advanced it to installation. The owner Mac is currently preparing the all-users installation; the app/service runtime acceptance is pending the native macOS authorization and successful completion.
- The package manifest reports about 2.08 GB of required free space while source and destination coexist. Installer's stock destination screen displays “no additional space” because `productbuild` zeroes the script-only payload estimate; the package's native volume check enforces the exact byte requirement before installation.

The artifact is `dist/notarization-package116-fresh-native/Account-Access-arm64-notarized.pkg`.
