# Direct build-118 candidate qualification - 2026-10-30

- Source revision: `f2f311b0b31d29806b89af17a17b11e2d47b40d9`; exact build-110 predecessor and build-118 target manifests are pinned.
- Package: 229,356,521 bytes; SHA-256 `aa17002026aa1bc937cd4dca720d5019710ed2b1dcd4fc664f6084e53b181cb6`.
- Developer ID Application helper signature and Developer ID Installer package signature pass. Apple notarization was accepted, the ticket was stapled and validated, and Gatekeeper accepted the package.
- Independent post-build rechecks also passed: `pkgutil --check-signature` reports Apple Developer ID distribution and trusted notarization, `stapler validate -v` succeeds, and `spctl --assess --type install --verbose` reports `accepted` from `Notarized Developer ID`.
- Independent expansion verified the exact package resource set, PackageInfo, the 387-node sparse target image (376 planned payload nodes plus 11 signed owner-app nodes) and the embedded app's strict signature.
- The helper refuses ordinary-user execution with the expected installer-context response. Installer was not run and the package is not installed; this evidence does not claim live restart or account acceptance.
- Full machine-readable report: [candidate review](direct-runtime-notarized-candidate-2026-10-30.json). The exact package was copied to `/Users/nirfeinstein/Downloads/Account-Access-Direct-Upgrade-118-signed.pkg`; its copied SHA-256 matches. Opening that file with macOS Installer returned successfully. The installed `/Applications/Account Access.app` still reports build 110, so build 118 has not been installed or live-tested. Computer-use access to the Installer window timed out; the owner can start it by double-clicking the package in Downloads.
