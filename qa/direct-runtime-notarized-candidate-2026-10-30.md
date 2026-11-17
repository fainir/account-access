# Direct build-118 candidate qualification - 2026-10-30

- Source revision: `f2f311b0b31d29806b89af17a17b11e2d47b40d9`; exact build-110 predecessor and build-118 target manifests are pinned.
- Package: 229,356,521 bytes; SHA-256 `aa17002026aa1bc937cd4dca720d5019710ed2b1dcd4fc664f6084e53b181cb6`.
- Developer ID Application helper signature and Developer ID Installer package signature pass. Apple notarization was accepted, the ticket was stapled and validated, and Gatekeeper accepted the package.
- Independent post-build rechecks also passed: `pkgutil --check-signature` reports Apple Developer ID distribution and trusted notarization, `stapler validate -v` succeeds, and `spctl --assess --type install --verbose` reports `accepted` from `Notarized Developer ID`.
- Independent expansion verified the exact package resource set, PackageInfo, the 387-node sparse target image (376 planned payload nodes plus 11 signed owner-app nodes) and the embedded app's strict signature.
- The helper refuses ordinary-user execution with the expected installer-context response. Installer was opened but **Install was not run**; build 118 is not installed. This evidence does not claim live restart or account acceptance.
- Full machine-readable report: [candidate review](direct-runtime-notarized-candidate-2026-10-30.json). The exact package was copied to `/Users/nirfeinstein/Downloads/Account-Access-Direct-Upgrade-118-signed.pkg`; its copied SHA-256 matches. The installed `/Applications/Account Access.app` still reports build 110, so build 118 has not been installed or live-tested. See [sanitized Installer history](gates/installer-history-2026-10-30.md) for the causes of the earlier generic failure screens and current install precondition.
