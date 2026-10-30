# Direct build-119 candidate qualification - 2026-10-30

- Source revision: `4ad561ca3318a5b06581de76e8f1877f10bf53bb`; target app source: `d5f7c074a4cc1df48b743bf109cf6d99986a2ca5`; exact build-110 predecessor is required.
- Package: 229,356,204 bytes; SHA-256 `e1c51ca16e7fef40b8c33806c96d126b09cb816d23f1e4ae51e891ba94945edf`.
- Developer ID Installer signature verified; Apple notarization was accepted; the ticket was stapled and validated; Gatekeeper accepted the package as `Notarized Developer ID`.
- Independent package expansion verified all eight resources, the PackageInfo, 387 target-image nodes including the complete signed owner app, and the owner app's strict Developer ID signature.
- The signed updater helper has a Developer ID Application signature and refuses ordinary-user execution with the expected installer-context response. The 184-unit delta covers 216 changed nodes and preserves the exact build-110 predecessor contract.
- The package was copied to `/Users/nirfeinstein/Downloads/Account-Access-Direct-Upgrade-119-signed.pkg`; its SHA-256 matches the qualified package. `pkgutil --check-signature`, `stapler validate`, and `spctl --assess --type install` all passed on the downloaded copy.
- **Not installed:** `/Applications/Account Access.app` remains build 110; no build-119 receipt exists. The package has not been run, so protected-service restart and fresh-agent acceptance remain open. Machine report: [candidate review](direct-runtime-notarized-candidate-2026-10-30-build119.json).
