# Build 119 release package availability - 2026-10-30

- The earlier qualified build-119 package was missing from its temporary path and Downloads. Its prior handoff was stale; it was not installed.
- Recovered the exact pinned build-118 public image, rebuilt and requalified build 119, re-derived the pinned updater plan, and ran the durable package publisher.
- Final path: `/Users/nirfeinstein/Downloads/Account-Access-Direct-Upgrade-119-signed.pkg` (229,356,259 bytes; SHA-256 `a78dc42ce52d1fdf537ae87127ce2eb424cdad1d8cd92071146dc86e485f79ec`).
- The published file independently passes Developer ID Installer signature and trusted notarization, stapler validation, and Gatekeeper install assessment. The candidate builder also independently expanded the signed package and verified its resources and owner-app signature. Evidence: [recovered candidate QA](direct-runtime-notarized-candidate-2026-10-30-build119.md) and [machine report](direct-runtime-notarized-candidate-2026-10-30-build119-recovered.json).
- `--publish-to` durable publication remains protected by 16 tests covering atomic copy, overwrite refusal, digest mismatch cleanup and symlink-parent refusal; Ruff and Python compilation passed.
- **Not installed:** owner installation and installed-service/agent acceptance remain open under F1. The previous build-117 package is not the requested update.
