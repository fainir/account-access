# Build 117 direct updater qualification

- Candidate: `Account-Access-Direct-Upgrade-117-signed.pkg`
- State: signed, notarized, stapled and independently verified; not installed
- SHA-256: `39fe445f38953025ffa1b901cf011d29ee6ecf1211b21f38ac84d67580f763bf`
- Size: 229,133,503 bytes
- Apple notarization: Accepted (`46c3fc9a-50e2-462f-8218-970ddb38ee76`)
- Installer identity: Developer ID Installer, notarization trusted
- Gatekeeper: accepted as a notarized Developer ID installer
- Staple: `stapler validate` passed
- App identity: the full embedded `owner.app` passed strict Developer ID signature verification after independent package expansion
- Payload: exact equality with the pinned updater inventory; 289 planned nodes plus the complete 21-node signed app bundle produce 300 packaged nodes (492,884,849 bytes of files)
- Resource layout: `pkgutil --expand-full` yields a `Scripts/` directory; exact eight resource names and node types verified
- Scope: build 110 to build 116, 207 changed nodes, 191 update units; ordinary-user helper refusal verified
- Tests: direct-updater planner 11 passed; Ruff, Python compilation and `git diff --check` passed. Native direct source, runtime (72 checks) and shared installed-adapter probes are linked in [direct updater QA](direct-runtime-update-2026-10-29/summary.log).
- Build revision: `ccc288f53d09661ea4b1f3ec6efdcc0334244b90`
- Package record: `/private/tmp/account-access-direct117-candidate/review.json`

The first independent-package check failed because the verifier treated the expanded `Scripts/` directory as an archive. The verifier now checks the expanded directory directly, rejects symlinks and unexpected entries, and the exact signed candidate passes that corrected check. No Installer process was launched during qualification.
