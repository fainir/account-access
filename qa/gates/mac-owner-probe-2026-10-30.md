# Mac owner probe - 2026-10-30

- Command: `uv run python scripts/mac_full_image_installed_probe.py --output /private/tmp/account-access-full-image-installed-probe-20261030-continue`
- Result: **PASSED** on the local Mac; one combined native compile and all frozen fixture/refusal checks completed.
- Scope: ordinary-user temporary fixtures only. The probe reported `installed_reads: false` and `production_ready: false`; it did not install or invoke a provider.
- The pinned `ComponentUpdate.swift` digest and composed-source digest now match the reviewed source. Unit contract tests: `uv run --no-sync pytest -q tests/test_mac_full_image_installed_probe.py` - **34 passed**.
