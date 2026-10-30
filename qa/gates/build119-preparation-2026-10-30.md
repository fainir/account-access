# Build 119 preparation QA - 2026-10-30

- Target application source: `d5f7c074a4cc1df48b743bf109cf6d99986a2ca5`; the agent skill-upgrade fix is in `3dae82f`.
- Full source regression: `uv run --no-sync pytest -q` -> 4,586 passed, 5 skipped in 18m 33s.
- Release target-image builder regression: `uv run --no-sync pytest -q tests/test_direct_runtime_target_image.py tests/test_direct_runtime_upgrade_plan.py` -> 18 passed.
- Release builder lint and compilation passed: Ruff and `py_compile`.
- Build 119 app bundle is Developer ID signed; `codesign --verify --deep --strict --all-architectures` passed. Its embedded account-access wheel SHA-256 is `d378c9d246c3325dabb5e4b5e5ea947e7d0d536ccde56083947a0765878274e6`.
- Standalone app Gatekeeper assessment reports `Unnotarized Developer ID`; this is expected before packaging. No installer package has been built or installed from build 119 yet.
- Installed `/Applications/Account Access.app` is still build 110, and no system-package receipt exists.
- Android hosted journey run 40978030874 passed both Android 11 and Android 15 jobs. The initial Android 15 retry failed because SDK manager could not unpack a corrupted system-image archive; the single-job rerun passed through install and refusal checks.
