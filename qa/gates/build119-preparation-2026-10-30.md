# Build 119 preparation QA - 2026-10-30

- Target application source: `d5f7c074a4cc1df48b743bf109cf6d99986a2ca5`; the agent skill-upgrade fix is in `3dae82f`.
- Full source regression: `uv run --no-sync pytest -q` -> 4,586 passed, 5 skipped in 18m 33s.
- Focused updater regression: `uv run --no-sync pytest -q tests/test_direct_runtime_target_image.py tests/test_direct_runtime_upgrade_plan.py tests/test_mac_full_image_installed_probe.py` -> 52 passed.
- Release builder and pinned probe lint/compilation passed: Ruff and `py_compile`.
- Build 119 app bundle is Developer ID signed; `codesign --verify --deep --strict --all-architectures` passed. Its embedded account-access wheel SHA-256 is `d378c9d246c3325dabb5e4b5e5ea947e7d0d536ccde56083947a0765878274e6`.
- The release app was rebuilt with `ACCOUNT_ACCESS_SYSTEM_INSTALL=1`; its required install marker is present and the strict universal signature check passed.
- The build-119 public image qualified from build 118: base manifest SHA-256 `bb14a99941c7a82938cd0e9b3f91a16ab975e6cdd61a30741d29726a7f7bed38`, target manifest SHA-256 `630e77605faac2dfdace9faaa5da55e671335c6b18e62114d7f0224a8574f24c`. Publisher signatures for all 49 native files passed; image audit reported 34 wheels and one signed app bundle.
- Native updater probes passed: shared installed-adapter refusal checks, 72 generic runtime checks, and the pinned 184-unit direct delta covering 216 changed nodes. Evidence: [build-119 native reports](../direct-runtime-update-2026-10-30-build119/) and [target qualification](../direct-runtime-target-image-2026-10-30-build119.json).
- Standalone app Gatekeeper assessment reports `Unnotarized Developer ID`; this is expected before packaging. No installer package has been built or installed from build 119 yet.
- Installed `/Applications/Account Access.app` is still build 110, and no system-package receipt exists.
- Android hosted journey run 40978030874 passed both Android 11 and Android 15 jobs. The initial Android 15 retry failed because SDK manager could not unpack a corrupted system-image archive; the single-job rerun passed through install and refusal checks.
