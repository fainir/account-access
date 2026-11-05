# Full system-package build timeout

- The build-116 inspection passed with the pinned Python tree, current wheels, reviewed Bitwarden source archive and freshly signed native helpers.
- A full package attempt was terminated by the package builder's 600-second `pkgbuild` subprocess limit while Apple was still traversing the 25,167-file offline payload. No installer was produced.
- The limit now applies only to the full script payload and is 1,800 seconds; unrelated package commands retain their 600-second limit.
- `uv run pytest -q tests/test_system_package.py` - **45 passed in 130.60s**, including `test_full_payload_pkgbuild_has_a_bounded_archive_timeout`.
- Fresh complete package assembly is being retried with the current-source helpers.
