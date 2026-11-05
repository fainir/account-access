# Signed Chrome runner check

- The cross-user workflow at [run 41068495925](https://github.com/fainir/account-access/actions/runs/41068495925) reached the signed-Chrome `signature` stage, then reported `runtime_unavailable`. No provider or SMS fixture submissions occurred.
- On this Mac, the installed Chrome bundle has `com.apple.FinderInfo`. Strict `codesign --verify --strict --all-architectures` rejects it as Finder metadata; the same Google publisher requirement passes with normal signature verification. The signed Chrome probe still uses strict verification.
- The disposable macOS workflow now removes only `com.apple.FinderInfo` from its own preinstalled Chrome bundle before acceptance. This preserves strict rejection of resource forks and checks Chrome’s signed identifier and Google team requirement. A hosted rerun is required before treating the correction as verified.
- Local verification: `uv run pytest -q tests/test_mac_signed_chrome_evidence.py` (72 passed); `uv run ruff check scripts/mac_signed_chrome_probe.py tests/test_mac_signed_chrome_evidence.py`; Python compilation and `git diff --check` passed.
