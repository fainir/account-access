# Installation root recovery v2 - source contract QA - 2026-10-30

The recovery path accepts one narrowly defined transition: a valid protected v1
receipt, the same APFS volume UUID, an unchanged `/Applications/Account Access.app`
alias inode, and a replaced support-root inode. It embeds and revalidates the
canonical prior v1 receipt. V1 is retained unchanged. Other root, volume, receipt,
publisher, policy, public-image or signature mismatches remain fail-closed.

Checks on the current source changes:

- `uv run pytest -q tests/test_component_update_builder.py tests/test_component_update_review_workflow.py tests/test_mac_component_update_native_probe.py tests/test_mac_component_update_installer_probe.py` - 309 passed.
- `uv run ruff check` on changed Python source and test files - passed.
- `python3 -m py_compile` on changed Python source files - passed.
- `git diff --check` - passed.

Native Swift type-check and synthetic fixtures, plus the actual Installer
root-replacement fixture, have not passed yet. They require exact-source
disposable macOS CI. This source-contract result does not qualify or authorize an
owner install. Build 119 remains rejected and must not be retried.
