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
- Exact-source hosted macOS native acceptance on commit `952902e64ac5638f5e7c50e43cce7a35a328c507` - passed, including warnings-as-errors Swift compilation, all 386 ordinary core fixture assertions, all 41 policy assertions, ordinary updater refusal and ordinary root-revalidation refusal ([workflow](https://github.com/fainir/account-access/actions/runs/41057988364); [retained native report](native-component-update-952902e/report.json)). The fixture recorded no installed reads, root execution or service actions.

The actual Installer root-replacement scenario is still pending. It requires a
newly built, signed root-revalidation package and candidate, followed by exact-
source disposable macOS Installer qualification. This native result does not
qualify or authorize an owner install. Build 119 remains rejected and must not
be retried.
