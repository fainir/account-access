# Agent skill upgrade regression - 2026-10-30

- The full regression run exposed that the managed-skill inventory compared `Path` values with strings and copied/checked generated Python cache files as product templates. That made safe skill upgrades fail after installation.
- The installer now compares normalized paths, copies only the three reviewed skill templates, generates the launcher with bytecode writes disabled, and checks the same fixed template list during installed-state verification.
- `uv run --no-sync pytest -q tests/test_agent_setup.py tests/test_install_service.py::test_sync_skill_omits_generated_python_bytecode tests/test_install_service.py::test_installed_skill_calls_real_private_service_and_worker`: **48 passed**.
- `uv run --no-sync pytest -q tests/test_mailboxes.py::test_owner_browser_connects_one_mailbox_then_completes_approved_email_login`: **1 passed**; its browser locator now targets the expanded email-setup form.
- Ruff and Python compilation passed. The full regression suite is running; this record does not claim it passed.
- Installed build 110 and the pending build-118 native installation are not evidence for this source fix. The updated installer still needs a signed build and owner-Mac acceptance.
