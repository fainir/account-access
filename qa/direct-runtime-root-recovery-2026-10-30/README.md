# Direct runtime root recovery native QA

Build 119 was safely refused at the context checkpoint because its recorded support-root inode no longer matched. The installed app and protected service remained at build 110. The 119 package shown in Installer is not a successor and must not be retried.

The direct 110-to-119 entrypoint now validates the exact old image, signatures, policies, owner and live service before publishing the resumable recovery v2 binding. A resumed transition still requires the original receipt. The recovery runs before preparation only on a first-time direct update.

Evidence from the current source:

- [Full-image native probe](full-image.json): passed with a stable source snapshot and the inherited-group recovery case.
- [Runtime native probe](runtime.json): all 72 assertions passed; the ordinary-user entrypoint refused safely.
- [Direct plan probe](direct.json): passed 184 plan units and 216 changed nodes, including two full-tree projections and four refusal cases.
- `uv run pytest -q tests/test_direct_runtime_upgrade_plan.py tests/test_direct_runtime_target_image.py tests/test_runtime_upgrade_plan.py tests/test_runtime_upgrade_review.py tests/test_runtime_upgrade_installer_acceptance.py tests/test_mac_full_image_installed_probe.py`: 123 passed.
- Ruff, Python compilation and `git diff --check` passed for changed Python sources.

These probes use public fixtures only. They made no installed-system reads or service changes and explicitly report `production_ready: false`. The recovery has not yet passed actual Installer acceptance; no successor package is published or eligible for owner installation.
