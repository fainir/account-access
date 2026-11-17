# Installer probe pin refresh

The exact-source Account Access run on commit `7bfbbef` exposed one stale SHA-256 pin for `scripts/mac_component_update_installer_probe.py`: the test expected `a4507756…`, while the reviewed current helper was `1b790d06…`. The old full run had 4,481 passed, 112 skipped and this single failure ([CI run](https://github.com/fainir/account-access/actions/runs/41061358951)).

Updated the expected helper digest in the fresh-image, installer-timeout, broker-repair and full-image acceptance probes. The four focused suites then passed: 267 passed. Ruff, Python compilation and `git diff --check` passed. Hosted full-suite rerun is pending the pin-refresh commit.
