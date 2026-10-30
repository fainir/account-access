# Full-image native regression after root-binding recovery - 2026-10-30

Refreshed the reviewed exact-source digests for `ComponentUpdate.swift`,
`InstallationRootBinding.swift`, and their composed source in
`scripts/mac_full_image_installed_probe.py`. The source-pin contract suite passed
34 tests. The full ordinary-user native probe then compiled once and passed all
six fixture reports: counts 159, 625, 40, 63 and 164; the runtime source fixture
passed 54 source, 49 recovery and 88 transaction assertions. All six guarded
entrypoint refusals were observed.

`result.json` reports `PASSED`, stable sources, no installed reads, no root
execution, no service actions, no provider process/network, and
`production_ready: false` ([machine report](full-image-root-recovery-2026-10-30.json)).
The result qualifies these source fixtures only. The disposable actual Installer
root-replacement scenario and a signed successor package remain outstanding.
