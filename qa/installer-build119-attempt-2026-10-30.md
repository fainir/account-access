# Build 119 Installer attempt - 2026-10-30

- The owner opened the persistent build 119 package from Downloads and completed the native Installer authorization. Installer ended with PackageKit error 112.
- `/var/log/install.log` records the postinstall refusal `component_base_not_verified` at checkpoint `context`. The runtime updater validates its installation binding before any transition or write, so the failed attempt did not update the app or protected service.
- The installed owner app remains version 0.8.0, build 110. The protected support root no longer has the inode recorded by the v1 binding. The `/Applications/Account Access.app` alias inode and the APFS volume UUID still match the recorded binding.
- A corrected root-run native verifier opened a root-owned copy of the candidate BaseManifest and verified the current public image: 25,167 files, 2,297 directories and 21 aliases. It did not traverse private account branches.
- No installer retry is qualified. A successor needs a reviewed, explicit recovery binding for the verified same-volume support-root replacement, native fixture coverage, disposable-Mac Installer acceptance, signature, notarization and Gatekeeper checks before an install request.

Evidence: `/var/log/install.log` lines around 14:11 on 2026-10-30; installed build metadata; protected v1 binding metadata; native verifier result `VERIFIED`.
