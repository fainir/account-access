# Owner Mac build-120 refusal

The owner approved the install at 21:38 local time. Installer safely refused before changing the image; the installed app remains build 110.

```text
2026-10-30 21:38:58+02 Nirs-MacBook-Air-2 package_script_service[95372]: ./postinstall: {"schema":1,"status":"REFUSED","reason":"full_image_transition_conflict","checkpoint":"context"}
```

Read-only, noninteractive privileged metadata inspection found one unpublished `.preparing-681f2b48c2b35bc1ccdb4309da636b1b88fcbeb2b2ae982b92dbf0c4198dd51e-…` directory in the root-owned runtime-recovery namespace, retained since 04:15. The current plan is different; its orphan inspector only accepts the current plan prefix. No account material was read or modified.

Fix: the direct updater can retain bounded, strictly inspected unpublished preparations from other plans without giving them authority. Published foreign transitions and heads, malformed names, unsafe metadata and excess retained state must continue to refuse. Actual Installer acceptance will seed this older preparation and verify its inode and bytes survive upgrade/reapply.
