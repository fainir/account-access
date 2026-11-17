# macOS updater failure diagnosis - 2026-10-29

## Finding

The recent owner-upgrade installers were signed and notarized, but their helpers refused the installed state before making changes. Repeating macOS authentication could not resolve this source/predecessor mismatch.

- Build 106: `owner_upgrade_transition_conflict` at `predecessor_runtime_intent_structure` (`artifacts/owner-upgrade106-build-20261028.json`).
- Build 109: `owner_upgrade_source_not_verified` at `predecessor_repair_history` (`artifacts/owner-upgrade109-build-20261028.json`).
- Build 110: notarization was accepted, but the helper returned `owner_upgrade_source_not_verified` at `predecessor_component_revalidation` (`artifacts/owner-upgrade110-build-20261028.json`). The fixed-install retry also refused `owner_upgrade_predecessor_not_verified` at `predecessor_view` (`artifacts/owner-upgrade110-fixed-install-20261028.json`). The installed owner app did not change.
- The installed `/Applications/Account Access.app` is bundle build 110. Its public `package-identity.json` and app/broker code signatures match each other. The failed packages therefore target a history that this install does not carry; more authorization attempts are not a repair.
- Build 116 is a separate first-install image. Its image manifest is `78113e53f553cdec0bfb9d0744406a18baaaa3327e1be834af5b45b74c3926aa`; the existing-install preflight correctly refuses it as an update.

## Next engineering step

Build a narrowly pinned migration from the installed image and peer identities to a current image, with a tested rollback/retry path. Do not reuse owner-upgrade 106/109/110 or fresh-install build 116 as an update package. No owner install action is requested until that candidate passes package and native updater acceptance.

## Limits

This diagnosis reads only public package identity/signature metadata and existing QA reports. It did not inspect the account vault, mailbox contents or phone messages. It diagnoses the package refusal; it does not qualify an update or prove the AI connection works.
