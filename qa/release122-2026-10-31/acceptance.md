# Build 122 acceptance - 31 October 2026

Build 122 repairs two defects observed on the installed owner Mac: the closed native gateway omitted the public connection repair and Android connection-test routes, and an enrolled service could still be stopping when the updater immediately checked absence. Setup approval and existing account grants remain required. Polling and cancellation do not request fresh setup approval.

The matching owner app, native broker and bootstrap were compiled from the same source. [Application CI](https://github.com/fainir/account-access/actions/runs/41218147648) passed 4,601 tests, lint, dependency audit and native owner checks. [Native qualification](https://github.com/fainir/account-access/actions/runs/41220363999) passed the exact 121-to-122 plan, earlier transition compatibility and refusal boundaries. The enrolled-service fixture passes 392 assertions; the gateway passes 80 checks.

The [qualified image](signed-runtime-image.json) preserves all native browser dependency bytes, verifies 49 publisher signatures and executes the signed sandboxed browser offline. The [updater](signed-updater.json) and [fresh package](signed-fresh-install.json) are publisher-signed, accepted by Apple's notarization service, stapled and Gatekeeper-accepted. These results alone do not establish installation or account access.

Actual fresh installation, same-image repair, upgrade and reapply are pending on disposable macOS 15 runners. Owner-Mac update, real protected-worker health, the authorized public names/prices read through both installed launchers, and Android setup UI remain pending. No private account read, credential, code, key, cookie or client token was used in release qualification.
