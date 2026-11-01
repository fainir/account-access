# Build 122 acceptance - 31 October 2026

Build 122 repairs two defects observed on the installed owner Mac: the closed native gateway omitted the public connection repair and Android connection-test routes, and an enrolled service could still be stopping when the updater immediately checked absence. Setup approval and existing account grants remain required. Polling and cancellation do not request fresh setup approval.

The matching owner app, native broker and bootstrap were compiled from the same source. [Application CI](https://github.com/fainir/account-access/actions/runs/41222791453) passed 4,609 tests, lint, dependency audit and native owner checks. [Native qualification](https://github.com/fainir/account-access/actions/runs/41220363999) passed the exact 121-to-122 plan, earlier transition compatibility and refusal boundaries. The enrolled-service fixture passes 396 assertions; the gateway passes 80 checks.

The [qualified image](signed-runtime-image.json) preserves all native browser dependency bytes, verifies 49 publisher signatures and executes the signed sandboxed browser offline. The [updater](signed-updater.json) and [fresh package](signed-fresh-install.json) are publisher-signed, accepted by Apple's notarization service, stapled and Gatekeeper-accepted. These results alone do not establish installation or account access.

Actual [fresh installation, repair, upgrade and reapply](https://github.com/fainir/account-access/actions/runs/41221383565) passed on disposable macOS 15 runners. The [fresh report](installer-fresh.json) records eleven successful checks; the [upgrade report](installer-upgrade.json) records twenty-seven, including preservation of synthetic private/root/receipt state and both earlier recovery histories. The fresh image is unchanged by the later helper correction.

The first owner-Mac update refused before exchange at the shutdown check. The same signed package resumed successfully and installed build 122. Six captured directory identities survived: support root, application alias, private vault directory, installation binding, build-120 recovery namespace and build-121 JIT namespace. The installed protected worker reports browser READY and background recovery RUNNING with zero failures. No full macOS reboot is claimed.

A normal fixed-service restart captured the exact missing state: launchd reports `SIGTERMed` with the existing PID for about twelve seconds, then returns the exact missing-service response. [Observed metadata](shutdown-observations.log). The removal observer now accepts only that measured additional state; it grants no PID authority. The running-job identity parser still rejects it. [396 native assertions](native-shutdown.json) and 236 focused Python cases pass. A read-only executable compiled from the same production `ComponentCommands.waitUntilAbsent` sources passed against the real enrolled service in 12.14 seconds. Normal bootstrap then succeeded. [Actual production wait](production-removal-wait.log).

The corrected helper passed [exact-source native qualification](https://github.com/fainir/account-access/actions/runs/41222791457) and [actual upgrade/reapply acceptance](https://github.com/fainir/account-access/actions/runs/41223552608), including all twenty-seven checks in the current [report](installer-upgrade.json). Only the updater helper changed; the qualified app/browser image and fresh package remain identical. Its final package reapplied on the owner Mac with Installer reporting `ALREADY_UPDATED_GUI_UNVERIFIED`, checkpoint `complete`. Read-back confirmed build 122, all six preserved directory identities, the connected public example, browser READY, background worker RUNNING and zero failures. Owner reapplication validates the already coherent image; the live production-wait check is the evidence for the enrolled shutdown condition.

The owner approved the installed public connection repair in the separate macOS setup dialog. The repair control disappeared, with the existing read and permission expiry retained. Both installed launchers then completed `personal-store:inventory`, returning six items with only `name` and `price`, explicitly classified `public-example`. Both completed again after the real service restart. [Codex output](codex-public-read.json), [Claude output](claude-public-read.json), [native connected state](public-connected.png). The public result does not establish private-provider acceptance. Namecheap remains paused at the same unrecognized challenge and was not retried.

The native Android entry is reachable from Verification. Empty sender shows the expected error and returns focus to the input after dismissal. Back/navigation work without creating a pairing or account grant. [Page](android-empty-sender.png), [observed validation](android-validation.txt). No pairing QR, token, SMS or website code was read. Physical pairing, real delivery and Android publisher-key custody remain owner actions.

The native Verification screen also reports an existing mailbox with its last connection check passed. No mailbox address is stored in this evidence and no message was fetched. Do not ask for its saved app password again; real supported website email-code delivery remains separate owner acceptance. No private account read, credential, code, key, cookie or client token was used in this run.

Final compatibility read-back: the unchanged packages also pass [all four actual Installer journeys on macOS 26.6.2 arm64](https://github.com/fainir/account-access/actions/runs/41224876706). [Fresh/repair](macos26-fresh.json) records eleven checks; [upgrade/reapply](macos26-upgrade.json) records twenty-seven. The real owner Mac is macOS 27.2. [Current Mac cross-user CI](https://github.com/fainir/account-access/actions/runs/41222791525) and [Android CI](https://github.com/fainir/account-access/actions/runs/41222791409) passed.

The earlier macOS 14 runner outage is resolved. On 1 November the same packages
passed [actual macOS 14.8.9 arm64 execution](https://github.com/fainir/account-access/actions/runs/41286876216).
Both completed result artifacts were read: [fresh/repair](macos14-fresh-result/report.json)
records 11 checks; [upgrade/reapply](macos14-upgrade-result/report.json) records 27.
They confirm publisher-signed sandboxed browser execution under the service identity,
patched dependency checks and preserved vault/receipts/earlier histories. Both
fixture jobs stopped their created service. They used zero personal accounts and
retain `production_ready: false`; installer qualification does not prove private MFA.
The completed follow-up was deleted through the automation tool and its config is
absent. No further public sign-in, export, AI enrollment or completed repair approval is needed.

On 1 November both installed Codex and Claude launchers again completed
`personal-store inventory`: six public-example product names/prices each. Installed
discovery reports browser READY, recovery RUNNING and zero failures; Namecheap
remains paused. These public results do not close private-provider acceptance.
