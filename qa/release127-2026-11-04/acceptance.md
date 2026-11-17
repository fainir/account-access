# Login navigation update 127 - 4 November 2026

The real Lemon password import and status-only grant are saved in installed build
126. Its last approved operation returned browser_execution_failed. Build 127
routes session-only typed server-page checks through the already approved login
entry; controlled reproduction failed before the fix and passes afterwards.
This is not installed or private MFA acceptance. Google Authenticator is unenrolled.

## Program and public image

[Exact program CI](https://github.com/fainir/account-access/actions/runs/41814053650)
passes 4,757 tests /114 skips, native jobs, lint and dependency audit;
[actual log read-back](source-program-ci-summary.log). The 94 focused controlled
browser/provider/import/security checks include fresh, warm and expired TOTP
sessions and refusal before password submission for absent or disabled factors.
[Controlled proof](../one-time-setup-2026-11-03/native-enrollment-2026-11-04.md).

[Mac-worker CI](https://github.com/fainir/account-access/actions/runs/41814053618)
completed. All 18 downloaded reports are PASSED, all 427 boolean checks are true,
and the 16 applicable workflow validators pass. Actual reports are retained in
worker/. Owner/wheel compilation
[41814053787](https://github.com/fainir/account-access/actions/runs/41814053787)
contains actual owner build 127, matching project wheel and 61 PASS groups.

The [qualified public image](target127-qualification.json) preserves the signed
native dependency/JIT bytes. Publisher signature audit and fixed offline
sandboxed-browser execution pass. An earlier attempt passed signatures but its
browser probe timed out; a later unchanged probe passed. The publisher allows
one bounded retry, and still refuses two failures. No cause is inferred from
swap usage. Only this final qualified image will enter package assembly.
Program source is 15ef230; image publisher is 843a121. The exact update plan has
15 changed nodes, 15 units (two project trees, four fixed files, nine direct
files), and a separate fixed Login Navigation recovery namespace. Existing
120-126 update contracts and namespaces remain unchanged.

## Delivery and installed acceptance

[Exact-source native run](https://github.com/fainir/account-access/actions/runs/41825605936)
completed successfully at source 6fcba2e. All ten downloaded reports pass:
[shared](native/full-image.json), [runtime](native/runtime.json),
[new exact plan](native/direct.json), and all seven retained 120-126 contracts.
The fixed helper is compiled from that same run. The
[6.1 MB updater](updater-qualification.json) is signed, Apple-accepted, stapled,
Gatekeeper accepted and independently expanded with its exact owner signature
and resource inventory. Its persistent customer copy passes signature/ticket/
Gatekeeper checks again. No owner installation yet.

The [289 MB full installer](fresh-qualification.json) is signed, Apple-accepted,
stapled and Gatekeeper accepted. Its exact image inventory, unchanged-source
and native preflight checks pass. Both persistent customer copies independently
pass signature, ticket and Gatekeeper checks. The
[final Installer input contract](../../artifacts/runtime127-installer-inputs.json)
pins the qualified package bytes and exact public126 baseline. All four QA-only
assets are independently [read back](qa-release-readback.json): complete states,
server sizes/digests and unchanged unpublished draft match all pins. Existing
controlled Installer journeys are dispatched once per OS at source cc6d903.

## Actual signed Installer acceptance

All six completed journeys pass on exact source cc6d903 and unchanged final
package bytes. No personal account or private credential was used.

| OS | Fresh / identical repair | Update / reapply |
|---|---|---|
|14.8.9 arm64|[11 checks](macos14-fresh/report.json)|[27 checks](macos14-upgrade/report.json)|
|15.8.2 arm64|[11 checks](macos15-fresh/report.json)|[27 checks](macos15-upgrade/report.json)|
|26.6.2 arm64|[11 checks](macos26-fresh/report.json)|[27 checks](macos26-upgrade/report.json)|

All 114 checks pass: exact127 public bytes/build, publisher sandboxed browser,
patched dependency guard, fixture private inode, receipts/policies, original
recovery binding, all seven120-126 histories and old unpublished preparation.
Every fixture job is stopped/absent. Completed runs:
[macOS14](https://github.com/fainir/account-access/actions/runs/41828689075),
[macOS15](https://github.com/fainir/account-access/actions/runs/41828681946),
[macOS26](https://github.com/fainir/account-access/actions/runs/41828695162).

## Owner Mac and customer handoff

[Actual owner preflight](owner-preflight.json) matches all 14 selected public
files, including browser.py, to qualified 126 and preserves 11 metadata roots.
Installed discovery still shows the four original/new grants, browser READY,
and the exact Lemon status permission. Google Authenticator is unenrolled.
The final customer draft has13 exact labeled assets, all 11 prior IDs/bytes
preserved, qualified source cc6d903, matching notes, tagv0.8.0 and unpublished
state independently [read back](customer-release-readback.json). No public
release or private MFA success is claimed.

The canonical owner GUI was normally quit and zero matching processes verified.
Reading its AX state after quitting had reopened it; the second normal Quit was
followed by Finder/process observation instead. Finder selected the exact
persistent126-to-127 updater; native Installer opened that precise file URL.
Continue/Install advanced into real installation without a new owner request.
Native AX reports Running package scripts; scoped postinstall starts 14:40:37.
Do not call this an approval wait or retry Installer. Inspect actual build and
scoped completion before proceeding to health and the approved Lemon read.
During installation free space briefly measured367MiB, then recovered to2.3GiB
while only read-only cache inspections ran. No cache purge, user-file deletion,
protected-data read, permission bypass or force termination occurred.


## Restart interrupted the owner installation

The Mac restarted at 15:10:55 local, with no scoped completed/refused postinstall
result. Do not infer timeout, crash or an owner action as its cause. The
[post-restart public/metadata check](owner-post-restart-preflight.json) confirms
all 14 selected public files remain exact126 and all 11 prior metadata identities
are preserved. No prior updater process remains. The installed launcher now
returns [RETRYABLE/service_unavailable](post-restart126-health.json), so current
private/public operations are unavailable and no installed 127/MFA success is
claimed. Free disk is17GiB after restart; no agent cache purge occurred.

The same persistent qualified update was rechecked for signature, notarization,
stapling and Gatekeeper, revealed in Finder and reopened in native Installer.
The actual new Installer log and open package descriptor are
[read back](owner-installation-outcome.log). All 13 draft assets and 11 earlier
IDs/bytes remain preserved; no source rebuild, repeated CI, credential access,
private operation, permission bypass or completed-update replay occurred.
Native UI tools disappeared after restart; remaining native installation and
local authorization are handed to the owner as action 19. Only after matching127
completion should actual files/metadata/health, existing grants and the approved
Lemon status be checked, then the local Google Authenticator transfer staged.


### Reopened installation resumed

Before making any owner request, read-back found a new native postinstall at
15:27:37, package_script_service15241 and helper15242, against the exact same
qualified package. No owner request was sent. Action 19 is complete as an
installation-start step; actual 127 acceptance and MFA remain pending. Preserve
this active attempt and inspect its final result before another action.


## Actual 127 installation and available acceptance complete

The matching resumed update finishes at 15:33:39 local with scoped
UPDATED_GUI_UNVERIFIED/checkpointcomplete. The helper exits. Independent
[public/metadata read-back](owner-installed127.json) confirms actual 127, all 14
selected qualified files (including browser.py), all 11 preserved prior metadata
identities and the new fixed root-owned 0700 Login Navigation namespace. This
is actual delivery of the routing fix. The kernel boot is15:10:55, before the
update; a full new 127 OS reboot has not yet been observed and remains F1/action 20.

[Actual service](installed127-health.json) is RUNNING/zero failures and browser
READY. [Claude discovery](installed127-claude-discovery.json) independently
preserves all four standing grants. Both actual launchers complete only
[Codex private status](installed127-codex-private.json) and
[Claude private status](installed127-claude-private.json): outer environment live,
authenticated=true. Separate [Codex](installed127-codex-public.json) and
[Claude](installed127-claude-public.json) public-example reads each return six
names/prices. These are labelled examples, not Lemon MFA evidence.

### Real Lemon navigation result and remaining owner action

One [durable approved task](lemon127-task-result.json) now returns
NEEDS_USER/authenticator_not_enrolled with kind totp, instead of the previous
browser_execution_failed. Task 82250e562d9b8864541c3d2854885eee, key
lemon127-acceptance-20261104, is preserved; challenge b68d7ac0307f278a37d06d8841ef30cb.
No duplicate/private retry is submitted. In the reviewed Broker.run path,
Browser.read reaches guarded login/form checks before Codes.begin raises this
missing-source result. This verifies the navigation defect's installed path;
it does not prove password/TOTP submission or private automatic MFA completion.
The saved Lemon credential and exact status-only grant remain unchanged.

The signed127 native owner app is opened for local setup. Its unchanged
Automatic sign-in page exposes Import my authenticator accounts. Native UI
control is unavailable after restart, so no file picker or QR content is read.
Only the owner can select the existing Google Authenticator transfer images
and approve the correct Lemon mapping. Passwords/keys/codes/QR images stay local.
After owner enrollment inspect the same durable task; do not ask for another
Chrome export, manual password or manual website code. Namecheap remains paused.
The technical follow-up is removed after matching installation and all available
automated checks; personal enrollment, postupdate restart, phone and publication
stay in the ledger. No personal-enrollment monitor or production-ready/private
MFA claim is made.
