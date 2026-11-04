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
assets will be checked against server size/digest/complete state before the
three existing controlled Installer journeys are dispatched.

[Actual owner preflight](owner-preflight.json) matches all14 selected public
files, including browser.py, to qualified126 and preserves11 metadata roots.
Installed discovery still shows the four original/new grants, browser READY,
and the exact Lemon status permission. Google Authenticator is unenrolled.
The installed app remains126; no new private operation, authenticator import,
owner install approval or public customer release is claimed.
