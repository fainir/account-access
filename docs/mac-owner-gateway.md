# Native Mac owner channel

`macos/OwnerGateway.swift` is the native owner-channel component for a separately
managed broker. It is not enabled in the installed consumer app and does not
install a root service, register an authorization rule, migrate credentials or
replace the existing setup transport.

The intended path is the signed owner app → a privileged XPC gateway → the
worker's root-private Unix owner socket. The agent API remains separate. A
trusted supervisor/provisioner must supply protected state, current approved
code hashes and the worker's private capability; none come from a caller's
request. Publisher keys, root and the provisioner remain trusted.

## Peer and operation checks

The listener checks the expected OS user and applies an XPC code-signing
requirement for the Apple-issued publisher, bundle identifier and exact approved
code-directory hash. Debuggable peers are rejected. The production client uses
the system bootstrap namespace, pins the service code and checks the root peer
in a health-only handshake before releasing setup authorization or credentials.
A failed handshake cannot send either. The health request itself can reach a
service before the client's reply-side signature rejection; the negative test
therefore checks that only health was dispatched and no setup input was sent.

Only named owner routes are accepted. Arbitrary paths/URLs, queries, traversal,
local installation and interactive browser handoff are excluded. The Unix
backend has no TCP fallback, bounds HTTP framing and JSON responses, refuses
redirects/ambiguous framing, and keeps its owner capability inside the gateway.
Production construction requires root and a protected root-owned socket path.

## Setup authorization

New credentials and permission changes require a setup session. The native app
creates a fresh Authorization Services reference, obtains the dedicated
`com.fainir.accountaccess.owner-enrollment.v1` right and passes its opaque
external form through the pinned XPC channel. That form is a secret: it is not
saved, logged, placed in an argument/environment variable or returned to agents.
The gateway verifies the exact returned right without displaying a prompt or
extending authorization itself. An API success code or a valid external
reference alone is insufficient.

Provisioning must install the exact rule declared in the source: authenticate
the session owner, disallow a root shortcut and shared credentials, allow a
30-second authorization handoff and limit attempts. An absent, changed, overly
permissive or long-lived rule fails closed. The canned session-owner rule has a
long lifetime on the inspected Mac, so delegating to it alone was rejected.
See [Apple's authorization policy source](https://github.com/apple-oss-distributions/Security/blob/main/OSX/authd/authorization.plist)
and [external authorization references](https://developer.apple.com/documentation/security/authorizationexternalform).

One accepted proof enables configuration writes on that connection for ten
minutes. End setup, expiration and disconnect remove that authority; a late
authorization result cannot revive a disconnected session. Revocation and Pause
remain available to the correctly signed owner app without another setup proof.
Routine agent logins do not use this setup channel. No request is automatically
replayed after a timeout or lost response; integration must preserve the form
and inspect state before the owner decides what to do next.

## Verified scope

The synthetic harness builds a separate app with two XPC helper processes.
Actual local Developer ID signing exercised the production publisher/identifier/
hash requirement; the ad-hoc mode used by CI exercises exact hash checks only.
The accepted helper reached a real Python owner server over a private Unix
socket for state, a permission grant, authenticator enrollment, CSV preview and
revocation. Wrong client code, wrong server code and a mismatched expected user
were rejected. A real Authorization Services reference was exported/imported
without requesting a grant, and the production verifier rejected unconfigured
setup. Session, route, framing and evidence checks are
included. Only fixed test metadata is retained publicly.

The configuration approval in the positive journey is an explicitly synthetic
QA verifier, excluded from production compilation. Genuine owner approval has
not been completed. All test processes run as the ordinary test user; this is
not a Mac root/cross-user deployment test. The harness changes no installed app,
authorization database, privacy permission or real account. The separate Linux
[worker acceptance](isolated-worker.md) does test an actual cross-user boundary.
These results cannot be combined into an untested Mac installation claim.

The production supervisor, protected packaging/update and key custody, native
UI wiring, client issuance/migration, real owner-approval test and notarized
installation remain required. Private email, SMS and authenticator acceptance
remain open.

## Root host integration

`OwnerGatewayHost.swift` adds a root-only host for the fixed system Mach service.
The trusted parent supplies the validated owner peer and private Unix backend;
caller requests cannot select either. Stopping the host closes active setup
sessions and connections. Connections are bounded and never resurrect after stop.
This class does not obtain a vault key or install a consumer service.

The Mac worker CI harness now deploys this host as a temporary root launchd
service beside the separate-user broker. A test-only daemon receives its owner
capability once over a root-private, peer-checked Unix socket, in memory. No key
or capability is supplied through a file, argument or environment variable.
The client uses the production privileged connection and root-peer check.
Wrong code/user/server identities, missing setup authorization, owner revocation
and service shutdown have a separate, strict evidence report. Code identities
are ad-hoc hash-pinned in CI; genuine owner setup approval and publisher trust
are not established by that report. Revision `de1b0d7` passed **24 root integration
checks** alongside the worker's 25 cross-user checks in
[Mac CI](https://github.com/fainir/account-access/actions/runs/38995617514/job/117287405676).
The service ran as UID 0; a pinned client reached the separate-user broker and
revoked an approved read. Wrong client code, wrong OS user and wrong server
code were rejected. Setup writes without OS authorization were refused.
Removing the service invalidated an open owner connection while approved broker
reads kept working. The service/process and temporary users/domains were removed.
The existing 54 ordinary-user checks also passed locally with Developer ID
signatures after the listener lifecycle change. See
[root integration evidence](../artifacts/mac-root-owner-080.json).
This is not consumer installation, durable key custody or migration acceptance.
