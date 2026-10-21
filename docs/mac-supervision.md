# Native Mac worker supervision

The development candidate contains an existing-store supervisor. It is an
internal native component; the consumer installer and installed owner app do
not enable it. It cannot enroll a vault, install a system service, resume a
paused vault or migrate the current installation.

`RootBrokerHost.swift` composes the System-key worker supervisor and privileged
owner gateway. The hosting binary must register its own strict setup policy so
authd's registrar identity matches the verifier. A native timer checks the worker
every 250 ms. The protected runtime, dedicated identity, approved code pins,
enrolled vault identity and owner identity must already exist.

## Recovery and Pause

`RootWorkerSupervisor.swift` owns one `RootWorkerProcess` at a time. Only an exit
observed and reaped from that owned child can enter automatic recovery. The
supervisor retires the old owner capability and native sessions before exposing
a replacement. The replacement loads the existing System key, opens the same
encrypted store and receives new owner entropy through its one-shot pipe.

Three consecutive restarts use delays of one, two and four seconds. A fourth
unexpected exit stops recovery. Five minutes of observed stable running resets
the budget. Startup failures, missing keys, unsafe code, changed socket identities
and unknown occupied paths do not enter an automatic retry or enrollment loop.
Managed worker health stays unavailable until the agent server has finished
starting, including signal-handler setup. A callback failure or a non-boolean
readiness value cannot report success. Only the trusted scheduler starts a replacement; an agent or owner request
cannot trigger one. A write is never replayed after a lost response.

The durable Pause marker prevents startup and recovery. Any object at that path,
including a dangling symlink, is treated as Pause. If it appears while a worker
is running, the supervisor stops that worker. After successful host startup, the native gateway can still
report a fixed health/status response while paused, recovering or failed;
ordinary state/configuration requests cannot start a worker. A future trusted
consumer resume flow must handle explicit owner intent. This component never
deletes Pause to make a login work.

Readiness probes have a one-second maximum and honor the remaining startup
budget. Ordinary owner requests retain their separate bounded transport. A
stalled-health test checks an actual unresponsive Unix responder, rather than
substituting a successful health result.

## System-owned listeners and parent recovery

The composed `RootBrokerHost` now requires `RootActivatedListeners`: two fixed
socket-activation names from its system job. The native adapter accepts exactly
one Unix stream listener for each name, checks its bound path, root ownership,
protected parent directories and root socket ownership. On first activation it
sets the required group/mode and retains the filesystem identity; subsequent
worker acquisition verifies both metadata and that identity without repairing it.
It reserves the pair for one worker at a time. The adapter duplicates descriptors;
it never creates a replacement socket or unlinks an unknown occupied path.
Lower-level standalone worker tests can still create and clean their own sockets.

The system job retains the listener namespace across daemon generations. The
job must keep process-group cleanup enabled (`AbandonProcessGroup = false`), and
the host must be the launchd child and its process-group leader. The crash journey
checks the worker's actual kernel parent/group and dedicated UID/GID. It kills
only the named disposable job through launchctl; metadata PIDs are observations,
never adoption or signaling authority. A new parent loads the existing System
key, issues a fresh owner capability and opens the existing encrypted store.

Apple documents [socket activation](https://developer.apple.com/documentation/xpc/launch_activate_socket)
and [job process-group cleanup](https://github.com/apple-oss-distributions/launchd/blob/main/man/launchd.plist.5).
The API is a lifecycle mechanism, not owner authorization. Genuine setup proof,
code/user pins, root-owned runtime and the separate worker identity remain
necessary. Consumer provisioning must install the corresponding protected job;
the installed preview does not enable this path.

## Owner connection generations

The XPC listener keeps a generation counter. Worker replacement closes existing
sessions, removes their setup approval and invalidates their connections.
An incoming connection whose session was being constructed during retirement
cannot join the next generation. New connections must complete peer validation
and obtain their own setup approval when they need configuration writes.

The separate-process owner-channel test keeps its client process and control
connection alive during retirement. It checks that the old approved connection
cannot send a setup request and that a fresh connection has no inherited setup
approval. Its positive approval is a deliberately synthetic QA verifier. It
does not replace a genuine Authorization Services owner approval.

## Acceptance limits

The System-key supervision journey runs in a disposable hosted Mac VM. It uses
the actual dedicated worker and an empty encrypted fixture store. The monotonic
clock is controlled to test backoff and the stable interval without long sleeps;
worker startup, signaling, reaping, store access and listener cleanup are real.
Its owner-session lifecycle checks are in-process synthetic sessions. The native
XPC retirement test is a separate ordinary-user journey, including a local
Developer ID signed run. They do not establish a deployed consumer composition.

The standalone 21-check supervisor journey is not parent-daemon/reboot
acceptance. The separate composed-host crash journey passed 31 checks, including a
supervisor SIGKILL, owned-worker exit, socket continuity, cold service restart
and paused native XPC access. See [composed-host evidence](../artifacts/mac-root-coordinator-080.json). No component adopts a recorded PID or kills an
unknown process. The activated-listener path never removes socket files itself. Active-operation crash
acceptance must also verify browser descendants and durable task recovery; an
empty-store worker restart does not establish either. Consumer installation,
trusted initial enrollment, native source collectors, client issuance, migration,
genuine owner approval and publisher update continuity also remain open. Private
email/SMS/authenticator and physical-phone acceptance are separate gates.

See [production acceptance](production-gates.md), [key custody](mac-key-custody.md)
and [worker boundary](isolated-worker.md).

Revision `40c9fa4` passed [21 supervisor checks](../artifacts/mac-root-supervisor-080.json)
in [Mac CI](https://github.com/fainir/account-access/actions/runs/39004132984/job/117312998074).
The separate [58-check XPC journey](../artifacts/mac-owner-gateway-080.json) passed
both local publisher signing and ad-hoc CI at the same revision.

Revision `e756d18` passed the composed journey in two disposable Mac CI runs:
[push](https://github.com/fainir/account-access/actions/runs/39006452093/job/117319816135)
and [PR](https://github.com/fainir/account-access/actions/runs/39006454910/job/117319824512).
The exact cold-start claim is service removal and re-registration; an actual
machine reboot, active browser descendants and interrupted account tasks are
not covered by this empty-store journey.
