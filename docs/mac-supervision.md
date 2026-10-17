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
Only the trusted scheduler starts a replacement; an agent or owner request
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

The supervisor is not recovery for a crashed parent daemon or a reboot. It never
adopts a recorded PID, kills an unknown process or removes an occupied socket
without its own recorded inode identity. Parent recovery needs a separately
verified ownership/quiescence design and fault tests. Active-operation crash
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
