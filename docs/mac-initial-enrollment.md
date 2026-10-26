# Native first-vault enrollment

This candidate component connects the native owner authorization channel to
fresh System-key creation, staged initialization, publication and the first
worker. It passed [27 checks in two independent Mac VM runs](../artifacts/mac-desktop-connection-080.json).
The installed preview does not use this
isolated setup path. Native screen/transport integration is implemented and
covered by controlled checks; consumer provisioning, genuine owner approval
through those screens, consumer client provisioning and migration are still required.

## Owner flow

The trusted system installer supplies a fixed root-owned enrollment plan,
approved native code identities and private broker-owned directories. With
`RootBrokerHost(enrollmentPolicy: ...)`, the owner gateway can remain available
before a vault exists or when its existing key needs repair.

The signed owner application first prepares its pinned native connection. Owner
state reports `needs_owner`, and normal account requests cannot create a vault.
An explicit setup action obtains the dedicated OS authorization through
`OwnerSetupApproval`. The app then submits `owner/vault/enroll` with an empty
object. It does not supply a UUID, file path, command, account credential or
keychain destination.

The gateway verifies the live setup lease and creates native
`OwnerEnrollmentApproval` authority. That type has no serialized representation
or public initializer. Enrollment uses a separate backend method, so accepting a
route cannot accidentally forward key creation to the old HTTP owner backend.

The request returns `INITIALIZING` while a serial background operation prepares
the store. The owner application can read setup state and health during this
work. The native parent checks the bootstrap signature, loads or explicitly
creates the fresh key, initializes the empty stage, authenticates completion and
publishes it. The worker must verify encrypted data before reporting readiness.

First worker startup retires existing owner connections. The UI must reconnect
and read state rather than replay the setup POST. Importing credentials,
granting specific account operations and issuing agent clients remain separate
owner actions; creating a vault grants no account access. The new
[portable client connection](mac-agent-setup.md) lets the native app continue into
one shared client setup without selecting Claude or Codex. The client itself
receives no account permissions until the owner approves specific operations.

## Restart, Pause and repair

Before key creation, the gateway records approval in the protected publication
journal. That record binds the fixed enrollment transaction and owner UID; it
is not a reusable authorization for other owner operations. Startup can continue
that approved transaction without asking the owner again.

Pause is available to the pinned owner without a new setup approval. It persists
in the journal, blocks further setup progress and survives reopening. An already
running bounded step can finish safely; completed initialization is recorded so
its receipt is not discarded. Resume requires a live approved setup session.
A resume that arrives while Pause is settling reuses the serial operation and
does not launch a competing initializer.

Ready or published data requires its existing System key. If the key is absent,
the coordinator reports `needs_repair`, keeps the owner channel available and
never enrolls a replacement. A partial unverified stage also requires repair;
it is not erased or initialized again. Full setup recovery from every crash and
storage power-loss boundary remains unfinished.

Store-startup refusals now retain a fixed checkpoint and reason in owner state
and health, and in the `store-startup` system-log category. The projection never
formats arbitrary errors or includes paths, journal values, account identifiers,
keychain values or OS error descriptions. The native UI maps recognized pairs
to fixed explanations. Unknown results retain the generic repair screen.

The original publication record binds both directory inodes and the device
number observed at enrollment. A changed device number with unchanged inodes
receives a distinct refusal; it is not accepted as the same volume. Changed
inodes, mixed devices and substituted directories are also refused. A trusted
volume-aware migration for existing publication records remains unfinished.
This diagnostic addition does not repair an existing store by itself.

## Acceptance scope

The new VM journey uses real temporary System keys, permanent identity drop,
production initialization/publication and actual workers. It tests a real
production-verifier denial and a synthetic positive setup session. A controlled
checkpoint before initialization makes the Pause/Resume race deterministic.
This is not evidence of a genuine positive owner approval or a completed
consumer installation. No private passwords, mailbox messages, SMS or
authenticator accounts are used.

Positive setup sessions run in the same hosting process as the coordinator.
The [system entrypoint](mac-system-service.md) now exercises the first-enrollment
mode through a separate native XPC owner process before key creation. That
18-check journey covers reads and rejected requests, with no positive approval.
Its additional desktop-transport assertions load the protected public profile,
read without approval and reject an invalid OS proof. The positive first-store
coordinator now also checks durable Pause after readiness and an immediate
approved Resume without a competing worker. Existing-store composed-host and native owner-channel acceptance are separate journeys. Setup
objects are reopened against their durable files; a setup-process crash and
power-loss injection remain unverified.

See [staged setup](mac-staged-setup.md), [owner transport](mac-owner-gateway.md)
and the [production acceptance matrix](production-gates.md).

See the [native desktop flow](mac-desktop-connection.md) for setup, progress,
Pause/Resume and lost-response behavior.
