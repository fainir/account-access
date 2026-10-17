# Mac system broker entrypoint

`SystemBroker.swift` provides the service entrypoint needed by the isolated
consumer installer. It composes `RootBrokerHost`, its fixed initial-enrollment
plan and the native owner gateway. Its pre-enrollment connection passed
[15 checks in two independent Mac VM runs](../artifacts/mac-initial-gateway-080.json).
This is a development component; it is not
installed or enabled by the published preview.

## Build and installation contract

`bash macos/build-broker.sh OUTPUT_DIRECTORY` builds the service and permanent
identity-drop launcher as universal arm64/x86_64 executables, targeting macOS
14. It verifies their signatures. An existing `ACCOUNT_ACCESS_SIGNING_IDENTITY`
uses Developer ID signing with a timestamp; otherwise the output is ad-hoc and
is for development. The script builds files only. It does not elevate, register
a service, create system users or modify the System keychain.

The trusted installer must prepare the dedicated non-login broker identity,
private state, protected runtime and root-owned policies. The production
entrypoint accepts no command-line arguments and reads only:

`/Library/Application Support/Account Access/broker/host.json`

The host policy identifies the worker and enrollment plans, approved bootstrap,
canonical vault ID, owner UID and publisher-bound owner/bootstrap code hashes.
The publisher, identifiers and code hashes form native code requirements; no
policy can supply a script, module, callback URL, key or setup command.
Existing path/runtime/identity protections apply before startup. The enrollment
vault, worker policy and owner UID must agree across the plans.

The system job must declare the fixed owner Mach service and the two activated
listeners from [system supervision](mac-supervision.md). The service requires
the system daemon context; an ordinary process exits before reading installed
configuration. It disables core dumps and keychain interaction before secrets
can enter the process. The hosting binary provisions its own strict setup rule,
so its registrar matches the process that verifies the owner's approval.

## First use and shutdown

Before a vault exists, the pinned owner application can prepare its native
connection and read `needs_owner`. Unapproved enrollment and invalid proofs do
not create a key. A genuinely approved setup request uses the
[initial coordinator](mac-initial-enrollment.md). Mandatory OS approval still
belongs to the owner application; the daemon never prompts or synthesizes it.

The entrypoint retains its host and signal sources in its permanent dispatch loop.
SIGTERM/SIGINT stop owner connections and drain/stop the owned lifecycle through
the host. Error output is a fixed reason code, without exception text,
configuration, keys, credentials or caller arguments.

## Disposable acceptance

CI compiles the same entrypoint with two explicit QA flags. Only that binary can
select a protected fixture policy, use ad-hoc pinned peers and emit sanitized
readiness metadata once in its temporary namespace. There is no test-only timer
keeping the entrypoint alive. Its key provider uses the separate
QA service. It can remove only the QA setup rule registered to its own code.
Production builds contain none of those command-line modes.

The new journey exercises first-enrollment state through separate native XPC
processes while no key or worker exists. It rejects wrong client/server code,
wrong owner UID, unapproved setup, invalid OS proof and caller configuration,
then checks key absence after shutdown in the cleanup process. It removes its temporary job and setup
rule. This is a negative pre-enrollment boundary test: a genuine positive owner
approval, consumer package/native screens, client issuance, migration, publisher
update continuity and private account/phone QA remain separate release gates.

See [production acceptance](production-gates.md) and [validation](validation.md).
