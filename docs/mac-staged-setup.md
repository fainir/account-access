# Staged Mac vault setup

First-time consumer enrollment needs a genuinely approved owner setup session,
explicit System-key creation, staged initialization, publication and client
issuance. This page describes the staged initializer now implemented in the
candidate. It does not claim that the installed preview performs that complete
sequence.

## Private initialization

`RootStoreInitializer` accepts an opaque key already obtained by its trusted
system parent. It does not create/replace a key, authorize enrollment, publish a
stage or grant an agent. The parent must perform those responsibilities through
the approved setup flow. Native setup policy, the signed owner channel and a
genuine positive owner approval remain separate gates.

A protected initialization plan binds the existing runtime/identity policy, a
sibling staging directory and canonical vault/enrollment identifiers. The stage
has the exact private broker ownership and must be empty. No caller-supplied
script, Python module, environment key or plaintext key file is accepted.

The native launcher permanently drops UID/GID and replaces its image with
isolated Python. Its enrollment descriptor allowlist retains only standard I/O,
the one-shot 64-byte bootstrap pipe and a private receipt socket. The ordinary
worker keeps its separate listener descriptors. Kernel descriptor tests cover
both forms, including an inheritable descriptor above a lowered soft limit.

The initializer atomically claims the empty stage before creating configuration
or SQLite data. It creates an empty production configuration (or an explicit
controlled fixture), writes an encrypted enrollment marker and verifies it.
Competing initialization or an existing file stops the operation; neither is
silently replaced. Temporary and final staging files never contain the master
key as a key file.

A receipt authenticates the vault identifier, enrollment identifier and canonical
stage path using the fresh owner entropy from the inherited envelope. It stays
on private IPC. Before acknowledging it, the native parent checks the child's
kernel PID/parent/process group and real/effective/saved UID/GID. Success also
requires the owned child to exit normally. A receipt alone is not publication.

## Key verification before readiness

The isolated worker now authenticates an encrypted record before starting its
owner or agent servers. New stages have the dedicated enrollment marker.
Previously enrolled stores can authenticate an existing encrypted record. A
legacy store with no encrypted record cannot claim that its key was verified;
the worker requests setup/repair instead of silently creating a marker with an
uncertain key. A wrong key fails before readiness and does not replace data.

This check is separate from parsing the plaintext configuration. An empty
account list by itself cannot establish that the encrypted vault key works.

## Remaining work

The initializer is a production component under CI validation, not consumer
setup acceptance. The current fixture uses an explicitly created temporary
System key and tests an unpublished private stage. The approved first-install
flow still needs its owner-authorized key creation, recoverable atomic
publication, native UI integration, client issuance and installed migration.
Genuine owner approval, publisher update continuity, notarized clean installation
and private password/email/SMS/authenticator/physical-phone QA remain open.

See [production acceptance](production-gates.md), [native owner channel](mac-owner-gateway.md)
and [system supervision](mac-supervision.md).
