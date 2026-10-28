# Mac worker launcher

`macos/WorkerBootstrap.swift` is a root-invoked child launcher for the isolated
broker. It is not a privilege-elevation utility, setuid executable, installer or
production supervisor. It is not enabled in the consumer app. The trusted parent
must already run as root and execute a protected, approved launcher/runtime.

A root-owned policy fixes the Python runtime, worker policy, dedicated broker
identity/home and browser installation. Policy and code paths reject writable
ancestors and untrusted symlink targets. The broker account must have a separate
primary group, private home and non-login shell. The existing enrolled state
must belong to that identity. A development CA is allowed only in explicitly
controlled fixtures.

The launcher also checks descendants of the venv, managed Python installation
and browser tree. Root-owned top-level folders are insufficient: imported code,
site hooks, standard-library files and browser components must also be root
owned and unwritable by other users. Special/set-ID objects are rejected;
directory symlink targets are recursively checked, including external targets.
Enumeration is bounded, tracks visited targets to prevent cycles and
fails on unreadable entries. Runtime provisioning and updates still need their
own trusted package verification; filesystem ownership is not publisher trust.

The parent passes a root-created secret pipe and two Unix listeners. The child
checks their types and bound socket paths, normalizes them to three fixed
descriptors and permanently drops supplementary groups, group and user IDs.
Attempts to regain root must fail. Isolated Python starts with a fresh minimal
environment and inherited channels only; unrelated descriptors close on exec.
There is no command/shell input, owner-keyring lookup, plaintext key-file
fallback or inherited Python/DYLD configuration. The bootstrap accepts descriptor
numbers and non-secret policy paths, never credentials on its command line.

Darwin's anonymous-pipe `fstat` reports the caller's UID/GID, not the pipe
creator's. The launcher and worker require a kernel pipe with zero device and
link count, rejecting filesystem FIFOs. Root provenance comes from the trusted
root parent and protected launch chain, not from pipe stat ownership. Linux
retains its creator-UID check. See Apple's
[`pipe_stat` implementation](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/sys_pipe.c).

Image replacement uses `POSIX_SPAWN_SETEXEC` and
`POSIX_SPAWN_CLOEXEC_DEFAULT`, with explicit inheritance of stdio and the three
approved channels. The kernel closes every other descriptor, including handles
above a lowered file limit and handles opened by library threads. A native
regression creates such a high handle, lowers the limit, then verifies that
only descriptors 0–5 remain and that PID/environment binding is preserved.
There is no descriptor-table-size assumption. The parent must supervise/reap
the child and retain appropriate custody of its key. Root and the complete
runtime/provisioning chain remain trusted.

The parent must also establish the dedicated user's Mac execution context.
Changing UID/GID alone does not adopt a Mach bootstrap namespace or security
audit session. The disposable harness creates a user launchd domain and adopts
it with `launchctl asuser` before the root-invoked native launcher drops its
credentials. The harness does not create a GUI login. CI must confirm that sandboxed
Chromium actually starts and that the final process has the expected UID/GID.
The initial UID-only launch failed browser startup and is not acceptance.

## Acceptance scope

`mac-worker.yml` prepares a root-owned runtime in a disposable Mac CI VM and
creates two temporary, hidden, non-admin accounts. The native launcher starts
the broker as one account; the other uses the scoped CLI and attempts forbidden
file, process-control and Mach task-port access. Fictional password/email/SMS/
TOTP flows exercise the actual broker; email and phone transport remain synthetic
TLS IMAP and certificate-checked HTTPS. The test refuses Directory Services
changes outside its disposable CI context, and never modifies an installed
owner app or personal account. Passing the workflow must be confirmed from its
actual report, not inferred from compilation.

The Mac checks differ from Linux `/proc` checks: a denied task-port request tests
Mac memory/control access, while the native launcher additionally verifies its
permanent identity drop and rejects a deliberately writable runtime descendant
before key handoff. The report validator requires the platform's exact
check set and does not count one platform's checks as the other platform's proof.

The same VM also verified the privileged root owner channel in
[24 separate integration checks](../artifacts/mac-root-owner-080.json), including
kernel peer identity, unauthorized setup rejection and revocation through the
actual worker. These are not downloaded consumer installation tests.
The production supervisor, protected packaging/update, durable key
custody, native owner/UI integration, source collector integration, migration
and client issuance remain required. Genuine owner authorization, notarization,
private-account and physical-phone acceptance remain open.
