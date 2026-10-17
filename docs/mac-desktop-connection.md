# Native desktop setup for the isolated service

The desktop app can use the protected system broker through native XPC. This
connection is separate from the owner HTTP capability used by the published
preview. It does not install the system service, migrate an existing store,
provision agent identities or establish phone/email connections by itself.

## Installation contract

A trusted installer must publish this non-secret registration at the fixed path:

`/Library/Application Support/Account Access/owner.json`

```json
{
  "managed_by": "account-access-desktop-owner-v1",
  "schema": 1,
  "owner_uid": 501,
  "publisher_team": "ABCDEFGHIJ",
  "server_identifier": "com.fainir.accountaccess.broker",
  "server_hashes": ["REPLACE_WITH_THE_INSTALLED_BINARY_CODE_DIRECTORY_HASH"]
}
```

These are placeholders, not an installation command. The UID must be the actual
owner. The publisher team and 40-character code-directory hashes must identify
the installed broker, including supported architectures. The broker's separate
host policy must pin the corresponding owner application and UID. Both sides
check native code identity; the desktop also checks that its peer runs as root.

The registration and every ancestor must be root-owned, without group/other
write access, special mode bits, symbolic links or extended ACL entries. The
file must be a regular file with one hard link, at most 4096 bytes. The desktop
opens components relative to verified directory descriptors, reads the bounded
file through its descriptor and verifies its identity, size and modification
time again. Unknown fields, another UID, boolean numeric fields, malformed
publisher identity and caller-selected endpoints are refused.

The registration contains no key, password, cookie, authorization form, token,
URL, socket path, interpreter or command. Production code has no environment
variable for selecting another registration or native service. An installed
registration selects native mode before the old runtime checks or installer
execute. An invalid or unavailable native installation produces an error. Once
selected in a running app, removing the file cannot select the legacy transport.
With no system registration, the existing preview flow remains available; it
retains the security limits documented in [production acceptance](production-gates.md).

## Owner experience

Before a vault exists, the desktop reads setup state without asking for OS
approval. It offers **Set up Account Access**. That explicit owner action requests
the dedicated macOS authorization, verifies the root peer, submits an empty
enrollment request and accepts a pending response. It then checks progress
without repeating the enrollment write. On success, the existing account import
and verification forms use the same native request path.

Initialization polls stop after sixty checks or when the view changes. **Check
progress** and reopening reconnect with a read. A lost enrollment response
never automatically creates a second enrollment request. Missing or unknown
state displays repair guidance, preserves data and offers no automatic reset.
A short enrollment `ready` response does not claim account readiness: the
desktop first fetches the published worker's full state.

Setup writes use the server's ten-minute session authorization, renewed slightly
earlier by the desktop. Reads, Pause, revocation and routine agent account
operations do not request a new setup approval. A new native connection does
not inherit authorization from a retired connection; a subsequent explicit
setup action may need fresh OS approval. Authorization bytes are cleared after
handoff and the desktop destroys its local OS authorization reference. Password
and verification fields continue to use the existing local masked forms.

**Pause** records the enrollment journal even after the first worker is ready.
Owner state remains readable. An immediate approved Resume can reuse a worker
whose queued pause was superseded, or start it after the pause completed,
without attempting to start a second worker. The journal prevents ordinary
startup from silently undoing Pause. The desktop clears unsaved setup secrets
when Pause succeeds.

## Acceptance scope

The local desktop transport suite covers 31 controlled cases: protected profile
reads, mode/ACL/link/identity failures, approval expiry and reuse, refusal before
proof or credential release, malformed replies and reconnect without write
replay. Its channel and positive approval are synthetic. Native owner-screen
checks render first setup, Pause and repair; a synthetic asynchronous enrollment
advances to the account view. They also check a lost reply followed by reopening,
without a legacy registration or another enrollment write.

Disposable Mac CI additionally uses the desktop transport against the actual
system broker over privileged XPC before a vault exists. It loads the protected
root-owned public profile, reads state without approval, and refuses a synthetic
invalid OS proof. This negative boundary journey is separate from the positive
first-store coordinator tests, whose authorization remains synthetic. Exact
revision, run results and limitations are recorded in [validation](validation.md).

Consumer provisioning, positive genuine owner approval through these screens,
full password/email/SMS/authenticator setup through the isolated service,
trusted browser/phone collectors, agent-client issuance, migration, publisher
update continuity, notarized clean installation and private/physical-phone QA
remain release gates. Host actions absent from the native route allowlist are
refused rather than sent to the legacy HTTP channel. The installed owner app
and its unfinished mailbox form are not replaced during these checks.
