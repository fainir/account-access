# Protected Mac installation provisioning

`account_access.system_provision` prepares and registers a fresh system installation after a
trusted package has installed its immutable payload. It does not elevate itself,
download code, initialize a vault, create keys, import credentials or obtain
owner approval. The production entrypoint accepts no arguments or environment
path overrides and requires root on macOS. The published preview does not use it.

## Payload and identity

Production locations are fixed under `/Library/Application Support/Account Access`.
The authoritative owner app is
`/Library/Application Support/Account Access/owner.app`. The ordinary
`/Applications/Account Access.app` entry is the exact root-owned relative alias
`../Library/Application Support/Account Access/owner.app`, used for navigation.
Programmatic launches, protected resources and signature checks bind the
canonical bundle and running executable; they do not trust the shared
Applications directory as code authority. The installer preserves that shared
directory's existing ownership and mode. Its image permits only this specific
root alias, verifies and copies the protected support tree first, and preserves
unknown or substituted public entries on failure.

The payload must already contain the managed Python runtime, browsers, signed
broker and signed permanent identity-drop bootstrap. Static signature checks require matching publisher teams,
exact identifiers and no debug task-allow entitlement. Code-directory hashes bind
the policies and desktop profile to the verified binaries.

The installer binds the OS console user and reserves `_accountaccess`, a dedicated
non-login identity with its own primary group, private home and disabled password.
An unrecognized existing account/group is a conflict. The root-owned transaction
records a fresh vault/enrollment identity before account creation. A retry can
complete missing fields in that reserved record; conflicting values or a reused
UID are refused. The helper does not overwrite another account or silently adopt
old credential data.

The broker's home and initial/staged stores belong to that identity with mode 0700.
Their parents, public policy files, runtime and listeners remain root-controlled.
The owner and broker identities/groups must differ. Policies contain paths and
identities only, with no password, token or vault key.

New private directories are prepared inside a root-only staging container in the
protected broker subtree. Their ownership, group and mode are set and checked
before an exclusive rename publishes the final name. An interrupted retry can
resume only the exact empty staged directory or remove its empty container after
publication. Existing private directories are checked through non-following
descriptors without listing their contents, rewriting ownership or replacing
their inode. Unknown children, ACL grants and conflicting ownership remain errors.
Staging never adds a temporary sibling to the immutable public-image inventory.

Public policy directories are created with their requested mode in the initial
directory operation. A restrictive inherited file-creation mask cannot leave a
half-prepared final directory awaiting a later permission change. Retries check
ownership, permissions, ACLs and descriptor/name identity without rewriting an
existing directory or inspecting its contents. Conflicting objects still require
review.

## Publication and service start

The provisioner publishes the worker/stage/enrollment/host policies, a launchd job
and the [public desktop connection profile](mac-desktop-connection.md). File
publication uses Darwin's exclusive rename: readers see a complete file with one
hard link, existing content is never replaced, and a retry accepts identical
metadata. Unknown, altered or unsafe files require repair. The private transaction
is mode 0600; public non-secret policies/profile are 0644.

The job declares the fixed native owner Mach service and activated listeners. The
agent socket is root-owned and available to the owner's group; the owner socket
is root-only. The launchd job retains its process group for child cleanup. The
provisioner exclusively publishes the identical generated job at
`/Library/LaunchDaemons/com.fainir.accountaccess.broker.plist` and registers it
in the system domain. A retry preserves an identical existing registration;
an unknown or changed persistent job is refused before launch. Failed bootstrap
leaves the protected plist for retry. `REGISTERED` means launchd accepted the job,
not that owner enrollment or any website sign-in succeeded.

A non-login broker account has no interactive login to establish its Mach user
domain. Provisioning prepares that domain. The system-service entrypoint also
recreates it, after validating its fixed policy and identity, if it is missing
when the service starts again. This does not log the user in, grant additional
account permissions or create a vault key.

Before owner setup, the service must report `needs_owner` with no worker/key. The
[existing native enrollment](mac-initial-enrollment.md) and
[portable client connection](mac-agent-setup.md) remain separate authenticated
actions. Preparing installation files alone grants no website access.

## Disposable verification

Unit tests cover fixed paths, early privilege refusal, generated policy bindings,
exclusive/idempotent publication, unsafe existing files, Directory Services error
classification, interrupted record creation and UID conflicts. These use ordinary
user fixtures and do not create system accounts.

The disposable Mac journey uses the same publisher with a gated fixture layout,
ad-hoc pinned peers and a new temporary non-login identity. It checks idempotent
preparation, private empty state, profile/plan bindings and native connection to
the actual system entrypoint. It removes the broker's user domain before startup
to check recreation, then exercises pre-enrollment reads and refused setup. Cleanup
checks key absence, removes the QA setup rule, temporary jobs, identity and user
domain. It uses no private accounts or genuine positive owner approval.

The [current 37-check evidence](../artifacts/consumer-mail-setup-080.json) also
kills actual subprocesses after five empty private-directory staging/publication
boundaries and retries with the same reserved UID. Both Macs preserve a published
inode, require the exact UID/GID/0700 mode and remove only empty intermediates.
Two further kills occur immediately after public directory creation, before
validation or mask restoration, under an inherited 0777 mask. Retries preserve
the published inode and exact requested 0755/0700 mode.
This does not establish recovery from every provisioning step or physical power
loss; existing conflicting public directories still require repair.

Exact results and revision are recorded in [validation](validation.md). A reset
user bootstrap domain is not a full machine-reboot test. The generated job/profile
journey is not a downloaded consumer package, bundled-runtime installation or
notarization test. Current controlled package assembly, runtime provisioning and
same-image interrupted recovery pass. Signed consumer installation, interrupted
positive provisioning, migration/update continuity, genuine owner approval and
private email/SMS/authenticator/physical-device acceptance remain release gates. All root
installation experiments run only in disposable CI; the installed owner app and
its unfinished mailbox form remain untouched.

## Offline package assembly

`uv run python -m macos.system_package` builds an installer archive without
installing anything on the build host. Inputs are the protected-mode owner app,
matching broker/bootstrap executables, the pinned standalone Python 3.12.16 distribution,
a binary wheelhouse and the matching browser runtime. The wheel in the owner
app must match its signed hash. The runtime dependency hash lock comes from that
wheel. The current binary runtime requires Apple silicon and macOS 14 or later.
Consumer inspection and assembly also require `--pip-wheel` pointing to the
exact official `pip-26.2.2-py3-none-any.whl` pinned by `macos/runtime_ca.py`.
Only the Python-build-standalone release 20261026 Apple-silicon archive for
Python 3.12.16 is accepted. Its archive SHA-256 and extracted tree digest are
pinned in `macos/runtime_ca.py`. The assembler re-installs the same hash-pinned
pip wheel into fresh private copies so entry points target the protected
runtime path, then checks active pip, the ensurepip seed and bundled CA bytes.
Pip and ensurepip are never executed for this transformation; source inputs and
any installed runtime remain untouched. This does not audit other trust stores.
The assembler refuses Intel before opening supplied payload paths: the pinned
cryptography release has no Intel Mac wheel. Native universal builds do not
establish a usable Intel runtime, and source compilation is not an installer
fallback. See the [upstream removal](https://cryptography.io/en/50.0.2/changelog/#v49-0-0).

Build the owner variant with `ACCOUNT_ACCESS_SYSTEM_INSTALL=1` and an explicit
`ACCOUNT_ACCESS_MAC_BUILD` decimal number greater than historical build 76 when
invoking `macos/build.sh` (for example, `ACCOUNT_ACCESS_MAC_BUILD=77`). Its signed bundle requires protected registration, including
when that registration is missing; it cannot fall back to legacy credential
storage after an incomplete system installation.

Package construction uses Apple's `pkgbuild` and `productbuild`. All app bundles,
including nested browser bundles, have relocation disabled. A fresh install
refuses existing installation paths, app, job or service identity. It does not
migrate, erase or silently adopt an older installation. The maintainer builds the
complete runtime image before creating the archive. The root-volume script uses
that installed image to invoke the fixed system provisioner. No user needs
terminal commands, Python or a separate dependency download during this install.

A distribution build requires matching Developer ID application publishers and
an Installer signing identity. `--development` accepts ad-hoc artifacts and
creates an explicitly named development package; it does not weaken production
provisioning. The resulting package metadata always records `production_ready:
false`, `notarized: false` and `installed: false`. Building/signing a package is
not evidence of a successful consumer installation.

The assembler now inventories its private build copies, including native code
inside dependency wheels, before running the supplied Python. A production build
requires valid Developer ID Application signatures, secure timestamps, the target
architecture and hardened runtime for executables. It checks every native slice
and the enclosing app/framework bundle seals. Unsafe filesystem aliases, wheel
paths, symlinks, collisions and oversized/invalid native containers stop the build.
Development builds record an inventory with publisher verification explicitly
false. Neither mode changes the source payload or its dependency hash lock.

An optional maintainer preparation step now signs private runtime copies and
rebuilds native dependency wheels. It requires an exact input plan, verifies every
vendor wheel against the original app-pinned hash lock and leaves the project
wheel byte-for-byte intact. Rebuilt wheels get fresh `RECORD` hashes; obsolete
upstream wheel-signature files are removed rather than presented as still valid.
The installer receives a derived hash lock and a receipt binding original and
prepared artifacts, source/prepared runtime trees and the signing plan. The source
lock inside the app's pinned project wheel is unchanged.

The verifier and preparer do not notarize the package or establish installed
runtime compatibility. A real publisher, complete signed runtime compatibility,
Apple acceptance and positive consumer installation remain required. An Installer
signature protects the package, but does not establish these code properties or
runtime compatibility. Apple's
[notarization requirements](https://developer.apple.com/documentation/security/notarizing-macos-software-before-distribution)
apply to the executables being distributed. A production build must verify the
complete payload and its installed behavior, including binary extension modules,
before claiming a downloaded package is ready for consumers.

The CI package journey is intentionally negative: it runs Apple's actual
Installer on the development package in a fresh disposable VM, checks the final
protected offline runtime can import its dependencies, then checks refusal
before any vault, service identity or registration is created. It removes only
its new credential-free payload. It does not test a signed positive installation,
owner consent, migration, interrupted-install repair, notarization or private
accounts. The development package is not uploaded as a user download.

Apple's [packaging documentation](https://developer.apple.com/documentation/xcode/packaging-mac-software-for-distribution)
explains Installer signing. The standalone Python input follows the upstream
[distribution model](https://github.com/astral-sh/python-build-standalone/blob/main/docs/distributions.rst).

## Maintainer runtime preparation

These are release-engineering options, not end-user setup or per-agent commands.
Using the same input arguments as package assembly, add `--inspect-runtime` to
write `runtime-signing-plan.json` in a fresh output directory. Inspection does not
run the supplied Python, use a signing identity or create a package. It binds the
Python/browser trees and lists every native executable by content hash and path.
The generated entitlement dictionaries are empty for review.

Review the exact inputs and only the runtime exceptions each executable needs.
The plan permits explicit JIT, unsigned-executable-memory and library-validation
exceptions. Debugging, DYLD-environment and executable-page-protection exceptions
are not inherited from third-party signatures. Missing, extra, renamed or changed
executables and changed non-native runtime resources require a new review.

Build with `--runtime-plan /path/to/runtime-signing-plan.json` and
`--runtime-identity 'Developer ID Application: …'`, alongside the matching owner
app/broker and Installer identity. The tool signs only its private temporary build
copy, refuses external aliases/shared source inodes and privileged file modes,
checks the resulting publisher, and reseals nested bundles from the inside out.
Production native validation then runs before the interpreter/version probe.
The package embeds `runtime-preparation.json`; its public build report records
the same receipt, including original/prepared native-file hashes, bundle paths
and the unchanged project-wheel pin. No private key is exported or placed in
that receipt.

`--development --runtime-identity -` permits only an explicit ad-hoc fixture
identity and never reports publisher or notarization acceptance. A separate
ordinary-user disposable Mac probe exercises the actual dependency's Node binary
with a reviewed JIT permission and a sandboxed static-page browser. It uses a
synthetic wheel lock and stub runtime directories: it cannot establish complete
Python/browser preparation or positive publisher-signed consumer compatibility.
Exact passing results must be recorded in [validation](validation.md).

CI also builds a complete prepared development package after the original
unprepared-package regression. Its separate test profile explicitly disables
library validation for ad-hoc executables, which have no publisher team, and
enables JIT only for the Python/Node/Chromium fixture roles. This is not a
production permission plan or evidence that those exceptions are needed with a
real publisher.

The composed check runs Apple's actual Installer, binds the installed receipt,
derived requirements and original project lock, then checks native bytes at
their final Python/browser/site-package paths. It requires intact signatures,
bundle seals, root-controlled nonprivileged code, native crypto/validation and
CFFI/ctypes callbacks, and a sandboxed browser. The ad-hoc owner app must still
fail before service identity, vault or account setup. Cleanup preserves system
parent permissions and removes only its fresh credential-free payload. Passing
this check is controlled runtime compatibility; genuine publisher signing,
notarization, owner approval and positive consumer installation remain separate.

Revision `3c59a87` passed the complete 17-check prepared-install journey on two
disposable Macs, with identical sets of sixteen worker reports. The original
unprepared-package checks remain separate and pass too. Both main regression
runs passed 1,235 tests with seven skips. See the
[exact source, workflow links and sanitized reports](../artifacts/prepared-runtime-install-080.json).
The successful fixture does not establish that its explicit ad-hoc permission
exceptions are needed by, or sufficient for, a real publisher's runtime.

## Unfinished-install recovery work

The next package candidate includes a bounded public payload inventory in its
installer scripts and pins its SHA-256 in build metadata. It binds the fixed
support/app roots, every file's bytes and permissions, directory permissions and
internal aliases. Ambiguous names, external/intermediate alias escapes, shared
file inodes, privileged/writable modes, special objects and changed file
snapshots stop inventory generation before the supplied interpreter runs.
Source inputs and preparation receipts' exact permission modes are preserved.

The disposable package check now expands the actual archive and rebuilds that
inventory before invoking Installer. This is the identity foundation for a
subsequent protected recovery transaction. Retrying an existing installation is
still refused: the transaction and retry behavior are not yet implemented, and
this inventory alone grants no overwrite or deletion permission. The owner
installation is unchanged. The inventory passed independent archive binding on
two disposable Macs; see [exact evidence](../artifacts/package-recovery-inventory-080.json).

## Complete runtime image candidate

The assembler now copies the audited standalone Python into a separate complete
runtime and installs the exact locked wheels using PyPA `installer` 1.1.0. This
is an ordinary-user build operation in the private package staging directory.
It does not execute wheel code, run setup scripts or compile bytecode. Generated
entrypoints name the final system interpreter, rather than the temporary build
path. The administrator-level installer no longer creates a virtual environment,
runs pip or changes runtime permissions recursively.

Selection checks target CPython 3.12/macOS 14 architecture and markers, each
original artifact filename and approved hash, complete wheel checksum records,
metadata identity, Python requirements and the resolved dependency graph,
including extras. Prepared native wheels must also match this build's signing
receipt. An upstream wheel with generic internal platform metadata can narrow
its platform only through the verified original filename; renaming a Linux
artifact cannot turn it into an accepted Mac wheel. Startup-hook additions,
ambiguous/missing/unused distributions and destination escapes are refused.

The original Python, wheels and preparation receipts remain unchanged. The
complete copied runtime receives a second native-code audit, a byte/mode/alias
inventory and its own build receipt. The final package inventory binds both
copies. Disposable Mac acceptance compares the installed runtime against that
receipt before exercising imports, native callbacks and sandboxed browsing.
Revision `3a54663` passed real Installer acceptance on two disposable Macs, with
identical sixteen-report worker sets. Both original 12-check and prepared
19-check packages match the installed complete-image inventory and execute their
native/browser probes. Both full regression runs passed 1,342 tests with seven
platform skips. See [exact evidence](../artifacts/complete-runtime-image-080.json).
Interrupted-install retry, genuine publisher compatibility and positive consumer
setup remain separate work.

## Native public-image verification candidate

The next package candidate also carries a universal native verifier. After
Installer writes the fresh image, it verifies the fixed public support/app roots
against the package's bounded inventory before Python provisioning can run.
The package builder verifies the helper's publisher alongside the broker and
bootstrap. Archive acceptance additionally binds the helper in the scripts to
the exact executable in the public payload.

The verifier opens directory/file descriptors without following aliases, checks
ownership, permissions and ACLs, hashes regular files with stable metadata, and
requires the exact listed children. Alias text must match and resolve within
the inventoried root. It checks the app through a pinned descriptor and reopens
its namespace after hashing. The standard root:admin writable `/Applications`
parent is allowed for this read-only app check; privileged Python runs only from
the separate protected support tree. Shared system-parent permissions are not
changed. Ordinary invocation stops before reading installed paths.

The script records only the resulting public manifest digest and object counts,
after verification finishes and before Python runs. It creates that receipt
without overwriting an existing file. Disposable acceptance requires a matching
successful receipt; a failed or absent native check cannot count as installation
acceptance. The receipt grants no account access, retry or deletion authority.

The ordinary-user assembler also sends both source and final inventories to the
native parser through bounded stdin before packaging. This metadata-only mode
has no path argument, cannot run as root, and reports `INSPECTED`, which cannot
substitute for installed-image `VERIFIED` evidence. It binds the exact digest
and typed object counts. Invalid schemas, excessive alias work and directory
depth stop during the build. Assembly refuses root or unequal real/effective
identities before opening supplied payload paths.

Local checks cover 129 native, receipt, archive-binding and package cases, both
native architectures and a signed universal helper's ordinary-user refusal.
The first real Installer attempt refused its script-resource path beneath
`/private/tmp`: Apple uses this root-owned sticky shared directory for its
root-owned script sandbox. A separate tiny actual-Installer probe reproduced
the failure and recorded only public object metadata. The corrected resource
walk allows exactly this ancestor with mode `01777`, while requiring root
ownership, no ACL grants and protected non-alias children throughout. The sticky
directory prevents other users from renaming its root-owned child. This rule is
unavailable to installed payload walks; files and shared-parent permissions
remain unchanged. Thirteen ordinary-user synthetic cases exercise the boundary,
including missing sticky protection, writable children, ACLs and aliases.
The directory rule follows Apple's documented
[sticky-directory behavior](https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man2/chmod.2.html).

Revision `5802fde` passed the tiny actual-Installer check on two disposable Macs,
with identical native digests/counts (three public synthetic files and five
directories), exit zero, cleanup and unchanged shared-parent permissions. This
check neither provisions the service nor uses accounts. Complete-package
acceptance also passed on both Macs: identical sixteen-report worker sets,
original 13-check and prepared 20-check packages, including a matching native
verification receipt before privileged Python runs. Both regression runs passed
1,380 tests with 66 platform skips. The complete development inventory contains
64 native files, 23 executables, eleven bundles and 33 wheels. See
[exact-source evidence](../artifacts/native-install-verification-080.json).
These are development signatures and controlled inputs; positive consumer
installation and genuine owner approval remain unverified. That package refused
existing installations; the subsequent recovery implementation is described below.
The installed owner app and deferred Gmail form remain untouched.

## Resumable source-image installation

The candidate is a script-only package. PackageKit archives the public
image under its script resources and writes no automatic target payload. A
native guard verifies that immutable source before replacing itself with its
isolated interpreter. Only two verified public descriptors and a clean
environment cross that boundary. The Python coordinator accepts no destination,
identity, fixture or command overrides; it requires the real Mac root context.

An exclusive lease and private journal under
`/Library/Application Support/Account Access Installer` bind one exact manifest
and interactive owner. Existing unmanaged targets, a changed image/owner or
conflicting state stop without adoption or overwrite. The coordinator copies
missing public files into private staging, validates matching existing files,
and resumes only byte-for-byte matching temporary prefixes. Exclusive kernel
rename publishes each complete directory. Immutable, synced phase records bind
the published device/inode identities, covering a process death between the two
publications. Conflicting files and unknown data are preserved.

After publication, native code rechecks the installed public image before
provisioning. Fixed private branches remain opaque; they are neither traversed
nor copied. The verification receipt can be resumed but never replaces an
existing conflicting file. Package-bound publisher/hash identities constrain
the actual owner, broker and bootstrap peers before provisioning writes.
Synchronous privileged command children retain the install lease; the ordinary
owner app inherits no privileged handles. A completed same-image retry verifies
the image and reopens setup without repeating provisioning.

Revision `a777168` passed all eight push/PR workflows, including two complete
regressions with 1,445 passes and 74 platform skips each. The focused Mac suites
passed 744 cases with one platform skip each. Recovery checks include every
mutation checkpoint, eight actual SIGKILL scenarios, cross-process lock
exclusion, conflicting records/files, namespace replacement, read-only
temporaries, receipt recovery, native opaque-branch boundaries and changed
signed-peer refusal. Both native architectures type-check.

Actual Installer acceptance passed on two disposable Macs. Both produced
identical sixteen-report worker sets, including original 16-check and prepared
23-check package journeys. Each kills the actual coordinator after its protected
intent, reinstalls the same package and rechecks the published image without
replacing the public roots or receipt. A separate eight-check native handoff
fixture verifies process identity, public descriptors, clean environment and
unrelated-descriptor closure; it does not execute Python. The full-package
journey separately executes the real source runtime and materializes the image.
See [exact-source evidence](../artifacts/resumable-installer-080-a777168.json).

No such experiment runs on the owner's Mac. The unsigned development package
stops before owner setup, so actual completed consumer registration and
interrupted positive provisioning remain unverified. Positive consumer setup,
physical power loss/reboot and different-image updates/migration remain open.

The subsequent `b2dddbc` revision corrects direct publisher-requirement input to
`codesign`, with the predicate unchanged. All eight workflows pass; both focused
Mac suites pass 745 cases with one skip and no warnings. Package recovery reports
remain identical at 16/23 checks. Genuine Developer ID component checks and an
ordinary-user signed runtime now pass, including callbacks and headless browsing
with library validation enabled. These do not establish publisher-signed installed
deployment or genuine owner enrollment. See the [publisher check method](publisher-runtime-checks.md),
[current recovery evidence](../artifacts/resumable-installer-080.json) and
[genuine runtime evidence](../artifacts/publisher-runtime-080.json).
