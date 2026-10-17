# Protected Mac installation provisioning

`account_access.system_provision` prepares and registers a fresh system installation after a
trusted package has installed its immutable payload. It does not elevate itself,
download code, initialize a vault, create keys, import credentials or obtain
owner approval. The production entrypoint accepts no arguments or environment
path overrides and requires root on macOS. The published preview does not use it.

## Payload and identity

Production locations are fixed under `/Library/Application Support/Account Access`.
The owner app is `/Applications/Account Access.app`. The payload must already
contain the managed Python runtime, browsers, signed broker and signed permanent
identity-drop bootstrap. Static signature checks require matching publisher teams,
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

Exact results and revision are recorded in [validation](validation.md). A reset
user bootstrap domain is not a full machine-reboot test. The generated job/profile
journey is not a downloaded consumer package, bundled-runtime installation or
notarization test. Package assembly, trusted runtime provisioning, interrupted
package recovery, migration/update continuity, genuine owner approval and private
email/SMS/authenticator/physical-device acceptance remain release gates. All root
installation experiments run only in disposable CI; the installed owner app and
its unfinished mailbox form remain untouched.

## Offline package assembly

`uv run python -m macos.system_package` builds an installer archive without
installing anything on the build host. Inputs are the protected-mode owner app,
matching broker/bootstrap executables, a standalone Python 3.12 distribution,
a binary wheelhouse and the matching browser runtime. The wheel in the owner
app must match its signed hash. The runtime dependency hash lock comes from that
wheel. The package is specific to Apple Silicon or Intel and requires macOS 14.

Build the owner variant with `ACCOUNT_ACCESS_SYSTEM_INSTALL=1` when invoking
`macos/build.sh`. Its signed bundle requires protected registration, including
when that registration is missing; it cannot fall back to legacy credential
storage after an incomplete system installation.

Package construction uses Apple's `pkgbuild` and `productbuild`. All app bundles,
including nested browser bundles, have relocation disabled. A fresh install
refuses existing installation paths, app, job or service identity. It does not
migrate, erase or silently adopt an older installation. Its root-volume script
creates the virtual environment at the final path using the included Python,
installs binary wheels offline with required hashes, protects the resulting
runtime and invokes the fixed system provisioner. No user needs terminal
commands, Python or a separate dependency download during this install.

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
the same receipt. No private key is exported or placed in that receipt.

`--development --runtime-identity -` permits only an explicit ad-hoc fixture
identity and never reports publisher or notarization acceptance. A separate
ordinary-user disposable Mac probe exercises the actual dependency's Node binary
with a reviewed JIT permission and a sandboxed static-page browser. It uses a
synthetic wheel lock and stub runtime directories: it cannot establish complete
Python/browser preparation or positive publisher-signed consumer compatibility.
Exact passing results must be recorded in [validation](validation.md).
