# Bitwarden runtime and source assets

The Mac candidate uses the official OSS npm CLI 2026.10.0, its locked JavaScript
dependencies and WebAssembly SDK. It invokes the existing protected Playwright
Node 24.21.0 with `--no-global-search-paths --no-addons`. It adds no standalone
executable, embedded Node, shell launcher, npm invocation or install script.

`macos/bitwarden-cli.lock.json` fixes the official npm archive, entrypoint,
clients/SDK commits, runtime dependencies, Playwright wheel and Node input hashes.
`macos/bitwarden-overrides.lock.json` records exact compatible security updates
applied to the dependency assembly; the official CLI entrypoint remains
unchanged. The corresponding-source archive includes this ledger verbatim.
Consumer assembly requires these additional maintainer inputs:

```sh
--bitwarden-archive /absolute/path/to/cli-2026.10.0.tgz \
--bitwarden-sources /absolute/path/to/account-access-bitwarden-2026.10.0-corresponding-source.tar.gz \
--bitwarden-source-sha256 REVIEWED_SOURCE_SHA256
```

Prepare the separate source asset as an ordinary maintainer, before package
assembly:

```sh
python -m macos.bitwarden_sources --output /absolute/path/to/new-source-directory
```

This fetches immutable public data, verifies lockfile integrity and source
checksums, and retains the upstream licenses. It executes no upstream program.
Downloads must remain HTTPS on the reviewed hosts at every redirect. Source
archive member size, count, type and total bounds are checked before advancing
past each member. A previously reviewed public source asset can be reused with
`--reuse-sources PATH --reuse-sha256 SHA256`; the original is preserved.

The runtime is assembled into `python/libexec/bitwarden` before the existing
runtime preparation/signing step. The final image contains
`runtime/libexec/bitwarden/build/bw.js`, its adjacent assets/dependencies,
GPL text, dependency notices and `runtime-manifest.json`. The manifest records
the required separate source asset and its reviewed digest. The existing
native signing plan covers the reused Playwright Node; no additional native
signing exception is needed. The Python tree digest changes when this program
and notices are staged and must be reviewed normally.

The source asset contains the preferred upstream clients/SDK source, SDK Rust
dependencies, the actual npm runtime dependency archives, matching Node source,
build instructions and attribution evidence. Some dependency archives include
generated JavaScript. Their presence is not an independent determination that
every dependency's preferred development source or every license obligation has
been audited. The exact-hash supplemental notice catalog distinguishes upstream
license files, original notice excerpts and published SPDX declarations; it
does not infer a copyright notice from an author name.

Publish the corresponding-source asset alongside every binary installer that
contains this GPL program, with clear adjacent download directions and no
additional charge. Publishing the installer alone is incomplete. The MIT
Account Access application retains its own license; the separate Bitwarden
program and dependencies retain their upstream terms.

The anonymous compatibility probe validates version, an empty profile, SDK
generation and EU configuration with the protected Node flags and hardened
runtime with only `allow-jit`; library validation remains enabled. It uses no
personal account and does not establish private enrollment, password rotation
or delivery acceptance.

The 19 October 2026 registry audit found advisories in the original dependency
closure. The reviewed assembly updates multer to 2.4.0, tmp to 0.2.7, ws to 8.21.3,
qs to 6.16.1 and its required side-channel dependency to 1.1.1. These address the
published [multer](https://github.com/advisories/GHSA-3pph-fpjx-jg34),
[tmp](https://github.com/advisories/GHSA-ph9p-34f9-6g65),
[ws](https://github.com/advisories/GHSA-96hv-2xvq-fx4p) and
[qs](https://github.com/advisories/GHSA-4mjr-xmp4-gh2g) findings. A fresh audit of
the resulting 191 packages at 222 dependency paths retains the following finding.

The [node-forge RSA verification advisory](https://github.com/advisories/GHSA-86w9-cpqp-85rv)
still affects its latest official release 1.4.0; no patched version was available
at review time. It remains in the audit report. The exact official CLI bundle's
forge namespace is imported but never used; the adjacent chunks contain no
forge calls and no transitive dependency consumes forge. The CLI constructs
NodeCryptoFunctionService, which uses native Node crypto and SDK WASM rather
than forge RSA signature verification. Independent review identified no
reachable affected verification within the fixed allowed commands: version,
status, server configuration, API-key login, unlock, forced sync and exact-item
get. This command-scoped review does not certify the whole package as safe.
Recheck upstream releases/advisories before each distribution; no advisory is
silently removed and no cryptographic implementation is patched locally.

The packaging verifier now enforces these review assumptions before publishing
a runtime. The residual advisory ledger binds the exact worker source, every
official CLI JavaScript asset, the entrypoint and the reviewed command list.
It checks that the sole forge namespace remains an unused binding, rejects
another forge import in adjacent JavaScript, and checks the actual resolved
dependency graph for additional forge consumers or versions. Updating archive
and entrypoint pins alone cannot carry a stale review forward. Mutation tests
exercise new direct and alias consumers, an adjacent chunk consumer, changed
worker/command metadata and a removed or silently cleared advisory through the
real verifier. This is a release guard for the bounded review; the advisory
remains `under_investigation`, with no whole-package non-exploitability claim.

The ledger is copied verbatim into both the runtime and corresponding-source
asset. Its new review bindings therefore require a new corresponding-source
archive and reviewed digest before the next package assembly. Older source
archives and build 74 evidence retain their original hashes and are not relabeled
as having passed this newer guard.
