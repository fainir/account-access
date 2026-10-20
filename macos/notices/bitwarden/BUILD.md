# Bitwarden CLI corresponding source

This archive accompanies Account Access's CLI-specific derivative of the OSS npm CLI
2026.10.0 JavaScript/WebAssembly program. The upstream version remains 2026.10.0;
this is not an upstream patched release. The adjacent
`source-index.json` records exact source commits, URLs, hashes and dependency
archives. It excludes `bitwarden_license` directories and the commercial SDK;
those inputs are not used by the OSS build. Keep all included license notices.

The clients snapshot is commit
`b449ac1d255784380d75ef026343198891286be7`; the OSS SDK source is commit
`c5e53d3e82ab80fdc9fd79ebd74058399a6444b6`. The upstream build workflow is
`.github/workflows/build-cli.yml`. The complete upstream package lock is
included. General purpose, unmodified build tools can be obtained with those
lockfiles; this archive also includes the locked runtime dependencies.

To build a modified CLI on a Mac, unpack `clients-source.tar.gz`, use Node 24.21.0 (compatible with the upstream Node >=22 requirement)
and npm 11.18.0 as the upstream workflow specifies, then run at that source root:

```sh
npm ci
rm -rf node_modules/@bitwarden/commercial-sdk-internal
cd apps/cli
npm run build:oss:prod
```

Account Access derives `build/bw.js` and `package.json` from exact official npm
bytes. It removes one unused external import and the corresponding dependency
declarations; the adjacent JavaScript chunks/locales and WebAssembly SDK stay
unchanged. The modified files identify the Account Access change dated
20 October 2026. No RSA, ASN.1, MD5 or other cryptographic implementation is
patched. In particular, the shared upstream WebCrypto service remains unchanged.
It does not distribute the standalone
executable's older embedded Node or pkg-fetch patches. `node-source.tar.xz`
contains Node 24.21.0; the protected Node executable is supplied by the pinned
Playwright wheel. The exact official npm dependency closure is derived from the
included clients lockfile without running install scripts. Source-index records
the selected npm dependency archives and the pinned Node source hash. The
adjacent dependency-overrides.json records exact compatible security updates
to multer, tmp, ws, qs and its side-channel dependency. Account Access applies
these data-only replacements after resolving the original pinned lock. Only
`node_modules/node-forge` is then omitted, after checking that no other resolved
dependency consumes it and the sole import binding is unused. The conservative
source materials retain its original source for upstream provenance. To
reproduce the aggregate, use the recorded replacement versions/archives and omit
that one reviewed runtime path, preserving the original lockfile. The upstream
node-forge advisory remains explicitly retained; no official patched release is
claimed.

The included `account-access-cli.lock.json` records original and derived
entrypoint hashes. `dependency-overrides.json` records exact original/derived
package metadata hashes and the derivation script's hash. To reproduce the two
modified files, unpack the official archive selected by those pins into a local
directory, then run this included data-only script as an ordinary user:

```sh
python account-access-cli-derivation.py \
  --cli-directory /path/to/unpacked/official/package \
  --output /path/to/new/derived-overlay
```

It checks all three original JavaScript assets and metadata, refuses unknown
consumers or changed input/output hashes, and writes only `build/bw.js` and
`package.json` into a new overlay. Apply those two files to a separate copy of
the official CLI tree and omit `node_modules/node-forge` from its dependency
assembly. It executes no CLI, npm, upstream script or network request. The
original files remain intact. Rebuilding changed upstream TypeScript rather
than the exact official archive can produce different bytes; review that custom
output and adjust your own build's pins and derivation accordingly. No publisher
authorization or secret is needed for your private rebuild.

The SDK's Rust preferred source, Cargo.lock, Cargo registry source archives and
pinned passkey-rs source are included separately. The SDK snapshot's
`crates/bitwarden-wasm-internal/README.md` and
`.github/workflows/build-wasm-internal.yml` specify its OSS build:

```sh
rustup target add wasm32-unknown-unknown
brew install binaryen
cd crates/bitwarden-wasm-internal/npm
npm ci
cd ..
./build.sh -r
```

Use the Rust toolchain selected by that snapshot's `rust-toolchain.toml`. The
generated OSS package is in its `npm` directory. From the clients source root,
`npm link /absolute/path/to/sdk/crates/bitwarden-wasm-internal/npm` links that
modified SDK before rebuilding the CLI. Do not pass the commercial `-b` flag,
substitute the commercial SDK, or change the GPL choice for OSS sources.

The output is `apps/cli/build/bw.js`, its adjacent build assets and the runtime
npm dependencies. Run a modified build using your own compatible Node >=22:

```sh
node --no-global-search-paths --no-addons apps/cli/build/bw.js --version
```

No Account Access publisher secret or authorization key is needed to rebuild or
run this separate program. Account Access invokes its installed copy through a
fixed protected Node/JavaScript argument vector and disables native addons.
It never invokes npm, install scripts, a shell shebang, or an owner-selected Node.

Account Access's sources include its aggregation, signing and packaging code in
`macos/bitwarden_runtime.py`, `macos/runtime_prepare.py` and
`macos/system_package.py`. The release's Account Access source revision records
the exact scripts used. Only the two documented CLI files are modified by this
derivative; dependency files are assembled at the reviewed paths and notice
files are added. The protected service's reviewed hash policy intentionally
refuses silently substituting another executable; test custom service builds in
a disposable environment with your own owner-approved publisher policy.

The independent Account Access application remains under its own MIT license;
the separate Bitwarden program, its SDK and dependency notices retain their
upstream terms. These materials are supplied without an additional source fee.
