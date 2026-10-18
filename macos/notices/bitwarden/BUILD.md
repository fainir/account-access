# Bitwarden CLI corresponding source

This archive accompanies the official OSS npm CLI 2026.10.0 JavaScript/WebAssembly program. The adjacent
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

Account Access uses the official npm archive's `build/bw.js`, adjacent JavaScript
chunks/locales and WebAssembly SDK. It does not distribute the standalone
executable's older embedded Node or pkg-fetch patches. `node-source.tar.xz`
contains Node 24.21.0; the protected Node executable is supplied by the pinned
Playwright wheel. The exact official npm dependency closure is derived from the
included clients lockfile without running install scripts. Source-index records
the selected npm dependency archives and the pinned Node source hash. The
adjacent dependency-overrides.json records exact compatible security updates
to multer, tmp, ws, qs and its side-channel dependency. Account Access applies
these data-only replacements after resolving the original pinned lock; no
upstream entrypoint bytes or cryptographic implementation are patched. To
reproduce the aggregate, use those replacement versions/archives at their
recorded node_modules paths, preserving the original lockfile for provenance.
The remaining node-forge advisory and fixed-command applicability review are
explicitly retained in that ledger; there is no official patched release.

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
the exact scripts used. The official CLI program bytes are not modified; dependency files are
assembled at the paths selected by its pinned lockfile, and notice files are
added to the aggregate. The protected service's reviewed hash policy intentionally
refuses silently substituting another executable; test custom service builds in
a disposable environment with your own owner-approved publisher policy.

The independent Account Access application remains under its own MIT license;
the separate Bitwarden program, its SDK and dependency notices retain their
upstream terms. These materials are supplied without an additional source fee.
