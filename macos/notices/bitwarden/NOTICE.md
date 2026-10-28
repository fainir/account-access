Bitwarden CLI 2026.10.0 (OSS build)
Copyright Bitwarden Inc. and contributors.
GNU General Public License version 3. See GPL-3.0.txt.

This separate program is distributed with Account Access. It is not covered by
Account Access's MIT license. Bitwarden does not endorse Account Access.
No Bitwarden trademarks or logos are licensed by this distribution.

Account Access modifies the official npm CLI's build/bw.js and package.json,
dated 20 October 2026, to remove an unused external import and dependency
declarations. It omits that unused node-forge runtime component after checking
the original consumers and exact program hashes. Adjacent JavaScript and the
WebAssembly program remain unchanged. The upstream version stays 2026.10.0;
this is a local derivative, not an upstream patched release. No cryptographic
implementation or shared WebCrypto source is patched.
The dependency assembly applies the exact compatible security updates listed
in dependency-overrides.json. That ledger also retains the upstream advisory
and binds the documented derivation, original/derived bytes and removed path.
The CLI is invoked with a fixed protected Node 24.21.0 interpreter and native
addons disabled. The exact original npm archive and original/derived entrypoint
hashes are in runtime-manifest.json. No standalone executable or its embedded
Node is used.

The corresponding-source archive named in runtime-manifest.json must be
provided alongside the Account Access installer at no additional charge. It
contains the upstream GPL source, build instructions, lockfiles, the matching
Node interpreter source, and the locked runtime dependency sources. The archive's
SHA-256 is also recorded there. Do not publish the installer without that
source asset and clear adjacent download directions. No three-year written
offer is substituted for those source materials.

Additional bundled programs have their own licenses and copyright notices;
see THIRD_PARTY_NOTICES.txt and the corresponding-source archive. No warranty
is provided except as required by the applicable license or law. GPL recipients
may copy, modify and redistribute the covered program under that license.

The fixed interpreter/program paths and signed inventory protect the account service from
unapproved executable replacement. They do not restrict your GPL rights. See
BUILD.md in the source archive for rebuilding and running a modified CLI. Your
own private build does not require the Account Access publisher's private key.
