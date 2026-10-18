# Bitwarden password updates

Account Access accepts reviewed Bitwarden CSV and unencrypted JSON imports.
They are snapshots. Import a fresh export after changing a password. This does
not establish a continuous connection to a Bitwarden personal vault.

The public interfaces were checked on 18 October 2026:

- The [Password Manager Public API](https://bitwarden.com/help/bitwarden-apis/)
  manages organization administration. Vault items use the separate Vault
  Management API, which runs through a local Bitwarden CLI server.
- A [personal API key](https://bitwarden.com/help/personal-api-key/) authenticates
  the CLI but does not replace vault decryption. Reading a password still needs
  an unlocked client, except for the documented organization Key Connector case.
- A CLI [session key](https://bitwarden.com/help/cli/#using-a-session-key)
  decrypts vault data and supports more than the one approved item. The local
  `serve` interface exposes CLI actions; it is not a provider-issued read token
  restricted to that item.
- The [official CLI source documentation](https://github.com/bitwarden/clients/blob/main/apps/cli/README.md#unlock-with-desktop-biometrics)
  describes an interactive desktop biometric unlock in Desktop 2026.9.0 or
  newer, behind a feature flag. It can fall back to a master-password prompt and
  is skipped in noninteractive mode. It does not provide unattended exact-item
  authorization to the separate Account Access service.
- [Secrets Manager](https://bitwarden.com/help/secrets-manager-overview/) has
  machine accounts and access tokens for its own key/value secrets. That is a
  different source from a saved Password Manager login. Connecting a manually
  copied Secrets Manager value would not continuously follow the original login.
- The [Agent Access SDK](https://github.com/bitwarden/agent-access) can request a
  specific item, but remains an early preview with a local interactive provider
  backed by `bw`. Bitwarden's [documented workflow](https://bitwarden.com/blog/shadow-ai-agents-how-to-secure-credential-access-with-agent-access-sdk/)
  requires fresh human approval for each release. That is not an unattended
  standing exact-item sync authorization, and this review does not remove its
  approval step or treat its demonstration credentials as private acceptance.

No continuous Bitwarden provider is shipped on the basis of these interfaces.
Account Access does not collect a Bitwarden master password, retain an unlocked
personal CLI profile, start its full-vault HTTP server, or run commands from an
agent-supplied shell. Existing owner data was not accessed for this review.

## Pinned standalone-client feasibility

The official [CLI 2026.10.0 release](https://github.com/bitwarden/clients/releases/tag/cli-v2026.10.0)
includes an OSS macOS ARM64 archive, despite the installation guide's older
ARM64/npm advice. Its SHA-256 is
`1fe8f48b9d8c823af3b034368449fffba3e8f3fe738d64207671bdff635c048d`.
The archive contains only `bw`, not a source or license bundle.

A private extracted copy passed `--version`, unauthenticated `status`, and a
password-generation command after Developer ID signing with hardened runtime
and **only** the `allow-jit` entitlement. Library validation remained enabled;
the upstream `allow-unsigned-executable-memory` entitlement was removed. Every
command used a fresh private HOME/TMPDIR, stripped environment and no input.
Only `data.json` appeared in that directory; this observation does not audit
other extraction paths. The pinned client
[loads its WebAssembly SDK before commands](https://github.com/bitwarden/clients/blob/cli-v2026.10.0/apps/cli/src/platform/services/cli-sdk-load.service.ts).
Optional desktop IPC and private login were not accepted by this probe.

This is feasibility evidence, **not a shipped sync connection**. No personal
profile, password, API key or account was used. Login, remote rotation,
revocation, owner enrollment and installed-runtime containment remain untested.
Any redistribution also needs the applicable
[upstream licenses](https://github.com/bitwarden/clients/blob/cli-v2026.10.0/LICENSE.txt),
corresponding source/build inputs and dependency notices; a link to the binary
alone does not provide those materials. No Bitwarden binary was added to the
repository or installer.

A future integration needs a supported, explicitly enrolled source with bounded
read-only authority, protected executable inputs, reliable revocation, and
checked website/username/item binding. Contract fixtures alone would not prove
private Bitwarden enrollment, rotation or delivery. The existing
[1Password exact-item source](onepassword-sync.md) remains a separate opt-in
option; its private acceptance is also unverified.
