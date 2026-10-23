# Read-only store registration check

This development diagnostic is for the exact public image installed by repair
package 85. It helps distinguish a stale publication device number from changed
directory identities without replacing the running broker to add diagnostics.
It does not repair the store or establish successful account access.

The builder runs as an ordinary user. It binds committed helper, builder and
wrapper sources, verifies the already installed public Python interpreter, and
assembles a package with no payload. It expands the package and compares both
scripts, modes and byte hashes before producing its review record. Building it
does not execute the diagnostic. The package is unsigned and not a consumer
release.

Run the reviewed package only through native macOS Installer after local owner
approval. The helper accepts no arguments, path overrides or alternate runtime.
Its entrypoint requires the fixed isolated interpreter with site loading and
bytecode writes disabled. It checks the fixed broker, package-identity and app
metadata hashes before reading registration metadata.

The read scope is limited to:

- Three root-owned program policies: enrollment, worker and worker launcher.
- The existing enrollment lock and the root-owned publication record and its
  authorization, ready and pause markers.
- Metadata for the two registered store directories. Their contents are never
  opened or enumerated.

It uses a nonblocking shared lock, refuses unsafe file metadata and aliases,
checks schema/identities and rereads observed metadata for stability. There are
no database, credential, client-token, Keychain, network or service-control APIs.
It creates no files and does not change keys, registrations, permissions or
account grants. Installer's own ordinary package receipt/log handling is separate.

The only output is a fixed status and reason with Boolean scope fields. No path,
UUID, inode, device number, account identifier, raw policy or exception text is
emitted. `registration_matches` means only that the publication registration
matches the observed directory pair and ready marker. It does not prove that the
key can be loaded or a worker can start. `device_number_changed` is a refusal;
matching inode values alone do not prove the same persistent volume.

The 60 ordinary-user tests use fictional registration files and simulated broker
ownership. They cover both classifications, concurrent enrollment, pause,
malformed bindings, unsafe file substitution and the prohibition on opening or
enumerating store contents. They are not owner-Mac diagnostic acceptance.
