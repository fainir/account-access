# Automatic password updates from Bitwarden

The 0.8 development candidate can keep an approved website login's password
current through a separately connected Bitwarden Password Manager account.
This is not included in the 0.7.4 public download. The protected Mac runtime
must include the reviewed Bitwarden component; otherwise setup offers repair
and file import remains available. Private Bitwarden acceptance is unfinished.

## Connect once

1. Import and approve a supported login from a local Bitwarden **unencrypted
   JSON** export. Account Access remembers that selected item's ID without
   retaining unrelated entries. Import alone does not connect your vault.
2. In **Password sync**, choose **Connect Bitwarden** and your United States or
   Europe server region. Self-hosted servers are not supported by this source.
3. In Bitwarden's web vault, open **Settings → Security → Keys → View API key**.
   Enter the personal client ID, client secret and your master password only in
   the local Account Access form. Review its vault-access explanation and connect.
4. Choose the approved website login and connected vault, then enable its password
   updates. A valid JSON import fills the exact item ID automatically. The
   advanced item-ID field is available for older exports and CSV imports.

Bitwarden documents the [personal API key](https://bitwarden.com/help/personal-api-key/)
and its separate [vault session key](https://bitwarden.com/help/cli/#using-a-session-key).
An API key alone cannot decrypt saved passwords. Account Access uses the master
password for this initial unlock and does not save it. It retains the separate
CLI profile and decryption session encrypted in the protected local service.

**That session can decrypt the whole vault.** Bitwarden does not issue a token
restricted to one personal password item. Account Access's own link checks limit
which item it fetches and which approved website can receive the password. This
is an application boundary, not a provider-enforced exact-item permission. The
setup requires explicit consent to this broader local authority.

## After setup

Ask your agent for the approved account read in ordinary language. Password
checks run when due, every five minutes and before a password login. The source
must confirm a fresh remote sync; a cached item cannot stand in for that check.
A changed password clears the saved browser session so the next login uses the
updated value. Unchanged passwords allow session reuse. No new owner approval is
needed for these routine checks.

The source must keep the same vault identity, item, website origin and username.
Deleted, archived, re-prompted or changed-identity items stop the link. Mobile-only,
regular-expression and **Never** URI entries cannot authorize a website. Sync
does not change account permissions or enroll an authenticator key.

Temporary source failures stop password use and retry automatically. Removed
access or identity changes need a local repair. A fresh explicit vault connection
gets a new generation; review and reconnect its existing item links rather than
silently reviving them. Mandatory provider presence and organization policies can
still prevent unattended use.

## Disconnect

**Disconnect Bitwarden vault** removes its saved local profile/session and clears
the still-linked passwords and browser sessions. Approved account-read grants
remain, but they cannot use the removed credential source. A password explicitly
replaced through local editing or a new import is no longer linked and is not
deleted by that source's disconnect.

An active browser operation keeps the original source enrollment. Disconnecting
or replacing that enrollment stops subsequent password/code entry, new browser
requests and saved-session publication. A request already sent to a website
cannot be recalled. Short local browser commands serialize with disconnect;
waiting for a website, message or owner does not hold that authority lock.

Source-bound browsing currently supports the attached main-frame transport,
including its XHR/fetch requests. Child-frame and worker requests stop with
`password_source_browser_surface_unsupported`; they do not fall back to an
unchecked transport. Websites that require those surfaces need further reviewed
support. This restriction applies to the Bitwarden connection.

This is a separate Bitwarden client. Locking the Bitwarden desktop app or browser
extension does not disconnect Account Access. To withdraw access, disconnect here
and, when needed, revoke the client/API access in Bitwarden itself. Local removal
cannot retract a provider request already in flight.

## Runtime and verification

The protected Mac package stages the pinned official OSS JavaScript/WebAssembly
CLI and its locked dependencies. It uses the package's protected Node runtime
with global module lookup and native addons disabled. Each invocation has a new
private HOME/TMPDIR, a stripped environment, bounded pipes and a deadline. It
cannot discover a separate Bitwarden desktop helper. No shell, CLI server,
agent-selected executable or existing owner CLI profile is used.

The installer build requires the matching source archive and dependency notices
as adjacent release materials. See [the source build notes](../macos/notices/bitwarden/BUILD.md).
Controlled tests cover import, source enrollment, exact-item rotation, browser
session reuse, changed-password reauthentication, revocation, concurrent writes
and secret redaction. Those tests do not prove a private Bitwarden connection or
the complete product's [production gates](production-gates.md).
