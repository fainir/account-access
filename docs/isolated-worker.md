# Separate-user worker component

The 0.8 candidate includes an internal POSIX worker entry point for a trusted
service supervisor. It is not enabled by the consumer installer. The installed
Mac app still runs under the owner's identity and therefore does not isolate
credentials from unrestricted agents running as that user.

The supervisor must provision a root-owned runtime and policy, create a
dedicated non-root broker identity distinct from the agent, and keep the vault
directory private to that identity. It must launch isolated Python with a
sanitized environment. On Linux the worker also requires `NoNewPrivs` and empty
capability sets. Root and the supervisor are trusted.

The worker accepts an existing enrolled store only. A root-created inherited
pipe carries exactly 32 vault-key bytes and 32 owner-channel secret bytes, then
EOF. Neither value is accepted through arguments, environment variables, a key
file or the logged-in user's keyring. The pipe is bounded, consumed once and
closed. Disabling core dumps and zeroing the temporary buffer do not guarantee
erasure of all Python or cryptographic-library copies from memory.

Two root-created Unix listeners are inherited separately. The agent socket
exposes only the scoped API and requires its client credential. The private
owner socket sits inside a root-only directory and additionally requires its
separate owner capability and exact Host/Origin. A non-secret root-owned policy
binds both paths, state directory and identities. The worker cannot grant an
agent access to the private listener's directory. Browser-session transfer,
interactive browser handoff, local installation and host-specific phone setup
are disabled in this transport; they require a future trusted host gateway.

## Acceptance

`worker-boundary.yml` builds a root-owned runtime in a disposable Ubuntu VM and
creates two locked system accounts with no administrator rights. The synthetic
harness checks approved API and browser password/email/SMS/TOTP reads through the CLI;
ungranted operations; revocation; vault/configuration access; code and policy
modification; process memory, environment and descriptors; signaling; and the
private owner channel. Email uses a TLS test mailbox; SMS uses a synthetic
handset over the paired, certificate-checked HTTPS ingress. These are not public
email/carrier delivery or physical-phone acceptance. It retains only fixed test metadata. It uses no personal
website accounts, phone inbox, mailbox or installed owner store.

The root-only harness is CI machinery, not a service installation command. It
must not be run against a user's Mac or an existing service deployment.

The [Mac launcher](mac-worker.md) also passed
[25 cross-user checks](../artifacts/mac-worker-boundary-080.json) in a disposable
Mac VM. It validates the root-owned runtime and its descendants, adopts the
dedicated user's execution context, permanently drops UID/GID and closes
unapproved descriptors in the kernel at image replacement. Two temporary
non-admin users exercised the real broker and synthetic authentication sources.
The additional native tests reject writable code reached directly or through a
directory alias, before key handoff. This does not deploy a consumer root service.

## Still required

This component needs a production supervisor with key custody, authenticated
owner enrollment, secure client issuance and migration, lifecycle/recovery,
audited packaging and update policy. The Mac consumer path also needs its
approved service installation and integration of the tested
[native owner-channel component](mac-owner-gateway.md). Its internal root host
passed 24 deployment checks beside the worker in a disposable Mac VM; genuine
owner approval and approved consumer installation remain unverified. Private email,
SMS and authenticator acceptance, physical phones and independent security
review remain open. Passing the Linux component test does not close those gates
or make the complete product production-ready.
