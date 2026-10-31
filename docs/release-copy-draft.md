# Account Access release copy draft

**Status: the publisher approved the complete 0.8.0 privacy notice and terms on 1 November 2026. They take effect with the public release. Store listing copy remains proposed; the product release remains a draft pending the recorded acceptance checks.**

## Publisher details

- Legal publisher name: **Nir Fainshtein**.
- Business status: **עוסק פטור**, as stated by the owner on 31 October 2026.
- Public support/privacy contact: **[welcometothebestplace@gmail.com](mailto:welcometothebestplace@gmail.com)**, chosen by the owner on 31 October 2026.

These details do not change the existing Apple-issued signing certificate identity.

## Short description

Account Access is a local-first macOS app that helps you manage approved sign-ins and verification for supported sites. Its optional Android companion can deliver an approved SMS login code to the local Mac service.

## Store listing draft

Account Access helps you keep sign-in details and verification inside a protected local workflow. Import a Chrome password export, choose which entries to save, connect an approved email or SMS verification source, or enroll an authenticator for a supported account. Local Codex and Claude Code sessions can request only the account operations you approve.

Account Access supports only reviewed connectors. It does not provide automatic Chrome password sync, arbitrary-site support, a cloud relay, insurance policy access, payments, policy changes or account recovery. Harel and Phoenix are not supported connectors yet. Verify a site's current compatibility in the app before relying on it.

## Approved privacy notice

The complete publication text is prepared in [Privacy notice](privacy.md).
The following short description is release-listing copy, not a replacement for
that notice.

Account Access keeps saved secrets in encrypted records on your Mac. Depending on features you enable, these may include login credentials, identity and phone details for a reviewed sign-in, email connection material, authenticator seeds, Android pairing material, approved site session state and task results. Configuration, record identifiers, permission and audit metadata are protected by local file permissions but are not all encrypted fields. Verification codes are handled for the active approved sign-in and must not be shared with an AI agent.

When you use a supported sign-in, the relevant website receives the information required by that site's login flow. When you connect Gmail or IMAP, the mail provider receives the connection requests and permissions required for the selected mailbox operation. Configured Gmail OAuth uses the mailbox-wide `gmail.readonly` scope; Account Access applies narrower login-message filters locally. Optional password-manager connections contact the selected provider for the approved item. When you pair Android, the phone sends matching SMS notification details to the Mac over pinned HTTPS on private Wi-Fi. Notification access is broad at the Android permission level, with sender/template filtering in the app. The current product is local-first and does not require an Account Access hosted account database or cloud SMS relay.

Local AI tools receive only their approved results and status. Those tools may transmit these results to their own AI providers. No publisher analytics, advertising or remote crash-report collector is configured in the application code; operating-system and provider diagnostics are separate.

You control which accounts and operations are connected. You can review, export and forget supported saved logins. Forgetting a login keeps its reviewed connector, shared verification sources and audit/task history; disconnect shared sources separately. Local configuration and history have no general automatic retention period in v1. Two-minute login-code expiry and the 24-hour structural-diagnostic display limit do not promise physical erasure or a background storage purge. Portable full-vault backup and restore of the installed protected service is not included in v1. A user-requested login CSV export contains a plaintext password and should be stored securely. Removing local data does not erase copies held by websites, email providers, Android, Chrome, AI tools, exports or backups.

The [data-handling disclosure](data-handling.md) records the verified technical details, permissions, recipients and removal limits for this candidate. For support or privacy requests, contact [welcometothebestplace@gmail.com](mailto:welcometothebestplace@gmail.com). Do not include passwords, verification codes or recovery keys. The owner approved the complete privacy notice and terms on 1 November 2026; do not request that approval again for these unchanged documents.

## Terms summary

The complete publication text is prepared in [Terms of use](terms.md).

Use Account Access only for accounts you own or are authorized to access. Review every requested account operation. Account Access supports only the sites and actions listed by the current app; it is not a password-recovery, insurance-advice, financial-transaction or policy-change service. Website providers can change their pages, authentication requirements and availability at any time. Never share passwords, recovery codes or one-time codes with an AI agent or in support messages.

This short summary does not replace the full terms or the repository's MIT
License. The publisher approved the complete privacy notice and terms on 1 November
2026. They take effect with the public release; the separate store listing
text has not been submitted or approved by a store.

## Pre-publication owner checklist

- Public privacy/support contact, legal publisher name and business status are recorded above. Add a mailing address if required by the chosen store.
- Have qualified counsel review the privacy notice and full terms for the release regions and intended users.
- Review the prepared [data-handling disclosure](data-handling.md), which has been checked against the candidate source. Recheck it if the release behavior changes; physical Android and private MFA acceptance remain separate ledger rows.
- Prepare store screenshots and data-safety answers from the release build; do not list Harel or Phoenix until their complete login journeys pass.
- Keep the public channel labeled preview until the Mac install, protected agent connection, supported login flows and rollback gates pass.
