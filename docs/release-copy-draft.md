# Account Access release copy draft

**Status: owner/legal review required. Do not publish this draft or accept it as terms.**

## Short description

Account Access is a local-first macOS app that helps you manage approved sign-ins and verification for supported sites. Its optional Android companion can deliver an approved SMS login code to the local Mac service.

## Store listing draft

Account Access helps you keep sign-in details and verification inside a protected local workflow. Import a Chrome password export, choose which entries to save, connect an approved email or SMS verification source, or enroll an authenticator for a supported account. Local Codex and Claude Code sessions can request only the account operations you approve.

Account Access supports only reviewed connectors. It does not provide automatic Chrome password sync, arbitrary-site support, a cloud relay, insurance policy access, payments, policy changes or account recovery. Harel and Phoenix are not supported connectors yet. Verify a site's current compatibility in the app before relying on it.

## Privacy notice draft

Account Access is designed to keep the account data you save in its encrypted local store on your Mac. Depending on features you enable, that store may contain login credentials, identity and phone details for a reviewed sign-in, email connection material, authenticator seeds, Android pairing material, approved site session state and backup data. Verification codes are handled for the active approved sign-in and must not be shared with an AI agent.

When you use a supported sign-in, the relevant website receives the information required by that site's login flow. When you connect Gmail or IMAP, the mail provider receives the connection requests and permissions required for the selected mailbox operation. When you pair Android, the phone and Mac use the approved local connection to deliver matching SMS verification data. The current product is local-first and does not require an Account Access hosted account database or cloud SMS relay.

You control which accounts and operations are connected. You can review, export and forget supported saved logins. Portable full-vault backup and restore of the installed protected service is not included in v1. A user-requested export may contain plaintext and should be stored securely. Deleting data from Account Access does not erase copies held by websites, email providers, Android, Chrome or backups you created elsewhere.

Before publication, the owner must verify the final release's analytics and diagnostic behavior, retention details, exact Android permissions, mailbox scopes, supported-site list, deletion behavior and the contact address for privacy requests. No public support or privacy contact has been supplied in this draft.

## Terms summary draft

Use Account Access only for accounts you own or are authorized to access. Review every requested account operation. Account Access supports only the sites and actions listed by the current app; it is not a password-recovery, insurance-advice, financial-transaction or policy-change service. Website providers can change their pages, authentication requirements and availability at any time. Never share passwords, recovery codes or one-time codes with an AI agent or in support messages.

This summary is not a complete agreement and makes no warranty or liability determination. Obtain owner/legal review and complete the required jurisdiction-specific terms before publication.

## Pre-publication owner checklist

- Supply the legal publisher name, privacy/support contact and mailing address if required by the chosen store.
- Have qualified counsel review the privacy notice and full terms for the release regions and intended users.
- Verify analytics, crash reporting, diagnostics, retention, deletion, Android permissions and every external data recipient against the final signed build.
- Prepare store screenshots and data-safety answers from the release build; do not list Harel or Phoenix until their complete login journeys pass.
- Keep the public channel labeled preview until the Mac install, protected agent connection, supported login flows and rollback gates pass.
