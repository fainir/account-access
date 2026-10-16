# Reuse an approved GitHub sign-in from Chrome

The 0.8 candidate can copy an existing GitHub sign-in from Chrome into Account
Access. This can reduce repeated device approvals after you have signed in
normally. The broker verifies the website and expected GitHub username before
saving the session. The original approved task then resumes with the same read
permissions. This is session reuse, not proof that a fresh password/SMS login
works or a connection to Chrome's password vault.

1. In **Accounts**, choose **Use signed-in Chrome** for your already approved
   GitHub account. The action appears only for the reviewed GitHub profile read.
2. Confirm your GitHub username. It may be prefilled from an imported username;
   an email address cannot identify the GitHub session. Choose **Prepare Chrome
   connection**.
3. Update the existing Account Access helper once using **Reload** in Chrome
   Extensions. For a first install, load the app's `GoogleMessagesExtension`
   folder. The helper is named **Account Access — Browser Connections**.
4. Open your signed-in GitHub tab. In the helper, choose the requested account
   and **Connect this GitHub sign-in**. Review Chrome's optional permission prompt.
5. The app updates automatically after verification. Ask Codex, Claude Code or
   another supported agent normally; no command is required.

Requests expire after five minutes and can be cancelled in the app. A failed,
wrong-user, cancelled or revoked check leaves the previous connection and pending
challenge untouched. A verified connection clears login challenges and retains
independent transaction approvals. It never adds an account read or agent grant.

## Permission and custody

Cookies pass through Chrome's local native messaging pipe directly into the
encrypted broker. The agent API never returns them. The helper copies only
GitHub cookies from the selected tab's cookie store, including the correct
incognito store when available. It does not read Chrome's password database,
localStorage, page contents, authenticator keys or other sites' cookies for this
transfer. Partitioned-cookie sessions are currently rejected.

Chrome's optional `cookies` permission can cover other sites already granted to
the same helper, including Google Messages. The implemented transfer reads only
`https://github.com/`. GitHub site access and cookie permission are removed in
`finally`; a persistent cleanup alarm and browser-start cleanup cover an abandoned
popup or interrupted helper. The existing Google Messages permission is preserved
for the separately approved SMS connection. This limits the access window, not
the scope of Chrome's underlying permission while it is granted.

The broker accepts a bounded cookie state for the exact GitHub origin only after
a local owner request. Its check uses the existing fixed read destinations and
performs no automatic password login or code request. Identity/readiness,
configuration, expiry, permission revocation and cancellation are checked before
the encrypted session, resolved login challenge and request result are committed
together. Replaying a consumed request cannot open the website again.

The former `extensions/chrome` prototype is retired: unverified direct session
imports are refused. Use the app-created request and the current helper.

## Acceptance status

Controlled tests cover the actual browser verification, original-task resume,
native framing, wrong-user rejection, stale grants, late cancellation/expiry,
atomic rollback and the browser-helper cookie-store/permission contract. A real
extension load checks that site and cookie permissions are absent initially.
These tests are not private GitHub acceptance or a Chrome Web Store release.
Cookies can be device-bound or expire, and a provider can require fresh genuine
verification later. Private-account validation and consumer extension distribution
remain release gates.

See Chrome's official [cookie API](https://developer.chrome.com/docs/extensions/reference/api/cookies)
and [native messaging protocol](https://developer.chrome.com/docs/extensions/develop/concepts/native-messaging).
