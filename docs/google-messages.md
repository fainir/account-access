# Google Messages login SMS

The 0.8 development candidate includes an optional **Account Access — Browser Connections**
Chrome extension for a Google Messages conversations tab already paired to an
Android phone. This first adapter supports the reviewed GitHub login message
template only. It is not a Google API or a general inbox connector.

## One-time connection

1. Pair [Google Messages for Web](https://messages.google.com/web/conversations)
   to your phone using Google's normal device-pairing flow. Keep one conversations
   tab open, with the conversation list at the top.
2. Import the matching GitHub password and approve its supported read in Account
   Access. An imported password alone does not create a website connector.
3. In **Verification**, choose **Set up Google Messages**, review the scope and
   click **Prepare browser connection**. This registers a local native host for
   the exact extension identity and opens its folder.
4. This preview requires a local extension installation: in Chrome Extensions,
   enable Developer mode, choose **Load unpacked**, and select the
   `GoogleMessagesExtension` folder opened by Account Access.
5. Open **Account Access — Browser Connections** in Chrome, select the reviewed GitHub
   account, click **Connect GitHub login texts**, and approve access to
   `messages.google.com` in Chrome's permission prompt.

The service then checks the approved website sign-in automatically. Later agent
requests use the same installed skill/CLI, with no SMS-copying command. The account
is verified only when the website check succeeds. The app's **Disable this
verification method** action cancels its window; the extension removes its site
permission when no Google Messages source remains enabled.

Google requires an online paired phone and browser. Only one computer can be
active at a time, and inactive pairings can expire. Initial phone unlock and
pairing use Google's genuine owner flow. [Google's setup and device limits](https://support.google.com/messages/answer/7611075?hl=en).

## Protected Mac candidate

The isolated installation now has a separate native SMS host. **Prepare browser
connection** registers that app entrypoint and opens the extension inside the
installed app's resources. It does not reopen the legacy vault or copy extension
code into a user-writable credential folder. Registration first checks that all
six resource files match the protected runtime's extension payload. An existing
unknown or unsafe registration requires review rather than silent replacement.

The host accepts the exact public extension origin and verifies that its parent
is signed stable Google Chrome under the same OS user. It rechecks that parent
around each protected request. The app connects through the pinned native owner
channel. **Connect GitHub login texts** requires the normal macOS setup approval;
later active-login polls and SMS replies need no new approval. The worker still
checks the enrolled source and login window before accepting a delivery. No
password, vault key, cookie export or code-retrieval operation is available in
this bridge. The preview's browser-session import is not enabled through it.

The host uses Chrome's documented framed stdin/stdout protocol, with a smaller
64 KiB application limit and fixed message shapes.
[Chrome native messaging documentation](https://developer.chrome.com/docs/extensions/develop/concepts/native-messaging).

[18 native component checks](../artifacts/mac-browser-bridge-080.json), temporary
registration tests and a separate private worker/DOM/browser fixture passed.
The complete installed Chrome/native/XPC/worker path, positive parent validation,
genuine owner approval, physical delivery and consumer installation remain
unverified. The current parent policy does not include Chrome Beta, Chromium or
Chrome for Testing. Web Store distribution remains required for the final simple
consumer setup; loading an unpacked folder is still a developer-preview step.

The installed app/resources are protected from ordinary owner-user writes by
the isolated package. Chrome's per-user registration and the browser itself
remain under the owner's control. This does not isolate an inbox from software
already authorized to control that Chrome profile or protect a compromised browser.

## What stays local

The SMS feature requests optional access to `https://messages.google.com/*`,
plus Chrome storage, scripting, alarms and native messaging. Chrome's site
permission technically permits reading and changing that site's pages; this
connector implements only reading and has no send, delete or mark-read operation.
Cookie permission is absent by default and is not required for SMS. A separate
[GitHub session-transfer action](browser-sessions.md) can request temporary cookie
and GitHub site access; it removes both after the transfer. Chrome's cookie
permission can also cover sites already granted to the helper while enabled.
The helper has no debugger or arbitrary-website permission. It registers its reader
only after the owner connects it. No website scripts or AI instructions can change
its template, destinations or approved account reads.

Before password submission, the service opens a short login window and waits for
the paired tab to establish a baseline. Existing texts are excluded, even if their
visible age is “Now.” Only newly appearing matching texts ahead of the original
list boundary, or a changed message in an existing thread, can be eligible.
Changed pages, scrolling, lost state, unknown/localized timestamps and expired
windows stop safely. The current timestamp parser supports the English “Now,”
“Just now,” “0 min ago” and seconds-ago labels.

Matching codes travel through Chrome's local native messaging pipe, enter the
encrypted pending window, and are submitted only to the reviewed GitHub login
form. The agent API never receives them. Duplicate delivery is idempotent; several
new matching codes are delivered as one batch and require attention instead of
silently choosing one. Source revocation and changed enrollment are checked again
before the browser fills a code. There is no SMS content log or cloud relay.

GitHub rotates SMS sender numbers. This adapter explicitly uses the exact GitHub
login-message template and a pending-login arrival boundary, rather than a fixed
sender number. It does **not** cryptographically authenticate SMS senders. A forged
matching text can disrupt a login; the browser's fixed destinations and
transaction-challenge checks still apply. This source is unsuitable where stronger
sender authentication is required.

## Validation and remaining gates

The real paired page's selectors, full template availability and timestamp shape
were inspected with code values excluded from the result. Fresh-message checks
have not yet established a completed private sign-in. Synthetic tests cover the
DOM reader, cached messages, native framing/origin checks, window freshness,
revocation, ambiguity and password → SMS → browser verification. A real extension
load was checked in a separate temporary Chromium profile with site access absent
initially. These tests do not establish physical-phone reliability.

Chrome Web Store distribution, broader language/DOM coverage and live private
account acceptance remain release gates. Local unpacked-extension setup is a
developer-preview path, not the final consumer installation experience.
