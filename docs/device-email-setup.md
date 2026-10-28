# Connect PyPI confirmation email

The 0.8 development candidate can handle PyPI's new-device confirmation email
locally after a supported password and authenticator sign-in. Connect it once
in the app; your AI does not need a command, password, code or email link.
Private PyPI acceptance is still unverified. This feature is not in the 0.7.4
public download.

1. Import your PyPI login and approve the offered username read.
2. Enroll its authenticator locally in **Verification**. The email connection
   supplements that authenticator; it does not replace it.
3. Connect your email mailbox and check its connection. With a configured Google
   application, use **Connect with Google**; the app checks your mailbox address
   after consent. A saved Google connection can use **Check Google connection**
   without another password or consent prompt. The picker also supports saved
   TLS IMAP mailboxes, including Gmail connected with an app password.
   [Gmail and authenticator setup](gmail-authenticator-and-sms.md).
4. In **Verification → PyPI · Device confirmation email**, choose that mailbox
   and click **Review email connection**.
5. Check the email address and the existing approved reads, then click
   **Confirm email connection**.

No password needs to be entered again when choosing an already checked mailbox.
The owner approves this setup once; routine supported sign-ins can then handle
a matching confirmation email automatically. Saving setup does not establish
that PyPI sent an email or that delivery succeeded. The setup card labels delivery
unverified; the separate website check reports whether sign-in completed.

A Google connection appears after its mailbox address has been checked. Selecting
it grants no additional website reads: review and confirm the intended email
connection once. Ordinary Google token refresh keeps the binding working; a new
Google consent or changed account requires checking and reviewing it again.
The publisher's registered Google application remains necessary for browser
consent. The public preview does not include that registration; Google accounts
without app passwords need a configured Google connection.

## Change or disconnect

Use **Disconnect device email** to remove the binding. It remains available when
the saved mailbox is missing or needs attention. You can also choose another
checked mailbox to replace a broken connection. Other websites using a shared
mailbox keep their own connections.

Healthy changes retain only the same still-valid approved account reads. A
revoked or expired permission is not restored. After an interrupted change,
reopen **Verification** to inspect its saved state. If account permissions need
review, approve the intended reads again locally. The app preserves the saved
website password and authenticator rather than requesting them again.

## Email access and scope

The mailbox connection grants email access. Account Access uses it for fresh,
matching PyPI login messages during an active approved sign-in. Setup itself
fetches no messages and starts no website login. The recipient, sender, subject
and message purpose come from the reviewed connection; the AI cannot choose a
mailbox, a filter or a confirmation URL.

PyPI verifies its confirmation link. Account Access keeps that link, credentials,
authenticator key and browser session outside agent responses. The resulting
operation reads only the already approved signed-in username; it does not fetch
the projects page. Provider passkeys, biometric checks, recovery and mandatory
human approval remain owner actions. [Provider policy and limits](other-service-validation.md).
