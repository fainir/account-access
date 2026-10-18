# Automatic updates from 1Password

Account Access can follow password changes for an exact login in 1Password. It
does not import additional accounts or permissions in the background. Chrome
CSV imports remain snapshots; this connection does not enable Chrome live sync.

## Connect without running a Connect server

Choose **1Password service account** in **Password sync**. This uses the official
1Password SDK and does not require the 1Password CLI or a Connect server.

1. Import the website login into Account Access and approve the supported reads.
2. In 1Password, create a dedicated vault containing only logins you want Account
   Access to use. Create a service account with **read** permission for that
   vault. Keep write and sharing permissions disabled. Built-in Personal,
   Private, Employee and default Shared vaults cannot be used with service accounts.
3. In Account Access, select the imported account and **1Password service
   account**. Enter the service token, vault ID and exact item ID locally.
4. Select **Connect automatic updates**. Account Access checks the item against
   the imported username and the approved website before saving the connection.

Do not paste the token, password or an authenticator key into an AI conversation.
The token is encrypted in Account Access's private store. The AI receives only
the result of an approved account operation.

These requirements come from 1Password's [SDK authentication guide](https://www.1password.dev/sdks)
and [service-account setup guide](https://www.1password.dev/service-accounts/get-started).
This is administrator-style enrollment. It is not a one-click connection to
every personal 1Password vault. Desktop-app approval is a separate supported
1Password mechanism, and Account Access does not silently fall back to it.

## When a password changes

While the service runs, it checks linked items about every five minutes and
checks again before a new password sign-in when the previous check is due. A
changed password replaces the encrypted credential and clears the cached
website session in one transaction. Existing operation grants remain unchanged.
The source never silently changes the username, website, connector or TOTP key.

A changed item identity, missing built-in username/password field, mismatched
website, or removed source access blocks a new sign-in. Timeouts and SDK rate
limits retry automatically. Other SDK failures use a fixed attention state; a
later successful check repairs the source prerequisite without a new grant.
No provider error text is exposed to the agent.

Disconnecting removes the local service token, cached credential and website
session for that link. If the same service token was enrolled for other links,
those links remain connected. Revoke the token in 1Password to revoke its vault
authority everywhere. Saving a new imported or edited credential disconnects its
previous source so a later background update cannot overwrite the owner's edit.

## How the local read is contained

The runtime pins `onepassword-sdk==0.4.1` and its wheel hashes. Each read starts a
fresh isolated Python process from the installed runtime. It passes the token
through a private pipe, removes inherited CLI/proxy/Python environment settings,
uses a new temporary home and working directory, suppresses SDK diagnostics,
caps pipe messages at 64 KiB, and kills and reaps a stalled process group after
20 seconds. The SDK request itself has a 15-second deadline. Temporary files and
the SDK process are removed when the read ends.

The integration calls only the exact-item API with the approved vault and item
IDs. It returns only the standard username and password for the approved
origin. It does not enumerate a vault, resolve OTPs, download files, follow item
references or use the desktop app. A service token may have authority over
everything in its configured vault; the dedicated read-only vault is the
provider-side limit, and Account Access's exact-item binding is the local limit.

The official wheels cover the candidate's Python 3.12/3.13 Mac and Linux
runtimes. macOS 14 or later is required. The Linux SDK requires glibc 2.32 or
later. The installer refuses to build native dependencies from source.

## Existing 1Password Connect deployments

Choose **1Password Connect** instead and enter the HTTPS server origin,
read-only token, vault ID and item ID. Existing links retain their format and
continue to work. No Connect token is used as a service-account token or vice
versa. Both providers use the same account identity checks, update scheduling
and revocation behavior.

## Validation limit

Contract tests use fictional items and tokens. The native runtime smoke test
loads the real SDK and verifies that a deliberately invalid synthetic token is
rejected without returning credentials. These checks do not establish a
successful connection to a private 1Password account. Genuine service-account
enrollment, real password rotation and revocation still need acceptance testing
before this provider is described as production verified.
