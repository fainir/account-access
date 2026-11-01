# Private authenticator acceptance - 1 November 2026

At 08:38 Asia/Jerusalem, after the owner said “i checked it”, the installed
`/Library/Application Support/Account Access/owner.app` showed Read the Docs
selected and **Confirm your signed-in Read the Docs username** checked.
The username and secure password fields were empty; **Connect account** and
**Use saved sign-in** were disabled. No account had been saved.

Installed `scripts/access accounts` independently returned only the existing
paused live Namecheap account and connected public shopping example. Browser
status was READY; recovery was RUNNING with zero failures. No private operation
was submitted and no credential, code or seed was read.

F5 remains owner acceptance. The already-staged action needs the owner's existing
Read the Docs credentials entered only in the native form and **Connect account**.
The checked permission alone does not verify connection or a TOTP login. If the
owner does not own this account, no signup is requested.
