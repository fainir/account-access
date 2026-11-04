# Installed one-time setup handoff - 4 November 2026

Best way: use Chrome's own export UI, then the installed app's native review.
Keep file contents, passwords and verification keys outside agent tools; save only
the explicitly selected connection and its narrow permission after owner approval.
This follows the existing [qualified setup contract](acceptance.md).

Native control is available again. The canonical installed owner app at
`/Library/Application Support/Account Access/owner.app` opens normally and exposes
Automatic sign-in, password import and authenticator transfer. Its Accounts screen
retains the same two service connections and separate public example.

The installed Codex launcher discovery reports service 0.8.0, worker RUNNING,
zero consecutive/total failures and browser READY. Its grants remain exactly
Namecheap status (paused), Betterloop status and public-example inventory. No
Namecheap or Lemon operation was submitted.

In personal Chrome, a separate tab was opened through Chrome > Passwords and
autofill > Google Password Manager > Settings. Its own export UI saved one file
locally in Downloads; the Save panel filename/destination were read back first.
Chrome reported Export successful, and the native app picker independently showed
the resulting file. The agent never opened or read its contents.

Account Access's native setup authorization completed and the review appeared.
The complete export has eight supported candidates and 815 unsupported entries.
Unlike the previous file, it includes Lemon Squeezy's reviewed authentication
origin and existing authenticator variant. All account checkboxes began unchecked.
Only Lemon Squeezy was selected, with the single permission "Confirm your Lemon
Squeezy sign-in status". Every other candidate remains unchecked, including the
existing Betterloop and paused Namecheap connections. The native option to move
the plaintext export to Trash after import remains checked. The app is scrolled
to its final Import selected accounts button, ready for the owner's approval.

No import/apply click, new credential/grant, file Trash or authenticator transfer
has occurred. Private account identifiers in the native screenshot remain only
in ignored local runtime; this public note intentionally omits them. No password,
code, QR/key, Chrome store or protected configuration file was read.

Next: the owner approves this exact selected import locally. Verify the saved
connection/grant through the installed launcher, then stage Google Authenticator's
existing-key transfer as the next single owner action. The completed manual Chrome
MFA, Betterloop import, mailbox setup and build-126 installation are not repeated.
Physical SMS, email-challenge acceptance, Namecheap and publication retain their
recorded limits. No package, source CI job or personal-enrollment monitor was created.
