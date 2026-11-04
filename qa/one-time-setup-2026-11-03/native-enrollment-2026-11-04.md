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

## Import completed after the reported failure

The owner confirmed native setup approval and reported that the import did not
work. On inspection the app was back at its initial import page and discovery
still had only the original three accounts. No earlier error remained visible,
so the prior failure cause is not established. In particular, preview expiry
was not observed and must not be stated as the cause.

The same export was still available in the native Downloads picker. A fresh
native preview was created without re-exporting or reading the file. Only Lemon
Squeezy and its same status permission were selected. The exact import completed:

- Native result: Passwords imported; selected login encrypted locally.
- Installed discovery: new personal-lemonsqueezy, environment live, only status
  with description Confirm your Lemon Squeezy sign-in status.
- The original three accounts/grants remain present; Namecheap was not retried.
- Worker RUNNING/zero failures and browser READY.
- Native account check: website took too long to connect; configuration preserved.
- One permitted installed status read: RETRYABLE, browser_execution_failed.
- Native Verification exposes the matching unenrolled Lemon authenticator source.

This verifies the saved import/grant, not private sign-in or MFA. No authenticator
seed, code or QR was read, supplied or enrolled; no additional private sign-in
retry follows the one diagnostic read.

Investigation D20: public unauthenticated application navigation presents an auth
redirect interstitial ([provider response](https://app.lemonsqueezy.com/dashboard)).
The existing controlled fixture jumps directly from the dashboard to the password
form, omitting that intermediate route. Reproduce the failure with a controlled
interstitial before changing any routing. Keep the fixed approved destinations,
POST validation and session-only result. This is a candidate explanation, not a
confirmed live root cause. Chrome diagnostic control was interrupted by changed
app state, then timed out; no product conclusion comes from that failed control.

## Controlled routing repair

A controlled application gate now reproduces the extra auth-redirect route.
With the original runner and a working pinned Chromium, all three new cases
failed with the same RETRYABLE/browser_execution_failed result: fresh/reused/expired
session, missing authenticator and disabled authenticator. [Before repair](d20-before-fix.log).
The initial local attempts had a removed browser cache and were not valid routing
evidence; the recorded before-repair run followed the pinned headless install.

The candidate enters the already permitted authentication URL for session-only
checks that have an exact server-page readiness marker. Other operations keep
their original start URL. The status operation, allowed origins/resources/POSTs,
connector fingerprint, stored credentials and existing grants are unchanged.
It does not permit the intermediate query route or execute its scripts.

All [94 focused browser/provider/import/security cases](d20-source-regression.log)
pass, including actual local password/TOTP, warm-session reuse, expired-session
recovery and refusal before password submission when the source is missing or
disabled. All [14 existing publisher profile checks](d20-image-profile.log) pass;
the image CLI accepts 127 against the exact qualified 126 predecessor. Ruff and
git diff checks pass. The current native owner compilation workflow now targets
127 while retaining all old build choices.

This proves the repaired controlled behavior. It does not establish that the
owner’s live failure has the same cause, nor claim installed 127 or private MFA.
Source/owner CI, signed matching delivery and installed read-back must follow.
No new installer, source/grant changes on the owner Mac or authenticator import
have occurred during this source qualification.
