# Betterloop private-account acceptance - 2 November 2026

## Method

Use Chrome's documented local export and the existing native selected-account
import. The app/protected service handles credentials; agents receive only the
explicitly approved operation result. This follows [Google's export flow](https://support.google.com/chrome/answer/13068232)
and the project's established import/grant boundary. No runtime or installer
change was needed.

## Actual native journey

The owner supplied the Chrome export in Downloads and confirmed the staged
import action with “i did”. Initial read-back still showed the selected review,
normal discovery had no Betterloop account, and the export still existed. The
approved import had not occurred, so it was completed once from that existing
review rather than loading/importing the file again.

Exactly Betterloop was checked. Every other supported row was unchecked. Its
sole permission was “Confirm your Betterloop sign-in status”; the local plaintext
export-to-Trash option was checked. After the final action, the real installed
0.8.0/build-123 app showed “Passwords imported / Betterloop Connected / Sign-in
verified. This approved account is ready for your AI.”

The [native success screenshot](import-connected.png) was read and inspected;
it contains no account email, password, unrelated login or verification code.
Returning to Accounts showed Betterloop Connected, Automatic agent integration,
one ready private service out of two configured services, and the existing ready
public example. Namecheap remained paused at its existing unsupported device
challenge. No Namecheap retry or other imported-account grant was created.

## Installed agent operations

Normal installed discovery added personal-betterloop with environment=live and
only status permitted. Both actual installed launchers then completed that
operation successfully:

- [Codex result](codex-status.json): COMPLETED, environment=live,
  data={"authenticated":true}.
- [Claude Code result](claude-status.json): COMPLETED, environment=live,
  data={"authenticated":true}.

Both exited zero. Result validation confirmed that provider data contains only
that boolean; no page text, account email, project, billing or API-key value was
returned. The native import exercised the real saved email/password sign-in;
the two agent reads subsequently verified the approved authenticated session.
This is private-provider acceptance, not a public example or synthetic fixture.

## Data and scope limits

The agent never opened the password CSV, browser password database, credential
file, vault key or login code. The app handled the selected credential locally.
The original plaintext CSV is now absent from Downloads. The app completed its
selected Trash action before presenting success; independent Trash-directory
metadata access was denied, so destination contents were not inspected. No
permanent deletion or emptying Trash was attempted.

This closes D15 and adds real private-account evidence to F2/F6. Betterloop uses
email/password here; no email/SMS/TOTP challenge was encountered. F3/F4/F5 and
physical-phone acceptance remain unverified. The customer release remains an
unpublished draft. No signing, rebuild, upload, new signup, scope expansion or
legal reapproval occurred.
