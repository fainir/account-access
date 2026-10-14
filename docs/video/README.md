# Install, import and use Account Access

[Watch the computer walkthrough](https://github.com/fainir/account-access/releases/download/v0.5.0/account-access-install-import-and-verify.mp4) · [Captions](install-import-and-verify.vtt)

[![Actual installation, import and Claude Code result](install-import-and-verify-preview.png)](https://github.com/fainir/account-access/releases/download/v0.5.0/account-access-install-import-and-verify.mp4)

The recording shows the native Mac installer, local verification settings, password import review, the actual Claude Code desktop interface and actual browser form submissions. Every application and website pixel comes from recorded footage. The edit adds narration and caption bars, shortens waits, crops window padding, slows login playback and holds the final result for reading.

The flow is:

1. Open Account Access and click **Install Account Access**. The portable skill and CLI are installed automatically; Codex and Claude Code are detected without an agent-choice screen.
2. Connect the configured email source and review the SMS setup instructions.
3. Import a compatible password export, approve specific account reads, and explicitly opt into included authenticator keys.
4. Copy the request, open Claude Code and ask for four permitted summaries in one saved task.
5. Watch automatic password, authenticator, email and SMS login steps, followed by Claude's completed result.

The four accounts and all credentials/messages are controlled examples. Email uses an actual TLS IMAP server with synthetic delivery. SMS uses a Messages-format SQLite fixture; the video does not establish delivery from a carrier, physical iPhone or Gmail mailbox. The Mac permission screen is described, but broad disk access was not granted for the recording. The separate [Android emulator journey passed](https://github.com/fainir/account-access/actions/runs/38543728385), including an actual Android notification, Keystore-encrypted pairing, pinned HTTPS delivery and browser code submission. Physical phones remain unvalidated.

The sample export is a Chrome-compatible CSV with a supported authenticator column. It was created for these examples, rather than extracted from the user's private Chrome vault. No private password or authenticator export appears in the recording. The selected export was moved to Trash after import; Trash is recoverable and was not emptied.

Claude completed task `1133af469fc3e7f5ecce38a7536b2c65` at **4/4** with no owner input during the task. The four login recordings occurred after the example sessions were expired. Its saved tool-output receipt was inspected in Claude after a Mac restart removed the temporary vault. Setup was repeated for additional recorded takes after that restart; the walkthrough is edited footage, not one continuous take. A separate task through this Codex desktop session completed **4/4** and exercised the same three verification factors. [Machine-readable evidence](../../artifacts/video/install-import-and-verify.json) records receipts, source hashes, validation links and limits.

The app installed the published checksum-verified 0.5.0 wheel; dependency downloads were cached. The configured recording build uses a separate example vault and app identity to keep it separate from the normal installation. The normal installed app and portable skill were restored after filming. The Mac preview is Developer ID signed; **Apple notarization is pending**, and Gatekeeper may block a fresh download. This recording does not demonstrate a clean-Mac notarized installation.

Reviewed connectors and standing permissions determine available operations. Importing a password does not add a connector for an arbitrary website. Passwords, cookies and codes are excluded from agent results; an agent with unrestricted same-user shell access is outside the local custody boundary. Genuine passkey, biometric, device or administrator approval remains an owner action. Both AI hosts used their existing approval settings.

Reproduce the edit on macOS with ffmpeg, Pillow and the private captures/receipts:

```sh
python scripts/make_verification_walkthrough.py \
  --work /path/to/recordings \
  --output /path/to/account-access-install-import-and-verify.mp4
```

The [previous three-account walkthrough](https://github.com/fainir/account-access/releases/download/v0.4.1/account-access-install-and-use.mp4) and [legacy overview](legacy-guide.md) describe older setup flows.
