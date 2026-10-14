# Download, connect and use Account Access

[Watch the 85-second explainer](https://github.com/fainir/account-access/releases/download/v0.6.0/account-access-gmail-authenticator-sms.mp4) · [Captions](gmail-authenticator-sms.vtt) · [Setup guide](../gmail-authenticator-and-sms.md) · [Recording evidence](../../artifacts/video/gmail-authenticator-sms.json)

[![Claude Code returns the four completed account results](gmail-authenticator-sms-preview.jpg)](https://github.com/fainir/account-access/releases/download/v0.6.0/account-access-gmail-authenticator-sms.mp4)

Account Access handles supported sign-ins for existing AI tools. Connect saved logins and verification sources once, then ask your AI for account work in ordinary language. The software handles routine password and code challenges, reducing repeated login interruptions. Personal approvals still need the owner.

The new narration explains the Gmail app-password route, how a website's original authenticator key can generate the same codes as Google Authenticator on your phone, and that iPhone/Android pairing is for codes arriving by **SMS text message**. [Read the narration](gmail-authenticator-sms-narration.txt).

| Time | Action |
| --- | --- |
| 0:00 | Download and open the Mac app |
| 0:05 | Install; existing AI tools connect automatically |
| 0:11 | Import saved passwords and approve account reads |
| 0:19 | Show the configured Gmail address/app-password fields |
| 0:31 | Show iPhone Messages and Android companion setup for SMS codes |
| 0:42 | Import the website's original authenticator setup QR/key |
| 0:55 | Ask Claude Code normally, without a command or skill name |
| 1:02 | Watch automatic password, authenticator, email and SMS sign-ins |
| 1:20 | Read Claude's four completed results |

The computer footage comes from Chrome, Finder, the native 0.6 app, Claude Code and actual browser form submissions. Narration and caption strips explain the actions; the edit crops windows, shortens waits and slows website login clips. There are no slides or generated application screens. Setup uses several recorded takes, with the new Gmail/phone guide footage combined with the original verified task.

The Gmail form is configured for `imap.gmail.com:993`. An example Gmail address and masked example app password are entered locally, **without submitting them**. The video does not record creating a real Google credential or completing Gmail consent/connection. Google recommends Sign in with Google; a reviewed Gmail OAuth connection is supported when configured, but the public preview does not bundle a ready-to-use Google OAuth application. The separate [setup guide](../gmail-authenticator-and-sms.md) links Google's current instructions and explains app-password availability.

Google Authenticator remains on your phone. Account Access uses an explicitly enrolled copy of the **website's original setup key** to generate codes on the computer. It does not read the phone screen or fetch Authenticator keys through Gmail. The preview supports standard website TOTP setup QR/keys; Google's Transfer/Export QR format is not supported. No physical Google Authenticator app was tested for this recording.

The phone connections are for SMS. iPhone forwards texts to Messages on the Mac; Android uses the paired notification companion. The new footage shows their instructions, without granting broad Mac permission or pairing a physical phone. Recorded SMS delivery uses a Messages-format test database. The [Android emulator journey](../../android/README.md) is separate evidence, not a physical-phone test.

The retained Claude prompt was **“Summarize my four connected accounts and save the results as one task. Keep it short.”** Task `1e13faf6ade0621229dfb2f2c4dd6ff2` was independently inspected through the installed client at **4/4 completed**. The four website recordings come from fresh logins after example sessions expired, during this task. No further owner password/code input occurred after the request. Existing Claude approval settings were retained.

Atlas Membership, Juniper Workspace, Beacon Rewards and Orbit Travel are fictional accounts. Their password export is synthetic; the user's private Chrome vault was not accessed. The retained email login uses real local TLS IMAP with synthetic delivery, and the authenticator code is generated locally from an explicitly enrolled test key. The new Gmail tutorial is not the source of that recorded email-code delivery.

The original install used the public checksum-verified 0.6 archive/bootstrap and cached browser dependencies. Configured recording copies use an isolated vault, app identity and installation paths. The new setup copy also saves its app inside the private recording folder. The earlier recording app had copied itself back over the canonical launcher during reopening; the normal signed 0.6 app was restored again, its binary/signature checked, and its normal three-account dashboard opened. Normal client tokens and standing grants were checked unchanged. The [original evidence](../../artifacts/video/quickstart.json) includes this restoration correction. Apple notarization remains pending; this does not demonstrate a clean-Mac notarized download opening.

Importing passwords does not add unsupported website connectors. Fingerprint, passkey, push, device and administrator approvals remain owner actions.

Reproduce the edit on macOS with ffmpeg, Pillow and the private source recordings:

```sh
python scripts/make_quickstart_video.py \
  --work /path/to/recordings \
  --output /path/to/account-access-gmail-authenticator-sms.mp4 \
  --verification-guide
```

Earlier recordings: [75-second explainer](https://github.com/fainir/account-access/releases/download/v0.6.0/account-access-explainer.mp4), [original quickstart](https://github.com/fainir/account-access/releases/download/v0.6.0/account-access-quickstart.mp4), and [0.5 walkthrough](https://github.com/fainir/account-access/releases/download/v0.5.0/account-access-install-import-and-verify.mp4).
