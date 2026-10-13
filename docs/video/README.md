# Beginner video: install and use Account Access

[Watch or download the video](https://github.com/fainir/account-access/releases/download/v0.3.1/account-access-walkthrough.mp4) · [English SRT captions](https://github.com/fainir/account-access/releases/download/v0.3.1/account-access-walkthrough.en.srt)

![Video preview](poster.jpg)

This **3:09, 1080p English walkthrough** has synthetic narration and visible captions. It uses macOS and Account Access **0.3.1**. Installation waits are shortened, terminal output is abridged, and verified agent results are reformatted for readability. The owner-console image is captured from the actual application. It is an edited tutorial, not an uncut desktop recording.

No real financial or personal accounts are shown. The demo's balances are fictional. Codex and Claude Code each completed a three-account task; the service independently verified their results. See [video evidence](../../artifacts/video/evidence.json). The displayed prompts are suitable for users; the CLI verification runs used the repository's [smoke harness](../../scripts/agent_smoke.py) with existing agent logins and hooks.

## Chapters

| Time | Topic |
| --- | --- |
| 0:00 | What Account Access does |
| 0:13 | What you need |
| 0:27 | Download the repository |
| 0:38 | Install Python and Chromium |
| 0:52 | Install the command |
| 1:05 | Start the demo and install the skills |
| 1:20 | Check the connection |
| 1:31 | Use Codex |
| 1:48 | Use Claude Code |
| 2:03 | Owner console and real-account setup |
| 2:19 | Passwords and verification codes |
| 2:37 | Troubleshooting |
| 2:52 | Try your first task |

## Before you start

Use a Mac or Linux computer with Git and [uv](https://docs.astral.sh/uv/getting-started/installation/) installed. Codex or Claude Code should already be installed and signed in. You can also use the client without an AI agent. No AI API key or personal website credentials are needed for this demo.

Native Windows transport is not implemented. On Linux, follow [browser dependencies and sandbox setup](../setup.md#linux-sandbox-setup).

## Copy the installation commands

Open Terminal. Run these commands in order, waiting for each to finish:

```sh
git clone https://github.com/fainir/account-access.git
cd account-access
uv sync --locked --python 3.13
uv run playwright install chromium
uv build
uv tool install --python 3.13 --force ./dist/account_access-0.3.1-py3-none-any.whl
```

On Linux, use `uv run playwright install --with-deps chromium` for the browser installation and review the sandbox instructions linked above. That command may request administrator access for OS libraries.

If `account-access` is not found, run `uv tool update-shell`, then open a new terminal. The skill launcher also needs `python3`: if that command is missing, run `uv python install 3.13 --default`, then `uv tool update-shell` and open a new terminal.

## Start the demo

```sh
account-access --root "$HOME/.local/share/account-access-demo" demo --install
```

**Leave this terminal open.** The command starts the service, prepares the synthetic accounts, and installs the skill for Codex and Claude Code. Re-running it refreshes demo client identities. Use the separate demo directory shown here; never run the demo against a real-account vault.

In a second terminal, check the connection:

```sh
python3 "$HOME/.agents/skills/account-access/scripts/access.py" doctor
```

Look for `"status": "OK"` and `"service_reachable": true`.

## Ask your agent

In a fresh **Codex** chat:

> Use $account-access to read one permitted operation from every connected demo account. Save progress as a task and label the results as demo data.

In a fresh **Claude Code** session:

> /account-access Read one permitted operation from every connected demo account, save progress as a task, and label the results as demo data.

The successful demo results are:

| Account | Method exercised | Synthetic balance |
| --- | --- | --- |
| `demo-api` | OAuth API | 1,234.56 ILS |
| `demo-web` | Password and browser session | 987.65 ILS |
| `demo-mfa` | Password and enrolled authenticator TOTP | 987.65 ILS |

The agent discovers permitted operations, submits a task and waits for the results. You do not type the demo password or verification code.

Without an agent, you can try one read directly:

```sh
python3 "$HOME/.agents/skills/account-access/scripts/access.py" run demo-api summary
```

## Move from the demo to a real account

A reviewed connector with defined destinations, operations and authentication markers must exist first. Follow [real-account setup](../setup.md#real-account-setup) to initialize that configuration, install the agent clients, run the service and open `account-access setup` in a second terminal. The real-account commands use a separate storage directory and the OS keyring.

In the owner console, enter credentials locally, connect or repair access, and choose which operations each agent may use. Saved passwords are not displayed back to the console. The demonstration form shows a synthetic account with blank credential fields.

Current authentication coverage:

- Passwords: enter once in local setup; no password-manager import is shipped.
- Authenticator TOTP: explicitly enroll a login-only secret; the service generates codes.
- Email/SMS: configured Gmail and Twilio adapters have contract tests; live delivery is not validated.
- Existing iPhone/Android SMS inboxes: no native companion or universal capture is shipped.
- Fingerprint, passkey, device and administrator approvals: complete the actual provider-required owner step.

The release candidate does not connect arbitrary websites automatically. Private Google, Meta, financial and insurance accounts require adapters, enrollment and testing.

## If something stops

| Status or symptom | Next step |
| --- | --- |
| Skill missing | Open a fresh agent chat/session after installation. |
| `service_unavailable` | Start the service again and leave its terminal open. |
| `NEEDS_USER` | Complete the specified owner step, then continue the same task. |
| `DENIED` | Review the granted account operations. |

The service must keep running and the computer must stay awake. Completed task steps are preserved; repairing access does not automatically reopen a terminated AI conversation.

## Transcript and reproduction

The [storyboard](storyboard.json) contains the complete narration and on-screen commands. The [caption file](https://github.com/fainir/account-access/releases/download/v0.3.1/account-access-walkthrough.en.srt) contains timed narration. [Chapter times](../../artifacts/video/chapters.json) are recorded in seconds.

To recreate the video on macOS, install Pillow, ffmpeg and ffprobe. The renderer uses the installed macOS Samantha voice and system fonts. From the repository root:

```sh
uv run --with pillow python scripts/make_walkthrough.py
```

The renderer uses the committed, sanitized demo evidence and owner screenshots. It does not log into accounts. Temporary audio and private raw traces are Git-ignored under `artifacts/video/work`; the finished MP4 is distributed as a release asset.
