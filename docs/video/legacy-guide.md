# Install, connect an account, and start using your agent

[Watch or download the walkthrough](https://github.com/fainir/account-access/releases/download/v0.3.1/account-access-walkthrough.mp4) · [English captions](https://github.com/fainir/account-access/releases/download/v0.3.1/account-access-walkthrough.en.srt)

![Video preview](poster.jpg)

The **2:35 walkthrough** follows a shopping task: install Account Access, save a login locally, allow catalog reads, ask Codex for the two cheapest products, and ask Claude Code for a backpack price. It shows the normal `init`, `install`, `serve`, and `setup` flow. The opening note identifies the illustrative account and sample data.

## Install

Have Git, [uv](https://docs.astral.sh/uv/getting-started/installation/), and your chosen agent installed. Codex or Claude Code should already be signed in. On macOS, open Terminal and run:

```sh
git clone https://github.com/fainir/account-access.git
cd account-access
uv sync --locked --python 3.13
uv run playwright install chromium
uv build
uv tool install --python 3.13 --force ./dist/account_access-0.3.1-py3-none-any.whl
```

If `account-access` is not found, run `uv tool update-shell` and open a new terminal. If the skill launcher cannot find `python3`, run `uv python install 3.13 --default`, then update the shell and reopen Terminal.

Linux users should use `uv run playwright install --with-deps chromium` and follow the [browser sandbox instructions](../setup.md#linux-sandbox-setup). Native Windows transport is not shipped.

## Choose the service and install the skill

The walkthrough uses the included [shopping connector](../../examples/shopping.json):

```sh
account-access init --config examples/shopping.json
account-access install --agent codex
account-access install --agent claude
```

Install only the agent you use, or both. These commands initialize the encrypted store and create agent clients; permissions are granted in the setup page next.

The included connector targets SauceDemo's intentionally public example website. For another service, use its reviewed connector configuration with fixed destinations and supported operations. Installing Account Access alone does not add support for every website.

## Start and connect your account

In the first terminal:

```sh
account-access serve
```

Leave that terminal open. In a second terminal:

```sh
account-access setup
```

In the browser setup page:

1. Open the password form for the shopping account.
2. Enter the username and password, then click **Save locally**.
3. Choose **codex** or **claude** in the agent selector.
4. Select the catalog read and click **Allow selected operations**.
5. If using both agents, grant the operation to each.

To reproduce the exact public website example, SauceDemo publishes username `standard_user` and password `secret_sauce` on its login page. Enter these in the local setup form. For your own supported accounts, enter your own credentials there.

The website can now be accessed using the permitted login recovery. The first read signs in and saves the session; later requests reuse it.

## Ask for useful work

In a fresh **Codex** chat:

> Use $account-access to check my shopping account. Find the two cheapest products and show their names and prices. Save progress as a task.

In a fresh **Claude Code** session:

> /account-access Check my shopping account and tell me the backpack price. Save progress as a task.

The recorded website reads returned:

| Request | Answer |
| --- | --- |
| Two cheapest products | Sauce Labs Onesie — $7.99; Sauce Labs Bike Light — $9.99 |
| Backpack price | Sauce Labs Backpack — $29.99 |

Both requests were submitted through actual CLI agents and independently verified against completed service tasks. No cart or purchase action is allowed by this connector.

You can also check the client from a second terminal:

```sh
python3 "$HOME/.agents/skills/account-access/scripts/access.py" doctor
python3 "$HOME/.agents/skills/account-access/scripts/access.py" run shopping inventory
```

Look for `"status": "OK"` in the connection check and `"status": "COMPLETED"` for the read.

## Keep using it

Keep the service running and your computer awake. Start a fresh chat or session after installing the skill. Change grants or revoke access in the setup page whenever needed.

If an account later requires your participation, complete the specific connection or approval step in owner setup and continue the same task. The service preserves completed task steps. See [real-account setup](../setup.md#real-account-setup) for OAuth providers, other agents, and additional connectors.

## Video source and verification

This is an edited, narrated walkthrough with captions, recorded owner-form states, and actual website results. The recording used an isolated OS-keyring-backed data directory; the commands above use the normal default directory. The recorded site is a public example, and private banks, insurers, Google or Meta accounts were not validated by this video.

[Storyboard and narration](storyboard.json) · [Chapter times](../../artifacts/video/chapters.json) · [Recorded evidence](../../artifacts/video/evidence.json) · [Video checks](../../artifacts/video/validation.json)

To render it on macOS with ffmpeg/ffprobe installed:

```sh
uv run --with pillow python scripts/make_walkthrough.py
```

The renderer uses the included sanitized evidence, owner screenshots, system fonts and macOS Samantha voice. It does not log into accounts. Private recordings and intermediate audio stay in the Git-ignored `artifacts/video/work` directory.
