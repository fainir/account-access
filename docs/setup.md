# Setup and advanced usage

Start with the [README quick start](../README.md#quick-start) for a demo that needs no private credentials. The instructions below are for reviewed real-account connectors and additional agents.

## Real-account setup

### 1. Prepare the connector

A connector is an owner-reviewed configuration of fixed destinations, named operations, provider scopes and, for browser sites, login/readiness/challenge markers. It is not supplied by website content or the AI agent.

The [Google Drive example](../examples/google-drive.json) defines `google-drive:list-files`. Copy it outside the checkout and replace its placeholder client ID with your registered desktop application's ID. The Google application credential is entered through owner setup, not written into the JSON file or a shell argument. This is an example, not a live-validated Google integration.

For a consumer deployment, the operator should register and provide approved OAuth applications. Each unsupported website needs an adapter and testing before credentials are connected.

### 2. Initialize and install agent clients

```sh
account-access init --config /absolute/path/to/reviewed-config.json
account-access install --agent codex
account-access install --agent claude
```

The default storage location is `~/Library/Application Support/AccountAccess` on macOS and `~/.local/share/account-access` on Linux. Keep it outside the repository. The vault key uses a supported OS keyring. A locked/missing secure keyring stops setup; it does not silently fall back to a plaintext production key.

These installations create separate client identities. They start without operation grants. Installing the skill alone does not authorize access to an account.

### 3. Start the service and open setup

In one terminal:

```sh
account-access serve
```

In a second terminal:

```sh
account-access setup
```

The local owner console lets you enter credentials, connect or repair the account, select permitted operations and revoke access. Keep the service running. The owner console is ephemeral and separate from the agent API.

For the Google example, enter the registered application's credential, complete provider consent and grant `list-files` to the intended agent. Never paste credentials or callback URLs into chat or issues.

The equivalent owner CLI commands are:

```sh
account-access credential google-drive
account-access connect google-drive
account-access grant codex google-drive list-files
account-access grant claude google-drive list-files
account-access grants
account-access challenges
```

`grant` replaces the selected principal's operation set for that account. To restrict a grant to seven days, append `--days 7`.

### 4. Use and revoke access

Ask the agent to discover the account and perform its available operation, or use the installed client:

```sh
python3 "$HOME/.agents/skills/account-access/scripts/access.py" accounts
python3 "$HOME/.agents/skills/account-access/scripts/access.py" run google-drive list-files
```

Owner revocation commands:

```sh
account-access revoke --account google-drive
account-access revoke --principal claude
```

Revocation stops new requests and access to persisted results. An already issued request may have reached the provider. Local revocation does not invalidate the provider's own token/session; also use the provider's account settings when required.

## Another agent

For a host supporting Agent Skills and command execution, choose its supported skill directory:

```sh
account-access install --agent generic \
  --skills-dir /absolute/path/to/other-agent/skills
account-access grant generic google-drive list-files
```

The installer creates `account-access/SKILL.md` and its executable client resources in that directory. It preserves other skills and refuses to replace an unrecognized existing `account-access` directory. The skill contains executable paths and configuration references; its private client token is stored separately. `generic` is one shared principal; this installer does not yet provide arbitrary per-host principal names.

For an additional client pointed at the development demo, use its explicit root/key flags instead of the real-account defaults:

```sh
account-access --root "$HOME/.local/share/account-access-demo" \
  --development --key-file "$HOME/.local/share/account-access-demo/demo.key" \
  install --agent generic --skills-dir /absolute/path/to/other-agent/skills
account-access --root "$HOME/.local/share/account-access-demo" \
  --development --key-file "$HOME/.local/share/account-access-demo/demo.key" \
  grant generic demo-api summary
```

Agents without a skills loader can invoke the installed client script directly. Its allowed command set is `accounts`, `doctor`, `status`, `run`, `task` and `audit`. Owner and credential commands are unavailable through that script.

## Scheduled reads

For an initialized real-account service and an existing standing grant:

```sh
account-access schedule codex --interval 86400 --steps 'google-drive:list-files'
account-access schedules
account-access disable-schedule SCHEDULE_ID
```

The service must run and the machine must be awake. Missed intervals coalesce instead of producing a burst of catch-up runs. Schedules resume supported service operations, not a stopped agent conversation. Email/SMS/push notifications are not configured by these commands.

## Experimental Chrome session adoption

The bridge transfers a specifically selected account's browser session; it does not read Chrome's saved-password vault, passkeys or authenticator apps.

1. Configure the reviewed browser account first.
2. Open Chrome's extensions page, enable developer mode, and load the repository's `extensions/chrome` directory as an unpacked extension.
3. Copy that exact extension ID and register it from this checkout:

   ```sh
   uv run python scripts/register_chrome.py \
     --root /absolute/path/to/initialized/service-data EXTENSION_ID
   ```

4. Open the configured account's signed-in tab, choose the account in the extension, and click Connect. Chrome requests permission for that origin.

The native host transfers filtered cookies/localStorage directly to the owner store. Parent-domain cookies, IndexedDB, sessionStorage and device bindings may prevent reuse. The bridge has unit tests but has not been exercised with live Chrome accounts or distributed as a signed extension.

## Remote and isolated deployment

The service binds a private Unix socket and authenticates client requests. For cloud agents or stronger custody, deploy it under a separate OS identity/host behind a narrow HTTPS endpoint. See the [TLS proxy example](../deployment/nginx.conf.example) and [architecture](architecture.md). Hosting is not provisioned automatically.

A private client configuration can reference that endpoint as `url` instead of `socket`:

```json
{
  "url": "https://your-private-broker.example",
  "token_file": "/absolute/path/to/private-client-token"
}
```

Set configuration/token files to owner-only permissions. The token must be issued by the owner service. Never put it in a Git URL, README, agent prompt or provider request. Arbitrary same-user shell access remains outside the local pilot's isolation guarantee.
