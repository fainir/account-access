# Contributing

Use fictional accounts and purpose-built providers for development. Do not commit live credentials, cookies, browser profiles, authentication messages, private account data or raw agent traces.

## Development setup

```sh
git clone https://github.com/fainir/account-access.git
cd account-access
uv sync --locked --python 3.13
uv run playwright install chromium
uv run ruff check account_access tests scripts
uv run pytest -q
uv run pip-audit --local
uv build
```

On Linux, use `uv run playwright install --with-deps chromium` if system libraries are missing. The ordinary regression suite uses local fixtures and mocked message-provider contracts; it does not sign into private accounts.

## Connector changes

Keep agent-facing operations fixed and narrow. Review every URL and its side effects: a GET endpoint is not necessarily read-only. Browser connectors use exact resource allowlists and a separate allowlist for login POSTs. Redirects must remain checked at every hop.

Distinguish login challenges from authorization of a payment or account change. Unknown challenges stop. Genuine required passkey, device or biometric presence must remain an owner interaction.

Add meaningful coverage for repeated use, expired/revoked access, transient failures, configuration drift and interrupted tasks. Record observed provider results separately from fixtures and expectations. An accelerated demo is not a thirty-day reliability test.

Update the README/setup guide when usage changes. Keep version fields in `pyproject.toml` and `account_access/__init__.py` consistent; update the documented wheel filename for a new release.

When runtime dependencies change, regenerate `account_access/runtime-requirements.txt`
from the locked graph before building the wheel. The [Mac build guide](macos/README.md)
has the export command. CI rejects drift; the installer requires those dependency
hashes and refuses source builds.

Review the [production acceptance matrix](docs/production-gates.md) before making
release claims. Fixture success and private-account success are separate results.

## External experiments

`scripts/public_demos.py` uses intentionally published testing identities and makes network requests to those demo providers. Run it only when you intend that experiment. `scripts/agent_smoke.py` invokes an existing logged-in Codex or Claude CLI and can consume account usage; no AI key is required or provisioned.

`scripts/service_preflight.py` checks the reviewed Namecheap public login form
through the application's network guard, without submitting credentials or using
an existing browser profile. Run it explicitly; an anonymous form check does not
establish successful private authentication or verification-code delivery.

`scripts/agent_verification_smoke.py` runs an ordinary-language request against
four isolated fictional websites: password, TLS IMAP email, Messages-format SMS
and an authenticator imported through the owner transfer-QR endpoints. It uses
project-local skill discovery and does not replace global skills or account
connections. Invoke it explicitly with `claude` or `codex` and `--workspace` in
an ignored QA directory. An optional `--codex-model` is an invocation-only
compatibility setting. The report independently checks the durable task and
provider counters; physical phones and private mailboxes are separate tests.

For Codex, that harness uses an invocation-only profile extending the workspace
sandbox, an active network proxy with no allowed domains, and the exact temporary
fixture socket. It preserves global configuration and managed restrictions.
See the [official OpenAI permissions reference](https://learn.chatgpt.com/docs/permissions).

Inspect artifacts before sharing them. Raw agent traces are ignored because they can contain unrelated host metadata. Report only sanitized outcomes and reproducible task evidence.

For vulnerabilities, follow [SECURITY.md](SECURITY.md) rather than posting secrets or an exploit against a live account in a public issue.
