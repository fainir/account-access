"""Owner-authored connector configuration and a deliberately small agent API."""

import hashlib
import ipaddress
import json
from typing import Annotated, Literal
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, model_validator

Handle = Annotated[str, Field(pattern=r"^[a-z][a-z0-9_-]{0,63}$")]


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


def origin(url: str) -> str:
    parts = urlsplit(url)
    port = parts.port
    suffix = f":{port}" if port and port != {"https": 443, "http": 80}.get(parts.scheme) else ""
    return f"{parts.scheme}://{parts.hostname}{suffix}"


def validate_url(url: str, test_mode: bool = False) -> str:
    p = urlsplit(url)
    if p.username or p.password or p.fragment or not p.hostname:
        raise ValueError("URLs must have a host and no credentials or fragment")
    if p.scheme == "https":
        try:
            if ipaddress.ip_address(p.hostname).is_private:
                raise ValueError("Private IP destinations are unsupported")
        except ValueError as exc:
            if "Private IP" in str(exc):
                raise
        return url
    if test_mode and p.scheme == "http" and p.hostname == "127.0.0.1":
        return url
    raise ValueError("HTTPS is required; test mode permits only literal 127.0.0.1 HTTP")


class ApiOperation(StrictModel):
    kind: Literal["api"] = "api"
    description: str = Field(min_length=1, max_length=240)
    url: str
    required_scopes: list[str] = Field(default_factory=list, max_length=32)
    fields: list[str] = Field(min_length=1, max_length=16)


class BrowserOperation(StrictModel):
    kind: Literal["browser"] = "browser"
    description: str = Field(min_length=1, max_length=240)
    url: str
    fields: dict[Handle, str] = Field(min_length=1, max_length=16)


class OAuthAccount(StrictModel):
    kind: Literal["oauth"]
    label: str = Field(min_length=1, max_length=100)
    authorization_url: str
    token_url: str
    revoke_url: str | None = None
    client_id: str = Field(min_length=1, max_length=500)
    token_auth_method: Literal["none", "client_secret_post", "client_secret_basic"] = "none"
    scopes: list[str] = Field(min_length=1, max_length=32)
    authorization_params: dict[str, str] = Field(default_factory=dict)
    api_origins: list[str] = Field(min_length=1, max_length=8)
    operations: dict[Handle, ApiOperation]

    @model_validator(mode="after")
    def no_protocol_overrides(self):
        reserved = {"state", "redirect_uri", "client_id", "response_type", "scope",
                    "code_challenge", "code_challenge_method"}
        if reserved & self.authorization_params.keys():
            raise ValueError("Authorization parameters cannot override protocol protections")
        for op in self.operations.values():
            if origin(op.url) not in self.api_origins:
                raise ValueError("Operation destination is outside the API origin allowlist")
            if not set(op.required_scopes) <= set(self.scopes):
                raise ValueError("Operation requires scopes absent from the connection")
        return self


class LoginForm(StrictModel):
    username_selector: str
    password_selector: str
    submit_selector: str
    code_selector: str | None = None
    code_submit_selector: str | None = None
    code_source: Handle | None = None
    code_wait_ms: int = Field(default=60000, ge=5000, le=120000)
    login_only: Literal[True] = True


class BrowserAccount(StrictModel):
    kind: Literal["browser"]
    label: str = Field(min_length=1, max_length=100)
    login_url: str
    ready_selector: str
    login: LoginForm | None = None
    challenge_selectors: dict[Literal["login", "sms", "email", "totp", "device", "passkey",
                                     "admin", "action", "unknown"], str] = Field(default_factory=dict)
    # Exact URLs, including query strings. GET alone does not prove a URL is read-only.
    read_resources: list[str] = Field(default_factory=list, max_length=100)
    login_resources: list[str] = Field(default_factory=list, max_length=100)
    login_post_urls: list[str] = Field(default_factory=list, max_length=32)
    javascript: bool = False
    state_timeout_ms: int = Field(default=5000, ge=0, le=15000)
    operations: dict[Handle, BrowserOperation] = Field(min_length=1)


class GitHubIdentityOperation(StrictModel):
    kind: Literal["github_identity"] = "github_identity"
    description: Literal["Confirm the signed-in GitHub username"] = "Confirm the signed-in GitHub username"


class GitHubCLIAccount(StrictModel):
    kind: Literal["github_cli"] = "github_cli"
    label: str = Field(min_length=1, max_length=100)
    executable: str = Field(min_length=1, max_length=1024)
    executable_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    user_id: int = Field(gt=0)
    login: str = Field(pattern=r"^[a-zA-Z0-9][a-zA-Z0-9-]{0,38}$")
    operations: dict[Literal["status"], GitHubIdentityOperation] = Field(min_length=1, max_length=1)


class CodeSource(StrictModel):
    kind: Literal["totp", "gmail", "twilio", "imap", "mac_messages", "phone_relay"]
    account: Handle | None = None
    sender: str | None = Field(default=None, max_length=200)
    recipient: str | None = Field(default=None, max_length=200)
    subject: str | None = Field(default=None, max_length=200)
    # Exact owner-reviewed message template; one {code}, no arbitrary regex supplied by the agent.
    template: str | None = Field(default=None, max_length=2000)
    host: str | None = Field(default=None, pattern=r"^[a-zA-Z0-9.-]{1,253}$")
    port: int = Field(default=993, ge=1, le=65535)

    @model_validator(mode="after")
    def requirements(self):
        if self.kind != "totp" and (not self.sender or not self.recipient or not self.template
                                    or self.template.count("{code}") != 1):
            raise ValueError("Message sources require sender, recipient and one {code} template")
        if self.kind == "gmail" and (not self.account or not self.subject):
            raise ValueError("Gmail code sources require an OAuth account and exact subject")
        if self.kind == "imap" and (not self.host or not self.subject):
            raise ValueError("IMAP requires a TLS mail server and exact subject")
        return self


class Configuration(StrictModel):
    version: Literal[1] = 1
    test_mode: bool = False
    accounts: dict[Handle, Annotated[OAuthAccount | BrowserAccount | GitHubCLIAccount, Field(discriminator="kind")]]
    code_sources: dict[Handle, CodeSource] = Field(default_factory=dict)

    @model_validator(mode="after")
    def check_all_urls(self):
        for account in self.accounts.values():
            if isinstance(account, OAuthAccount):
                urls = [account.authorization_url, account.token_url, *account.api_origins]
                if account.revoke_url:
                    urls.append(account.revoke_url)
            elif isinstance(account, BrowserAccount):
                urls = [account.login_url, *account.read_resources, *account.login_resources, *account.login_post_urls]
                if account.login and account.login.code_source not in self.code_sources and account.login.code_source:
                    raise ValueError("Unknown login code source")
            else:
                urls = []
            urls.extend(op.url for op in account.operations.values() if hasattr(op, "url"))
            for url in urls:
                validate_url(url, self.test_mode)
        for source in self.code_sources.values():
            if source.kind == "imap":
                if not (self.test_mode and source.host == "127.0.0.1"):
                    validate_url("https://" + source.host, self.test_mode)
                if source.account and not isinstance(self.accounts.get(source.account), OAuthAccount):
                    raise ValueError("IMAP OAuth source must reference an OAuth account")
            if source.kind == "gmail":
                account = self.accounts.get(source.account)
                if not isinstance(account, OAuthAccount):
                    raise ValueError("Gmail source must reference an OAuth account")
                if "https://www.googleapis.com/auth/gmail.readonly" not in account.scopes:
                    raise ValueError("Gmail code source requires the gmail.readonly scope")
        return self

    def fingerprint(self, account: str) -> str:
        data = self.accounts[account].model_dump()
        if isinstance(self.accounts[account], BrowserAccount) and data.get("login"):
            if data["login"].get("code_wait_ms") == 60000:
                data["login"].pop("code_wait_ms", None)
        if isinstance(self.accounts[account], BrowserAccount):
            form = self.accounts[account].login
            if form and form.code_source:
                data["code_source_config"] = self.code_sources[form.code_source].model_dump()
                if self.code_sources[form.code_source].kind != "imap":
                    data["code_source_config"].pop("host", None)
                    data["code_source_config"].pop("port", None)
        data["test_mode"] = self.test_mode
        return hashlib.sha256(json.dumps(data, sort_keys=True).encode()).hexdigest()


class Step(StrictModel):
    account: Handle
    operation: Handle


class TaskRequest(StrictModel):
    key: str = Field(min_length=1, max_length=128, pattern=r"^[a-zA-Z0-9_.:-]+$")
    steps: list[Step] = Field(min_length=1, max_length=32)


class RunRequest(Step):
    pass
