"""Owner-authored connector configuration and a deliberately small agent API."""

import hashlib
import ipaddress
import json
import re
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
    fields: dict[Handle, str] = Field(default_factory=dict, max_length=16)
    session_only: bool = False

    @model_validator(mode="after")
    def one_result_kind(self):
        if self.session_only == bool(self.fields):
            raise ValueError("Choose a session-status result or nonempty read fields, never both")
        return self


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


class LoginFactor(StrictModel):
    code_selector: str = Field(min_length=1)
    code_submit_selector: str = Field(min_length=1)
    code_source: Handle


class LoginChoice(StrictModel):
    kind: Literal["email", "sms", "totp"]
    selector: str = Field(min_length=1)
    url: str


class LoginCodeRequest(StrictModel):
    kind: Literal["email", "sms"]
    selector: str = Field(min_length=1)
    url: str


class LoginIdentityStep(StrictModel):
    submit_selector: str = Field(min_length=1, max_length=500)
    post_url: str
    password_url: str
    password_post_url: str
    # Explicitly reviewed JavaScript POST instead of a native form submission.
    scripted: bool = False


class IdentityContactFields(StrictModel):
    identity_selector: str = Field(min_length=1, max_length=500)
    phone_selector: str = Field(min_length=1, max_length=500)
    post_url: str


class LoginForm(StrictModel):
    username_selector: str = ""
    password_selector: str = ""
    submit_selector: str
    identity_contact: IdentityContactFields | None = None
    identity_step: LoginIdentityStep | None = None
    code_selector: str | None = None
    code_submit_selector: str | None = None
    code_source: Handle | None = None
    device_email_source: Handle | None = None
    code_wait_ms: int = Field(default=60000, ge=5000, le=120000)
    login_only: Literal[True] = True
    factors: dict[Literal["email", "sms", "totp"], LoginFactor] = Field(default_factory=dict)
    choices: list[LoginChoice] = Field(default_factory=list, max_length=3)
    code_requests: list[LoginCodeRequest] = Field(default_factory=list, max_length=2)
    choice_toggle_selector: str | None = Field(default=None, min_length=1, max_length=500)

    @model_validator(mode="after")
    def one_factor_configuration(self):
        if self.identity_contact:
            if (self.username_selector or self.password_selector or self.identity_step
                    or self.device_email_source or set(self.factors) != {"sms"}
                    or self.choices or self.code_requests or self.choice_toggle_selector):
                raise ValueError("Identity and phone login requires its own fields and a single SMS factor")
            if self.identity_contact.identity_selector == self.identity_contact.phone_selector:
                raise ValueError("Identity and phone must use distinct controls")
        elif not {"username_selector", "password_selector"} <= self.model_fields_set:
            # These fields were required before identity/contact enrollment.
            # Preserve already-serialized empty selectors: the browser refuses
            # unusable controls when connecting, without blocking config load.
            raise ValueError("Password login requires username and password controls")
        if self.factors and any([self.code_source, self.code_selector, self.code_submit_selector]):
            raise ValueError("Use per-method factors or the legacy single source, never both")
        if len({choice.kind for choice in self.choices}) != len(self.choices):
            raise ValueError("Configure each verification choice once")
        if len({item.kind for item in self.code_requests}) != len(self.code_requests):
            raise ValueError("Configure each code request once")
        return self

    def credential_fields(self):
        return ("identity", "phone") if self.identity_contact else ("username", "password")

    def credential_ready(self, value):
        if not (isinstance(value, dict) and all(isinstance(value.get(key), str)
                and 0 < len(value[key]) <= 4096 for key in self.credential_fields())):
            return False
        return not self.identity_contact or (set(value) == {"identity", "phone"} and all(
            len(value[key]) <= 128 and value[key].strip() and not any(ord(char) < 32 or ord(char) == 127
                for char in value[key]) for key in self.credential_fields()))

    def sources(self):
        values = ({factor.code_source for factor in self.factors.values()} if self.factors
                  else {self.code_source} if self.code_source else set())
        return values | ({self.device_email_source} if self.device_email_source else set())

    def factor(self, kind):
        if self.factors:
            return self.factors.get(kind)
        if self.code_source and self.code_selector and self.code_submit_selector:
            return LoginFactor(code_source=self.code_source, code_selector=self.code_selector,
                               code_submit_selector=self.code_submit_selector)
        return None

    def authenticator_source(self, config):
        factor = self.factor("totp")
        return factor.code_source if factor and config.code_sources[factor.code_source].kind == "totp" else None


class BrowserAccount(StrictModel):
    kind: Literal["browser"]
    label: str = Field(min_length=1, max_length=100)
    login_url: str
    ready_selector: str
    login: LoginForm | None = None
    # Explicit reviewed aliases for password-manager exports, never a hostname
    # suffix match. This does not grant browser network access to an alias.
    password_import_origins: list[str] = Field(default_factory=list, max_length=8)
    challenge_selectors: dict[Literal["login", "sms", "email", "totp", "device", "passkey", "captcha",
                                     "admin", "action", "recovery", "unknown", "method"], str] = Field(default_factory=dict)
    # Exact URLs, including query strings. GET alone does not prove a URL is read-only.
    read_resources: list[str] = Field(default_factory=list, max_length=100)
    login_resources: list[str] = Field(default_factory=list, max_length=100)
    login_assets: list[str] = Field(default_factory=list, max_length=150)
    login_asset_discovery: Literal["github"] | None = None
    login_challenge: Literal["pypi-totp-v1"] | None = None
    browser_channel: Literal["chrome"] | None = None
    login_post_urls: list[str] = Field(default_factory=list, max_length=32)
    javascript: bool = False
    state_timeout_ms: int = Field(default=5000, ge=0, le=15000)
    operations: dict[Handle, BrowserOperation] = Field(min_length=1)


class CodeSource(StrictModel):
    kind: Literal["totp", "gmail", "twilio", "imap", "mac_messages", "phone_relay", "google_messages"]
    message_purpose: Literal["pypi-device-confirmation"] | None = None
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
        if self.message_purpose:
            if (self.kind not in {"gmail", "imap"} or self.sender != "noreply@pypi.org"
                    or self.subject != "[PyPI] Unrecognized login to your PyPI account"
                    or not self.recipient or re.fullmatch(r"[^\s<>@]+@[^\s<>@]+", self.recipient) is None
                    or self.template is not None):
                raise ValueError("PyPI device mail requires its reviewed sender, subject and a recipient; no code template")
        if self.kind == "google_messages" and (
                self.sender != "github-login-rotating-senders" or self.recipient != "paired-google-messages"
                or self.template != "{code} is your GitHub authentication code."):
            raise ValueError("Google Messages currently supports only the reviewed GitHub login template")
        if self.kind != "totp" and not self.message_purpose and (not self.sender or not self.recipient or not self.template
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
    accounts: dict[Handle, Annotated[OAuthAccount | BrowserAccount, Field(discriminator="kind")]]
    code_sources: dict[Handle, CodeSource] = Field(default_factory=dict)

    @model_validator(mode="after")
    def check_all_urls(self):
        for account in self.accounts.values():
            if isinstance(account, OAuthAccount):
                urls = [account.authorization_url, account.token_url, *account.api_origins]
                if account.revoke_url:
                    urls.append(account.revoke_url)
            else:
                if account.login_challenge:
                    from .pypi_challenge import validate_configuration
                    validate_configuration(account, self.test_mode)
                for alias in account.password_import_origins:
                    validate_url(alias, self.test_mode)
                    if alias != origin(alias):
                        raise ValueError("Password import aliases must be exact origins")
                if account.login_asset_discovery and (
                        not account.javascript or origin(account.login_url) != "https://github.com"
                        or urlsplit(account.login_url).path != "/login"
                        or not account.login or account.login.username_selector != "#login_field"
                        or account.login.password_selector != "#password" or account.login.identity_step is not None):
                    raise ValueError("GitHub asset discovery requires the reviewed GitHub login form")
                urls = [account.login_url, *account.read_resources, *account.login_resources,
                        *account.login_assets, *account.login_post_urls]
                if account.login:
                    if account.login.identity_contact and (
                            account.password_import_origins or account.login_challenge
                            or account.login_asset_discovery
                            or account.login.identity_contact.post_url not in account.login_post_urls
                            or account.login.identity_contact.post_url not in account.login_resources
                            or origin(account.login.identity_contact.post_url) != origin(account.login_url)
                            or any(not operation.session_only for operation in account.operations.values())):
                        raise ValueError("Identity and phone login requires explicit POST routes and session-status-only operations")
                    identity = account.login.identity_step
                    if identity and (
                            identity.post_url not in account.login_post_urls
                            or identity.post_url not in account.login_resources
                            or identity.password_url not in account.login_resources
                            or identity.password_post_url not in account.login_post_urls
                            or identity.password_post_url not in account.login_resources
                            or any(origin(url) != origin(account.login_url)
                                   for url in [identity.post_url, identity.password_url, identity.password_post_url])
                            or identity.scripted and not account.javascript):
                        raise ValueError("Identity steps require reviewed same-origin login pages and POST; scripted steps require JavaScript")
                    if not account.login.sources() <= self.code_sources.keys():
                        raise ValueError("Unknown login code source")
                    if account.login.code_source and self.code_sources[account.login.code_source].message_purpose:
                        raise ValueError("A device confirmation source cannot supply a numeric code")
                    device = account.login.device_email_source
                    if device and (account.login_challenge != "pypi-totp-v1"
                                   or self.code_sources[device].message_purpose != "pypi-device-confirmation"):
                        raise ValueError("Device confirmation mail is bound only to the reviewed PyPI login")
                    kinds = {"totp": {"totp"}, "email": {"imap", "gmail"},
                             "sms": {"twilio", "mac_messages", "phone_relay", "google_messages"}}
                    for kind, factor in account.login.factors.items():
                        if (self.code_sources[factor.code_source].kind not in kinds[kind]
                                or self.code_sources[factor.code_source].message_purpose):
                            raise ValueError("Verification method and source kind must match")
                    for choice in account.login.choices:
                        factor = account.login.factor(choice.kind)
                        if (choice.url not in account.login_resources
                                or origin(choice.url) != origin(account.login_url)
                                or (factor and self.code_sources[factor.code_source].kind not in kinds[choice.kind])):
                            raise ValueError("Verification choices require a reviewed login URL and any configured source must match")
                    for delivery in account.login.code_requests:
                        if (delivery.url not in account.login_resources
                                or origin(delivery.url) != origin(account.login_url)):
                            raise ValueError("Code requests require a reviewed same-origin login page")
            urls.extend(op.url for op in account.operations.values())
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
        if isinstance(self.accounts[account], BrowserAccount):
            for operation in data["operations"].values():
                if operation.get("session_only") is False:
                    # Adding this explicit result kind must not revoke existing
                    # field-read grants or their saved sessions on upgrade.
                    operation.pop("session_only", None)
        if isinstance(self.accounts[account], BrowserAccount) and not data.get("login_assets"):
            data.pop("login_assets", None)
        if isinstance(self.accounts[account], BrowserAccount) and data.get("browser_channel") is None:
            data.pop("browser_channel", None)
        if isinstance(self.accounts[account], BrowserAccount) and data.get("login_asset_discovery") is None:
            data.pop("login_asset_discovery", None)
        if isinstance(self.accounts[account], BrowserAccount) and data.get("login_challenge") is None:
            data.pop("login_challenge", None)
        if isinstance(self.accounts[account], BrowserAccount) and not data.get("password_import_origins"):
            # Existing grants and saved sessions must survive an upgrade when
            # no alias was added. A nonempty alias is still permission-bound.
            data.pop("password_import_origins", None)
        if isinstance(self.accounts[account], BrowserAccount) and data.get("login"):
            if data["login"].get("identity_contact") is None:
                data["login"].pop("identity_contact", None)
            if data["login"].get("device_email_source") is None:
                data["login"].pop("device_email_source", None)
            if data["login"].get("identity_step") is None:
                data["login"].pop("identity_step", None)
            if not data["login"].get("factors"):
                data["login"].pop("factors", None)
            if not data["login"].get("choices"):
                data["login"].pop("choices", None)
            if not data["login"].get("code_requests"):
                data["login"].pop("code_requests", None)
            if data["login"].get("choice_toggle_selector") is None:
                data["login"].pop("choice_toggle_selector", None)
            if data["login"].get("code_wait_ms") == 60000:
                data["login"].pop("code_wait_ms", None)
        if isinstance(self.accounts[account], BrowserAccount):
            form = self.accounts[account].login
            if form and form.code_source:
                data["code_source_config"] = self.code_sources[form.code_source].model_dump()
                if data["code_source_config"].get("message_purpose") is None:
                    data["code_source_config"].pop("message_purpose", None)
                if self.code_sources[form.code_source].kind != "imap":
                    data["code_source_config"].pop("host", None)
                    data["code_source_config"].pop("port", None)
            if form and form.factors:
                data["code_source_configs"] = {key: self.code_sources[key].model_dump()
                                               for key in sorted(form.sources())}
                for source in data["code_source_configs"].values():
                    if source.get("message_purpose") is None:
                        source.pop("message_purpose", None)
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
