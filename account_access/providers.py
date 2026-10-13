"""Provider requests happen here, never in model-visible commands."""

import math
import re
import secrets
import time
from urllib.parse import parse_qs, urlsplit

import httpx2 as httpx
from authlib.integrations.httpx_client import OAuth2Client
from authlib.integrations.base_client.errors import OAuthError

from .errors import AccessError
from .models import OAuthAccount

MAX_RESPONSE = 1_000_000


def response_json(response):
    if len(response.content) > MAX_RESPONSE:
        raise AccessError("DENIED", "provider_response_too_large")
    if response.status_code in (429, 500, 502, 503, 504):
        raise AccessError("RETRYABLE", "provider_temporarily_unavailable")
    if response.status_code == 401:
        raise AccessError("NEEDS_USER", "provider_rejected_access")
    if response.status_code == 403:
        raise AccessError("DENIED", "provider_forbidden")
    if 300 <= response.status_code < 400:
        raise AccessError("DENIED", "provider_redirect_blocked")
    if response.status_code >= 400:
        raise AccessError("DENIED", "provider_request_rejected")
    try:
        return response.json()
    except Exception:
        raise AccessError("RETRYABLE", "invalid_provider_response") from None


def get_json(url, **kwargs):
    try:
        with httpx.Client(timeout=15, follow_redirects=False, trust_env=False) as client:
            with client.stream("GET", url, **kwargs) as response:
                content = bytearray()
                for chunk in response.iter_bytes():
                    content.extend(chunk)
                    if len(content) > MAX_RESPONSE:
                        raise AccessError("DENIED", "provider_response_too_large")
                response._content = bytes(content)
                return response_json(response)
    except httpx.HTTPError:
        raise AccessError("RETRYABLE", "network_unavailable") from None


def credential_values(value):
    """Collect secret strings, including cookies/localStorage, for defense-in-depth redaction."""
    result = set()
    if isinstance(value, dict):
        for key, item in value.items():
            if isinstance(item, str) and (key in {"password", "seed", "access_token", "refresh_token",
                                                 "client_secret", "id_token", "auth_token", "value"}):
                if item:
                    result.add(item)
            result.update(credential_values(item))
    elif isinstance(value, list):
        for item in value:
            result.update(credential_values(item))
    return result


def redact(value, secret_values):
    if isinstance(value, dict):
        return {k: ("[REDACTED]" if re.search(r"password|secret|cookie|authorization|token|seed", k, re.I)
                    else redact(v, secret_values)) for k, v in value.items()}
    if isinstance(value, list):
        return [redact(v, secret_values) for v in value]
    if isinstance(value, str):
        for item in sorted(secret_values, key=len, reverse=True):
            if len(item) >= 4:
                value = value.replace(item, "[REDACTED]")
        return value[:100_000]
    return value


class OAuth:
    def __init__(self, store):
        self.store = store

    def client(self, account, config: OAuthAccount, **kwargs):
        secret = self.store.get("credential:" + account, {}).get("client_secret")
        if config.token_auth_method != "none" and not secret:
            raise AccessError("NEEDS_USER", "client_secret_not_configured")
        return OAuth2Client(config.client_id, client_secret=secret,
                            token_endpoint_auth_method=config.token_auth_method,
                            scope=" ".join(config.scopes), code_challenge_method="S256",
                            timeout=15, follow_redirects=False, trust_env=False, **kwargs)

    def begin(self, account, redirect_uri):
        config = self.store.config()
        account_config = config.accounts[account]
        if not isinstance(account_config, OAuthAccount):
            raise AccessError("DENIED", "wrong_connector_kind")
        verifier = secrets.token_urlsafe(48)
        with self.client(account, account_config, redirect_uri=redirect_uri) as client:
            url, state = client.create_authorization_url(account_config.authorization_url,
                                                        code_verifier=verifier,
                                                        **account_config.authorization_params)
        self.store.put("oauth-pending:" + account, {
            "state": state, "verifier": verifier, "redirect_uri": redirect_uri,
            "fingerprint": config.fingerprint(account), "expires": time.time() + 300,
        })
        return url

    def finish(self, account, callback_url):
        with self.store.lock("account:" + account):
            config = self.store.config()
            pending = self.store.get("oauth-pending:" + account)
            params = parse_qs(urlsplit(callback_url).query)
            if (not pending or pending["expires"] < time.time()
                or config.fingerprint(account) != pending["fingerprint"]
                or len(params.get("state", [])) != 1
                or not secrets.compare_digest(params["state"][0], pending["state"])
                or callback_url.split("?", 1)[0] != pending["redirect_uri"]
                or len(params.get("code", [])) != 1):
                raise AccessError("DENIED", "invalid_oauth_callback")
            # Consume state before network I/O. Never replay an authorization code after a lost response.
            self.store.put("oauth-pending:" + account, None)
            try:
                with self.client(account, config.accounts[account], state=pending["state"],
                                 redirect_uri=pending["redirect_uri"]) as client:
                    token = client.fetch_token(config.accounts[account].token_url,
                                               authorization_response=callback_url,
                                               code_verifier=pending["verifier"])
                self.save(account, token, config)
            except (OAuthError, httpx.HTTPError, ValueError):
                raise AccessError("NEEDS_USER", "oauth_connection_failed") from None
            self.store.resolve_login(account)

    def save(self, account, token, config, previous=None):
        previous = previous or {}
        if not token.get("access_token") or token.get("token_type", "").lower() != "bearer":
            raise AccessError("NEEDS_USER", "unsupported_provider_token")
        expires = token.get("expires_at")
        if expires is None:
            # An unknown expiry is refreshed on next use; no invented perpetual lifetime.
            expires = time.time() + float(token.get("expires_in", 0))
        if not math.isfinite(float(expires)):
            raise AccessError("NEEDS_USER", "invalid_provider_token")
        scope = token.get("scope", previous.get("scope", " ".join(config.accounts[account].scopes)))
        self.store.put("connection:" + account, {
            "token": {"access_token": token["access_token"], "token_type": "Bearer",
                      "refresh_token": token.get("refresh_token", previous.get("refresh_token")),
                      "expires_at": float(expires), "scope": scope},
            "fingerprint": config.fingerprint(account), "refresh_in_flight": False,
            "generation": secrets.token_hex(8),
        })

    def token(self, account, config, *, force=False):
        """Caller holds the account lock throughout refresh and protected execution."""
        connection = self.store.get("connection:" + account)
        if not connection:
            raise AccessError("NEEDS_USER", "account_not_connected")
        if connection.get("revoked"):
            raise AccessError("DENIED", "connection_revoked")
        if connection.get("invalid"):
            raise AccessError("NEEDS_USER", "provider_grant_revoked_or_expired")
        if connection["fingerprint"] != config.fingerprint(account):
            raise AccessError("DENIED", "connection_configuration_changed")
        if connection.get("refresh_in_flight"):
            # Includes crash or response loss after server-side rotation. Blind reuse can revoke a family.
            raise AccessError("NEEDS_USER", "refresh_outcome_uncertain")
        token = connection["token"]
        if not force and token["expires_at"] > time.time() + 15:
            return token
        if not token.get("refresh_token"):
            raise AccessError("NEEDS_USER", "renewal_unavailable")
        connection["refresh_in_flight"] = True
        self.store.put("connection:" + account, connection)
        try:
            with self.client(account, config.accounts[account], token=token) as client:
                refreshed = client.refresh_token(config.accounts[account].token_url,
                                                 refresh_token=token["refresh_token"])
            self.save(account, refreshed, config, previous=token)
            self.store.audit("service", account, "", "token_refreshed")
            return self.store.get("connection:" + account)["token"]
        except OAuthError as exc:
            if exc.error in {"invalid_grant", "invalid_token"}:
                connection["refresh_in_flight"] = False
                connection["invalid"] = True
                self.store.put("connection:" + account, connection)
                raise AccessError("NEEDS_USER", "provider_grant_revoked_or_expired") from None
            raise AccessError("NEEDS_USER", "refresh_outcome_uncertain") from None
        except (httpx.HTTPError, ValueError, KeyError):
            raise AccessError("NEEDS_USER", "refresh_outcome_uncertain") from None

    def read(self, account, op, config):
        token = self.token(account, config)
        if not set(op.required_scopes) <= set(token["scope"].split()):
            raise AccessError("DENIED", "provider_scope_missing")
        try:
            data = get_json(op.url, headers={"Authorization": "Bearer " + token["access_token"]})
        except AccessError as exc:
            if exc.reason != "provider_rejected_access":
                raise
            token = self.token(account, config, force=True)
            if not set(op.required_scopes) <= set(token["scope"].split()):
                raise AccessError("DENIED", "provider_scope_missing")
            data = get_json(op.url, headers={"Authorization": "Bearer " + token["access_token"]})
        if not isinstance(data, dict):
            raise AccessError("RETRYABLE", "unexpected_provider_shape")
        return {field: data[field] for field in op.fields if field in data}
