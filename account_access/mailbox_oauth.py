"""Owner browser handoff for reviewed Gmail connections in the isolated worker.

The desktop owns the loopback listener and system browser. The PKCE verifier, token
exchange and renewal credentials stay in the worker's encrypted store.
"""

import re
import secrets
import time
from urllib.parse import parse_qs, urlsplit

from .errors import AccessError
from .models import OAuthAccount

GMAIL_SCOPE = "https://www.googleapis.com/auth/gmail.readonly"
AUTHORIZATION_URL = "https://accounts.google.com/o/oauth2/v2/auth"
TOKEN_URL = "https://oauth2.googleapis.com/token"
API_ORIGIN = "https://gmail.googleapis.com"
PREFIX = "mailbox-oauth:"


def supported(config, account):
    spec = config.accounts.get(account)
    if (not isinstance(spec, OAuthAccount) or set(spec.scopes) != {GMAIL_SCOPE}
            or not any(source.kind == "gmail" and source.account == account
                       for source in config.code_sources.values())):
        return False
    if (spec.authorization_url == AUTHORIZATION_URL and spec.token_url == TOKEN_URL
            and set(spec.api_origins) == {API_ORIGIN}):
        return True
    # Synthetic providers remain visibly controlled tests; this never relaxes
    # the public endpoint policy for a consumer configuration.
    authorization, token = urlsplit(spec.authorization_url), urlsplit(spec.token_url)
    return bool(config.test_mode and authorization.scheme == token.scheme == "http"
                and authorization.hostname == token.hostname == "127.0.0.1"
                and authorization.port == token.port and authorization.port)


def validate_grant(token):
    """New owner consent must provide the narrowly scoped, renewable grant.

    Never carry a refresh token from an earlier consent into a new one: the
    owner may have selected another Google account this time.
    """
    if not isinstance(token, dict):
        raise AccessError("NEEDS_USER", "invalid_provider_token", "email")
    scope = token.get("scope")
    scopes = set(scope.split()) if isinstance(scope, str) else set()
    if GMAIL_SCOPE not in scopes:
        raise AccessError("NEEDS_USER", "mailbox_scope_missing", "email")
    if scopes != {GMAIL_SCOPE}:
        raise AccessError("NEEDS_USER", "mailbox_scope_not_allowed", "email")
    refresh = token.get("refresh_token")
    if not isinstance(refresh, str) or not refresh.strip():
        raise AccessError("NEEDS_USER", "mailbox_oauth_renewal_unavailable", "email")


def connection_issue(connection):
    if not connection:
        return None
    if connection.get("revoked"):
        return "connection_revoked"
    if connection.get("invalid"):
        return "provider_grant_revoked_or_expired"
    if connection.get("refresh_in_flight"):
        return "refresh_outcome_uncertain"
    try:
        validate_grant(connection.get("token"))
    except AccessError as error:
        return error.reason
    return None


def view(broker):
    config = broker.store.config()
    result = []
    for account, spec in config.accounts.items():
        if not supported(config, account):
            continue
        sources = [{"id": key, "recipient": source.recipient,
                    "websites": [name for name, website in config.accounts.items()
                                 if getattr(website, "login", None) and key in website.login.sources()]}
                   for key, source in config.code_sources.items()
                   if source.kind == "gmail" and source.account == account]
        credential_ready = (spec.token_auth_method == "none"
                            or bool((broker.store.get("credential:" + account) or {}).get("client_secret")))
        connection = broker.store.get("connection:" + account) or {}
        issue = connection_issue(connection)
        state = broker.connection_view(account, config)
        renewable = bool(connection and not issue and connection.get("fingerprint") == config.fingerprint(account))
        if issue:
            state.update(connected=False, connection_state="needs_attention", reason=issue)
        result.append({"account": account, "label": spec.label,
                       "fingerprint": config.fingerprint(account), "sources": sources,
                       "publisher_configured": credential_ready,
                       "environment": "controlled-demo" if config.test_mode else "personal",
                       **state, "renewable_access_saved": renewable,
                       "login_delivery_verified": False})
    return result


def prepare(broker, account, fingerprint):
    config = broker.store.config()
    if (not isinstance(account, str) or not isinstance(fingerprint, str)
            or not re.fullmatch(r"[a-f0-9]{64}", fingerprint)
            or not supported(config, account)):
        raise AccessError("DENIED", "mailbox_oauth_not_configured", "email")
    if config.fingerprint(account) != fingerprint:
        raise AccessError("DENIED", "mailbox_oauth_configuration_changed", "email")
    return config


def redirect_uri(account, value):
    if not isinstance(value, str) or len(value) > 300:
        raise AccessError("DENIED", "invalid_mailbox_oauth_redirect", "email")
    try:
        parts = urlsplit(value)
        valid = (parts.scheme == "http" and parts.hostname == "127.0.0.1"
                 and parts.username is None and parts.password is None
                 and parts.port is not None and 1024 <= parts.port <= 65535
                 and parts.path == "/callback/" + account and not parts.query and not parts.fragment
                 and value == f"http://127.0.0.1:{parts.port}/callback/{account}")
    except ValueError:
        valid = False
    if not valid:
        raise AccessError("DENIED", "invalid_mailbox_oauth_redirect", "email")
    return value


def begin(broker, account, fingerprint, redirect):
    prepare(broker, account, fingerprint)
    redirect = redirect_uri(account, redirect)
    store = broker.store
    with store.lock("account:" + account):
        prepare(broker, account, fingerprint)
        previous = store.get(PREFIX + account) or {}
        if previous.get("expires", 0) > time.time():
            raise AccessError("RETRYABLE", "mailbox_oauth_already_running", "email")
        url = broker.oauth.begin(account, redirect)
        pending = store.get("oauth-pending:" + account)
        attempt = secrets.token_hex(16)
        store.put(PREFIX + account, {"attempt": attempt, "state": pending["state"],
                                     "fingerprint": fingerprint, "redirect_uri": redirect,
                                     "expires": pending["expires"]})
    return {"status": "AWAITING_CONSENT", "account": account, "attempt": attempt,
            "authorization_url": url, "expires": pending["expires"],
            "login_delivery_verified": False}


def active(store, account, attempt):
    if (not isinstance(account, str) or not re.fullmatch(r"[a-z][a-z0-9_-]{0,63}", account)
            or not isinstance(attempt, str) or not re.fullmatch(r"[a-f0-9]{32}", attempt)):
        raise AccessError("DENIED", "invalid_mailbox_oauth_attempt", "email")
    flow = store.get(PREFIX + account) or {}
    if not secrets.compare_digest(flow.get("attempt", ""), attempt):
        raise AccessError("DENIED", "invalid_mailbox_oauth_attempt", "email")
    return flow


def clear(store, account, flow):
    pending = store.get("oauth-pending:" + account) or {}
    with store.db() as db:
        if secrets.compare_digest(pending.get("state", ""), flow["state"]):
            store.put("oauth-pending:" + account, None, db=db)
        store.put(PREFIX + account, None, db=db)


def finish(broker, account, attempt, callback):
    store = broker.store
    if not isinstance(account, str) or not re.fullmatch(r"[a-z][a-z0-9_-]{0,63}", account):
        raise AccessError("DENIED", "invalid_mailbox_oauth_attempt", "email")
    with store.lock("account:" + account):
        flow = active(store, account, attempt)
        if flow["expires"] < time.time():
            clear(store, account, flow)
            raise AccessError("NEEDS_USER", "mailbox_oauth_expired", "email")
        prepare(broker, account, flow["fingerprint"])
        if not isinstance(callback, str) or len(callback) > 8192:
            raise AccessError("DENIED", "invalid_oauth_callback", "email")
        try:
            parts = urlsplit(callback)
            params = parse_qs(parts.query)
        except ValueError:
            raise AccessError("DENIED", "invalid_oauth_callback", "email") from None
        if (callback.split("?", 1)[0] != flow["redirect_uri"] or parts.fragment
                or len(params.get("state", [])) != 1
                or not params["state"][0].isascii()
                or not secrets.compare_digest(params["state"][0], flow["state"])):
            raise AccessError("DENIED", "invalid_oauth_callback", "email")
        if "error" in params:
            if len(params["error"]) != 1 or "code" in params:
                raise AccessError("DENIED", "invalid_oauth_callback", "email")
            clear(store, account, flow)
            reason = "oauth_connection_declined" if params["error"] == ["access_denied"] else "oauth_connection_failed"
            raise AccessError("NEEDS_USER", reason, "email")
        try:
            broker.oauth._finish_locked(account, callback, validate_token=validate_grant)
        except AccessError as exc:
            if exc.reason != "invalid_oauth_callback":
                clear(store, account, flow)
            raise
        clear(store, account, flow)
    # Return the committed connection before the normal service loop resumes
    # queued work. Website recovery and password-source reads can exceed the
    # native owner's reply deadline and must not run inside this setup RPC.
    return {"status": "CONNECTED", "account": account,
            "mailbox_identity_verified": False, "login_delivery_verified": False}


def cancel(broker, account, attempt):
    if not isinstance(account, str) or not re.fullmatch(r"[a-z][a-z0-9_-]{0,63}", account):
        raise AccessError("DENIED", "invalid_mailbox_oauth_attempt", "email")
    with broker.store.lock("account:" + account):
        flow = active(broker.store, account, attempt)
        clear(broker.store, account, flow)
    return {"status": "CANCELLED", "account": account}
