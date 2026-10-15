"""Owner-only enrollment of a forwarded SMS filter for the reviewed GitHub pilot."""

import hashlib
from urllib.parse import urlsplit

from .browser_updates import APP_LINK, APP_PAGE, METHOD_PAGE, SMS_LINK, SMS_PAGE
from .errors import AccessError
from .models import BrowserAccount, CodeSource, LoginChoice, LoginCodeRequest, LoginFactor, origin

TEMPLATES = {
    "{code} is your github authentication code.",
    "your github authentication code is {code}.",
    "github authentication code: {code}",
    "github authentication code: {code}.",
    "{code} is your github verification code.",
}


def eligible(config, account):
    spec = config.accounts.get(account)
    if (not isinstance(spec, BrowserAccount) or not spec.login
            or origin(spec.login_url) != "https://github.com" or urlsplit(spec.login_url).path != "/login"
            or spec.login.username_selector != "#login_field" or spec.login.password_selector != "#password"
            or not spec.login.authenticator_source(config)
            or any(op.url != "https://github.com/settings/profile" for op in spec.operations.values())):
        return False
    factor = spec.login.factors.get("sms")
    return factor is None


def view(store):
    config = store.config()
    return [{"account": account, "fingerprint": config.fingerprint(account)}
            for account in config.accounts if eligible(config, account)]


def save(store, config, account, previous, *, source=None):
    """Preserve the already-approved reads and expiry through this owner repair."""
    validated = type(config).model_validate(config.model_dump())
    current = validated.fingerprint(account)
    connection = store.get("connection:" + account)
    with store.db() as db:
        if source:
            store.put("source:" + source, {"enabled": True}, db=db)
        db.execute("UPDATE grants SET fingerprint=? WHERE account=? AND fingerprint=?", (current, account, previous))
        if connection and connection.get("fingerprint") == previous:
            connection["fingerprint"] = current
            store.put("connection:" + account, connection, db=db)
        store.configure(validated)
    return current


def prepare(store, account, fingerprint):
    if not isinstance(account, str) or not isinstance(fingerprint, str):
        raise AccessError("DENIED", "invalid_sms_setup")
    with store.lock("account:" + account, timeout=5), store.lock("catalog"):
        config = store.config()
        if not eligible(config, account) or config.fingerprint(account) != fingerprint:
            raise AccessError("DENIED", "sms_setup_changed")
        spec = config.accounts[account]
        if not spec.login.factors:
            factor = spec.login.factor("totp")
            spec.login.code_source = spec.login.code_selector = spec.login.code_submit_selector = None
            spec.login.factors = {"totp": factor}
        for url in [METHOD_PAGE, APP_PAGE, SMS_PAGE, "https://github.com/sessions/two-factor/sms"]:
            if url not in spec.login_resources:
                spec.login_resources.append(url)
        if SMS_PAGE not in spec.login_post_urls:
            spec.login_post_urls.append(SMS_PAGE)
        spec.challenge_selectors["method"] = APP_LINK + ", " + SMS_LINK
        spec.login.choices = [LoginChoice(kind="totp", selector=APP_LINK, url=APP_PAGE),
                              LoginChoice(kind="sms", selector=SMS_LINK, url=SMS_PAGE)]
        spec.login.code_requests = [LoginCodeRequest(kind="sms", url=SMS_PAGE,
                                                     selector='form[action="/sessions/two-factor/sms/confirm"] button')]
        current = save(store, config, account, fingerprint)
        store.audit("owner", account, "", "sms_setup_prepared")
        return current


def apply(store, account, fingerprint, sender, template):
    if (not isinstance(sender, str) or not 1 <= len(sender) <= 200 or not sender.isprintable()
            or not isinstance(template, str) or template.lower() not in TEMPLATES):
        raise AccessError("DENIED", "invalid_sms_filter")
    source = "github-sms-" + hashlib.sha256(account.encode()).hexdigest()[:16]
    with store.lock("account:" + account, timeout=5), store.lock("catalog"), store.lock("source:" + source):
        config = store.config()
        if (not eligible(config, account) or config.fingerprint(account) != fingerprint
                or source in config.code_sources or store.get("source:" + source)):
            raise AccessError("DENIED", "sms_setup_changed")
        spec = config.accounts[account]
        if not any(item.url == SMS_PAGE and item.kind == "sms" for item in spec.login.code_requests):
            raise AccessError("DENIED", "sms_setup_not_prepared")
        config.code_sources[source] = CodeSource(kind="mac_messages", sender=sender,
                                                 recipient="messages-on-this-mac", template=template)
        spec.login.factors["sms"] = LoginFactor(code_source=source, code_selector="#sms_totp",
                                                code_submit_selector=spec.login.factor("totp").code_submit_selector)
        spec.challenge_selectors["sms"] = "#sms_totp"
        save(store, config, account, fingerprint, source=source)
        store.audit("owner", account, "", "factor_enrolled", "mac_messages")
    return {"status": "ENROLLED", "account": account, "source": source}
