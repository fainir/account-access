"""Owner-reviewed, narrowly scoped repairs to a known browser login connector."""

from urllib.parse import urlsplit

from .errors import AccessError
from .models import BrowserAccount, LoginChoice, origin

METHOD_PAGE = "https://github.com/sessions/two-factor/webauthn"
APP_PAGE = "https://github.com/sessions/two-factor/app"
APP_LINK = 'a[href="/sessions/two-factor/app"]'


def proposal(config, account):
    spec = config.accounts.get(account)
    if (not isinstance(spec, BrowserAccount) or not spec.login
            or origin(spec.login_url) != "https://github.com"
            or urlsplit(spec.login_url).path != "/login"
            or spec.login.username_selector != "#login_field"
            or spec.login.password_selector != "#password"
            or spec.login.authenticator_source(config) is None
            or APP_PAGE not in spec.login_resources
            or not spec.operations or any(op.url != "https://github.com/settings/profile"
                                          for op in spec.operations.values())):
        return None
    updated = spec.model_copy(deep=True)
    if METHOD_PAGE not in updated.login_resources:
        updated.login_resources.append(METHOD_PAGE)
    updated.challenge_selectors["method"] = APP_LINK
    updated.login.choices = [LoginChoice(kind="totp", selector=APP_LINK, url=APP_PAGE)]
    return updated if updated.model_dump() != spec.model_dump() else None


def view(store):
    config = store.config()
    return [{"account": account, "fingerprint": config.fingerprint(account),
             "summary": "Support GitHub's offered authenticator-app choice"}
            for account in config.accounts if proposal(config, account)]


def apply(broker, account, fingerprint):
    store = broker.store
    if not isinstance(account, str) or not isinstance(fingerprint, str):
        raise AccessError("DENIED", "invalid_browser_update")
    with store.lock("account:" + account), store.lock("catalog"):
        config = store.config()
        if account not in config.accounts or config.fingerprint(account) != fingerprint:
            raise AccessError("DENIED", "browser_update_changed")
        updated = proposal(config, account)
        if updated is None:
            raise AccessError("DENIED", "browser_update_unavailable")
        previous = config.accounts[account]
        # This repair can only add the reviewed login GET and optional choice.
        # It cannot widen reads, POST destinations, credentials or recipients.
        if (updated.operations != previous.operations or updated.read_resources != previous.read_resources
                or updated.login_post_urls != previous.login_post_urls
                or updated.login.sources() != previous.login.sources()):
            raise AccessError("DENIED", "invalid_browser_update")
        config.accounts[account] = updated
        store.configure(type(config).model_validate(config.model_dump()))
        current = config.fingerprint(account)
        connection = store.get("connection:" + account)
        with store.db() as db:
            db.execute("UPDATE grants SET fingerprint=? WHERE account=? AND fingerprint=?",
                       (current, account, fingerprint))
            if connection and connection.get("fingerprint") == fingerprint:
                connection["fingerprint"] = current
                store.put("connection:" + account, connection, db=db)
        store.audit("owner", account, "", "login_connector_updated", "authenticator_choice")
    return {"status": "UPDATED", "account": account}
