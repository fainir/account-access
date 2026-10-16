"""Owner-reviewed, narrowly scoped repairs to a known browser login connector."""

import json
import re
from pathlib import Path
from urllib.parse import urlsplit

from .errors import AccessError
from .models import BrowserAccount, LoginChoice, LoginFactor, origin

METHOD_PAGE = "https://github.com/sessions/two-factor/webauthn"
APP_PAGE = "https://github.com/sessions/two-factor/app"
APP_LINK = 'a[href="/sessions/two-factor/app"]'
SMS_PAGE = "https://github.com/sessions/two-factor/sms/confirm"
SMS_LINK = 'a[href="/sessions/two-factor/sms/confirm"]'
RECOVERY_PAGE = "https://github.com/sessions/two-factor/recovery"


def github_assets():
    assets = json.loads(Path(__file__).with_name("github_login_assets.json").read_text())["resources"]
    if (not isinstance(assets, list) or not 1 <= len(assets) <= 150
            or any(not isinstance(url, str) or not re.fullmatch(
                r"https://github\.githubassets\.com/assets/[A-Za-z0-9_.-]+\.(?:js|css)", url)
                   for url in assets)):
        raise AccessError("DENIED", "invalid_github_login_assets")
    return assets


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
    if spec.javascript and spec.login_assets:
        # A signed connector update may refresh exact public vendor assets, but
        # never activate JavaScript or add an arbitrary CDN URL through this path.
        updated.login_assets = sorted(set(spec.login_assets) | set(github_assets()))
        if len(updated.login_assets) > 150:
            return None
        updated.login_asset_discovery = "github"
    for url in [METHOD_PAGE, SMS_PAGE, RECOVERY_PAGE]:
        if url not in updated.login_resources:
            updated.login_resources.append(url)
    recovery = '#recovery_code, input[name="recovery_code"]'
    existing_action = updated.challenge_selectors.get("action")
    if not existing_action:
        updated.challenge_selectors["action"] = recovery
    elif recovery not in existing_action:
        updated.challenge_selectors["action"] = existing_action + ", " + recovery
    # Recognize the offered SMS method even before its source is enrolled. The
    # browser must report local setup instead of an unrecognized page. Reading
    # this confirmation page does not authorize its form POST or a new source.
    updated.challenge_selectors["method"] = APP_LINK + ", " + SMS_LINK
    # Legacy single-source forms match every kind at lookup time. Normalize the
    # existing authenticator factor so an offered, unenrolled SMS source cannot
    # accidentally resolve to that key.
    if not updated.login.factors:
        updated.login.factors["totp"] = LoginFactor(
            code_source=updated.login.code_source, code_selector=updated.login.code_selector,
            code_submit_selector=updated.login.code_submit_selector)
        updated.login.code_source = updated.login.code_selector = updated.login.code_submit_selector = None
    updated.login.choices = [LoginChoice(kind="totp", selector=APP_LINK, url=APP_PAGE),
                             LoginChoice(kind="sms", selector=SMS_LINK, url=SMS_PAGE)]
    return updated if updated.model_dump() != spec.model_dump() else None


def view(store):
    config = store.config()
    return [{"account": account, "fingerprint": config.fingerprint(account),
             "summary": "Update reviewed GitHub sign-in controls and public assets"}
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
        # This repair only adds reviewed login GETs, optional choices and
        # GitHub's bounded, anonymous public script/stylesheet loader.
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
