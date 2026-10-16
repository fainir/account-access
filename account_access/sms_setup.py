"""Owner-only enrollment of a forwarded SMS filter for the reviewed GitHub pilot."""

import hashlib
import re
import sys
from pathlib import Path
from urllib.parse import urlsplit

from .browser_updates import APP_LINK, APP_PAGE, METHOD_PAGE, SMS_LINK, SMS_PAGE, github_assets
from .errors import AccessError
from .models import BrowserAccount, CodeSource, LoginChoice, LoginCodeRequest, LoginFactor, origin

TEMPLATES = {
    "{code} is your github authentication code.",
    "your github authentication code is {code}.",
    "github authentication code: {code}",
    "github authentication code: {code}.",
    "{code} is your github verification code.",
}


def diagnostics(page):
    """Closed structural metadata for owner troubleshooting; never input values."""
    from .navigation import route_hint
    forms = page.locator("form").evaluate_all("""forms => forms.slice(0, 8).map(form => ({
        action: form.action, method: form.method,
        dispatch: form.classList.contains('js-send-auth-code'),
        auto: form.hasAttribute('data-autosubmit')
    }))""")
    controls = {}
    for name, selector in {"sms": SMS_LINK, "totp": APP_LINK, "toggle": ".more-options-two-factor"}.items():
        control = page.locator(selector)
        controls[name] = {"count": min(control.count(), 8), "visible": control.first.is_visible()}
    # These filenames are public vendor assets, not page text or user data.
    assets = page.locator("script[src], link[rel='stylesheet'][href]").evaluate_all(
        "elements => elements.map(el => el.src || el.href)")
    assets = sorted({url for url in assets if re.fullmatch(
        r"https://github\.githubassets\.com/assets/[A-Za-z0-9_.-]+\.(?:js|css)", url)})[:150]
    return {
        "controls": controls,
        "assets": assets,
        "forms": [{"route": route_hint(form["action"], ["https://github.com"]),
                   "method": form["method"].upper() if form["method"].upper() in {"GET", "POST"} else "other",
                   "dispatch": form["dispatch"] is True, "auto": form["auto"] is True}
                  for form in forms],
        "fields": {name: page.locator(selector).count() > 0 for name, selector in {
            "sms_totp": "#sms_totp", "app_totp": "#app_totp", "otp_id": "#otp",
            "otp_name": 'input[name="otp"]', "one_time_code": 'input[autocomplete="one-time-code"]',
            "recovery_code": '#recovery_code, input[name="recovery_code"]'}.items()},
        "dispatch_state": page.locator("body").evaluate("""body => ({
            sending: body.classList.contains('is-sending'), sent: body.classList.contains('is-sent'),
            failed: body.classList.contains('is-not-sent')})"""),
        "notices": page.locator("body").evaluate("""body => {
            const text = Array.from(body.querySelectorAll('.flash-error, .flash-warn, [role="alert"], .js-sms-error'))
                .slice(0, 8).map(el => el.innerText).join(' ').slice(0, 8000).toLowerCase();
            return {
                delivery_failed: /(?:unable|failed|could not|couldn't|cannot|can't).{0,50}(?:send|deliver).{0,50}(?:sms|text|message|code)/s.test(text),
                rate_limited: /too many.{0,50}(?:sms|text|code|request|attempt)|rate limit|try again later/s.test(text),
                unavailable: /sms.{0,50}(?:unavailable|not available|not enabled|not configured)/s.test(text),
                invalid_request: /csrf|authenticity token|invalid request|request.{0,30}(?:expired|invalid)/s.test(text)
            };
        }"""),
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
        assets = github_assets()
        spec.javascript = True
        # Use the owner's current stable vendor build in an isolated temporary
        # profile, never the personal Chrome profile or its saved credentials.
        if sys.platform == "darwin" and Path("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome").is_file():
            spec.browser_channel = "chrome"
        spec.login_assets = assets
        spec.login_asset_discovery = "github"
        spec.login.choice_toggle_selector = ".more-options-two-factor"
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
