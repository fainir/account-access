"""Bundled, owner-selectable connectors. No URLs or selectors are accepted from the browser."""

from .models import BrowserAccount, BrowserOperation, Configuration, LoginForm
from .public_demo import configuration

NAMECHEAP_LOGIN = "https://www.namecheap.com/myaccount/login/"
NAMECHEAP_LANDING = "https://ap.www.namecheap.com/"
NAMECHEAP_FORM = "[id$='_loginDiv']"
NAMECHEAP_USER = "[id$='_alreadyLoggedInDiv'] [id$='_ltUsername']"


def namecheap():
    """Bounded password pilot, reviewed against the actual public login form.

    The only operation returns the signed-in username from the login page.
    Email/TOTP/security-key pages are deliberately not inferred from docs or
    treated as successful login. They need their own reviewed provider routes.
    """
    return BrowserAccount(
        kind="browser", label="Namecheap", login_url=NAMECHEAP_LOGIN,
        password_import_origins=["https://ap.www.namecheap.com"],
        ready_selector=(NAMECHEAP_USER + ", "
                        "a[href='https://www.namecheap.com/myaccount/signout']"),
        login=LoginForm(
            username_selector=NAMECHEAP_FORM + " input[name='LoginUserName']",
            password_selector=NAMECHEAP_FORM + " input[name='LoginPassword']",
            submit_selector=NAMECHEAP_FORM + " input[id$='_LoginButton']"),
        challenge_selectors={"login": NAMECHEAP_FORM},
        login_resources=[NAMECHEAP_LANDING],
        login_post_urls=[NAMECHEAP_LOGIN],
        operations={"status": BrowserOperation(
            url=NAMECHEAP_LOGIN,
            description="Confirm your signed-in Namecheap username",
            fields={"username": NAMECHEAP_USER})})


def entries():
    public = configuration()
    definitions = [
        ("personal-store", "Personal shopping account", "sauce-standard", "inventory", "Read product names and prices"),
        ("work-store", "Work shopping account", "sauce-problem", "inventory", "Read product names and prices"),
        ("member-portal", "Membership account", "internet-valid", "summary", "Read your account welcome message"),
    ]
    result = {}
    for handle, label, source, operation, description in definitions:
        spec = public.accounts[source].model_copy(deep=True)
        spec.label = label
        spec.operations[operation].description = description
        result[handle] = spec
    result["personal-namecheap"] = namecheap()
    return result


def add(store, handle):
    available = entries()
    if handle not in available:
        from .errors import AccessError
        raise AccessError("DENIED", "unsupported_service")
    with store.lock("catalog"):
        config = store.config()
        if handle in config.accounts:
            from .errors import AccessError
            raise AccessError("DENIED", "account_already_added")
        config.accounts[handle] = available[handle]
        store.configure(Configuration.model_validate(config.model_dump()))


def view():
    return [{"id": key, "label": spec.label, "url": spec.login_url,
             "operations": [{"name": name, "description": operation.description}
                            for name, operation in spec.operations.items()]}
            for key, spec in entries().items()]
