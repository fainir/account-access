"""Bundled, owner-selectable connectors. No URLs or selectors are accepted from the browser."""

from .models import BrowserAccount, BrowserOperation, CodeSource, Configuration, LoginFactor, LoginForm
from .public_demo import configuration
from .account_context import describe

NAMECHEAP_LOGIN = "https://www.namecheap.com/myaccount/login/"
NAMECHEAP_LANDING = "https://ap.www.namecheap.com/"
NAMECHEAP_FORM = "[id$='_loginDiv']"
NAMECHEAP_USER = "[id$='_alreadyLoggedInDiv'] [id$='_ltUsername']"
PYPI_ACCOUNT = "personal-pypi"
PYPI_SOURCE = "personal-pypi-totp"


def pypi():
    """Username-only pilot; new-device email confirmation remains a stop."""
    from . import pypi_challenge as policy
    root = "https://pypi.org"
    login = root + policy.LOGIN_PATH + "?" + policy.LOGIN_QUERY
    return BrowserAccount(
        kind="browser", label="PyPI", login_url=login, login_challenge=policy.POLICY,
        ready_selector=policy.READY,
        login=LoginForm(username_selector=policy.USERNAME, password_selector=policy.PASSWORD,
                        submit_selector=policy.PASSWORD_SUBMIT,
                        factors={"totp": LoginFactor(code_selector=policy.TOTP,
                            code_submit_selector=policy.TOTP_SUBMIT, code_source=PYPI_SOURCE)}),
        challenge_selectors=dict(policy.CHALLENGES),
        login_resources=[root + policy.STATUS_PATH, root + policy.DEVICE_PATH],
        login_post_urls=[login],
        operations={"status": BrowserOperation(url=root + policy.STATUS_PATH,
            description="Confirm your signed-in PyPI username", fields={"username": policy.READY})})


def include_sources(config, specs):
    """Merge only new fixed catalog definitions; never adopt an unrelated seed.

    Call before adding accounts. This mutates only the caller's configuration
    copy after all collisions pass; it never enrolls, enables, or grants a source.
    """
    selected = specs.get(PYPI_ACCOUNT)
    if selected is None or not selected.login or selected.login.sources() != {PYPI_SOURCE}:
        return
    expected = CodeSource(kind="totp")
    existing = config.code_sources.get(PYPI_SOURCE)
    connected = config.accounts.get(PYPI_ACCOUNT)
    if connected is None and selected != pypi():
        from .errors import AccessError
        raise AccessError("DENIED", "catalog_connector_changed")
    if existing is not None and (
            not isinstance(connected, BrowserAccount) or not connected.login
            or PYPI_SOURCE not in connected.login.sources() or existing != expected):
        from .errors import AccessError
        raise AccessError("DENIED", "catalog_code_source_conflict")
    if existing is None:
        config.code_sources[PYPI_SOURCE] = expected


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
    result[PYPI_ACCOUNT] = pypi()
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
        include_sources(config, {handle: available[handle]})
        config.accounts[handle] = available[handle]
        store.configure(Configuration.model_validate(config.model_dump()))


def view():
    return [{"id": key, **describe(spec), "url": spec.login_url,
             "operations": [{"name": name, "description": operation.description}
                            for name, operation in spec.operations.items()]}
            for key, spec in entries().items()]
