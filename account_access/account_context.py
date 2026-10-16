"""Describe configured account sources without changing authority fingerprints.

These labels identify known testing destinations, not account ownership or a
fresh sign-in. Exact origins prevent look-alike domains from receiving labels.
"""

from urllib.parse import urlsplit

from .models import BrowserAccount, origin

PUBLIC_EXAMPLES = frozenset({"https://www.saucedemo.com", "https://the-internet.herokuapp.com",
                             "https://demo.duendesoftware.com"})


def environment(spec, *, test_mode=False):
    urls = [operation.url for operation in spec.operations.values()]
    if isinstance(spec, BrowserAccount):
        urls += [spec.login_url, *spec.read_resources, *spec.login_resources,
                 *spec.login_assets, *spec.login_post_urls, *spec.password_import_origins]
    else:
        urls += [spec.authorization_url, spec.token_url, *spec.api_origins]
        if spec.revoke_url:
            urls.append(spec.revoke_url)
    origins = {origin(url) for url in urls}
    if origins and origins <= PUBLIC_EXAMPLES:
        return "public-example"
    if test_mode and urls and all(urlsplit(url).hostname == "127.0.0.1" for url in urls):
        return "controlled-demo"
    return "live"


def describe(spec, *, test_mode=False):
    context = environment(spec, test_mode=test_mode)
    return {"label": spec.label + (" · Public example" if context == "public-example" else ""),
            "environment": context, "environment_source": "connector-configuration"}


def aggregate(accounts, *, test_mode=False):
    values = {account["environment"] for account in accounts}
    if len(values) == 1:
        return next(iter(values))
    if values:
        return "mixed"
    return "controlled-demo" if test_mode else "live"


def result_view(result):
    """Do not retroactively infer source identity for old saved task results."""
    if result.get("environment_source") == "connector-configuration":
        return result
    return {**result, "environment": "unclassified", "environment_source": "legacy-unclassified"}
