"""Bundled, owner-selectable connectors. No URLs or selectors are accepted from the browser."""

from .models import Configuration
from .public_demo import configuration


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
