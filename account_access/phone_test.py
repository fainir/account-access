"""Owner-only Android connection test, independent of private website access."""

import time

from .errors import AccessError
from .factors import replace_source, source_mutation
from .models import BrowserAccount, CodeSource

SOURCE = 'android-connection-test'
ACCOUNT = 'owner-android-connection-test'
RECORD = 'owner-android-test'
TEMPLATE = 'Account Access connection test: {code}.'


def definition(sender):
    return CodeSource(kind='phone_relay', sender=sender, recipient='paired-android-phone', template=TEMPLATE)


def checked_source(store):
    config = store.config()
    source = config.code_sources.get(SOURCE)
    if any(isinstance(account, BrowserAccount) and account.login and SOURCE in account.login.sources()
           for account in config.accounts.values()):
        raise AccessError('DENIED', 'phone_test_source_in_use')
    if source is not None and (source.kind != 'phone_relay' or source != definition(source.sender)):
        raise AccessError('DENIED', 'phone_test_source_conflict')
    return config, source


def view(store):
    try:
        _, source = checked_source(store)
    except AccessError:
        return {'available': False}
    enrolled = store.get('source:' + SOURCE) or {}
    pair = store.get('phone-pair:' + SOURCE) or {}
    return {'available': True, 'configured': source is not None,
            'pairing_prepared': enrolled.get('enabled') is True and bool(pair.get('token')),
            'source': SOURCE, 'sender': source.sender if source else ''}


def configure(broker, sender):
    if (not isinstance(sender, str) or not 1 <= len(sender) <= 200 or sender != sender.strip()
            or any(ord(char) < 32 or ord(char) == 127 for char in sender)):
        raise AccessError('DENIED', 'invalid_phone_test_sender')
    store = broker.store
    with store.lock('catalog'), store.lock(RECORD):
        config, source = checked_source(store)
        current = definition(sender)
        if source != current:
            with source_mutation(store, SOURCE):
                config.code_sources[SOURCE] = current
                store.configure(type(config).model_validate(config.model_dump()))
                with store.db() as db:
                    replace_source(store, SOURCE, {'enabled': False}, db=db)
                    store.put('phone-pair:' + SOURCE, None, db=db)
                    store.put(RECORD, None, db=db)
            store.audit('owner', '', '', 'phone_test_configured')
    return {'status': 'CONFIGURED', 'source': SOURCE}


def start(broker):
    store = broker.store
    with store.lock(RECORD):
        _, source = checked_source(store)
        if source is None:
            raise AccessError('NEEDS_USER', 'phone_test_not_configured', 'sms')
        previous = store.get(RECORD) or {}
        if previous.get('status') == 'WAITING' and time.time() - previous['started'] < 120:
            # A double click or uncertain response does not open another window.
            try:
                broker.codes.check_window(SOURCE, previous['started'])
            except AccessError:
                pass  # Re-pairing/disable invalidated the old authority.
            else:
                return {'status': 'WAITING', 'expires': previous['started'] + 120}
        if previous.get('started'):
            broker.codes.finish(SOURCE, previous['started'])
        store.put(RECORD, None)
        started = time.time()
        broker.codes.begin(SOURCE, ACCOUNT, started)
        store.put(RECORD, {'status': 'WAITING', 'started': started})
    return {'status': 'WAITING', 'expires': started + 120}


def check(broker, *, cancel=False):
    store = broker.store
    with store.lock(RECORD):
        record = store.get(RECORD) or {}
        if record.get('status') != 'WAITING':
            return {'status': record.get('status', 'NOT_STARTED')}
        started = record['started']
        status = 'CANCELLED' if cancel else 'EXPIRED' if time.time() - started >= 120 else 'WAITING'
        if status == 'WAITING':
            try:
                checked_source(store)
                if broker.codes.resolve(SOURCE, started, set()) is not None:
                    status = 'COMPLETED'
            except AccessError:
                status = 'FAILED'
        if status != 'WAITING':
            broker.codes.finish(SOURCE, started)
            store.put(RECORD, {'status': status})
            store.audit('owner', '', '', 'phone_test_finished', status.lower())
        return {'status': status}
