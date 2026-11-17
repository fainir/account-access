import json
import threading
import time

import httpx2 as httpx
import pytest

from account_access import phone_test as test_phone
from account_access.errors import AccessError
from account_access.factors import enroll, revoke
from account_access.models import CodeSource
from account_access.owner import make_owner_server
from account_access.phone import deliver


def paired(broker):
    test_phone.configure(broker, 'Fixture sender')
    broker.store.put('source:' + test_phone.SOURCE, {'enabled': True})
    broker.store.put('phone-pair:' + test_phone.SOURCE, {'token': 'fixture-pair-token'})


def message(**changes):
    return {'id': 'fixture-message', 'sender': 'Fixture sender', 'recipient': 'paired-android-phone',
            'body': test_phone.TEMPLATE.replace('{code}', '123456'), 'received_at': time.time(), **changes}


def test_fresh_setup_preserves_accounts_grants_credentials_and_expiry(env):
    _, broker, _ = env
    before = broker.store.config()
    fingerprints = {key: before.fingerprint(key) for key in before.accounts}
    with broker.store.db() as db:
        grants = [dict(row) for row in db.execute('SELECT * FROM grants')]
    assert test_phone.view(broker.store)['configured'] is False
    paired(broker)
    after = broker.store.config()
    assert after.accounts == before.accounts
    assert {key: after.fingerprint(key) for key in after.accounts} == fingerprints
    with broker.store.db() as db:
        assert [dict(row) for row in db.execute('SELECT * FROM grants')] == grants
    assert set(after.code_sources) - set(before.code_sources) == {test_phone.SOURCE}
    assert test_phone.view(broker.store)['pairing_prepared'] is True


def test_one_fresh_message_completes_without_returning_its_value_and_double_start_reuses_window(env):
    _, broker, _ = env
    paired(broker)
    started = test_phone.start(broker)
    assert test_phone.start(broker) == started
    assert test_phone.check(broker) == {'status': 'WAITING'}
    assert deliver(broker.store, test_phone.SOURCE, message(), pair_token='fixture-pair-token') == {'status': 'RECEIVED'}
    result = test_phone.check(broker)
    assert result == {'status': 'COMPLETED'}
    assert '123456' not in json.dumps(result)
    assert broker.store.get('code-window:' + test_phone.SOURCE) is None
    assert test_phone.check(broker) == result
    with pytest.raises(AccessError, match='no_current_login_window'):
        deliver(broker.store, test_phone.SOURCE, message(id='late'), pair_token='fixture-pair-token')


@pytest.mark.parametrize('failure', ['cancel', 'expired', 'disabled', 'ambiguous', 'changed-sender'])
def test_expiry_cancellation_repair_and_ambiguity_discard_the_window(env, monkeypatch, failure):
    _, broker, _ = env
    paired(broker)
    test_phone.start(broker)
    started = broker.store.get(test_phone.RECORD)['started']
    status = 'FAILED'
    if failure == 'cancel':
        result = test_phone.check(broker, cancel=True)
        status = 'CANCELLED'
    else:
        if failure == 'expired':
            monkeypatch.setattr(test_phone.time, 'time', lambda: started + 121)
            status = 'EXPIRED'
        elif failure == 'disabled':
            revoke(broker.store, test_phone.SOURCE)
        elif failure == 'changed-sender':
            test_phone.configure(broker, 'Different fixture sender')
            assert test_phone.check(broker) == {'status': 'NOT_STARTED'}
            assert broker.store.get('code-window:' + test_phone.SOURCE) is None
            return
        else:
            for ident in ['first', 'second']:
                deliver(broker.store, test_phone.SOURCE, message(id=ident), pair_token='fixture-pair-token')
        result = test_phone.check(broker)
    assert result == {'status': status}
    assert broker.store.get('code-window:' + test_phone.SOURCE) is None


@pytest.mark.parametrize('changes', [
    {'sender': 'Other sender'}, {'recipient': 'Other phone'}, {'body': 'Payment: 123456'},
    {'received_at': 0},
])
def test_unrelated_messages_are_never_accepted(env, changes):
    _, broker, _ = env
    paired(broker)
    test_phone.start(broker)
    with pytest.raises(AccessError):
        deliver(broker.store, test_phone.SOURCE, message(**changes), pair_token='fixture-pair-token')
    assert test_phone.check(broker) == {'status': 'WAITING'}


def test_reserved_source_collision_refuses_without_changing_configuration(env):
    _, broker, _ = env
    config = broker.store.config()
    config.code_sources[test_phone.SOURCE] = CodeSource(kind='totp')
    broker.store.configure(config)
    assert test_phone.view(broker.store) == {'available': False}
    with pytest.raises(AccessError, match='phone_test_source_conflict'):
        test_phone.configure(broker, 'Fixture sender')
    assert broker.store.config() == config


def test_repairing_pairing_never_reuses_an_invalidated_test_window(env):
    _, broker, _ = env
    paired(broker)
    first = test_phone.start(broker)
    enroll(broker.store, test_phone.SOURCE, {})
    second = test_phone.start(broker)
    assert second['expires'] > first['expires']
    assert test_phone.check(broker) == {'status': 'WAITING'}


def test_new_routes_require_owner_authorization_and_correct_origin(env):
    _, broker, agent_token = env
    server, token = make_owner_server(broker, guided=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f'http://127.0.0.1:{server.server_port}'
    headers = {'Authorization': 'Bearer ' + token, 'Origin': base}
    try:
        with httpx.Client(base_url=base, trust_env=False) as client:
            for operation, body in [('configure', {'sender': 'Fixture sender'}), ('start', {}), ('check', {}), ('cancel', {})]:
                for invalid in [{}, {'Authorization': 'Bearer ' + agent_token, 'Origin': base},
                                {'Authorization': 'Bearer ' + token, 'Origin': 'https://evil.test'}]:
                    assert client.post('/owner/phone/test/' + operation, json=body, headers=invalid).status_code == 403
            assert client.post('/owner/phone/test/configure', json={'sender': 'Fixture sender'}, headers=headers).json()['status'] == 'CONFIGURED'
            assert client.post('/owner/phone/test/start', json={}, headers=headers).json()['reason'] == 'verification_source_disabled'
    finally:
        server.shutdown()
        server.server_close()
        thread.join(3)
