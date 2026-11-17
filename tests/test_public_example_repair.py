import time

import pytest

from account_access import browser_updates as repair
from account_access.errors import AccessError
from account_access.public_demo import configuration


def legacy_public(broker):
    config = broker.store.config()
    spec = configuration().accounts['sauce-standard'].model_copy(deep=True)
    spec.label = 'Owner public example'
    spec.operations['inventory'].description = 'Read product names and prices'
    for field in ('read_resources', 'login_resources'):
        setattr(spec, field, [url.replace(repair.PUBLIC_SCRIPT_CURRENT, repair.PUBLIC_SCRIPT_PREDECESSOR)
                              for url in getattr(spec, field)])
    config.accounts['public-example'] = spec
    broker.store.configure(config)
    broker.grant('test', 'public-example', ['inventory'], expires=time.time() + 300)
    return config


def test_exact_public_script_repair_preserves_credentials_reads_other_accounts_and_expiry(env):
    _, broker, _ = env
    before = legacy_public(broker)
    fingerprint = before.fingerprint('public-example')
    broker.store.put('credential:public-example', {'username': 'published-test-user', 'password': 'fixture'})
    with broker.store.db() as db:
        grants = [dict(row) for row in db.execute('SELECT * FROM grants')]
    proposal = repair.view(broker.store)
    assert proposal == [{'account': 'public-example', 'fingerprint': fingerprint,
                         'kind': 'public_example_assets', 'summary': 'Update the reviewed SauceDemo example script'}]
    assert repair.apply(broker, 'public-example', fingerprint) == {'status': 'UPDATED', 'account': 'public-example'}
    after = broker.store.config()
    for field in ('read_resources', 'login_resources'):
        assert getattr(after.accounts['public-example'], field) == [
            repair.PUBLIC_SCRIPT_CURRENT if url == repair.PUBLIC_SCRIPT_PREDECESSOR else url
            for url in getattr(before.accounts['public-example'], field)]
    old = before.model_dump()
    new = after.model_dump()
    for field in ('read_resources', 'login_resources'):
        old['accounts']['public-example'][field] = new['accounts']['public-example'][field]
    assert old == new
    assert broker.store.get('credential:public-example') == {'username': 'published-test-user', 'password': 'fixture'}
    with broker.store.db() as db:
        assert [dict(row) for row in db.execute('SELECT * FROM grants')] == [
            {**row, 'fingerprint': after.fingerprint('public-example')} if row['account'] == 'public-example' else row
            for row in grants]
    assert repair.view(broker.store) == []
    with pytest.raises(AccessError, match='browser_update_changed'):
        repair.apply(broker, 'public-example', fingerprint)


@pytest.mark.parametrize('change', ['origin', 'script', 'extra-resource', 'read', 'post', 'selector'])
def test_custom_or_unknown_public_definitions_are_never_adopted(env, change):
    _, broker, _ = env
    config = legacy_public(broker)
    spec = config.accounts['public-example']
    if change == 'origin':
        spec.login_url = 'https://not-saucedemo.example/'
    elif change == 'script':
        spec.login_resources = [url.replace('index-D3OxT1jE.js', 'unreviewed.js') for url in spec.login_resources]
    elif change == 'extra-resource':
        spec.read_resources.append('https://www.saucedemo.com/unreviewed')
    elif change == 'read':
        spec.operations['inventory'].fields['items'] = '#unreviewed'
    elif change == 'post':
        spec.login_post_urls = ['https://www.saucedemo.com/unreviewed']
    else:
        spec.login.password_selector = '#unreviewed'
    assert repair.public_example_proposal(config, 'public-example') is None
