import shutil
import tempfile
from pathlib import Path

import pytest

from account_access.demo import environment


@pytest.fixture
def env():
    # Short path also permits real Unix-domain socket tests on macOS.
    root = Path(tempfile.mkdtemp(prefix="aat-", dir="/tmp"))
    try:
        with environment(root) as (provider, broker, _):
            token = broker.store.new_client("test")
            for account in broker.store.config().accounts:
                broker.grant("test", account, list(broker.store.config().accounts[account].operations))
            yield provider, broker, token
    finally:
        shutil.rmtree(root)
