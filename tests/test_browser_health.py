import os
import signal
import subprocess
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from account_access.browser_health import BrowserHealth, OFFLINE_CHECK


@pytest.mark.parametrize('code,status', [(0, 'READY'), (-5, 'UNAVAILABLE'), (1, 'UNAVAILABLE')])
def test_health_requires_actual_offline_execution_without_inheriting_secrets(monkeypatch, code, status):
    monkeypatch.setenv('UNRELATED_SECRET', 'never-forward-this')
    child = Mock(pid=12345)
    child.wait.return_value = code
    launch = Mock(return_value=child)
    monkeypatch.setattr(subprocess, 'Popen', launch)
    health = BrowserHealth()
    assert health.view() == {'status': 'NOT_CHECKED'}
    health.check()
    assert health.view() == {'status': status}
    args, kwargs = launch.call_args
    assert args[0][-1] == OFFLINE_CHECK
    assert args[0][1:4] == ['-I', '-B', '-c']
    assert 'UNRELATED_SECRET' not in kwargs['env']
    assert kwargs['close_fds'] and kwargs['process_group'] == 0
    assert kwargs['stdout'] == kwargs['stderr'] == kwargs['stdin'] == subprocess.DEVNULL


def test_hanging_browser_group_is_killed_and_reaped_without_retaining_output(monkeypatch):
    child = Mock(pid=12345)
    child.wait.side_effect = [subprocess.TimeoutExpired('private exception text', 20), -9]
    monkeypatch.setattr(subprocess, 'Popen', Mock(return_value=child))
    kill = Mock()
    monkeypatch.setattr(os, 'killpg', kill)
    health = BrowserHealth()
    health.check()
    kill.assert_called_once_with(12345, signal.SIGKILL)
    assert child.wait.call_count == 2
    assert health.view() == {'status': 'UNAVAILABLE'}


def test_missing_interpreter_reports_fixed_status(monkeypatch):
    monkeypatch.setattr(subprocess, 'Popen', Mock(side_effect=OSError('private text')))
    health = BrowserHealth()
    health.check()
    assert health.view() == {'status': 'UNAVAILABLE'}


def test_discovery_reports_health_without_starting_a_browser(env, monkeypatch):
    _, broker, _ = env
    monkeypatch.setattr(subprocess, 'Popen', Mock(side_effect=AssertionError('must not start a check')))
    assert broker.accounts('test')['browser_runtime'] == {'status': 'NOT_CHECKED'}
    broker.browser_health = SimpleNamespace(view=lambda: {'status': 'READY'})
    assert broker.accounts('test')['browser_runtime'] == {'status': 'READY'}
