"""Cleanup regression tests with fake Popen/select/read/signal/wait globals."""

import ast
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace

import pytest

from account_access.errors import AccessError
from account_access import password_sync


class WaitTimeout(Exception):
    pass


class Pipe:
    def __init__(self, *, close_error=False):
        self.closed = False
        self.close_error = close_error

    def fileno(self):
        return 4243

    def close(self):
        self.closed = True
        if self.close_error:
            raise OSError("not exposed")


class Process:
    pid = 4242

    def __init__(self, *, close_error=False, wait_timeout=False, kill_error=False, exit_code=0):
        self.returncode = None
        self.stdout = Pipe(close_error=close_error)
        self.waits = []
        self.kills = 0
        self.wait_timeout = wait_timeout
        self.kill_error = kill_error
        self.exit_code = exit_code

    def wait(self, *, timeout):
        self.waits.append(timeout)
        if self.wait_timeout:
            raise WaitTimeout()
        self.returncode = self.exit_code
        return self.returncode

    def kill(self):
        self.kills += 1
        if self.kill_error:
            raise PermissionError("not exposed")


class Selector:
    def __init__(self, fixture):
        self.fixture = fixture
        self.registered = False

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.fixture.selector_closed = True

    def register(self, pipe, event):
        assert pipe is self.fixture.process.stdout and event == 1
        self.registered = True

    def unregister(self, pipe):
        assert pipe is self.fixture.process.stdout
        self.registered = False

    def get_map(self):
        return {4243: 1} if self.registered else {}

    def select(self, remaining):
        self.fixture.selects.append(remaining)
        return [] if self.fixture.select_timeout else [(4243, 1)]


class Fixture:
    def __init__(self, *, body=b"ok", group_error=None, read_error=None,
                 select_timeout=False, **process_options):
        self.body = body
        self.group_error = group_error
        self.read_error = read_error
        self.select_timeout = select_timeout
        self.process = Process(**process_options)
        self.groups = []
        self.selects = []
        self.set_blocking_calls = []
        self.selector_closed = False
        self.spawned = []

    def read(self, descriptor, bound):
        assert descriptor == 4243 and 0 < bound <= 4096
        if self.read_error:
            raise self.read_error
        value, self.body = self.body[:bound], self.body[bound:]
        return value

    def killpg(self, pid, sig):
        self.groups.append((pid, sig))
        if self.group_error:
            raise self.group_error("not exposed")

    def popen(self, argv, **kwargs):
        self.spawned.append((argv, kwargs))
        assert kwargs["start_new_session"] and kwargs["close_fds"]
        assert kwargs["stdout"] == "PIPE" and kwargs["stdin"] == "DEVNULL"
        return self.process

    def run(self, directory):
        # Extract only the actual tracked functions, then inject entirely fake
        # process/OS/selector/clock globals. No helper top-level imports run.
        path = Path(__file__).resolve().parents[1] / "account_access/bitwarden_source.py"
        parsed = ast.parse(path.read_text())
        functions = [node for node in parsed.body if isinstance(node, ast.FunctionDef)
                     and node.name in {"fail", "_run"}]
        assert len(functions) == 2
        namespace = {
            "AccessError": AccessError, "Path": Path, "CLI_DEADLINE": 20, "MAX_OUTPUT": 262144,
            "time": SimpleNamespace(monotonic=lambda: 0),
            "signal": SimpleNamespace(SIGKILL="SIGKILL"),
            "os": SimpleNamespace(read=self.read, killpg=self.killpg,
                                  set_blocking=lambda *args: self.set_blocking_calls.append(args)),
            "subprocess": SimpleNamespace(Popen=self.popen, DEVNULL="DEVNULL", PIPE="PIPE",
                                          TimeoutExpired=WaitTimeout),
            "selectors": SimpleNamespace(DefaultSelector=lambda: Selector(self), EVENT_READ=1),
        }
        exec(compile(ast.Module(body=functions, type_ignores=[]), str(path), "exec"), namespace)
        return namespace["_run"](["fake-provider"], ["get", "exact-item"], directory, 10,
                                 secret_environment={"BW_SESSION": "synthetic-session"})


def assert_clean_attempt(fixture):
    assert fixture.groups == [(4242, "SIGKILL")]
    assert fixture.process.stdout.closed and fixture.selector_closed
    assert fixture.set_blocking_calls == [(4243, False)]
    assert fixture.spawned[0][1]["env"] == {}  # Cleared even on failures.
    assert all(0 <= timeout <= 20 for timeout in fixture.process.waits)


@pytest.mark.parametrize("group_error", [None, ProcessLookupError])
def test_success_still_kills_background_group_or_accepts_absent_group(tmp_path, group_error):
    fixture = Fixture(group_error=group_error)
    assert fixture.run(tmp_path) == b"ok"
    assert fixture.process.kills == 0
    assert_clean_attempt(fixture)


@pytest.mark.parametrize("options", [{"group_error": PermissionError}, {"close_error": True}])
def test_successful_body_never_releases_output_when_cleanup_unverified(tmp_path, options):
    fixture = Fixture(**options)
    with pytest.raises(AccessError) as result:
        fixture.run(tmp_path)
    assert (result.value.status, result.value.reason) == ("RETRYABLE", "password_source_unavailable")
    assert_clean_attempt(fixture)


@pytest.mark.parametrize("options", [
    {"group_error": PermissionError},
    {"wait_timeout": True},
    {"close_error": True},
    {"group_error": PermissionError, "kill_error": True, "wait_timeout": True, "close_error": True},
])
def test_original_oversize_denial_survives_cleanup_failure_and_pipe_still_closes(tmp_path, options):
    fixture = Fixture(body=b"x" * 262145, **options)
    with pytest.raises(AccessError) as result:
        fixture.run(tmp_path)
    assert (result.value.status, result.value.reason) == ("DENIED", "password_source_item_changed")
    assert fixture.process.waits == [2]
    assert fixture.process.kills == (1 if options.get("group_error") else 0)
    assert_clean_attempt(fixture)


def test_original_access_error_instance_and_internal_context_are_preserved(tmp_path):
    error = AccessError("DENIED", "password_source_item_changed")
    error.source_id = "synthetic-source-context"
    fixture = Fixture(read_error=error, group_error=PermissionError, close_error=True)
    with pytest.raises(AccessError) as result:
        fixture.run(tmp_path)
    assert result.value is error and result.value.source_id == "synthetic-source-context"
    assert_clean_attempt(fixture)


@pytest.mark.parametrize("options", [{"select_timeout": True}, {"wait_timeout": True}, {"exit_code": 1}])
def test_original_timeout_or_exit_remains_closed_and_cleanup_bounded(tmp_path, options):
    fixture = Fixture(group_error=PermissionError, **options)
    with pytest.raises(AccessError) as result:
        fixture.run(tmp_path)
    assert (result.value.status, result.value.reason) == ("RETRYABLE", "password_source_unavailable")
    assert len(fixture.process.waits) <= 2
    assert fixture.process.waits[-1] <= 10
    assert_clean_attempt(fixture)


class Store:
    def __init__(self):
        self.link = {"provider": "bitwarden", "connection": "1" * 32,
                     "connection_generation": "2" * 32, "generation": "3" * 32,
                     "item": "synthetic-item", "username": "synthetic-owner",
                     "fingerprint": "fixture-fingerprint", "next_at": 0, "status": "SYNCED"}
        self.values = {"password-link:fixture": dict(self.link),
                       "credential:fixture": {"username": "synthetic-owner", "password": "synthetic-password"},
                       "connection:fixture": {"status": "signed-in"},
                       "password-source:bitwarden:" + "1" * 32:
                           {"generation": "2" * 32, "status": "CONNECTED"}}

    def get(self, key):
        return self.values.get(key)

    def put(self, key, value, *, db=None):
        assert db is self
        self.values[key] = value

    def unseal(self, key, value):
        assert value is self.values[key]
        return value

    def config(self):
        return SimpleNamespace(fingerprint=lambda account: "fixture-fingerprint",
                               accounts={"fixture": SimpleNamespace(login_url="https://example.test/login")})

    def execute(self, query, values=()):
        if query == "BEGIN IMMEDIATE":
            self.selected = None
        else:
            assert query == "SELECT value FROM records WHERE id=?"
            self.selected = self.values.get(values[0])
        return self

    def fetchone(self):
        return (self.selected,) if self.selected else None


@pytest.mark.parametrize("cleanup", [{"group_error": PermissionError}, {"wait_timeout": True}, {"close_error": True}])
def test_real_refresh_failure_path_invalidates_only_synthetic_cache(tmp_path, monkeypatch, cleanup):
    from account_access import bitwarden_source

    store = Store()
    fixture = Fixture(body=b"x" * 262145, **cleanup)

    @contextmanager
    def fake_database(selected):
        assert selected is store
        yield store

    monkeypatch.setattr(bitwarden_source, "_database", fake_database)
    monkeypatch.setattr(password_sync, "_fetch", lambda *args: fixture.run(tmp_path))
    with pytest.raises(AccessError) as result:
        password_sync.refresh(store, "fixture", force=True)
    assert (result.value.status, result.value.reason) == ("NEEDS_USER", "password_source_item_changed")
    assert store.get("credential:fixture") is None and store.get("connection:fixture") is None
    assert store.get("password-link:fixture")["status"] == "BLOCKED"
    assert store.get("password-link:fixture")["reason"] == "password_source_item_changed"
    assert_clean_attempt(fixture)
