import json
import os
import signal
import subprocess
import sys
import threading
import time

import httpx2 as httpx
import pytest

from account_access.desktop import launch, running, stop
from account_access.errors import AccessError
from account_access.models import TaskRequest
from account_access.storage import private_file
from account_access.supervisor import active, attached, disable, enable, guard_desktop, lease, registration, supervise


def wait_for(check, timeout=15):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        value = check()
        if value:
            return value
        time.sleep(0.1)
    raise AssertionError("Fixture service did not reach expected state")


def finish(root):
    stop(root)
    # Returning from stop must establish quiescence, not only HTTP acceptance.
    with lease(root):
        pass
    with lease(root, "service"):
        pass


def test_marker_is_not_liveness_and_stale_generation_cannot_start_a_host(env, monkeypatch):
    _, broker, _ = env
    root = broker.store.root
    old = enable(root)
    current = enable(root)
    assert current != old and not attached(root)
    with lease(root):
        assert attached(root)
    calls = []
    monkeypatch.setattr("account_access.supervisor.spawn", lambda *a, **k: calls.append(a))
    supervise(root, old, key_file=root / "demo.key")
    assert not calls and active(root, current)
    disable(root)


def test_supervisor_holds_its_lease_until_owned_child_cleanup_finishes(env, monkeypatch):
    _, broker, _ = env
    root = broker.store.root
    generation = enable(root)
    spawned = threading.Event()
    cleaning = threading.Event()
    finish_cleanup = threading.Event()
    failures = []
    class Child:
        returncode = None
        def poll(self):
            return self.returncode
        def terminate(self):
            cleaning.set()
            assert finish_cleanup.wait(5)
            self.returncode = 0
        def wait(self, timeout):
            return self.returncode
    def spawn(*_args, **_kwargs):
        spawned.set()
        return Child()
    monkeypatch.setattr("account_access.supervisor.spawn", spawn)
    monkeypatch.setattr("account_access.desktop.running", lambda _root: None)
    monkeypatch.setattr("account_access.supervisor.signal.signal", lambda *_args: signal.SIG_DFL)
    def run():
        try:
            supervise(root, generation)
        except BaseException as exc:
            failures.append(exc)
    worker = threading.Thread(target=run)
    worker.start()
    try:
        assert spawned.wait(5)
        disable(root)
        assert cleaning.wait(5)
        with pytest.raises(AccessError, match="account_busy"):
            with lease(root):
                pass
    finally:
        finish_cleanup.set()
        worker.join(timeout=5)
    assert not worker.is_alive() and not failures
    with lease(root):
        pass


@pytest.mark.parametrize("during", ["open", "read", "replace"])
def test_pause_or_replacement_during_generation_read_never_activates_old_inode(env, monkeypatch, during):
    _, broker, _ = env
    root = broker.store.root
    generation = enable(root)
    path = root / "supervisor.json"
    original_open, original_read = os.open, os.read
    target = None
    triggered = False

    def change():
        nonlocal triggered
        triggered = True
        path.unlink()
        if during == "replace":
            private_file(path, b'{"generation":"invalid replacement"}')

    def opened(name, flags, *args, **kwargs):
        nonlocal target
        fd = original_open(name, flags, *args, **kwargs)
        if name == path:
            target = fd
            if during == "open":
                change()
        return fd

    def read(fd, count):
        data = original_read(fd, count)
        if fd == target and not triggered:
            change()
        return data

    monkeypatch.setattr("account_access.supervisor.os.open", opened)
    monkeypatch.setattr("account_access.supervisor.os.read", read)
    assert not active(root, generation)
    assert triggered
    if during == "replace":
        with pytest.raises(AccessError, match="invalid_service_supervision"):
            active(root, generation)


@pytest.mark.parametrize("kind", ["symlink", "hardlink", "public", "malformed"])
def test_untrusted_supervision_control_is_refused(env, tmp_path, kind):
    _, broker, _ = env
    root = broker.store.root
    generation = enable(root)
    path = root / "supervisor.json"
    content = path.read_bytes()
    path.unlink()
    if kind == "symlink":
        outside = tmp_path / "outside"
        private_file(outside, content)
        path.symlink_to(outside)
    elif kind == "hardlink":
        outside = tmp_path / "outside"
        private_file(outside, content)
        os.link(outside, path)
    else:
        private_file(path, content if kind == "public" else b'{"generation":"unknown"}')
        if kind == "public":
            path.chmod(0o644)
    with pytest.raises(AccessError):
        active(root, generation)
    if kind in {"symlink", "hardlink"}:
        assert outside.read_bytes() == content


def test_actual_host_crash_resumes_same_queued_task_without_agent_reconnect(env):
    _, broker, _ = env
    root = broker.store.root
    info = launch(root, key_file=root / "demo.key", open_browser=False)
    stopped_pid = None
    try:
        assert attached(root)
        # Freeze only the child created for this fixture. Enqueue while it
        # cannot tick, then kill it; no client request triggers the restart.
        stopped_pid = info["pid"]
        os.kill(stopped_pid, signal.SIGSTOP)
        job = broker.submit("test", TaskRequest(key="survive-host-crash", steps=[
            {"account": "demo-api", "operation": "summary"}]))
        assert job["status"] == "QUEUED"
        os.kill(stopped_pid, signal.SIGKILL)
        stopped_pid = None
        def completed():
            result = broker.task("test", job["task_id"])
            return result if result["status"] == "COMPLETED" else None
        result = wait_for(completed)
        replacement = wait_for(lambda: running(root))
        assert replacement["pid"] != info["pid"] and attached(root)
        assert result["task_id"] == job["task_id"] and result["progress"] == 1
        before = broker.audit("test")
        os.kill(replacement["pid"], signal.SIGKILL)
        wait_for(lambda: (value := running(root)) and value["pid"] != replacement["pid"])
        time.sleep(1.2)
        assert broker.task("test", job["task_id"])["status"] == "COMPLETED"
        assert broker.audit("test") == before  # Completed reads are not replayed.
        assert os.stat(root / "supervisor.json").st_mode & 0o077 == 0
    finally:
        if stopped_pid:
            try:
                os.kill(stopped_pid, signal.SIGCONT)
            except ProcessLookupError:
                pass
        finish(root)


def test_pause_stops_supervision_and_reopen_reuses_saved_access(env):
    _, broker, _ = env
    root = broker.store.root
    first = launch(root, key_file=root / "demo.key", open_browser=False)
    try:
        finish(root)
        assert not running(root) and not attached(root) and registration(root) is None
        with pytest.raises(AccessError, match="service_paused"):
            launch(root, key_file=root / "demo.key", open_browser=False, on_demand=True)
        assert registration(root) is None
        second = launch(root, key_file=root / "demo.key", open_browser=False)
        assert second["pid"] != first["pid"] and attached(root)
        assert broker.run("test", "demo-api", "summary")["status"] == "COMPLETED"
    finally:
        finish(root)


def test_stop_accepts_actual_listener_exit_after_authenticated_readiness(env, monkeypatch):
    _, broker, _ = env
    root = broker.store.root
    info = launch(root, key_file=root / "demo.key", open_browser=False)
    refused = []
    original_post = httpx.post
    def after_exit(_root):
        # Stop has disabled supervision. Wait for that real process to reap
        # its child, then return the previously authenticated readiness result.
        # This deterministically exercises the readiness-to-POST race.
        with lease(root, timeout=20):
            pass
        with lease(root, "service", timeout=20):
            pass
        return info
    def post(*args, **kwargs):
        try:
            return original_post(*args, **kwargs)
        except httpx.ConnectError:
            refused.append(True)
            raise
    try:
        with monkeypatch.context() as patch:
            patch.setattr("account_access.desktop.running", after_exit)
            patch.setattr("account_access.desktop.httpx.post", post)
            stop(root)
        assert refused == [True]
        assert not running(root) and not attached(root) and registration(root) is None
        assert (root / "service.paused").is_file()
        with pytest.raises(AccessError, match="service_paused"):
            launch(root, key_file=root / "demo.key", open_browser=False, on_demand=True)
    finally:
        finish(root)


def test_unreachable_stop_still_refuses_a_held_service_lease(env, monkeypatch):
    _, broker, _ = env
    root = broker.store.root
    monkeypatch.setattr("account_access.desktop.running", lambda _: {"url": "http://127.0.0.1:1/", "token": "fixture"})
    def disconnected(*_args, **_kwargs):
        raise httpx.ConnectError("Synthetic closed listener")
    monkeypatch.setattr("account_access.desktop.httpx.post", disconnected)
    # Keep the real lease check, but don't wait twenty seconds to prove denial.
    monkeypatch.setattr("account_access.supervisor.lease", lambda root, name="desktop-supervisor", timeout=0: lease(root, name, timeout=0))
    with lease(root, "service"):
        with pytest.raises(AccessError, match="account_busy"):
            stop(root)
    assert (root / "service.paused").is_file()


def test_stop_does_not_hide_an_explicit_owner_endpoint_rejection(env, monkeypatch):
    _, broker, _ = env
    root = broker.store.root
    monkeypatch.setattr("account_access.desktop.running", lambda _: {"url": "http://127.0.0.1:1/", "token": "fixture"})
    monkeypatch.setattr("account_access.desktop.httpx.post", lambda *args, **kwargs: httpx.Response(403))
    with pytest.raises(AccessError, match="could_not_stop_local_app"):
        stop(root)


@pytest.mark.parametrize("runner", [supervise, guard_desktop])
def test_owner_setup_failure_stops_instead_of_repeating_keyring_prompts(env, runner):
    _, broker, _ = env
    root = broker.store.root
    generation = enable(root)
    invalid_key = root / "invalid-development.key"
    private_file(invalid_key, b"invalid")
    runner(root, generation, key_file=invalid_key)
    assert not attached(root) and registration(root) is None
    # The real child reports a fixed setup error once, with no secret material.
    log = (root / "desktop.log").read_text()
    assert log.count('"reason": "invalid_vault_key"') == 1
    assert '"status": "NEEDS_USER"' in log
    assert not running(root)


def test_project_modules_and_pythonpath_cannot_hijack_supervised_startup(env, tmp_path, monkeypatch):
    _, broker, _ = env
    root = broker.store.root
    project = tmp_path / "untrusted-project"
    module = project / "account_access"
    module.mkdir(parents=True)
    marker = project / "project-code-ran"
    (module / "__init__.py").write_text(
        "from pathlib import Path\nPath(" + repr(str(marker)) + ").write_text('unexpected import')\n"
        "raise RuntimeError('Untrusted project module was imported')\n")
    monkeypatch.chdir(project)
    monkeypatch.setenv("PYTHONPATH", str(project))
    try:
        info = launch(root, key_file=root / "demo.key", open_browser=False)
        assert running(root)["pid"] == info["pid"] and attached(root)
        assert not marker.exists()
    finally:
        finish(root)


def test_supervisor_observes_an_existing_host_without_signalling_its_pid(env):
    _, broker, _ = env
    root = broker.store.root
    command = [sys.executable, "-m", "account_access.cli", "--root", str(root),
               "--development", "--key-file", str(root / "demo.key")]
    host = subprocess.Popen([*command, "desktop-host"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    observer = None
    try:
        initial = wait_for(lambda: running(root))
        generation = enable(root)
        observer = subprocess.Popen([*command, "desktop-supervisor", "--generation", generation],
                                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        wait_for(lambda: attached(root))
        assert running(root)["pid"] == initial["pid"] == host.pid
        observer.terminate()
        assert observer.wait(timeout=10) == 0
        assert running(root)["pid"] == host.pid and host.poll() is None
        assert not attached(root)
    finally:
        finish(root)
        host.wait(timeout=15)
        if observer is not None and observer.poll() is None:
            observer.terminate()
            observer.wait(timeout=10)


def test_dead_api_thread_closes_owner_server_instead_of_claiming_readiness(env, monkeypatch):
    import uvicorn
    from account_access.desktop import host
    from account_access.owner import make_owner_server
    _, broker, _ = env
    exit_thread = threading.Event()
    class ExitingAPI:
        started = False
        should_exit = False
        def run(self):
            self.started = True
            exit_thread.wait(timeout=5)
    api = ExitingAPI()
    monkeypatch.setattr(uvicorn, "Server", lambda *_a, **_k: api)
    def owner(*args, **kwargs):
        result = make_owner_server(*args, **kwargs)
        exit_thread.set()
        return result
    monkeypatch.setattr("account_access.owner.make_owner_server", owner)
    started = time.monotonic()
    host(broker)
    assert api.should_exit and time.monotonic() - started < 5
    assert running(broker.store.root) is None
    with lease(broker.store.root, "service"):
        pass


@pytest.mark.parametrize("command, runner", [("desktop-supervisor", "supervise"), ("desktop-guardian", "guard_desktop")])
def test_supervisor_command_does_not_load_owner_store(env, monkeypatch, command, runner):
    from account_access.cli import main
    _, broker, _ = env
    called = []
    def forbidden(*_a, **_k):
        raise AssertionError("Supervisor must not load the vault key")
    monkeypatch.setattr("account_access.cli.owner_store", forbidden)
    monkeypatch.setattr("account_access.supervisor." + runner, lambda *a, **k: called.append((a, k)))
    previous_mask = os.umask(0o077)
    try:
        assert main(["--root", str(broker.store.root), command, "--generation", "a" * 64]) == 0
        assert len(called) == 1
        assert json.dumps(registration(broker.store.root)) == "null"
    finally:
        os.umask(previous_mask)


def test_standby_guardian_takes_over_after_both_processes_die_without_agent_reconnect(env):
    _, broker, _ = env
    root = broker.store.root
    generation = enable(root)
    command = [sys.executable, "-I", "-m", "account_access.cli", "--root", str(root),
               "--development", "--key-file", str(root / "demo.key")]
    first = subprocess.Popen([*command, "desktop-supervisor", "--generation", generation],
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    guardian = None
    frozen = None
    try:
        initial = wait_for(lambda: running(root))
        guardian = subprocess.Popen([*command, "desktop-guardian", "--generation", generation],
                                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(0.6)
        assert guardian.poll() is None and running(root)["pid"] == initial["pid"]
        frozen = initial["pid"]
        os.kill(frozen, signal.SIGSTOP)
        job = broker.submit("test", TaskRequest(key="survive-both-processes", steps=[
            {"account": "demo-api", "operation": "summary"}]))
        assert job["status"] == "QUEUED"
        first.kill()
        first.wait(timeout=5)
        os.kill(frozen, signal.SIGKILL)
        frozen = None
        def completed():
            result = broker.task("test", job["task_id"])
            return result if result["status"] == "COMPLETED" else None
        result = wait_for(completed)
        replacement = wait_for(lambda: running(root))
        assert result["task_id"] == job["task_id"] and result["progress"] == 1
        assert replacement["pid"] != initial["pid"] and guardian.poll() is None
    finally:
        if frozen:
            try:
                os.kill(frozen, signal.SIGCONT)
            except ProcessLookupError:
                pass
        finish(root)
        if first.poll() is None:
            first.terminate()
        first.wait(timeout=15)
        if guardian is not None:
            guardian.wait(timeout=15)


def test_pause_ends_an_os_guardian_waiting_for_the_active_supervisor(env):
    _, broker, _ = env
    root = broker.store.root
    launch(root, key_file=root / "demo.key", open_browser=False)
    generation = registration(root)["generation"]
    guardian = subprocess.Popen([sys.executable, "-I", "-m", "account_access.cli", "--root", str(root),
                                 "--development", "--key-file", str(root / "demo.key"),
                                 "desktop-guardian", "--generation", generation],
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        time.sleep(0.6)
        assert guardian.poll() is None
        finish(root)
        assert guardian.wait(timeout=5) == 0
        assert (root / "service.paused").exists() and registration(root) is None
    finally:
        finish(root)
        if guardian.poll() is None:
            guardian.terminate()
            guardian.wait(timeout=10)
