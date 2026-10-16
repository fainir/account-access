import json
import os
import signal
import subprocess
import sys
import threading
import time

import pytest

from account_access.desktop import launch, running, stop
from account_access.errors import AccessError
from account_access.models import TaskRequest
from account_access.storage import private_file
from account_access.supervisor import active, attached, disable, enable, lease, registration, supervise


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
    with lease(root, timeout=20):
        pass
    with lease(root, "service", timeout=20):
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


def test_owner_setup_failure_stops_instead_of_repeating_keyring_prompts(env):
    _, broker, _ = env
    root = broker.store.root
    generation = enable(root)
    invalid_key = root / "invalid-development.key"
    private_file(invalid_key, b"invalid")
    supervise(root, generation, key_file=invalid_key)
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


def test_supervisor_command_does_not_load_owner_store(env, monkeypatch):
    from account_access.cli import main
    _, broker, _ = env
    called = []
    def forbidden(*_a, **_k):
        raise AssertionError("Supervisor must not load the vault key")
    monkeypatch.setattr("account_access.cli.owner_store", forbidden)
    monkeypatch.setattr("account_access.supervisor.supervise", lambda *a, **k: called.append((a, k)))
    previous_mask = os.umask(0o077)
    try:
        assert main(["--root", str(broker.store.root), "desktop-supervisor", "--generation", "a" * 64]) == 0
        assert len(called) == 1
        assert json.dumps(registration(broker.store.root)) == "null"
    finally:
        os.umask(previous_mask)
