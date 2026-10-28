import os
from pathlib import Path
import selectors
import signal
import subprocess
import sys


def test_managed_worker_owns_sigterm_through_actual_server_and_cleanup():
    script = '''
import socket, sys, threading, time
from fastapi import FastAPI
import uvicorn
from account_access.worker_signals import ManagedWorkerServer, managed_worker_signals
listener = socket.socket()
listener.bind(("127.0.0.1", 0)); listener.listen(8)
server = ManagedWorkerServer(uvicorn.Config(FastAPI(), log_level="critical", access_log=False, log_config=None))
def announce():
    deadline = time.monotonic() + 15
    while not server.started and time.monotonic() < deadline: time.sleep(0.01)
    print("READY" if server.started else "FAILED", flush=True)
watcher = threading.Thread(target=announce)
with managed_worker_signals(server):
    watcher.start()
    server.run(sockets=[listener])
    watcher.join(timeout=1)
    assert not server._captured_signals
    print("CLEANING", flush=True)
    assert sys.stdin.readline().strip() == "finish"
    listener.close()
print("CLEANED", flush=True)
'''
    child = subprocess.Popen([sys.executable, "-c", script], cwd=Path(__file__).resolve().parents[1],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
    def line():
        with selectors.DefaultSelector() as ready:
            ready.register(child.stdout, selectors.EVENT_READ)
            assert ready.select(20)
        return child.stdout.readline().strip()
    try:
        assert line() == b"READY"
        child.send_signal(signal.SIGTERM)
        assert line() == b"CLEANING"
        child.send_signal(signal.SIGTERM)  # A second signal cannot skip private cleanup.
        stdout, stderr = child.communicate(b"finish\n", timeout=10)
        assert child.returncode == 0 and stdout.strip() == b"CLEANED" and not stderr
    finally:
        if child.poll() is None:
            os.killpg(child.pid, signal.SIGKILL)
            child.communicate(timeout=5)
