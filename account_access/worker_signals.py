"""Signal ownership for a supervisor-managed worker process, including cleanup."""
from contextlib import contextmanager
import signal
import threading

import uvicorn


class ManagedWorkerServer(uvicorn.Server):
    @contextmanager
    def capture_signals(self):
        # The outer worker context owns signals through owner-thread cleanup.
        # Do not capture/replay a delivered SIGTERM after graceful shutdown.
        yield


@contextmanager
def managed_worker_signals(server):
    if threading.current_thread() is not threading.main_thread():
        raise RuntimeError("managed_worker_requires_main_thread")
    def stop(_signal, _frame):
        server.should_exit = True
    previous = {kind: signal.signal(kind, stop) for kind in (signal.SIGTERM, signal.SIGINT)}
    try:
        yield
    finally:
        for kind, handler in previous.items():
            signal.signal(kind, handler)
