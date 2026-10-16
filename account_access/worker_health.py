"""In-memory, code-free health for the background recovery loop.

An unattached owner process reports UNKNOWN rather than guessing whether a
different process is healthy. No exception objects or provider data enter here.
"""

import threading
import time


class WorkerHealth:
    def __init__(self):
        self.lock = threading.Lock()
        self.state = {"status": "UNKNOWN", "consecutive_failures": 0, "failures_total": 0,
                      "last_success": None, "last_failure": None, "next_retry_at": None,
                      "in_progress": False}

    def start(self):
        with self.lock:
            self.state.update(status="RUNNING", consecutive_failures=0, next_retry_at=None, in_progress=False)

    def begin(self):
        with self.lock:
            self.state["in_progress"] = True

    def success(self):
        with self.lock:
            self.state.update(status="RUNNING", consecutive_failures=0, next_retry_at=None,
                              last_success=time.time(), in_progress=False)

    def failure(self):
        with self.lock:
            count = min(self.state["consecutive_failures"] + 1, 2**31 - 1)
            delay = min(30, 2 ** min(count - 1, 5))
            now = time.time()
            self.state.update(status="RETRYING", consecutive_failures=count,
                              failures_total=min(self.state["failures_total"] + 1, 2**31 - 1),
                              last_failure=now, next_retry_at=now + delay, in_progress=False)
            return delay

    def stop(self):
        with self.lock:
            self.state.update(status="STOPPED", next_retry_at=None, in_progress=False)

    def view(self):
        with self.lock:
            result = dict(self.state)
        if result["status"] in {"RETRYING", "STOPPED"}:
            result["reason"] = "background_worker_error" if result["status"] == "RETRYING" else "background_worker_stopped"
        return result
