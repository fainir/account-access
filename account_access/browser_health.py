"""An offline execution check in the protected worker's real launch context."""

import os
import signal
import subprocess
import sys


OFFLINE_CHECK = """from playwright.sync_api import sync_playwright
with sync_playwright() as pw:
    browser = pw.chromium.launch(headless=True, chromium_sandbox=True)
    try:
        context = browser.new_context(offline=True, service_workers='block')
        context.route('**/*', lambda route: route.abort())
        page = context.new_page()
        page.set_content('<script>window.runtimeAnswer=6*7</script>')
        assert page.evaluate('window.runtimeAnswer') == 42
        context.close()
    finally:
        browser.close()
"""


class BrowserHealth:
    def __init__(self):
        self.status = "NOT_CHECKED"

    def check(self):
        # No account, credential, cookie, network address or exception text is
        # supplied to or returned from this fixed child. Keep the worker's
        # bootstrap/audit context; only create a process group for timeout cleanup.
        self.status = "UNAVAILABLE"
        environment = {key: os.environ[key] for key in (
            'PATH', 'HOME', 'USER', 'LOGNAME', 'LANG', 'LC_ALL', 'PLAYWRIGHT_BROWSERS_PATH'
        ) if key in os.environ}
        try:
            process = subprocess.Popen([sys.executable, '-I', '-B', '-c', OFFLINE_CHECK],
                env=environment, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL, close_fds=True, process_group=0)
        except OSError:
            return
        try:
            code = process.wait(timeout=20)
        except subprocess.TimeoutExpired:
            # The child has not been reaped, so its PID/group cannot be reused.
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait()
            return
        if code == 0:
            self.status = "READY"

    def view(self):
        return {"status": self.status}
