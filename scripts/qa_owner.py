"""Render the owner console using synthetic account data only."""
import shutil
import tempfile
import threading
from pathlib import Path

from playwright.sync_api import sync_playwright

from account_access.demo import environment
from account_access.owner import make_owner_server

root = Path(tempfile.mkdtemp(prefix="aaui-", dir="/tmp"))
try:
    with environment(root) as (_, broker, _):
        broker.store.new_client("codex")
        for account in broker.store.config().accounts:
            broker.grant("codex", account, ["summary"])
        server, token = make_owner_server(broker)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with sync_playwright() as pw:
                browser = pw.chromium.launch()
                page = browser.new_page(viewport={"width": 1200, "height": 900})
                page.goto(f"http://127.0.0.1:{server.server_port}/#" + token)
                page.locator(".account").first.wait_for()
                assert page.locator(".account").count() == 3
                assert "controlled demo" in page.locator("#environment").inner_text().lower()
                Path("artifacts").mkdir(exist_ok=True)
                page.screenshot(path="artifacts/owner-console.png", full_page=True)
                browser.close()
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)
finally:
    shutil.rmtree(root)
