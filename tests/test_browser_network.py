import pytest
from playwright.sync_api import Error, sync_playwright


def test_native_redirect_preserves_final_document_url_relative_links_and_cookie(env):
    provider, broker, _ = env
    parent = provider.server.RequestHandlerClass
    seen = []

    class Handler(parent):
        def do_GET(self):
            seen.append((self.path, self.cookie("redirect-fixture")))
            if self.path == "/native/start":
                self.send(303, {}, {"Location": "/native/final", "Set-Cookie": "redirect-fixture=ok; Path=/; SameSite=Strict"})
            elif self.path == "/native/final":
                self.page('<script src="relative.js"></script><h1>Native redirect</h1>')
            elif self.path == "/native/relative.js":
                self.send(200, "window.relativeLoaded = true", content_type="application/javascript")
            else:
                super().do_GET()

    provider.server.RequestHandlerClass = Handler
    spec = broker.store.config().accounts["demo-web"]
    spec.javascript = True
    spec.login_resources += [provider.base + path for path in ["/native/start", "/native/final", "/native/relative.js"]]
    with sync_playwright() as pw:
        browser = pw.chromium.launch(chromium_sandbox=True)
        context = broker.browser.context(browser, spec, login=True)
        page = broker.browser.page(context)
        page.goto(provider.base + "/native/start")
        assert page.url == provider.base + "/native/final"
        assert page.evaluate("window.relativeLoaded") is True
        browser.close()
    assert ("/native/final", "ok") in seen
    assert ("/native/relative.js", "ok") in seen


@pytest.mark.parametrize("status", [307, 308])
def test_native_redirect_cannot_forward_password_to_get_only_resource(env, status):
    provider, broker, _ = env
    parent = provider.server.RequestHandlerClass

    class Handler(parent):
        def do_POST(self):
            if self.path == "/web/login":
                provider.login_count += 1
                self.rfile.read(int(self.headers.get("Content-Length", "0")))
                self.send(status, {}, {"Location": "/web/summary"})
            else:
                super().do_POST()

    provider.server.RequestHandlerClass = Handler
    result = broker.run("test", "demo-web", "summary")
    assert result["status"] != "COMPLETED"
    assert provider.login_count == 1
    assert "/web/summary" not in provider.posted_paths


@pytest.mark.parametrize("initiator", ["navigation", "fetch", "iframe", "worker", "popup"])
def test_redirects_from_each_browser_surface_remain_bounded(env, initiator):
    provider, broker, _ = env
    parent = provider.server.RequestHandlerClass
    destinations = []

    class Handler(parent):
        def do_GET(self):
            destinations.append(self.path)
            if self.path == "/reviewed-start":
                self.send(302, {}, {"Location": "/unreviewed-target"})
            else:
                super().do_GET()

    provider.server.RequestHandlerClass = Handler
    spec = broker.store.config().accounts["demo-web"]
    spec.javascript = True
    spec.login_resources.append(provider.base + "/reviewed-start")
    with sync_playwright() as pw:
        browser = pw.chromium.launch(chromium_sandbox=True)
        context = broker.browser.context(browser, spec, login=True)
        page = broker.browser.page(context)
        page.goto(spec.login_url)
        target = provider.base + "/reviewed-start"
        if initiator == "navigation":
            with pytest.raises(Error):
                page.goto(target)
        else:
            script = {
                "fetch": "url => fetch(url).catch(() => {})",
                "iframe": "url => {let f = document.createElement('iframe'); f.src = url; document.body.append(f)}",
                "worker": "url => {window.testWorker = new Worker(url)}",
                "popup": "url => window.open(url)",
            }[initiator]
            page.evaluate(script, target)
            page.wait_for_timeout(500)
        browser.close()
    assert "/reviewed-start" in destinations
    assert "/unreviewed-target" not in destinations


def test_native_response_size_and_redirect_limit_remain_bounded(env):
    provider, broker, _ = env
    parent = provider.server.RequestHandlerClass
    seen = []

    class Handler(parent):
        def do_GET(self):
            seen.append(self.path)
            if self.path.startswith("/hop/"):
                self.send(302, {}, {"Location": "/hop/" + str(int(self.path.rsplit("/", 1)[1]) + 1)})
            elif self.path == "/oversized":
                self.send(200, "x" * 8_000_001, content_type="text/plain")
            else:
                super().do_GET()

    provider.server.RequestHandlerClass = Handler
    spec = broker.store.config().accounts["demo-web"]
    spec.login_resources += [provider.base + "/hop/" + str(n) for n in range(10)] + [provider.base + "/oversized"]
    with sync_playwright() as pw:
        browser = pw.chromium.launch(chromium_sandbox=True)
        context = broker.browser.context(browser, spec, login=True)
        page = broker.browser.page(context)
        for path in ["/hop/0", "/oversized"]:
            with pytest.raises(Error):
                page.goto(provider.base + path)
        browser.close()
    assert "/hop/5" in seen and "/hop/6" not in seen
