"""Exact, ephemeral GitHub assets declared by reviewed server responses."""

import re
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed, TimeoutError
from html.parser import HTMLParser
from urllib.parse import urljoin, urlsplit

import httpx2 as httpx

from .errors import AccessError

BASE = "https://github.githubassets.com/assets/"
NAME = re.compile(r"[A-Za-z0-9_.-]{1,120}[-.][a-f0-9]{16}(?:\.module)?\.(?:js|css)")
IMPORT = re.compile(r'''(?:\bfrom\s*|\bimport\s*(?:\(\s*)?)["']((?:https://github\.githubassets\.com/assets/|\./)?[A-Za-z0-9_.-]+\.js)["']''')
AUTH_PATHS = {"/login", "/sessions/two-factor", "/sessions/two-factor/webauthn",
              "/sessions/two-factor/app", "/sessions/two-factor/sms",
              "/sessions/two-factor/sms/confirm", "/sessions/two-factor/recovery"}


def asset_url(value):
    return (isinstance(value, str) and value.startswith(BASE)
            and NAME.fullmatch(value[len(BASE):]) is not None)


class Declarations(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.urls = set()

    def handle_starttag(self, tag, attributes):
        attrs = dict(attributes)
        value = None
        if tag == "script":
            value = attrs.get("src")
        elif tag == "link" and set((attrs.get("rel") or "").lower().split()) & {"stylesheet", "modulepreload"}:
            value = attrs.get("href")
        if asset_url(value):
            self.urls.add(value)
        if len(self.urls) > 256:
            raise AccessError("NEEDS_USER", "login_asset_limit")


class GithubLoginAssets:
    def __init__(self, documents, pinned=(), *, transport=None):
        self.documents = set(documents)
        self.urls = set(pinned)
        if any(not asset_url(url) for url in self.urls):
            raise AccessError("DENIED", "invalid_login_assets")
        self.transport = transport
        self.cache = {}
        self.bytes = 0
        self.requests = 0
        self.lock = threading.RLock()
        self.dependencies = {}

    def add(self, urls):
        with self.lock:
            updated = self.urls | set(urls)
            if len(updated) > 256:
                raise AccessError("NEEDS_USER", "login_asset_limit")
            self.urls = updated

    def document(self, url, kind, body, headers, main_frame):
        if (not main_frame or kind != "document" or url not in self.documents
                or urlsplit(url).scheme != "https" or urlsplit(url).netloc != "github.com"
                or urlsplit(url).path not in AUTH_PATHS
                or headers.get("content-type", "").split(";", 1)[0].strip().lower() != "text/html"):
            return set()
        parser = Declarations()
        parser.feed(body.decode("utf-8", errors="replace"))
        self.add(parser.urls)
        return parser.urls

    def prefetch(self, roots):
        pending, seen = set(roots), set()
        if not pending:
            return
        deadline = time.monotonic() + 12
        pool = ThreadPoolExecutor(max_workers=8, thread_name_prefix="public-login-assets")
        try:
            while pending:
                batch = pending - seen
                if not batch:
                    break
                seen.update(batch)
                pending = set()
                futures = {pool.submit(self.fetch, url): url for url in batch}
                for future in as_completed(futures, timeout=max(0.01, deadline - time.monotonic())):
                    future.result()
                    pending.update(self.dependencies.get(futures[future], set()) - seen)
        except TimeoutError:
            raise AccessError("RETRYABLE", "login_asset_prefetch_timeout") from None
        finally:
            pool.shutdown(wait=True, cancel_futures=True)

    def fetch(self, url):
        with self.lock:
            if url not in self.urls or not asset_url(url):
                raise AccessError("DENIED", "undeclared_login_asset")
            if url in self.cache:
                return self.cache[url]
            self.requests += 1
            if self.requests > 256:
                raise AccessError("NEEDS_USER", "login_asset_limit")
        try:
            # A new anonymous client for each asset: no browser cookie jar,
            # inherited proxy/credentials, Referer, request body or redirects.
            with httpx.Client(trust_env=False, follow_redirects=False, timeout=10,
                              transport=self.transport) as client:
                with client.stream("GET", url, headers={"Accept": "application/javascript,text/css",
                                                       "Accept-Encoding": "identity"}) as response:
                    mime = response.headers.get("content-type", "").split(";", 1)[0].strip().lower()
                    expected = {"text/css"} if url.endswith(".css") else {"application/javascript", "text/javascript"}
                    if (response.status_code != 200 or mime not in expected
                            or response.headers.get("content-encoding", "identity") != "identity"):
                        raise AccessError("NEEDS_USER", "login_asset_response_rejected")
                    data = bytearray()
                    for chunk in response.iter_raw():
                        with self.lock:
                            if len(data) + len(chunk) > 2_000_000 or self.bytes + len(chunk) > 16_000_000:
                                raise AccessError("NEEDS_USER", "login_asset_size_limit")
                            self.bytes += len(chunk)
                            data.extend(chunk)
                    headers = {key: value for key, value in response.headers.items() if key in {
                        "content-type", "access-control-allow-origin", "cross-origin-resource-policy",
                        "content-security-policy", "x-content-type-options", "cache-control"}}
        except httpx.HTTPError:
            raise AccessError("RETRYABLE", "login_asset_fetch_failed") from None
        body = bytes(data)
        imports = {urljoin(BASE, name) for name in IMPORT.findall(body.decode("utf-8", errors="replace"))
                   if url.endswith(".js") and asset_url(urljoin(BASE, name))}
        with self.lock:
            self.add(imports)
            self.dependencies[url] = imports
            self.cache[url] = (body, headers)
        return body, headers
