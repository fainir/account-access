import pytest
import httpx2 as httpx

from account_access.errors import AccessError
from account_access.login_assets import BASE, GithubLoginAssets, asset_url

DOCUMENT = "https://github.com/sessions/two-factor/webauthn"
ENTRY = BASE + "sessions-0123456789abcdef.js"
CHUNK = BASE + "chunk-fedcba9876543210.js"


def declare(policy, url=DOCUMENT, *, main_frame=True):
    policy.document(url, "document", ('<script src="' + ENTRY + '"></script>').encode(),
                    {"content-type": "text/html; charset=utf-8"}, main_frame)


@pytest.mark.parametrize("value", [
    "https://github.githubassets.com.evil.test/assets/a-0123456789abcdef.js",
    BASE + "a-0123456789abcdef.js?code=123456", BASE + "a-0123456789abcdef.js#fragment",
    BASE + "../a-0123456789abcdef.js", BASE + "a.js", BASE + "a-0123456789abcdef.json",
    "http://github.githubassets.com/assets/a-0123456789abcdef.js",
    "https://user@github.githubassets.com/assets/a-0123456789abcdef.js",
    BASE + "a%2f-0123456789abcdef.js",
])
def test_asset_urls_reject_other_destinations_encodings_and_data_channels(value):
    assert not asset_url(value)
    policy = GithubLoginAssets([DOCUMENT])
    policy.document(DOCUMENT, "document", f'<script src="{value}"></script>'.encode(),
                    {"content-type": "text/html"}, True)
    assert not policy.urls


@pytest.mark.parametrize("url,main", [
    (DOCUMENT, False), ("https://evil.test/login", True),
    ("https://github.com/owner/repo", True), ("https://github.com/unreviewed", True),
])
def test_only_reviewed_main_authentication_responses_can_declare_assets(url, main):
    policy = GithubLoginAssets([DOCUMENT, url])
    declare(policy, url, main_frame=main)
    assert not policy.urls


def test_declared_assets_use_anonymous_gets_and_only_static_imports_expand_the_set():
    requests = []

    def vendor(request):
        requests.append(request)
        assert request.method == "GET" and not request.content
        assert not any(key in request.headers for key in ["cookie", "authorization", "referer", "origin"])
        body = (b'import "./chunk-fedcba9876543210.js"; const map={1:"unrelated-aaaaaaaaaaaaaaaa.js"};'
                if str(request.url) == ENTRY else b"window.vendorChunkLoaded = true;")
        return httpx.Response(200, headers={"content-type": "application/javascript",
                                           "set-cookie": "vendor-cookie=discard-me"},
                              stream=httpx.ByteStream(body))

    policy = GithubLoginAssets([DOCUMENT], transport=httpx.MockTransport(vendor))
    declare(policy)
    body, headers = policy.fetch(ENTRY)
    assert body.startswith(b"import") and "set-cookie" not in headers
    assert policy.urls == {ENTRY, CHUNK}
    policy.fetch(CHUNK)
    assert policy.fetch(ENTRY)[0] == body and len(requests) == 2
    with pytest.raises(AccessError, match="undeclared"):
        policy.fetch(BASE + "unrelated-aaaaaaaaaaaaaaaa.js")


@pytest.mark.parametrize("status,mime,encoding", [
    (302, "application/javascript", "identity"), (200, "text/html", "identity"),
    (200, "application/javascript", "gzip"),
])
def test_asset_redirects_html_and_compression_are_rejected(status, mime, encoding):
    def vendor(request):
        return httpx.Response(status, headers={"content-type": mime, "content-encoding": encoding,
                                              "location": "https://evil.test/"},
                              stream=httpx.ByteStream(b"untrusted"))

    policy = GithubLoginAssets([DOCUMENT], transport=httpx.MockTransport(vendor))
    declare(policy)
    with pytest.raises(AccessError, match="response_rejected"):
        policy.fetch(ENTRY)
    assert not policy.cache


@pytest.mark.parametrize("body,previous", [(b"x" * 2_000_001, 0), (b"xx", 15_999_999)])
def test_asset_and_total_transfer_budgets_stop_before_caching(body, previous):
    policy = GithubLoginAssets([DOCUMENT], transport=httpx.MockTransport(lambda request: httpx.Response(
        200, headers={"content-type": "application/javascript"}, stream=httpx.ByteStream(body))))
    declare(policy)
    policy.bytes = previous
    with pytest.raises(AccessError, match="size_limit"):
        policy.fetch(ENTRY)
    assert not policy.cache


def test_declaration_limit_is_bounded():
    policy = GithubLoginAssets([DOCUMENT])
    body = "".join(f'<script src="{BASE}a-{index:016x}.js"></script>' for index in range(257))
    with pytest.raises(AccessError, match="asset_limit"):
        policy.document(DOCUMENT, "document", body.encode(), {"content-type": "text/html"}, True)
    assert not policy.urls


def test_prefetch_parallelism_and_static_dependency_loading_are_bounded():
    import threading
    import time

    active = peak = 0
    guard = threading.Lock()

    def vendor(request):
        nonlocal active, peak
        with guard:
            active += 1
            peak = max(peak, active)
        time.sleep(0.02)
        body = b'import "./chunk-fedcba9876543210.js";' if "/t0-" in str(request.url) else b"// vendor asset"
        with guard:
            active -= 1
        return httpx.Response(200, headers={"content-type": "application/javascript"}, stream=httpx.ByteStream(body))

    policy = GithubLoginAssets([DOCUMENT], transport=httpx.MockTransport(vendor))
    declarations = "".join(f'<script src="{BASE}t{index}-{index:016x}.js"></script>' for index in range(9))
    roots = policy.document(DOCUMENT, "document", declarations.encode(), {"content-type": "text/html"}, True)
    policy.prefetch(roots)
    assert 1 < peak <= 8
    assert len(policy.cache) == policy.requests == 10 and CHUNK in policy.cache


@pytest.mark.parametrize("case", ["unrelated_site", "unrelated_github_page", "javascript_disabled"])
def test_discovery_cannot_expand_an_unrelated_connector(env, case):
    from pydantic import ValidationError
    from account_access.models import Configuration
    from test_browser_updates import github_config

    _, broker, _ = env
    config = github_config(broker)
    spec = config.accounts["github-pilot"]
    spec.javascript = case != "javascript_disabled"
    spec.login_asset_discovery = "github"
    if case == "unrelated_site":
        spec.login_url = "https://example.test/login"
    elif case == "unrelated_github_page":
        spec.login_url = "https://github.com/unrelated"
    with pytest.raises(ValidationError, match="GitHub asset discovery"):
        Configuration.model_validate(config.model_dump())
