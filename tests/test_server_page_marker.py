"""Exact top-level server-page readiness; no private attribute leaves Chromium."""

from html import escape
import json

import pytest
from playwright.sync_api import sync_playwright
from pydantic import ValidationError

from account_access.catalog import LEMON_ACCOUNT, entries, include_sources, lemonsqueezy
from account_access.models import BrowserAccount, Configuration


URL = "https://marker.example.test/dashboard"
PRIVATE = "fictional-private-page-props-canary"


@pytest.fixture(scope="module")
def marker_page():
    with sync_playwright() as pw:
        browser = pw.chromium.launch(headless=True, chromium_sandbox=True)
        context = browser.new_context(java_script_enabled=False)
        page = context.new_page()
        page.route("**/*", lambda route: route.fulfill(status=200, content_type="text/html", body="<html></html>"))
        page.goto(URL)
        yield page
        context.close()
        browser.close()


@pytest.mark.parametrize("case", [
    "valid", "wrong_component", "nested_component", "nested_route", "wrong_route", "non_string_route",
    "array", "null", "malformed", "missing", "duplicate", "oversized", "wrong_destination",
])
def test_only_the_exact_top_level_page_and_destination_establish_readiness(env, marker_page, case, monkeypatch):
    from playwright.sync_api import Locator
    _, broker, _ = env
    spec = lemonsqueezy()
    spec.operations["status"].url = spec.ready_page.url = URL
    value = {"component": "App/Dashboard", "props": {"private": PRIVATE}, "url": "/dashboard"}
    if case in {"wrong_component", "nested_component"}:
        value["component"] = "Auth/Challenge"
    if case == "nested_component":
        value["props"]["decoy"] = {"component": "App/Dashboard", "url": "/dashboard"}
    if case in {"wrong_route", "nested_route"}:
        value["url"] = "/settings/payouts"
    if case == "nested_route":
        value["props"]["decoy"] = {"component": "App/Dashboard", "url": "/dashboard"}
    if case == "non_string_route":
        value["url"] = {"route": "/dashboard"}
    if case == "array":
        value = [value]
    if case == "null":
        value = None
    raw = json.dumps(value)
    if case == "malformed":
        raw = "{not-json"
    if case == "oversized":
        raw = " " * 4_000_001
    html = "<div id='app' data-page='" + escape(raw, quote=True) + "'></div>"
    if case == "missing":
        html = "<div id='app'></div>"
    if case == "duplicate":
        html += html
    if case == "wrong_destination":
        spec.ready_page.url = "https://marker.example.test/other"
    marker_page.set_content(html)

    def never_extract(*args, **kwargs):
        raise AssertionError("Only a boolean may leave the page readiness predicate")

    monkeypatch.setattr(Locator, "get_attribute", never_extract)
    monkeypatch.setattr(Locator, "inner_text", never_extract)
    assert broker.browser.ready(marker_page, spec) is (case == "valid")


@pytest.mark.parametrize("change", ["scripts", "field_read", "other_url", "query", "attribute", "extra"])
def test_marker_cannot_expand_the_result_or_execute_provider_scripts(change):
    raw = lemonsqueezy().model_dump()
    if change == "scripts":
        raw["javascript"] = True
    elif change == "field_read":
        raw["operations"]["status"].update(session_only=False, fields={"private": "#app"})
    elif change == "other_url":
        raw["ready_page"]["url"] = "https://marker.example.test/other"
    elif change == "query":
        raw["ready_page"]["url"] = raw["operations"]["status"]["url"] = URL + "?private=value"
    elif change == "attribute":
        raw["ready_page"]["attribute"] = "data-private-key"
    else:
        raw["ready_page"]["props"] = {"private": PRIVATE}
    with pytest.raises(ValidationError):
        BrowserAccount.model_validate(raw)


def test_absent_marker_preserves_all_older_fingerprints_and_active_marker_is_bound(env, monkeypatch):
    _, broker, _ = env
    config = broker.store.config()
    include_sources(config, entries())
    config.accounts.update(entries())
    before = {key: config.fingerprint(key) for key in config.accounts}
    original = BrowserAccount.model_dump

    def legacy_dump(self, **kwargs):
        data = original(self, **kwargs)
        data.pop("ready_page", None)
        return data

    with monkeypatch.context() as patch:
        patch.setattr(BrowserAccount, "model_dump", legacy_dump)
        assert all(config.fingerprint(key) == value for key, value in before.items() if key != LEMON_ACCOUNT)
        assert config.fingerprint(LEMON_ACCOUNT) != before[LEMON_ACCOUNT]
    config.accounts[LEMON_ACCOUNT].ready_page.component = "Other/Page"
    assert config.fingerprint(LEMON_ACCOUNT) != before[LEMON_ACCOUNT]
    Configuration.model_validate(config.model_dump())
