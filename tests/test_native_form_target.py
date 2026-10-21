"""DOM fragments are not HTTP destinations; every other URL byte is authority."""

from html import escape

from playwright.sync_api import sync_playwright
from pydantic import ValidationError
import pytest

from account_access.browser import Browser, native_form_target
from account_access.errors import AccessError
from account_access.models import BrowserAccount, BrowserOperation, Configuration


def test_native_form_target_strips_only_a_literal_fragment():
    for target in ["https://reviewed.example/login", "https://reviewed.example/login?next=%2Faccount%2F",
                   "https://user:password@reviewed.example/login", "https://REVIEWED.example:443/login",
                   "https://reviewed.example/login?next=%23email", "HTTP://127.0.0.1:9000/login"]:
        assert native_form_target(target + "#/email") == target
    for value in [None, 12, "javascript:alert(1)#fragment", "data:text/html,fixture#fragment", "/login#fragment", "https://["]:
        assert native_form_target(value) is None


def test_native_form_fragments_are_still_forbidden_in_configuration():
    spec = BrowserAccount(kind="browser", label="Fictional form", login_url="https://reviewed.example/login",
                          ready_selector="#ready", operations={"status": BrowserOperation(
                              description="Read a fictional status", url="https://reviewed.example/status", fields={"status": "#ready"})})
    spec.login_post_urls = ["https://reviewed.example/login#/email"]
    with pytest.raises(ValidationError, match="no credentials or fragment"):
        Configuration(accounts={"fixture": spec})


def test_resolved_native_forms_keep_exact_origin_query_method_and_button_authority():
    target = "https://reviewed.example/login?next=%2Faccount%2F"
    spec = BrowserAccount(kind="browser", label="Fictional form", login_url=target, ready_selector="#ready",
                          login_post_urls=[target], operations={"status": BrowserOperation(
                              description="Read a fictional status", url="https://reviewed.example/status", fields={"status": "#ready"})})
    checker = Browser(None, None)
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True, chromium_sandbox=True)
        try:
            page = browser.new_page()
            page.route("https://reviewed.example/**", lambda route: route.fulfill(status=200, body="Fictional form"))
            page.goto(target)
            cases = [
                (target + "#/email", "post", "", True),
                (target + "#arbitrary-client-fragment", "post", "", True),
                ("https://reviewed.example.attacker.example/login?next=%2Faccount%2F#/email", "post", "", False),
                ("https://reviewed.example@attacker.example/login?next=%2Faccount%2F#/email", "post", "", False),
                ("https://reviewed.example/login?next=%2Fdelete%2F#/email", "post", "", False),
                (target + "%23/email", "post", "", False),
                ("http://reviewed.example/login?next=%2Faccount%2F#/email", "post", "", False),
                (target + "#/email", "get", "", False),
            ]
            for action, method, button, valid in cases:
                page.set_content("<form method='" + method + "' action='" + escape(action, quote=True) + "'>"
                                 "<input id='password' type='password'><button id='submit' " + button + ">Submit</button></form>")
                if valid:
                    checker.check_form(page, "#password", spec)
                    checker.check_staged_native_form(page, "#password", "#submit", target)
                else:
                    with pytest.raises(AccessError, match="login_form_destination_changed"):
                        checker.check_form(page, "#password", spec)
                    with pytest.raises(AccessError, match="login_form_destination_changed"):
                        checker.check_staged_native_form(page, "#password", "#submit", target)
            for button, valid in [
                ("formaction='" + target + "#/email'", True),
                ("formaction='https://attacker.example/login#/email'", False),
                ("formaction='https://reviewed.example/login?next=%2Fdelete%2F#/email'", False),
                ("formmethod='get'", False),
            ]:
                page.set_content("<form method='post' action='" + target + "#/email'>"
                                 "<input id='password' type='password'><button id='submit' " + button + ">Submit</button></form>")
                if valid:
                    checker.check_staged_native_form(page, "#password", "#submit", target)
                else:
                    with pytest.raises(AccessError, match="login_form_destination_changed"):
                        checker.check_staged_native_form(page, "#password", "#submit", target)
            # A native 303 may inherit the login form's fragment. This does not
            # change HTTP provenance; a changed query still does.
            page.goto(target + "#/email")
            page.set_content("<form method='post' action='" + target + "#/email'>"
                             "<input id='password' type='password'><button id='submit'>Submit</button></form>")
            checker.check_form(page, "#password", spec)
            spec.javascript = True
            with pytest.raises(AccessError, match="login_destination_changed"):
                checker.check_form(page, "#password", spec)
            spec.javascript = False
            page.goto("https://reviewed.example/login?next=%23email#/email")
            page.set_content("<form method='post' action='" + target + "#/email'>"
                             "<input id='password' type='password'><button id='submit'>Submit</button></form>")
            with pytest.raises(AccessError, match="login_destination_changed"):
                checker.check_form(page, "#password", spec)
        finally:
            browser.close()
