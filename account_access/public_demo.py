"""Reviewed public testing-site adapters; published demo identities only."""

import re

from .errors import AccessError
from .models import Configuration


def inventory_result(page, operation, account):
    """The reviewed store example returns only names/prices, never card text."""
    if (account.login_url != "https://www.saucedemo.com/"
            or operation.url != "https://www.saucedemo.com/inventory.html"
            or operation.fields != {"heading": "[data-test='title']", "items": "[data-test='inventory-list']"}):
        return None
    lists = page.locator("[data-test='inventory-list']")
    if lists.count() != 1:
        raise AccessError("NEEDS_USER", "public_example_layout_changed")
    cards = lists.locator("[data-test='inventory-item']")
    count = cards.count()
    if not 1 <= count <= 32:
        raise AccessError("NEEDS_USER", "public_example_layout_changed")
    items = []
    for index in range(count):
        card = cards.nth(index)
        name = card.locator("[data-test='inventory-item-name']")
        price = card.locator("[data-test='inventory-item-price']")
        if name.count() != 1 or price.count() != 1:
            raise AccessError("NEEDS_USER", "public_example_layout_changed")
        name_text = name.inner_text(timeout=5000).strip()
        price_text = price.inner_text(timeout=5000).strip()
        if not 1 <= len(name_text) <= 256 or re.fullmatch(r"\$[0-9]{1,6}\.[0-9]{2}", price_text) is None:
            raise AccessError("NEEDS_USER", "public_example_layout_changed")
        items.append({"name": name_text, "price": price_text})
    if cards.count() != count:
        raise AccessError("NEEDS_USER", "public_example_layout_changed")
    return {"items": items}


def configuration():
    sauce = "https://www.saucedemo.com"
    internet = "https://the-internet.herokuapp.com"
    duende = "https://demo.duendesoftware.com"
    assets = [sauce + "/assets/index-DnLqFcJI.js", sauce + "/assets/index-aSZoiKGF.css"]
    accounts = {}
    for handle, user in [("sauce-standard", "standard_user"), ("sauce-problem", "problem_user"),
                         ("sauce-locked", "locked_out_user")]:
        accounts[handle] = {
            "kind": "browser", "label": "Public SauceDemo: " + user,
            "login_url": sauce + "/", "ready_selector": "[data-test='inventory-container']",
            "javascript": True, "state_timeout_ms": 10000,
            "login": {"username_selector": "[data-test='username']",
                      "password_selector": "[data-test='password']", "submit_selector": "#login-button"},
            "challenge_selectors": {"login": "#login-button"},
            "read_resources": [sauce + "/", sauce + "/?/inventory.html", *assets],
            "login_resources": [sauce + "/inventory.html", sauce + "/?/inventory.html", *assets],
            "operations": {"inventory": {"url": sauce + "/inventory.html",
                "description": "Read public demo inventory; no cart or purchase actions",
                "fields": {"heading": "[data-test='title']", "items": "[data-test='inventory-list']"}}},
        }
    for handle in ["internet-valid", "internet-rejected"]:
        accounts[handle] = {
            "kind": "browser", "label": "Public The Internet password test",
            "login_url": internet + "/login", "ready_selector": "a[href='/logout']",
            "challenge_selectors": {"login": "#login"},
            "login": {"username_selector": "#username", "password_selector": "#password",
                      "submit_selector": "button[type='submit']"},
            "read_resources": [internet + "/login"],
            "login_resources": [internet + "/authenticate", internet + "/secure"],
            "login_post_urls": [internet + "/authenticate"],
            "operations": {"summary": {"url": internet + "/secure",
                "description": "Read public demo secure-area heading",
                "fields": {"heading": ".example h2", "message": ".example h4"}}},
        }
    for handle in ["duende-alice", "duende-bob"]:
        accounts[handle] = {
            "kind": "oauth", "label": "Public Duende OAuth test: " + handle.split("-")[1],
            "authorization_url": duende + "/connect/authorize", "token_url": duende + "/connect/token",
            "client_id": "interactive.public.short", "scopes": ["openid", "profile", "email", "offline_access"],
            "api_origins": [duende],
            "operations": {"profile": {"url": duende + "/connect/userinfo",
                "description": "Read published demo user's identity claims",
                "required_scopes": ["openid", "profile", "email"], "fields": ["sub", "name", "email"]}},
        }
    return Configuration.model_validate({"accounts": accounts})
