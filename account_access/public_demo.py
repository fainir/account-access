"""Reviewed public testing-site adapters; published demo identities only."""

from .models import Configuration


def configuration():
    sauce = "https://www.saucedemo.com"
    internet = "https://the-internet.herokuapp.com"
    duende = "https://demo.duendesoftware.com"
    assets = [sauce + "/assets/index-D3OxT1jE.js", sauce + "/assets/index-aSZoiKGF.css"]
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
