import json
import threading

import pytest
from playwright.sync_api import sync_playwright

from account_access.account_context import aggregate, describe, environment
from account_access.catalog import entries, namecheap, view
from account_access.models import Configuration, TaskRequest
from account_access.owner import make_owner_server
from account_access.password_import import apply, preview
from account_access.public_demo import configuration as public_configuration


def test_reviewed_examples_are_derived_without_changing_configuration_or_grants(env, monkeypatch):
    provider, broker, _ = env
    config = broker.store.config()
    config.accounts.update(entries())
    broker.store.configure(config)
    broker.grant("test", "personal-store", ["inventory"])
    before = broker.store.config().model_dump()
    fingerprints = {name: config.fingerprint(name) for name in config.accounts}
    result = broker.accounts("test")
    assert result["environment"] == "mixed"
    rows = {item["account"]: item for item in result["accounts"]}
    assert rows["personal-store"]["environment"] == "public-example"
    assert "Public example" in rows["personal-store"]["label"]
    assert rows["demo-api"]["environment"] == "controlled-demo"
    assert "personal-namecheap" not in rows  # No operation grant: no discovery leak.
    monkeypatch.setattr(broker.browser, "read", lambda *args, **kwargs: {
        "environment": "live", "message": "Fictional public result; metadata test only"})
    before_calls = provider.api_count
    read = broker.run("test", "personal-store", "inventory")
    assert read["environment"] == "public-example"
    assert read["environment_source"] == "connector-configuration"
    assert read["data"]["environment"] == "live"  # Untrusted body cannot replace outer metadata.
    assert provider.api_count == before_calls
    assert broker.store.config().model_dump() == before
    assert {name: broker.store.config().fingerprint(name) for name in config.accounts} == fingerprints
    broker.permit("test", "personal-store", "inventory")


@pytest.mark.parametrize("url", [
    "https://www.saucedemo.com.attacker.example/", "https://not-saucedemo.com/",
    "http://www.saucedemo.com/", "https://www.saucedemo.com:444/",
])
def test_public_labels_never_use_suffixes_names_or_unreviewed_ports(url):
    spec = entries()["personal-store"]
    spec.login_url = url
    spec.label = "Public example"
    assert environment(spec, test_mode=True) == "live"


def test_all_connector_destinations_must_be_testing_sites_and_test_flag_is_not_proof():
    public = public_configuration()
    for spec in public.accounts.values():
        assert environment(spec) == "public-example"
    spec = entries()["personal-store"]
    spec.login_url = "https://WWW.SAUCEDEMO.COM:443/"
    assert environment(spec) == "public-example"
    spec.operations["inventory"].url = "https://service.example/private"
    assert environment(spec, test_mode=True) == "live"
    spec = public.accounts["duende-alice"]
    spec.api_origins.append("https://service.example")
    assert environment(spec, test_mode=True) == "live"
    assert environment(namecheap(), test_mode=True) == "live"
    assert aggregate([describe(namecheap()), describe(entries()["personal-store"])]) == "mixed"


def test_malformed_legacy_url_cannot_break_other_account_discovery(env):
    _, broker, _ = env
    config = broker.store.config()
    config.accounts["demo-web"].login_url = "https://www.saucedemo.com:invalid/"
    broker.store.configure(config)
    broker.grant("test", "demo-web", ["summary"])
    result = broker.accounts("test")
    assert result["status"] == "OK"
    rows = {row["account"]: row for row in result["accounts"]}
    assert rows["demo-web"]["environment"] == "unclassified"
    assert rows["demo-api"]["environment"] == "controlled-demo"


def test_import_review_and_catalog_label_examples_without_altering_permission_fingerprints(env):
    _, broker, _ = env
    staged = preview(broker.store, "url,username,password\n"
                     "https://www.saucedemo.com/,standard_user,fictional-preview-password\n")
    matches = staged["rows"][0]["matches"]
    assert len(matches) == 2
    assert all(item["environment"] == "public-example" and "Public example" in item["label"] for item in matches)
    assert "fictional-preview-password" not in json.dumps(staged)
    assert all(item["environment"] == "public-example" for item in view() if item["id"] != "personal-namecheap")
    apply(broker, staged["id"], [{"row": "0", "account": "personal-store", "operations": ["inventory"]}], ["test"])
    spec = broker.store.config().accounts["personal-store"]
    assert spec.label == "Personal shopping account"  # Saved authority is unchanged.
    broker.permit("test", "personal-store", "inventory")


def test_historical_results_are_unclassified_without_rewriting_or_repeating_completed_steps(env, monkeypatch):
    provider, broker, _ = env
    job = broker.submit("test", TaskRequest(key="legacy-source-context", steps=[
        {"account": "demo-api", "operation": "summary"}, {"account": "demo-api", "operation": "details"}]))
    run = broker.run

    def pause(principal, account, operation):
        return {"status": "RETRYABLE", "reason": "fixture_pause", "account": account} if operation == "details" else run(principal, account, operation)

    with monkeypatch.context() as patch:
        patch.setattr(broker, "run", pause)
        broker.advance(job["task_id"])
    saved = broker.store.get("job:" + job["task_id"])
    assert len(saved["completed"]) == 1
    saved["completed"][0].pop("environment_source")
    saved["completed"][0]["environment"] = "live"
    broker.save_job(saved)
    before_api = provider.api_count
    projected = broker.task("test", job["task_id"])
    assert projected["results"][0]["environment"] == "unclassified"
    assert projected["results"][0]["environment_source"] == "legacy-unclassified"
    assert broker.store.get("job:" + job["task_id"])["completed"][0]["environment"] == "live"
    broker.advance(job["task_id"])
    completed = broker.task("test", job["task_id"])
    assert completed["status"] == "COMPLETED" and completed["progress"] == 2
    assert [row["environment"] for row in completed["results"]] == ["unclassified", "controlled-demo"]
    assert provider.api_count == before_api + 1


def test_owner_browser_counts_examples_separately_and_uses_explicit_example_prompt(env, monkeypatch):
    provider, broker, _ = env
    monkeypatch.setattr("account_access.install.install_detected", lambda store: {"status": "INSTALLED"})
    config = Configuration(accounts=entries())
    broker.store.configure(config)
    broker.store.new_client("generic")
    for key, spec in config.accounts.items():
        broker.grant("generic", key, list(spec.operations))
        if key != "personal-namecheap":
            # Stored-state projection test only; no website session or private login is claimed.
            broker.store.put("connection:" + key, {"fingerprint": config.fingerprint(key)})
    owner, token = make_owner_server(broker, guided=True)
    thread = threading.Thread(target=owner.serve_forever, daemon=True)
    thread.start()
    before = provider.api_count
    try:
        with sync_playwright() as pw:
            browser = pw.chromium.launch(headless=True, chromium_sandbox=True)
            try:
                page = browser.new_page()
                page.goto(f"http://127.0.0.1:{owner.server_port}/#" + token)
                page.get_by_text("Personal shopping account · Public example", exact=True).wait_for()
                assert page.locator("#account-count").inner_text() == "0 ready · 1 service connections · 3 ready / 3 examples"
                assert page.get_by_text("Example connected", exact=True).count() == 3
                assert "example accounts" in page.locator("#prompts").inner_text()
                broker.store.put("connection:personal-namecheap", {"fingerprint": config.fingerprint("personal-namecheap")})
                page.evaluate("refresh()")
                assert page.locator("#account-count").inner_text() == "1 ready · 1 service connections · 3 ready / 3 examples"
                assert "connected services" in page.locator("#prompts").inner_text()
                assert "example accounts" not in page.locator("#prompts").inner_text()
                assert provider.api_count == before
            finally:
                browser.close()
    finally:
        owner.shutdown()
        owner.server_close()
        thread.join(timeout=5)
