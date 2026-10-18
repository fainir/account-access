import base64
import json
import time
import threading
from urllib.parse import quote

import pytest
import httpx2 as httpx
from fastapi.testclient import TestClient

from account_access import authenticator_import as transfer
from account_access.errors import AccessError
from account_access.owner import make_owner_server
from account_access.service import create_app


def varint(value):
    result = bytearray()
    while value > 127:
        result.append((value & 127) | 128)
        value >>= 7
    return bytes(result + bytes([value]))


def field(number, value):
    if isinstance(value, int):
        return varint(number << 3) + varint(value)
    return varint((number << 3) | 2) + varint(len(value)) + value


def uri(parameters=None, batch_size=1, batch_index=None, batch_id=None):
    if parameters is None:
        parameters = [field(1, b"Hello!\xde\xad\xbe\xef") + field(2, b"owner@example.test")
                      + field(3, b"Example") + field(4, 1) + field(5, 1) + field(6, 2)]
    payload = b"".join(field(1, item) for item in parameters) + field(2, 1) + field(3, batch_size)
    if batch_index is not None:
        payload += field(4, batch_index)
    if batch_id is not None:
        payload += field(5, batch_id)
    return "otpauth-migration://offline?data=" + quote(base64.b64encode(payload).decode(), safe="")


def test_owner_selects_one_key_then_real_browser_sign_in(env):
    provider, broker, _ = env
    broker.store.put("source:demo-totp", None)
    first = field(1, b"Hello!\xde\xad\xbe\xef") + field(2, b"owner@example.test") + field(4, 1) + field(5, 1) + field(6, 2)
    second = field(1, b"separate-second-key") + field(2, b"other@example.test") + field(4, 1) + field(5, 1) + field(6, 2)
    preview = transfer.preview(broker.store, "demo-totp", uri([first, second]))
    assert len(preview["accounts"]) == 2
    assert "seed" not in json.dumps(preview) and "JBSWY3DPEHPK3PXP" not in json.dumps(preview)
    assert broker.store.get("source:demo-totp") is None
    assert transfer.apply(broker.store, preview["id"], 0)["status"] == "ENROLLED"
    assert broker.store.get("authenticator-import:" + preview["id"]) is None
    result = broker.run("test", "demo-mfa", "summary")
    assert result["status"] == "COMPLETED"
    assert provider.totp_count == 1
    assert provider.last_login_code not in json.dumps(result)
    with pytest.raises(AccessError, match="authenticator_preview_expired"):
        transfer.apply(broker.store, preview["id"], 1)


def test_import_binds_review_to_unchanged_source_and_account(env):
    _, broker, _ = env
    preview = transfer.preview(broker.store, "demo-totp", uri())
    before = broker.store.get("source:demo-totp")
    config = broker.store.config()
    config.accounts["demo-mfa"].operations["summary"].description = "Changed permission"
    broker.store.configure(config)
    with pytest.raises(AccessError, match="authenticator_selection_changed"):
        transfer.apply(broker.store, preview["id"], 0)
    assert broker.store.get("source:demo-totp") == before


def test_cancel_expiry_and_staging_limit(env):
    _, broker, _ = env
    preview = transfer.preview(broker.store, "demo-totp", uri())
    transfer.discard(broker.store, preview["id"])
    for _ in range(8):
        last = transfer.preview(broker.store, "demo-totp", uri())
    with pytest.raises(AccessError, match="too_many_import_previews"):
        transfer.preview(broker.store, "demo-totp", uri())
    staged = broker.store.get("authenticator-import:" + last["id"])
    staged["expires"] = time.time() - 1
    broker.store.put("authenticator-import:" + last["id"], staged)
    with pytest.raises(AccessError, match="authenticator_preview_expired"):
        transfer.apply(broker.store, last["id"], 0)
    assert transfer.preview(broker.store, "demo-totp", uri())["status"] == "PREVIEW"


def test_complete_multiframe_export_is_ordered_and_imports_only_selected_key(env):
    provider, broker, _ = env
    broker.store.put("source:demo-totp", None)
    other = field(1, b"separate-second-key") + field(2, b"other@example.test") + field(4, 1) + field(5, 1) + field(6, 2)
    first = uri(batch_size=2, batch_index=0, batch_id=42)
    second = uri([other], batch_size=2, batch_index=1, batch_id=42)
    preview = transfer.preview(broker.store, "demo-totp", [second, first])
    assert [entry["index"] for entry in preview["accounts"]] == [0, 1]
    assert "owner@example.test" in preview["accounts"][0]["label"]
    assert "other@example.test" in preview["accounts"][1]["label"]
    assert "JBSWY3DPEHPK3PXP" not in json.dumps(preview)
    assert broker.store.get("source:demo-totp") is None
    transfer.apply(broker.store, preview["id"], 0)
    assert broker.store.get("authenticator-import:" + preview["id"]) is None
    result = broker.run("test", "demo-mfa", "summary")
    assert result["status"] == "COMPLETED" and provider.totp_count == 1
    assert provider.last_login_code not in json.dumps(result)


@pytest.mark.parametrize("parts,reason", [
    ([uri(batch_size=2, batch_index=0, batch_id=42)], "authenticator_export_incomplete"),
    ([uri(batch_size=2, batch_index=0, batch_id=42)] * 2, "authenticator_export_mismatch"),
    ([uri(batch_size=2, batch_index=0, batch_id=42), uri(batch_size=2, batch_index=1, batch_id=43)], "authenticator_export_mismatch"),
    ([uri(batch_size=2, batch_index=0, batch_id=42), uri(batch_size=3, batch_index=1, batch_id=42)], "authenticator_export_mismatch"),
    ([uri(), uri()], "authenticator_export_incomplete"),
    ([uri(batch_size=2, batch_index=2, batch_id=42)], "invalid_authenticator_export"),
    ([uri(batch_size=2, batch_index=0)], "invalid_authenticator_export"),
    ([uri(batch_size=17, batch_index=0, batch_id=42)], "invalid_authenticator_export"),
    ([], "invalid_authenticator_export"),
    ([uri()] * 17, "invalid_authenticator_export"),
    ([None], "invalid_authenticator_export"),
    (["\ud800"], "invalid_authenticator_export"),
    (["otpauth-migration://offline?data=" + "A" * 31000] * 2, "invalid_authenticator_export"),
])
def test_incomplete_mixed_duplicate_or_unbounded_exports_never_stage_keys(env, parts, reason):
    _, broker, _ = env
    before = broker.store.get("source:demo-totp")
    with pytest.raises(AccessError, match=reason):
        transfer.preview(broker.store, "demo-totp", parts)
    assert broker.store.get("source:demo-totp") == before
    with broker.store.db() as db:
        assert db.execute("SELECT count(*) FROM records WHERE id LIKE 'authenticator-import:%'").fetchone()[0] == 0


def test_export_total_accounts_are_bounded():
    parameter = field(1, b"Hello!\xde\xad\xbe\xef") + field(4, 1) + field(5, 1) + field(6, 2)
    parts = [uri([parameter] * 51, batch_size=2, batch_index=index, batch_id=42) for index in range(2)]
    with pytest.raises(AccessError, match="invalid_authenticator_export"):
        transfer.parse_many(parts)


@pytest.mark.parametrize("change", ["revoke", "reenroll"])
def test_owner_source_change_invalidates_an_old_authenticator_preview(env, change):
    from account_access.factors import enroll, revoke
    _, broker, _ = env
    preview = transfer.preview(broker.store, "demo-totp", uri())
    if change == "revoke":
        revoke(broker.store, "demo-totp")
    else:
        enroll(broker.store, "demo-totp", {"seed": "JBSWY3DPEHPK3PXP"})
    current = broker.store.get("source:demo-totp")
    with pytest.raises(AccessError, match="authenticator_selection_changed"):
        transfer.apply(broker.store, preview["id"], 0)
    assert broker.store.get("source:demo-totp") == current


def test_selection_and_preview_consumption_commit_atomically(env, monkeypatch):
    _, broker, _ = env
    preview = transfer.preview(broker.store, "demo-totp", uri())
    before = broker.store.get("source:demo-totp")
    original = broker.store.put

    def fail(key, value, db=None):
        if key == "authenticator-import:" + preview["id"] and value is None:
            raise OSError("controlled transaction interruption")
        return original(key, value, db=db)

    monkeypatch.setattr(broker.store, "put", fail)
    with pytest.raises(OSError, match="controlled transaction interruption"):
        transfer.apply(broker.store, preview["id"], 0)
    assert broker.store.get("source:demo-totp") == before
    assert broker.store.get("authenticator-import:" + preview["id"]) is not None
    monkeypatch.setattr(broker.store, "put", original)
    assert transfer.apply(broker.store, preview["id"], 0)["status"] == "ENROLLED"


def test_transfer_endpoints_require_owner_origin_and_never_return_keys(env):
    _, broker, client_token = env
    server, token = make_owner_server(broker, guided=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{server.server_port}"
    before = broker.store.get("source:demo-totp")
    try:
        with httpx.Client(base_url=base, trust_env=False) as client:
            payload = {"source": "demo-totp", "uri": uri()}
            owner = {"Authorization": "Bearer " + token, "Origin": base}
            for headers in [{}, {"Authorization": "Bearer " + client_token, "Origin": base},
                            {"Authorization": "Bearer " + token, "Origin": "https://attacker.example"}]:
                assert client.post("/owner/authenticator/preview", json=payload, headers=headers).status_code == 403
            response = client.post("/owner/authenticator/preview", json=payload, headers=owner)
            assert response.status_code == 200
            assert "JBSWY3DPEHPK3PXP" not in response.text and "seed" not in response.text
            ident = response.json()["id"]
            assert client.post("/owner/authenticator/apply", json={"id": ident, "index": True}, headers=owner).status_code == 403
            assert broker.store.get("source:demo-totp") == before
            assert client.post("/owner/authenticator/discard", json={"id": ident}, headers=owner).status_code == 200
            parts = [uri(batch_size=2, batch_index=i, batch_id=42) for i in range(2)]
            response = client.post("/owner/authenticator/preview", json={"source": "demo-totp", "uris": parts}, headers=owner)
            assert response.status_code == 200 and len(response.json()["accounts"]) == 2
            assert "JBSWY3DPEHPK3PXP" not in response.text
        with TestClient(create_app(broker, worker=False)) as agent:
            assert agent.post("/owner/authenticator/preview", json=payload,
                              headers={"Authorization": "Bearer " + client_token}).status_code == 404
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


@pytest.mark.parametrize("value", ["", "otpauth-migration://online?data=AA==", uri(batch_size=2),
                                   "otpauth-migration://offline?data=////", uri([b"\x00"]),
                                   uri([field(1, b"too short")]),
                                   uri([field(1, b"1234567890") + field(4, 1) + field(5, 1) + field(6, 1)]),
                                   uri([field(1, b"1234567890") + field(4, 1) * 2 + field(5, 1) + field(6, 2)]),
                                   "otpauth-migration://offline?data=" + "A" * 40000])
def test_malformed_unsupported_and_partial_exports_do_not_guess(value):
    with pytest.raises(AccessError):
        transfer.parse(value)
