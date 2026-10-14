import json
import tempfile
import threading
import time
from pathlib import Path

import httpx2 as httpx

from account_access.demo import DEMO_PASSWORD, DEMO_SEED
from account_access.install import install_skill
from account_access.models import TaskRequest
from account_access.owner import make_owner_server
from account_access.verification_demo import environment, write_password_export


def test_owner_import_and_three_verification_channels_complete_one_task():
    with tempfile.TemporaryDirectory(prefix="aa-mfa-", dir="/tmp") as temporary:
        root = Path(temporary)
        with environment(root) as (provider, broker, mailbox):
            install_skill(broker.store, "generic", root / "skills")
            server, token = make_owner_server(broker, guided=True)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            base = f"http://127.0.0.1:{server.server_port}"
            headers = {"Authorization": "Bearer " + token, "Origin": base}
            try:
                with httpx.Client(base_url=base, trust_env=False, timeout=20) as client:
                    assert client.post("/owner/source", json={}).status_code == 403
                    for source, credential in [("demo-totp", {"seed": DEMO_SEED}),
                                               ("example-email", {"username": "demo@example.test", "password": DEMO_PASSWORD}),
                                               ("example-sms", {"enabled": True})]:
                        assert client.post("/owner/source", json={"source": source, "credential": credential}, headers=headers).status_code == 200
                    state = client.get("/owner/state", headers=headers).json()
                    assert DEMO_SEED not in json.dumps(state) and DEMO_PASSWORD not in json.dumps(state)
                    csv = write_password_export(root, broker.store.config()).read_text()
                    preview = client.post("/owner/import/preview", json={"csv": csv}, headers=headers).json()
                    assert DEMO_PASSWORD not in json.dumps(preview)
                    handles = list(broker.store.config().accounts)
                    selections = [{"row": str(index), "account": handle, "operations": ["summary"]} for index, handle in enumerate(handles)]
                    response = client.post("/owner/import/apply", json={"id": preview["id"], "selections": selections}, headers=headers)
                    assert response.status_code == 200, response.text
                    jobs = response.json()["jobs"]
                    deadline = time.monotonic() + 30
                    while time.monotonic() < deadline:
                        state = client.get("/owner/state", headers=headers).json()
                        if all(state["connection_jobs"][job["id"]]["status"] != "RUNNING" for job in jobs):
                            break
                        time.sleep(.1)
                    assert all(state["connection_jobs"][job["id"]]["status"] == "CONNECTED" for job in jobs), state["connection_jobs"]
                    assert provider.totp_count == provider.email_count == provider.sms_count == 1
                    assert mailbox.fetches == 1
                    provider.sessions.clear()
                    for handle in handles:
                        broker.store.put("login-attempt:" + handle, 0)  # Accelerated fixture, not production throttle.
                    request = TaskRequest.model_validate({"key": "all-verification-types", "steps": [{"account": handle, "operation": "summary"} for handle in handles]})
                    task = broker.submit("generic", request)
                    deadline = time.monotonic() + 30
                    while time.monotonic() < deadline:
                        broker.tick()
                        result = broker.task("generic", task["task_id"])
                        if result["status"] == "COMPLETED":
                            break
                        time.sleep(.1)
                    assert result["status"] == "COMPLETED", result
                    assert result["progress"] == result["total"] == 4
                    assert provider.totp_count == provider.email_count == provider.sms_count == 2
                    assert DEMO_PASSWORD not in json.dumps(result) and DEMO_SEED not in json.dumps(result)
                    assert provider.last_login_code not in json.dumps(result)
                    with broker.store.db() as db:
                        audit = [dict(row) for row in db.execute("SELECT * FROM audit")]
                    assert {x["reason"] for x in audit if x["event"] == "login_factor_completed"} == {"totp", "email", "sms"}
                    assert provider.last_login_code not in json.dumps(audit)
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=5)
