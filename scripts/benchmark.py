"""Accelerated controlled-provider experiment; not a real-account reliability benchmark."""
import json
import shutil
import tempfile
import time
from pathlib import Path
from importlib.metadata import version

from account_access.broker import Broker
from account_access.demo import connect_demo, environment
from account_access.models import TaskRequest
from account_access.storage import Store


def main():
    root = Path(tempfile.mkdtemp(prefix="aab-", dir="/tmp"))
    started = time.monotonic()
    report = {"environment": "controlled-demo", "observed_date": "2026-10-12",
              "package_version": version("account-access"),
              "setup": "Programmatic synthetic consent, password and TOTP enrollment; human setup effort not measured",
              "live_accounts_tested": 0, "repeated_access": [], "recovery": {}}
    try:
        with environment(root) as (provider, broker, _):
            broker.store.new_client("benchmark")
            for account, config in broker.store.config().accounts.items():
                broker.grant("benchmark", account, list(config.operations))
            for account in ["demo-api", "demo-web", "demo-mfa"]:
                completed = 0
                challenges_before = broker.metrics()["unique_challenges_per_account"].get(account, 0)
                refresh_before, login_before, totp_before = provider.refresh_count, provider.login_count, provider.totp_count
                for run in range(30):
                    # Reopen vault and broker for every run to exercise persisted state.
                    broker = Broker(Store(root, (root / "demo.key").read_bytes()))
                    if account == "demo-api":
                        state = broker.store.get("connection:demo-api")
                        state["token"]["expires_at"] = 0
                        broker.store.put("connection:demo-api", state)
                    task = broker.submit("benchmark", TaskRequest(key=f"{account}-{run}", steps=[{"account": account, "operation": "summary"}]))
                    broker.advance(task["task_id"])
                    completed += broker.task("benchmark", task["task_id"])["status"] == "COMPLETED"
                    if (run + 1) % 10 == 0:
                        print(f"{account}: {run + 1}/30 controlled runs", flush=True)
                challenges = broker.metrics()["unique_challenges_per_account"].get(account, 0) - challenges_before
                report["repeated_access"].append({"account": account, "runs": 30, "unattended_completions": completed,
                    "unattended_completion_fraction": completed / 30, "unique_post_setup_challenges": challenges,
                    "challenges_per_run": challenges / 30, "automatic_refreshes": provider.refresh_count - refresh_before,
                    "automatic_password_logins": provider.login_count - login_before, "automatic_totp_submissions": provider.totp_count - totp_before})
            provider.refresh_tokens.clear()
            state = broker.store.get("connection:demo-api")
            state["token"]["expires_at"] = 0
            broker.store.put("connection:demo-api", state)
            tasks = []
            for index in range(5):
                task = broker.submit("benchmark", TaskRequest(key=f"blocked-{index}", steps=[{"account": "demo-api", "operation": "summary"}]))
                broker.advance(task["task_id"])
                tasks.append(task["task_id"])
            before = [broker.task("benchmark", ident) for ident in tasks]
            repair_start = time.monotonic()
            connect_demo(broker)  # Simulated owner re-consent, not an actual human intervention.
            with broker.store.db() as db:
                db.execute("UPDATE jobs SET next_at=0")
            broker.tick()
            after = [broker.task("benchmark", ident) for ident in tasks]
            report["recovery"] = {"blocked_jobs": len(tasks), "unique_shared_challenges": len({x["blocked"]["challenge"]["id"] for x in before}),
                                  "simulated_owner_repairs": 1, "automatically_resumed_jobs": sum(x["status"] == "COMPLETED" for x in after),
                                  "repair_to_completion_seconds": round(time.monotonic() - repair_start, 3)}
            report["elapsed_seconds"] = round(time.monotonic() - started, 3)
            report["limits"] = ["Accelerated local fixtures; not 30 days of real use", "No live Gmail, Twilio, financial, Google or Meta account tested", "Actual notification delivery, mobile OS and biometric handoff not measured"]
    finally:
        shutil.rmtree(root)
    dest = Path("artifacts/benchmark.json")
    dest.parent.mkdir(exist_ok=True)
    dest.write_text(json.dumps(report, indent=2))
    print(json.dumps({"report": str(dest), "elapsed_seconds": report["elapsed_seconds"]}), flush=True)
    return 0 if all(x["unattended_completions"] == 30 for x in report["repeated_access"]) and report["recovery"]["automatically_resumed_jobs"] == 5 else 1


if __name__ == "__main__":
    raise SystemExit(main())
