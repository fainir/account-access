import json
import subprocess
import sys


def test_cross_process_token_rotation(env):
    provider, broker, _ = env
    state = broker.store.get("connection:demo-api")
    state["token"]["expires_at"] = 0
    broker.store.put("connection:demo-api", state)
    code = """import json,sys
from pathlib import Path
from account_access.storage import Store
from account_access.broker import Broker
root=Path(sys.argv[1])
result=Broker(Store(root,(root/'demo.key').read_bytes())).run('test','demo-api','summary')
print(json.dumps({'status':result['status']}))
"""
    processes = [subprocess.Popen([sys.executable, "-c", code, str(broker.store.root)], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True) for _ in range(4)]
    for process in processes:
        out, err = process.communicate(timeout=20)
        assert process.returncode == 0, err
        assert json.loads(out)["status"] == "COMPLETED"
    assert provider.refresh_count == 1
