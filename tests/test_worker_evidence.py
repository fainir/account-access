import copy
import json
from http.server import BaseHTTPRequestHandler
from pathlib import Path
import socketserver
import tempfile
import threading

import pytest

from scripts.check_worker_boundary_report import CHECKS, main, validate
from scripts.worker_boundary_probe import UnixHTTP as AgentWire
from scripts.worker_boundary_smoke import UnixHTTP as OwnerWire


def report():
    return {"status": "PASSED", "environment": "controlled-demo", "platform": "linux",
            "production_ready": False, "private_signins": 0, "real_distinct_uids": True,
            "checks": dict.fromkeys(CHECKS, True)}


@pytest.mark.parametrize("contents", [None, b"", b"{}", b"null", b"not JSON"])
def test_missing_or_empty_reports_fail_the_ci_gate(tmp_path, contents):
    target = tmp_path / "report.json"
    if contents is not None:
        target.write_bytes(contents)
    assert main([str(target)]) == 1


def test_every_required_assertion_must_be_present_and_exactly_true(tmp_path):
    value = report()
    assert validate(value)
    for name in CHECKS:
        for replacement in [False, 1, "passed", None]:
            broken = copy.deepcopy(value)
            broken["checks"][name] = replacement
            assert not validate(broken)
        broken = copy.deepcopy(value)
        del broken["checks"][name]
        assert not validate(broken)
    target = tmp_path / "report.json"
    target.write_text(json.dumps(value))
    assert main([str(target)]) == 0


@pytest.mark.parametrize("name,value", [("private_signins", True), ("production_ready", True),
                                      ("real_distinct_uids", False), ("environment", "personal")])
def test_fictional_acceptance_cannot_claim_a_production_or_private_result(name, value):
    changed = report()
    changed[name] = value
    assert not validate(changed)


@pytest.mark.parametrize("wire", [AgentWire, OwnerWire])
def test_acceptance_harness_wire_clients_really_connect_and_close(wire):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def do_GET(self):
            body = b'{"fixture":true}'
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    with tempfile.TemporaryDirectory(prefix="aaw-wire-", dir="/tmp") as folder:
        path = str(Path(folder) / "test.sock")
        with socketserver.UnixStreamServer(path, Handler) as server:
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                with wire(path) as client:
                    client.request("GET", "/fixture")
                    response = client.getresponse()
                    assert response.status == 200 and json.loads(response.read()) == {"fixture": True}
                assert client.sock is None
            finally:
                server.shutdown()
                thread.join(timeout=5)
