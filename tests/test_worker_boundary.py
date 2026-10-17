import os
from pathlib import Path
import secrets
import socket
import tempfile
import threading

import httpx2 as httpx
import pytest

from account_access.errors import AccessError
from account_access.owner import make_owner_server
from account_access.worker_bootstrap import BootstrapError, read_bootstrap, read_policy, root_managed_path, take_listener


def pipe_message(data):
    reader, writer = os.pipe()
    os.write(writer, data)
    os.close(writer)
    return reader


def test_private_bootstrap_consumes_once_closes_and_redacts():
    payload = secrets.token_bytes(64)
    reader = pipe_message(payload)
    result = read_bootstrap(reader, issuer_uid=os.getuid())
    assert result.vault_key == payload[:32] and len(result.owner_token) == 43
    assert len(result.owner_proof_key) == 32
    assert repr(result) == "<BootstrapSecrets redacted>"
    with pytest.raises(OSError):
        os.fstat(reader)


@pytest.mark.parametrize("size", [0, 1, 32, 63, 65, 128])
def test_partial_or_excess_bootstrap_never_yields_a_key(size):
    reader = pipe_message(b"x" * size)
    with pytest.raises(BootstrapError, match="invalid_worker_bootstrap"):
        read_bootstrap(reader, issuer_uid=os.getuid())
    with pytest.raises(OSError):
        os.fstat(reader)


def test_unfinished_handoff_is_bounded_and_closes_the_descriptor():
    reader, writer = os.pipe()
    try:
        os.write(writer, b"partial fixture")
        with pytest.raises(BootstrapError, match="worker_bootstrap_timed_out"):
            read_bootstrap(reader, issuer_uid=os.getuid(), timeout=0.05)
        with pytest.raises(OSError):
            os.fstat(reader)
    finally:
        os.close(writer)


def test_regular_file_and_different_issuer_cannot_supply_worker_secrets(tmp_path):
    path = tmp_path / "fictional-secret"
    path.write_bytes(b"x" * 64)
    reader = os.open(path, os.O_RDONLY)
    with pytest.raises(BootstrapError):
        read_bootstrap(reader, issuer_uid=os.getuid())
    assert path.read_bytes() == b"x" * 64
    reader = pipe_message(b"x" * 64)
    with pytest.raises(BootstrapError):
        read_bootstrap(reader, issuer_uid=os.getuid() + 1)


@pytest.mark.parametrize("fd", [0, 1, 2, -1, True])
def test_standard_streams_are_not_bootstrap_channels(fd):
    with pytest.raises(BootstrapError):
        read_bootstrap(fd, issuer_uid=os.getuid())


def test_inherited_listener_keeps_the_fixed_socket_and_cannot_leak_through_exec():
    with tempfile.TemporaryDirectory(prefix="aawl-", dir="/tmp") as folder:
        path = str(Path(folder) / "agent.sock")
        original = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        original.bind(path)
        original.listen(4)
        fd = original.detach()
        os.set_inheritable(fd, True)
        with take_listener(fd, issuer_uid=os.getuid()) as accepted:
            assert accepted.getsockname() == path and not accepted.get_inheritable()
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
                client.connect(path)
                connection, _ = accepted.accept()
                with connection:
                    client.sendall(b"fixture")
                    assert connection.recv(7) == b"fixture"


@pytest.mark.parametrize("kind", ["unbound", "tcp", "datagram", "wrong-issuer"])
def test_wrong_listener_shape_is_rejected_and_closed(kind):
    with tempfile.TemporaryDirectory(prefix="aawl-", dir="/tmp") as folder:
        server = socket.socket(socket.AF_INET if kind == "tcp" else socket.AF_UNIX,
                               socket.SOCK_DGRAM if kind == "datagram" else socket.SOCK_STREAM)
        if kind == "tcp":
            server.bind(("127.0.0.1", 0))
            server.listen(1)
        elif kind != "unbound":
            server.bind(str(Path(folder) / "private.sock"))
            if kind != "datagram":
                server.listen(1)
        fd = server.detach()
        with pytest.raises(BootstrapError):
            take_listener(fd, issuer_uid=os.getuid() + (kind == "wrong-issuer"))
        with pytest.raises(OSError):
            os.fstat(fd)


def test_user_writable_code_cannot_be_a_protected_runtime(tmp_path):
    path = tmp_path / "worker.py"
    path.write_text("fixture")
    path.chmod(0o666)
    with pytest.raises(BootstrapError, match="untrusted_worker_runtime"):
        root_managed_path(path)


def test_an_agent_owned_policy_cannot_nominate_itself_as_supervisor(tmp_path):
    policy = tmp_path / "policy.json"
    policy.write_text('{"managed_by":"account-access-worker-v1"}')
    policy.chmod(0o600)
    with pytest.raises(BootstrapError, match="invalid_worker_policy"):
        read_policy(policy)


def test_owner_console_uses_only_the_inherited_unix_listener(env, monkeypatch):
    _, broker, _ = env
    path = str(broker.store.root / "owner.sock")
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(path)
    listener.listen(8)
    token = secrets.token_urlsafe(32)
    def no_home(_cls):
        raise AssertionError("A separate worker must not inspect the owner's home")
    monkeypatch.setattr(Path, "home", classmethod(no_home))
    server, returned = make_owner_server(broker, guided=True, owner_token=token, server_socket=listener,
                                         origin_port=8765, local_host_actions=False)
    assert returned == token and server.address_family == socket.AF_UNIX
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        with httpx.Client(transport=httpx.HTTPTransport(uds=path), base_url="http://127.0.0.1:8765", trust_env=False) as client:
            assert client.get("/owner/state").status_code == 401
            headers = {"Authorization": "Bearer " + token, "Origin": "http://127.0.0.1:8765"}
            state = client.get("/owner/state", headers=headers).json()
            assert state["local_host_actions"] is False and state["portable_cli"] is None
            assert client.get("/owner/state", headers={**headers, "Host": "wrong.example"}).status_code == 403
            for route in ["install", "google-messages/prepare", "browser-session/start", "connect"]:
                result = client.post("/owner/" + route, headers=headers, json={})
                assert result.status_code == 403 and result.json()["reason"] == "trusted_host_action_required"
            result = client.post("/owner/revoke", headers={"Authorization": "Bearer " + token}, json={"account": "demo-api"})
            assert result.status_code == 403
            result = client.post("/owner/revoke", headers=headers, json={"account": "demo-api"})
            assert result.status_code == 200
            assert broker.run("test", "demo-api", "summary")["status"] == "DENIED"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def test_incomplete_private_transport_never_falls_back_to_tcp(env):
    _, broker, _ = env
    with pytest.raises(AccessError, match="invalid_owner_transport"):
        make_owner_server(broker, origin_port=8765)
    with pytest.raises(AccessError, match="invalid_owner_bootstrap"):
        make_owner_server(broker, owner_token="invalid")
