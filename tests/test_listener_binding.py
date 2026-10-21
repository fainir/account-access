from contextlib import contextmanager
from dataclasses import replace
import hashlib
import os
from pathlib import Path
import socket
import struct
import sys
import tempfile
from types import SimpleNamespace

import pytest

from account_access.listener_binding import (
    ListenerBindingError, METADATA_SIZE, parse_listener_bindings, validate_listener_binding,
)
from account_access.worker_bootstrap import BootstrapError, read_bootstrap, take_listener


HEADER = struct.Struct(">8sHBBI")
RECORD = struct.Struct(">BBHqQqQ32s32s")


def digest(value):
    return hashlib.sha256(value.encode("utf-8")).digest()


def metadata(records, header=(b"AALSN002", 2, 2, 0, 280)):
    return (HEADER.pack(*header) + b"".join(RECORD.pack(*record) for record in records)).hex()


def record(role, listener, canonical, source=0):
    fd, node = os.fstat(listener.fileno()), os.lstat(canonical)
    return [role, source, 0, fd.st_dev, fd.st_ino, node.st_dev, node.st_ino,
            digest(canonical), digest(listener.getsockname())]


@contextmanager
def listeners(*, renamed=False):
    with tempfile.TemporaryDirectory(prefix="aalb-", dir="/tmp") as folder:
        sockets, paths = [], []
        try:
            for name in ("agent", "owner"):
                canonical = str(Path(folder) / name)
                listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                sockets.append(listener)
                listener.bind(canonical + ".bound" if renamed else canonical)
                listener.listen(2)
                if renamed:
                    os.rename(canonical + ".bound", canonical)
                paths.append(canonical)
            yield sockets, paths, [record(index + 1, item, paths[index], int(renamed))
                                   for index, item in enumerate(sockets)]
        finally:
            for item in sockets:
                item.close()


def test_exact_public_v2_prefix_round_trips_without_secret_suffix():
    with listeners() as (_, paths, records):
        encoded = metadata(records)
        assert METADATA_SIZE == 216 and len(encoded) == 432
        first, second = parse_listener_bindings(encoded)
        assert first.role == 1 and second.role == 2
        assert first.canonical_digest == digest(paths[0])
        assert first.fd_device == records[0][3]
        # Only the public216-byte prefix is accepted; the64-byte secret suffix
        # remains exclusively on the inherited anonymous bootstrap pipe.
        with pytest.raises(ListenerBindingError, match="invalid_worker_listener_bindings"):
            parse_listener_bindings(encoded + (b"s" * 64).hex())


def test_disposable_ci_direct_parent_produces_same_v2_wire_contract():
    from scripts.worker_boundary_smoke import fixture_listener_prefix

    with listeners() as (sockets, paths, records):
        prefix = fixture_listener_prefix(*sockets, *paths)
        assert prefix.hex() == metadata(records)
        assert len(prefix + b"s" * 64) == 280
        assert parse_listener_bindings(prefix.hex())[1].canonical_digest == digest(paths[1])


def test_ci_parent_cannot_mark_a_renamed_listener_as_direct():
    from scripts.worker_boundary_smoke import fixture_listener_prefix

    with listeners(renamed=True) as (sockets, paths, _):
        with pytest.raises(RuntimeError, match="fixture_listener_binding_invalid"):
            fixture_listener_prefix(*sockets, *paths)


@pytest.mark.parametrize("header", [
    (b"AALSN001", 2, 2, 0, 280), (b"AALSN002", 1, 2, 0, 280),
    (b"AALSN002", 2, 1, 0, 280), (b"AALSN002", 2, 3, 0, 280),
    (b"AALSN002", 2, 2, 1, 280), (b"AALSN002", 2, 2, 0, 216),
    (b"AALSN002", 2, 2, 0, 281),
])
def test_v2_header_has_no_legacy_or_length_fallback(header):
    with listeners() as (_, _, records):
        with pytest.raises(ListenerBindingError):
            parse_listener_bindings(metadata(records, header))


@pytest.mark.parametrize("kind", ["empty", "truncated", "extra", "uppercase", "space", "not-hex", "bytes", "none"])
def test_only_exact_lowercase_hex_prefix_is_accepted(kind):
    with listeners() as (_, _, records):
        good = metadata(records)
        bad = {"empty": "", "truncated": good[:-2], "extra": good + "00",
               "uppercase": good.upper(), "space": good[:8] + " " + good[9:],
               "not-hex": "g" + good[1:], "bytes": good.encode(), "none": None}[kind]
        with pytest.raises(ListenerBindingError):
            parse_listener_bindings(bad)


@pytest.mark.parametrize("kind", ["swapped", "role", "source", "reserved", "fd-zero", "node-zero",
                                  "duplicate-fd", "duplicate-node", "duplicate-canonical",
                                  "duplicate-bind", "direct-renamed"])
def test_roles_sources_and_distinct_descriptor_node_bindings_are_fixed(kind):
    with listeners() as (_, _, records):
        if kind == "swapped":
            records.reverse()
        elif kind in {"role", "source", "reserved", "fd-zero", "node-zero"}:
            field, value = {"role": (0, 2), "source": (1, 2), "reserved": (2, 1),
                            "fd-zero": (4, 0), "node-zero": (6, 0)}[kind]
            records[0][field] = value
        elif kind in {"duplicate-fd", "duplicate-node"}:
            fields = (3, 4) if kind == "duplicate-fd" else (5, 6)
            for field in fields:
                records[1][field] = records[0][field]
        elif kind == "duplicate-canonical":
            records[1][7] = records[0][7]
            records[1][8] = records[0][7]
        elif kind == "duplicate-bind":
            records[1][1] = 1
            records[1][8] = records[0][8]
        else:
            records[0][8] = digest("/different-bind-name")
        with pytest.raises(ListenerBindingError):
            parse_listener_bindings(metadata(records))


def test_direct_listener_binding_keeps_canonical_name_and_actual_io():
    with listeners() as (sockets, paths, records):
        binding = parse_listener_bindings(metadata(records))[0]
        fd = sockets[0].detach()
        with take_listener(fd, issuer_uid=os.getuid(), canonical_path=paths[0], binding=binding, role=1) as accepted:
            assert not accepted.get_inheritable() and accepted.getsockname() == paths[0]
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
                client.connect(paths[0])
                connection, _ = accepted.accept()
                with connection:
                    client.sendall(b"bound fixture")
                    assert connection.recv(13) == b"bound fixture"


@pytest.mark.parametrize("kind", ["fd-device", "fd-inode", "canonical", "bind", "role", "swapped-fd"])
def test_wrong_or_stale_binding_rejects_and_closes_actual_descriptor(kind):
    with listeners() as (sockets, paths, records):
        binding = parse_listener_bindings(metadata(records))[0]
        changes = {"fd-device": {"fd_device": binding.fd_device + 1},
                   "fd-inode": {"fd_inode": binding.fd_inode + 1},
                   "canonical": {"canonical_digest": digest("/other-policy-path")},
                   "bind": {"bound_name_digest": digest("/other-bind-name")},
                   "role": {"role": 2}, "swapped-fd": {}}[kind]
        binding = replace(binding, **changes)
        fd = sockets[int(kind == "swapped-fd")].detach()
        with pytest.raises(BootstrapError, match="invalid_worker_listener"):
            take_listener(fd, issuer_uid=os.getuid(), canonical_path=paths[0], binding=binding, role=1)
        with pytest.raises(OSError):
            os.fstat(fd)


def test_renamed_bind_requires_exact_observed_name_and_darwin_source():
    with listeners(renamed=True) as (sockets, paths, records):
        binding = parse_listener_bindings(metadata(records))[0]
        info, observed = os.fstat(sockets[0].fileno()), sockets[0].getsockname()
        assert observed != paths[0]
        validate_listener_binding(binding, role=1, canonical_path=paths[0], descriptor=info,
                                  bound_name=observed, platform="darwin")
        for platform, bound in [("linux", observed), ("darwin", paths[0]), ("darwin", "/another-bound-name")]:
            with pytest.raises(ListenerBindingError):
                validate_listener_binding(binding, role=1, canonical_path=paths[0], descriptor=info,
                                          bound_name=bound, platform=platform)


@pytest.mark.skipif(sys.platform != "darwin", reason="native macOS named-listener contract")
def test_darwin_renamed_inherited_listener_remains_bound_to_canonical_node():
    with listeners(renamed=True) as (sockets, paths, records):
        binding = parse_listener_bindings(metadata(records))[0]
        with take_listener(sockets[0].detach(), issuer_uid=os.getuid(), canonical_path=paths[0],
                           binding=binding, role=1) as accepted:
            assert accepted.getsockname() != paths[0]
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
                client.connect(paths[0])
                connection, _ = accepted.accept()
                connection.close()


def test_without_native_binding_canonical_path_equality_is_never_skipped():
    with listeners(renamed=True) as (sockets, paths, _):
        fd = sockets[0].detach()
        with pytest.raises(BootstrapError, match="invalid_worker_listener"):
            take_listener(fd, issuer_uid=os.getuid(), canonical_path=paths[0])
        with pytest.raises(OSError):
            os.fstat(fd)


@pytest.mark.parametrize("kind", ["file", "tcp", "datagram", "wrong-issuer"])
def test_binding_cannot_bless_wrong_descriptor_shape_or_issuer(kind):
    with listeners() as (sockets, paths, records):
        binding = parse_listener_bindings(metadata(records))[0]
        if kind == "file":
            fd = os.open(__file__, os.O_RDONLY)
        elif kind == "wrong-issuer":
            fd = sockets[0].detach()
        else:
            wrong = socket.socket(socket.AF_INET if kind == "tcp" else socket.AF_UNIX,
                                  socket.SOCK_STREAM if kind == "tcp" else socket.SOCK_DGRAM)
            if kind == "tcp":
                wrong.bind(("127.0.0.1", 0))
                wrong.listen(1)
            else:
                wrong.bind(paths[0] + ".datagram")
            fd = wrong.detach()
        info = os.fstat(fd)
        binding = replace(binding, fd_device=info.st_dev, fd_inode=info.st_ino)
        with pytest.raises(BootstrapError, match="invalid_worker_listener"):
            take_listener(fd, issuer_uid=os.getuid() + int(kind == "wrong-issuer"),
                          canonical_path=paths[0], binding=binding, role=1)
        with pytest.raises(OSError):
            os.fstat(fd)


def test_worker_rechecks_public_fd_binding_without_traversing_private_socket_directory(monkeypatch):
    with listeners() as (sockets, paths, records):
        binding = parse_listener_bindings(metadata(records))[0]
        # Native already checked the canonical node/parent before identity
        # drop. The actual worker cannot traverse the root0700 owner directory.
        with monkeypatch.context() as protected:
            protected.setattr(os, "lstat", lambda *_: pytest.fail("worker must not traverse the private socket directory"))
            with take_listener(sockets[0].detach(), issuer_uid=os.getuid(), canonical_path=paths[0],
                               binding=binding, role=1):
                pass


def worker_fixture(monkeypatch, sockets, paths, bindings, platform="darwin"):
    from account_access import worker_host

    reader, writer = os.pipe()
    os.write(writer, b"a" * 32 + b"b" * 32)
    os.close(writer)
    args = SimpleNamespace(policy="fixture-only", bootstrap_fd=reader, agent_fd=sockets[0].detach(),
                           owner_fd=sockets[1].detach(), listener_bindings=bindings)
    monkeypatch.setattr(worker_host, "read_policy", lambda _: {"agent_socket": paths[0], "owner_socket": paths[1]})
    monkeypatch.setattr(worker_host, "require_worker_identity", lambda *_, **__: Path("/fixture-unused-state"))
    monkeypatch.setattr(worker_host, "sys", SimpleNamespace(platform=platform))
    monkeypatch.setattr(worker_host.resource, "setrlimit", lambda *_: None)
    # Real ordinary-user socket fixtures are intentionally not root-created.
    monkeypatch.setattr(worker_host, "take_listener", lambda fd, **kwargs: take_listener(fd, issuer_uid=os.getuid(), **kwargs))
    return worker_host, args


@pytest.mark.parametrize("bad_prefix", [None, "", "41414c534e303031"])
def test_mac_worker_refuses_missing_legacy_or_invalid_metadata_before_keys(monkeypatch, bad_prefix):
    with listeners() as (sockets, paths, _):
        host, args = worker_fixture(monkeypatch, sockets, paths, bad_prefix)
        monkeypatch.setattr(host, "read_bootstrap", lambda _: pytest.fail("invalid metadata must not consume secrets"))
        with pytest.raises(BootstrapError, match="invalid_worker_listener_bindings"):
            host.serve(args)
        for fd in (args.bootstrap_fd, args.agent_fd, args.owner_fd):
            with pytest.raises(OSError):
                os.fstat(fd)


@pytest.mark.parametrize("platform,with_prefix", [("darwin", True), ("linux", False), ("linux", True)])
def test_public_prefix_or_legacy_linux_leaves_exact_64_secret_bytes_for_existing_reader(monkeypatch, platform, with_prefix):
    class KeysConsumed(Exception):
        pass

    with listeners() as (sockets, paths, records):
        host, args = worker_fixture(monkeypatch, sockets, paths,
                                   metadata(records) if with_prefix else None, platform=platform)

        def consume(fd):
            secrets = read_bootstrap(fd, issuer_uid=os.getuid())
            assert secrets.vault_key == b"a" * 32
            assert len(secrets.owner_proof_key) == 32
            raise KeysConsumed()

        monkeypatch.setattr(host, "read_bootstrap", consume)
        with pytest.raises(KeysConsumed):
            host.serve(args)
        for fd in (args.bootstrap_fd, args.agent_fd, args.owner_fd):
            with pytest.raises(OSError):
                os.fstat(fd)


def test_legacy_linux_worker_still_requires_exact_canonical_listener_name(monkeypatch):
    with listeners(renamed=True) as (sockets, paths, _):
        host, args = worker_fixture(monkeypatch, sockets, paths, None, platform="linux")
        monkeypatch.setattr(host, "read_bootstrap", lambda _: pytest.fail("wrong direct socket must not consume secrets"))
        with pytest.raises(BootstrapError, match="invalid_worker_listener"):
            host.serve(args)
        for fd in (args.bootstrap_fd, args.agent_fd, args.owner_fd):
            with pytest.raises(OSError):
                os.fstat(fd)
