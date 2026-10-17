"""Internal worker for a trusted, separately privileged service supervisor.

This is not a consumer installer or a privilege-elevation command. The parent
must prepare a root-owned immutable runtime, a dedicated non-root identity,
private state, separately permissioned listeners and a sanitized environment.
"""

import argparse
import json
import os
import resource
import sys
import threading

from .worker_bootstrap import BootstrapError, read_bootstrap, read_policy, require_worker_identity, take_listener


def serve(args):
    policy = read_policy(args.policy)
    root = require_worker_identity(policy, worker_module=__file__)
    descriptors = [args.bootstrap_fd, args.agent_fd, args.owner_fd]
    if len(set(descriptors)) != 3 or any(type(fd) is not int or fd < 3 for fd in descriptors):
        raise BootstrapError("invalid_worker_descriptors")
    unclaimed = set(descriptors)
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    agent = owner_socket = owner = None
    server = None
    owner_thread = None
    closed = threading.Event()
    failed = threading.Event()
    native_messages = None
    try:
        unclaimed.remove(args.agent_fd)
        agent = take_listener(args.agent_fd)
        unclaimed.remove(args.owner_fd)
        owner_socket = take_listener(args.owner_fd)
        if (agent.getsockname() != policy["agent_socket"]
                or owner_socket.getsockname() != policy["owner_socket"]):
            raise BootstrapError("invalid_worker_descriptors")
        unclaimed.remove(args.bootstrap_fd)
        secrets = read_bootstrap(args.bootstrap_fd)
        from .broker import Broker
        from .owner import make_owner_server
        from .service import create_app
        from .storage import Store
        import uvicorn
        from .worker_signals import ManagedWorkerServer, managed_worker_signals

        store = Store(root, secrets.vault_key)
        from .worker_enroll import verify_store_key
        verify_store_key(store)
        config = store.config()
        if config.test_mode != args.controlled_fixture:
            raise BootstrapError("invalid_worker_configuration_mode")
        with store.lock("service", timeout=0):
            if (root / "service.paused").exists() or (root / "service.paused").is_symlink():
                return 0
            broker = Broker(store)
            if sys.platform == "darwin":
                from .native_messages import NativeMessagesRelay
                native_messages = NativeMessagesRelay()
                broker.codes.native_transport = native_messages.request
            owner, _ = make_owner_server(broker, guided=True, instance_key=secrets.owner_proof_key,
                                         owner_token=secrets.owner_token, server_socket=owner_socket,
                                         origin_port=policy["owner_port"], local_host_actions=False,
                                         ready=lambda: server is not None and server.started and not server.should_exit,
                                         native_messages=native_messages)
            owner_socket = None  # The owner server now owns this descriptor.
            server = ManagedWorkerServer(uvicorn.Config(create_app(broker), log_level="critical",
                                                   access_log=False, log_config=None))
            owner_thread = threading.Thread(target=owner.serve_forever, daemon=True)
            owner_thread.start()
            def watch():
                while not closed.wait(0.25):
                    if server.should_exit:
                        return
                    if not owner_thread.is_alive():
                        if not (root / "service.paused").exists():
                            failed.set()
                        server.should_exit = True
                        return
                    if server.started and broker.worker_health.view()["status"] == "STOPPED":
                        failed.set()
                        server.should_exit = True
                        return
            monitor = threading.Thread(target=watch, daemon=True)
            monitor.start()
            with managed_worker_signals(server):
                try:
                    server.run(sockets=[agent])
                    if not server.started:
                        failed.set()
                finally:
                    closed.set()
                    owner.shutdown()
                    owner.server_close()
                    owner = None
                    owner_thread.join(timeout=5)
                    monitor.join(timeout=2)
                    if owner_thread.is_alive():
                        failed.set()
        return 75 if failed.is_set() else 0
    finally:
        closed.set()
        if native_messages is not None:
            native_messages.close()
        if owner is not None:
            if owner_thread is not None and owner_thread.is_alive():
                owner.shutdown()
            owner.server_close()
        if owner_socket is not None:
            owner_socket.close()
        if agent is not None:
            agent.close()
        # Never close a consumed descriptor's integer again: it may have been
        # reused by a later library operation in this process.
        for fd in unclaimed:
            try:
                os.close(fd)
            except OSError:
                pass


def main(argv=None):
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--policy", required=True)
    parser.add_argument("--bootstrap-fd", type=int, required=True)
    parser.add_argument("--agent-fd", type=int, required=True)
    parser.add_argument("--owner-fd", type=int, required=True)
    parser.add_argument("--controlled-fixture", action="store_true")
    args = parser.parse_args(argv)
    try:
        return serve(args)
    except BootstrapError as exc:
        print(json.dumps({"status": "NEEDS_USER", "reason": exc.reason}))
        return 78
    except KeyboardInterrupt:
        return 130
    except Exception:
        # No exception text, argv, configuration or inherited secret material.
        print(json.dumps({"status": "RETRYABLE", "reason": "worker_unavailable"}))
        return 75


if __name__ == "__main__":
    raise SystemExit(main())
