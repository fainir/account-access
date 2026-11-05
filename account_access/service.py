"""Private HTTP API over a Unix socket; the same API can be placed behind authenticated TLS."""

import threading
import hashlib
import hmac
import math
import secrets
import time
from collections import OrderedDict, deque
from contextlib import asynccontextmanager

import anyio
from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from .errors import AccessError
from .models import RunRequest, TaskRequest


class _AuthFailureLimiter:
    """Bound repeated invalid credentials without retaining peer addresses."""

    def __init__(self, *, limit=8, window=60, max_peers=1024, clock=time.monotonic):
        self.limit = limit
        self.window = window
        self.max_peers = max_peers
        self.clock = clock
        self._key = secrets.token_bytes(32)
        self._failures = OrderedDict()
        self._lock = threading.Lock()

    def _peer_key(self, request):
        client = request.scope.get("client")
        peer = client[0] if isinstance(client, (tuple, list)) and client else "local"
        if not isinstance(peer, str):
            peer = "local"
        return hmac.digest(self._key, peer[:256].encode("utf-8", "replace"), hashlib.sha256)

    def _prune(self, peer, now):
        failures = self._failures.get(peer)
        if failures is None:
            return None
        while failures and now - failures[0] >= self.window:
            failures.popleft()
        if not failures:
            del self._failures[peer]
            return None
        self._failures.move_to_end(peer)
        return failures

    def retry_after(self, request):
        peer = self._peer_key(request)
        now = self.clock()
        with self._lock:
            failures = self._prune(peer, now)
            if failures is None or len(failures) < self.limit:
                return None
            return max(1, math.ceil(self.window - (now - failures[0])))

    def failed(self, request):
        peer = self._peer_key(request)
        now = self.clock()
        with self._lock:
            failures = self._prune(peer, now)
            if failures is None:
                failures = deque()
                self._failures[peer] = failures
            failures.append(now)
            self._failures.move_to_end(peer)
            while len(self._failures) > self.max_peers:
                self._failures.popitem(last=False)


def create_app(broker, *, worker=True, auth_failure_limit=8, auth_failure_window=60,
               clock=time.monotonic):
    stop = threading.Event()
    active_thread = None

    def work():
        health = broker.worker_health
        health.start()
        try:
            while not stop.is_set():
                health.begin()
                delay = 1
                try:
                    broker.tick()
                except Exception:
                    # Do not stringify, log or retain exception/provider details.
                    # Report only a fixed class and bounded retry metadata.
                    delay = health.failure()
                else:
                    health.success()
                stop.wait(delay)
        finally:
            health.stop()

    @asynccontextmanager
    async def lifespan(app):
        nonlocal active_thread
        if active_thread is not None and active_thread.is_alive():
            raise RuntimeError("background_worker_still_stopping")
        stop.clear()
        thread = threading.Thread(target=work, daemon=True) if worker else None
        active_thread = thread
        if thread:
            thread.start()
        try:
            yield
        finally:
            stop.set()
            if thread:
                await anyio.to_thread.run_sync(lambda: thread.join(timeout=5))

    app = FastAPI(title="Account Access", version="1", lifespan=lifespan,
                  docs_url=None, redoc_url=None, openapi_url=None)
    bearer = HTTPBearer(auto_error=False)
    auth_failures = _AuthFailureLimiter(limit=auth_failure_limit,
                                        window=auth_failure_window, clock=clock)

    def principal(request: Request,
                  auth: HTTPAuthorizationCredentials | None = Depends(bearer)):
        retry_after = auth_failures.retry_after(request)
        if retry_after is not None:
            raise HTTPException(429, "authentication_rate_limited",
                                headers={"Retry-After": str(retry_after)})
        if not auth or auth.scheme.lower() != "bearer":
            auth_failures.failed(request)
            raise AccessError("DENIED", "invalid_client")
        try:
            return broker.store.client(auth.credentials)
        except AccessError as exc:
            if exc.reason == "invalid_client":
                auth_failures.failed(request)
            raise

    @app.middleware("http")
    async def restrict_requests(request: Request, call_next):
        if request.headers.get("origin") or request.headers.get("cookie"):
            return JSONResponse({"status": "DENIED", "reason": "browser_rpc_forbidden"}, 403)
        try:
            length = int(request.headers.get("content-length", "0") or 0)
        except ValueError:
            return JSONResponse({"status": "DENIED", "reason": "invalid_request"}, 400)
        if length > 65536 or length < 0:
            return JSONResponse({"status": "DENIED", "reason": "request_too_large"}, 413)
        body = bytearray()
        async for chunk in request.stream():
            body.extend(chunk)
            if len(body) > 65536:
                return JSONResponse({"status": "DENIED", "reason": "request_too_large"}, 413)
        request._body = bytes(body)
        response = await call_next(request)
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Content-Type-Options"] = "nosniff"
        return response

    @app.exception_handler(AccessError)
    async def access_error(request, exc):
        return JSONResponse({"status": exc.status, "reason": exc.reason},
                            401 if exc.reason == "invalid_client" else 403)

    @app.exception_handler(Exception)
    async def unexpected(request, exc):
        return JSONResponse({"status": "RETRYABLE", "reason": "internal_error"}, 500)

    @app.exception_handler(RequestValidationError)
    async def invalid_request(request, exc):
        return JSONResponse({"status": "DENIED", "reason": "invalid_request"}, 422)

    @app.get("/v1/accounts")
    def accounts(who=Depends(principal)):
        return broker.accounts(who)

    @app.get("/v1/status/{account}/{operation}")
    def status(account: str, operation: str, who=Depends(principal)):
        return broker.status(who, account, operation)

    @app.post("/v1/run")
    def run(body: RunRequest, who=Depends(principal)):
        return broker.run(who, body.account, body.operation)

    @app.post("/v1/tasks")
    def submit(body: TaskRequest, who=Depends(principal)):
        return broker.submit(who, body)

    @app.get("/v1/tasks/{job_id}")
    def task(job_id: str, who=Depends(principal)):
        return broker.task(who, job_id)

    @app.get("/v1/audit")
    def audit(who=Depends(principal)):
        return broker.audit(who)

    return app
