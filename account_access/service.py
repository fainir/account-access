"""Private HTTP API over a Unix socket; the same API can be placed behind authenticated TLS."""

import threading
from contextlib import asynccontextmanager

import anyio
from fastapi import Depends, FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from .errors import AccessError
from .models import RunRequest, TaskRequest


def create_app(broker, *, worker=True):
    stop = threading.Event()

    def work():
        while not stop.is_set():
            try:
                broker.tick()
            except Exception:
                # Exceptions must not leak provider response bodies or credential values.
                pass
            stop.wait(1)

    @asynccontextmanager
    async def lifespan(app):
        thread = threading.Thread(target=work, daemon=True) if worker else None
        if thread:
            thread.start()
        yield
        stop.set()
        if thread:
            await anyio.to_thread.run_sync(lambda: thread.join(timeout=5))

    app = FastAPI(title="Account Access", version="1", lifespan=lifespan,
                  docs_url=None, redoc_url=None, openapi_url=None)
    bearer = HTTPBearer(auto_error=False)

    def principal(auth: HTTPAuthorizationCredentials | None = Depends(bearer)):
        if not auth or auth.scheme.lower() != "bearer":
            raise AccessError("DENIED", "invalid_client")
        return broker.store.client(auth.credentials)

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
