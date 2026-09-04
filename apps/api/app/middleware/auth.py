import os

from fastapi import Request
from fastapi.responses import JSONResponse
from sqlalchemy import func, select
from starlette.middleware.base import BaseHTTPMiddleware

from app.db import SessionLocal
from app.db_models import UserRecord
from app.services.auth import Identity, SESSION_COOKIE, identity_for_token


PUBLIC_PATHS = {"/api/health", "/api/auth/status", "/api/auth/login", "/api/auth/register", "/api/auth/bootstrap"}


def is_admin_operation(method: str, path: str) -> bool:
    if path.startswith("/api/auth/users"):
        return True
    if method == "DELETE" and path.startswith("/api/projects/"):
        return True
    if path.startswith("/api/sca/policies") or path.startswith("/api/sca/osv-mirror/import") or path.startswith("/api/sca/intelligence/import"):
        return True
    if method == "PATCH" and path.startswith("/api/sca/exceptions/"):
        return True
    if method in {"POST", "PUT", "PATCH", "DELETE"} and path.startswith("/api/sca/") and (path.startswith("/api/sca/vex/") or path.endswith("/vex")):
        return True
    if method in {"POST", "PUT", "PATCH", "DELETE"} and path.startswith("/api/sast/projects/") and "/suppressions" in path:
        return True
    if method in {"POST", "PUT", "PATCH", "DELETE"} and "/rules" in path and path.startswith("/api/sast/projects/"):
        return True
    if method in {"POST", "PUT", "PATCH", "DELETE"} and "/semgrep-rules" in path and path.startswith("/api/sast/projects/"):
        return True
    if path.startswith("/api/sast/rules/") or path.startswith("/api/sast/semgrep-rules/"):
        return True
    if method == "PATCH" and path.startswith("/api/agent/projects/") and (path.endswith("/profile") or "/exceptions/" in path):
        return True
    if path.endswith("/review") and path.startswith("/api/knowledge/entries/"):
        return True
    if path.endswith("/rollback") and path.startswith("/api/knowledge/entries/"):
        return True
    return False


class AuthenticationMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        if os.getenv("AUTH_DISABLED", "").lower() == "true":
            request.state.identity = Identity(
                "00000000-0000-0000-0000-000000000000",
                "00000000-0000-0000-0000-000000000001",
                "local-test-admin",
                "admin",
            )
            return await call_next(request)
        if request.method == "OPTIONS" or request.url.path in PUBLIC_PATHS:
            return await call_next(request)
        with SessionLocal() as db:
            initialized = bool(db.scalar(select(func.count()).select_from(UserRecord)))
            if not initialized:
                return JSONResponse({"detail": "Administrator initialization required"}, status_code=503)
            identity = identity_for_token(db, request.cookies.get(SESSION_COOKIE))
        if identity is None:
            return JSONResponse({"detail": "Authentication required"}, status_code=401)
        request.state.identity = identity
        if is_admin_operation(request.method, request.url.path) and not identity.is_admin:
            return JSONResponse({"detail": "Administrator permission required"}, status_code=403)
        return await call_next(request)
