from __future__ import annotations

import os
import re
import json
from uuid import UUID

from fastapi.responses import JSONResponse
from sqlalchemy import select
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request

from app.db import SessionLocal
from app.db_models import ComponentRecord, DastValidationRecord, FindingRecord, ProjectMembershipRecord, ProjectRecord, SandboxEvidenceRecord, ScanTaskRecord, UserRecord
from app.services.auth_security import AuthenticationError, Identity, parse_token


AUTH_REQUIRED = os.getenv("AI_SECURITY_AUTH_REQUIRED", "true").lower() not in {"0", "false", "no"}
PUBLIC_AUTH_PATHS = {"/api/auth/bootstrap-status", "/api/auth/bootstrap", "/api/auth/login"}
PUBLIC_PREFIXES = ("/api/health", "/docs", "/openapi.json", "/redoc")
PROJECT_PATH = re.compile(r"/projects/([0-9a-fA-F-]{36})(?:/|$)")


class SecurityContextMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):  # type: ignore[no-untyped-def]
        if not AUTH_REQUIRED or request.method == "OPTIONS" or request.url.path in PUBLIC_AUTH_PATHS or request.url.path.startswith(PUBLIC_PREFIXES):
            return await call_next(request)
        raw_header = request.headers.get("Authorization", "")
        if not raw_header.startswith("Bearer "):
            return JSONResponse(status_code=401, content={"detail": "Bearer token is required"})
        try:
            identity = parse_token(raw_header[7:].strip())
        except AuthenticationError as exc:
            return JSONResponse(status_code=401, content={"detail": str(exc)})
        with SessionLocal() as db:
            user = db.get(UserRecord, identity.user_id)
            if user is None or not user.enabled or str(user.tenant_id) != identity.tenant_id or user.role != identity.role:
                return JSONResponse(status_code=401, content={"detail": "Account is unavailable"})
            project_id = await project_id_from_request(request, db)
            if project_id:
                project = db.get(ProjectRecord, project_id)
                if project is None or str(project.tenant_id) != identity.tenant_id:
                    return JSONResponse(status_code=404, content={"detail": "Project not found"})
                if identity.role != "admin":
                    membership = db.scalar(select(ProjectMembershipRecord).where(ProjectMembershipRecord.project_id == project_id, ProjectMembershipRecord.user_id == identity.user_id))
                    if membership is None:
                        return JSONResponse(status_code=403, content={"detail": "Project membership is required"})
            if requires_security_role(request) and identity.role not in {"admin", "security_engineer"}:
                return JSONResponse(status_code=403, content={"detail": "Security engineer or administrator role is required"})
        request.state.identity = identity
        return await call_next(request)


async def project_id_from_request(request: Request, db) -> str | None:  # type: ignore[no-untyped-def]
    matched = PROJECT_PATH.search(request.url.path)
    candidate = matched.group(1) if matched else request.query_params.get("project_id")
    if candidate is None and request.method in {"POST", "PUT", "PATCH", "DELETE"} and request.headers.get("content-type", "").startswith("application/json"):
        try:
            payload = json.loads((await request.body()).decode("utf-8"))
            if isinstance(payload, dict):
                candidate = payload.get("project_id")
        except (ValueError, UnicodeDecodeError):
            candidate = None
    if candidate is None:
        candidate = project_id_from_resource_path(request.url.path, db)
    if not candidate:
        return None
    try:
        return str(UUID(candidate))
    except ValueError:
        return None


def project_id_from_resource_path(path: str, db) -> str | None:  # type: ignore[no-untyped-def]
    matches = re.search(r"/(findings|validations|evidence|scans)/([0-9a-fA-F-]{36})(?:/|$)", path)
    if not matches:
        return None
    resource, resource_id = matches.groups()
    record_type = {
        "findings": FindingRecord,
        "validations": DastValidationRecord,
        "evidence": SandboxEvidenceRecord,
        "scans": ScanTaskRecord,
    }.get(resource)
    record = db.get(record_type, str(UUID(resource_id))) if record_type else None
    return str(record.project_id) if record is not None else None


def requires_security_role(request: Request) -> bool:
    if request.method in {"GET", "HEAD"}:
        return False
    path = request.url.path
    return any(marker in path for marker in ("/api/sast/projects/", "/api/sast/rules/", "/api/sca/policies", "/api/sca/intelligence", "/api/sca/osv-mirror", "/api/sandbox/run"))
