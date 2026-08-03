from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db import get_db
from app.db_models import AuditRecord, ProjectMembershipRecord, ProjectRecord, TenantRecord, UserRecord
from app.models import AuthBootstrap, AuthLogin, ProjectMembershipCreate, UserCreate
from app.services.audit import record_audit
from app.services.auth_security import Identity, VALID_ROLES, hash_password, issue_token, verify_password


router = APIRouter()


def current_identity(request: Request) -> Identity:
    identity = getattr(request.state, "identity", None)
    if identity is None:
        raise HTTPException(status_code=401, detail="Authentication is required")
    return identity


def require_admin(request: Request) -> Identity:
    identity = current_identity(request)
    if identity.role != "admin":
        raise HTTPException(status_code=403, detail="Administrator role is required")
    return identity


@router.get("/bootstrap-status")
def bootstrap_status(db: Session = Depends(get_db)) -> dict[str, bool]:
    return {"needs_bootstrap": db.scalar(select(UserRecord.id).limit(1)) is None}


@router.post("/bootstrap", status_code=201)
def bootstrap(payload: AuthBootstrap, db: Session = Depends(get_db)) -> dict[str, object]:
    if db.scalar(select(UserRecord.id).limit(1)) is not None:
        raise HTTPException(status_code=409, detail="Bootstrap has already completed")
    tenant = db.scalar(select(TenantRecord).where(TenantRecord.name == payload.tenant_name.strip()))
    if tenant is None:
        tenant = TenantRecord(name=payload.tenant_name.strip())
        db.add(tenant)
        db.flush()
    user = UserRecord(tenant_id=str(tenant.id), username=payload.username.strip(), password_hash=hash_password(payload.password), role="admin")
    db.add(user)
    record_audit(db, tenant_id=str(tenant.id), user_id=str(user.id), action="identity.bootstrap", outcome="completed", detail={"username": user.username})
    db.commit()
    token, expires_at = issue_token(Identity(str(user.id), str(tenant.id), user.username, user.role))
    return identity_payload(user, str(tenant.name), token, expires_at)


@router.post("/login")
def login(payload: AuthLogin, db: Session = Depends(get_db)) -> dict[str, object]:
    statement = select(UserRecord, TenantRecord.name).join(TenantRecord, TenantRecord.id == UserRecord.tenant_id).where(UserRecord.username == payload.username.strip(), UserRecord.enabled.is_(True))
    if payload.tenant_name:
        statement = statement.where(TenantRecord.name == payload.tenant_name.strip())
    matches = db.execute(statement).all()
    if len(matches) != 1 or not verify_password(payload.password, matches[0][0].password_hash):
        raise HTTPException(status_code=401, detail="Invalid username, password, or tenant")
    user, tenant_name = matches[0]
    token, expires_at = issue_token(Identity(str(user.id), str(user.tenant_id), user.username, user.role))
    record_audit(db, tenant_id=str(user.tenant_id), user_id=str(user.id), action="identity.login", outcome="completed")
    db.commit()
    return identity_payload(user, str(tenant_name), token, expires_at)


@router.get("/me")
def me(identity: Identity = Depends(current_identity), db: Session = Depends(get_db)) -> dict[str, object]:
    user = db.get(UserRecord, identity.user_id)
    tenant = db.get(TenantRecord, identity.tenant_id)
    if user is None or tenant is None or not user.enabled:
        raise HTTPException(status_code=401, detail="Account is unavailable")
    return identity_payload(user, tenant.name, None, None)


@router.get("/users")
def list_users(identity: Identity = Depends(require_admin), db: Session = Depends(get_db)) -> list[dict[str, object]]:
    users = db.scalars(select(UserRecord).where(UserRecord.tenant_id == identity.tenant_id).order_by(UserRecord.created_at.asc())).all()
    return [user_payload(item) for item in users]


@router.post("/users", status_code=201)
def create_user(payload: UserCreate, identity: Identity = Depends(require_admin), db: Session = Depends(get_db)) -> dict[str, object]:
    if payload.role not in VALID_ROLES:
        raise HTTPException(status_code=400, detail="role must be admin, security_engineer, developer, or viewer")
    existing = db.scalar(select(UserRecord).where(UserRecord.tenant_id == identity.tenant_id, UserRecord.username == payload.username.strip()))
    if existing:
        raise HTTPException(status_code=409, detail="Username already exists in this tenant")
    user = UserRecord(tenant_id=identity.tenant_id, username=payload.username.strip(), password_hash=hash_password(payload.password), role=payload.role)
    db.add(user)
    record_audit(db, tenant_id=identity.tenant_id, user_id=identity.user_id, action="identity.user.create", outcome="completed", detail={"username": user.username, "role": user.role})
    db.commit()
    db.refresh(user)
    return user_payload(user)


@router.get("/projects/{project_id}/members")
def list_project_members(project_id: UUID, identity: Identity = Depends(current_identity), db: Session = Depends(get_db)) -> list[dict[str, object]]:
    project = tenant_project(db, str(project_id), identity)
    memberships = db.execute(select(ProjectMembershipRecord, UserRecord).join(UserRecord, UserRecord.id == ProjectMembershipRecord.user_id).where(ProjectMembershipRecord.project_id == str(project.id))).all()
    return [{**user_payload(user), "project_role": membership.role} for membership, user in memberships]


@router.post("/projects/{project_id}/members", status_code=201)
def add_project_member(project_id: UUID, payload: ProjectMembershipCreate, identity: Identity = Depends(require_admin), db: Session = Depends(get_db)) -> dict[str, object]:
    project = tenant_project(db, str(project_id), identity)
    if payload.role not in VALID_ROLES:
        raise HTTPException(status_code=400, detail="Invalid project role")
    user = db.scalar(select(UserRecord).where(UserRecord.tenant_id == identity.tenant_id, UserRecord.username == payload.username.strip()))
    if user is None:
        raise HTTPException(status_code=404, detail="User not found in tenant")
    membership = db.scalar(select(ProjectMembershipRecord).where(ProjectMembershipRecord.project_id == str(project.id), ProjectMembershipRecord.user_id == str(user.id)))
    if membership is None:
        membership = ProjectMembershipRecord(project_id=str(project.id), user_id=str(user.id), role=payload.role)
        db.add(membership)
    else:
        membership.role = payload.role
    record_audit(db, tenant_id=identity.tenant_id, user_id=identity.user_id, project_id=str(project.id), action="identity.project_member.upsert", outcome="completed", detail={"username": user.username, "role": payload.role})
    db.commit()
    return {**user_payload(user), "project_role": membership.role}


@router.get("/audit")
def list_audit(project_id: UUID | None = None, limit: int = 100, identity: Identity = Depends(require_admin), db: Session = Depends(get_db)) -> list[dict[str, object]]:
    statement = select(AuditRecord).where(AuditRecord.tenant_id == identity.tenant_id).order_by(AuditRecord.created_at.desc()).limit(min(max(limit, 1), 500))
    if project_id:
        statement = statement.where(AuditRecord.project_id == str(project_id))
    records = db.scalars(statement).all()
    return [{"id": str(item.id), "user_id": str(item.user_id) if item.user_id else None, "project_id": str(item.project_id) if item.project_id else None, "action": item.action, "outcome": item.outcome, "detail": item.detail or {}, "created_at": item.created_at} for item in records]


def tenant_project(db: Session, project_id: str, identity: Identity) -> ProjectRecord:
    project = db.get(ProjectRecord, project_id)
    if project is None or str(project.tenant_id) != identity.tenant_id:
        raise HTTPException(status_code=404, detail="Project not found")
    return project


def user_payload(user: UserRecord) -> dict[str, object]:
    return {"id": str(user.id), "username": user.username, "role": user.role, "enabled": user.enabled, "created_at": user.created_at}


def identity_payload(user: UserRecord, tenant_name: str, token: str | None, expires_at: int | None) -> dict[str, object]:
    payload: dict[str, object] = {"user": user_payload(user), "tenant": {"id": str(user.tenant_id), "name": tenant_name}}
    if token:
        payload.update({"access_token": token, "token_type": "bearer", "expires_at": expires_at})
    return payload
