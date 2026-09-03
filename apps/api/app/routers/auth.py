from datetime import datetime
import os
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel, Field
from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session

from app.db import get_db
from app.db_models import TenantRecord, UserRecord, UserSessionRecord
from app.services.auth import SESSION_COOKIE, SESSION_DAYS, create_session, current_identity, hash_password, normalize_role, require_admin, revoke_session, verify_password


router = APIRouter()
LEGACY_TENANT_ID = "00000000-0000-0000-0000-000000000001"


class Credentials(BaseModel):
    username: str = Field(min_length=3, max_length=120)
    password: str = Field(min_length=10, max_length=200)


class UserCreate(Credentials):
    role: str = "user"


class UserUpdate(BaseModel):
    enabled: bool | None = None
    role: str | None = None
    password: str | None = Field(default=None, min_length=10, max_length=200)


def user_payload(user: UserRecord) -> dict[str, object]:
    return {"id": str(user.id), "username": user.username, "role": normalize_role(user.role), "enabled": user.enabled, "created_at": user.created_at}


def set_session_cookie(response: Response, token: str) -> None:
    response.set_cookie(
        SESSION_COOKIE,
        token,
        max_age=SESSION_DAYS * 86400,
        httponly=True,
        samesite="lax",
        secure=False,
        path="/",
    )


@router.get("/status")
def auth_status(db: Session = Depends(get_db)) -> dict[str, bool]:
    return {"initialized": os.getenv("AUTH_DISABLED", "").lower() == "true" or bool(db.scalar(select(func.count()).select_from(UserRecord)))}


@router.post("/bootstrap", status_code=201)
def bootstrap_admin(payload: Credentials, response: Response, db: Session = Depends(get_db)) -> dict[str, object]:
    if db.scalar(select(func.count()).select_from(UserRecord)):
        raise HTTPException(status_code=409, detail="Administrator has already been initialized")
    tenant = db.get(TenantRecord, LEGACY_TENANT_ID)
    if tenant is None:
        tenant = TenantRecord(id=LEGACY_TENANT_ID, name="Local Workspace", created_at=datetime.utcnow())
        db.add(tenant)
        db.flush()
    try:
        password_hash = hash_password(payload.password)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    user = UserRecord(id=str(uuid4()), tenant_id=LEGACY_TENANT_ID, username=payload.username.strip(), password_hash=password_hash, role="admin", enabled=True)
    db.add(user)
    db.flush()
    token, _ = create_session(db, user)
    db.commit()
    set_session_cookie(response, token)
    return user_payload(user)


@router.post("/login")
def login(payload: Credentials, response: Response, db: Session = Depends(get_db)) -> dict[str, object]:
    user = db.scalar(select(UserRecord).where(func.lower(UserRecord.username) == payload.username.strip().lower()))
    if user is None or not user.enabled or not verify_password(payload.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid username or password")
    token, _ = create_session(db, user)
    db.commit()
    set_session_cookie(response, token)
    return user_payload(user)


@router.post("/logout", status_code=204)
def logout(request: Request, response: Response, db: Session = Depends(get_db)) -> Response:
    revoke_session(db, request.cookies.get(SESSION_COOKIE))
    response.delete_cookie(SESSION_COOKIE, path="/")
    response.status_code = 204
    return response


@router.get("/me")
def me(request: Request) -> dict[str, object]:
    identity = current_identity(request)
    return {"id": identity.user_id, "username": identity.username, "role": identity.role, "enabled": True}


@router.get("/users")
def list_users(request: Request, db: Session = Depends(get_db)) -> list[dict[str, object]]:
    identity = require_admin(request)
    users = db.scalars(select(UserRecord).where(UserRecord.tenant_id == identity.tenant_id).order_by(UserRecord.created_at)).all()
    return [user_payload(user) for user in users]


@router.post("/users", status_code=201)
def create_user(payload: UserCreate, request: Request, db: Session = Depends(get_db)) -> dict[str, object]:
    identity = require_admin(request)
    username = payload.username.strip()
    if db.scalar(select(UserRecord.id).where(UserRecord.tenant_id == identity.tenant_id, func.lower(UserRecord.username) == username.lower())):
        raise HTTPException(status_code=409, detail="Username already exists")
    user = UserRecord(tenant_id=identity.tenant_id, username=username, password_hash=hash_password(payload.password), role=normalize_role(payload.role), enabled=True)
    db.add(user)
    db.commit()
    db.refresh(user)
    return user_payload(user)


@router.patch("/users/{user_id}")
def update_user(user_id: str, payload: UserUpdate, request: Request, db: Session = Depends(get_db)) -> dict[str, object]:
    identity = require_admin(request)
    user = db.get(UserRecord, user_id)
    if user is None or str(user.tenant_id) != identity.tenant_id:
        raise HTTPException(status_code=404, detail="User not found")
    if payload.role is not None:
        user.role = normalize_role(payload.role)
    if payload.enabled is not None:
        if str(user.id) == identity.user_id and not payload.enabled:
            raise HTTPException(status_code=400, detail="You cannot disable your own account")
        user.enabled = payload.enabled
    if payload.password:
        user.password_hash = hash_password(payload.password)
        db.query(UserSessionRecord).filter(UserSessionRecord.user_id == str(user.id)).delete()
    db.commit()
    db.refresh(user)
    return user_payload(user)


@router.delete("/users/{user_id}", status_code=204)
def delete_user(user_id: str, request: Request, response: Response, db: Session = Depends(get_db)) -> Response:
    identity = require_admin(request)
    if user_id == identity.user_id:
        raise HTTPException(status_code=400, detail="You cannot delete your own account")
    user = db.get(UserRecord, user_id)
    if user is None or str(user.tenant_id) != identity.tenant_id:
        raise HTTPException(status_code=404, detail="User not found")
    db.execute(delete(UserSessionRecord).where(UserSessionRecord.user_id == user_id))
    db.delete(user)
    db.commit()
    response.status_code = 204
    return response
