from dataclasses import dataclass
from datetime import datetime, timedelta
import hashlib
import hmac
import os
import secrets

from fastapi import HTTPException, Request
from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from app.db_models import UserRecord, UserSessionRecord


SESSION_COOKIE = "ai_security_session"
SESSION_DAYS = max(1, int(os.getenv("AUTH_SESSION_DAYS", "7")))


@dataclass(frozen=True)
class Identity:
    user_id: str
    tenant_id: str
    username: str
    role: str

    @property
    def is_admin(self) -> bool:
        return self.role == "admin"


def hash_password(password: str) -> str:
    if len(password) < 10:
        raise ValueError("Password must contain at least 10 characters")
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(password.encode("utf-8"), salt=salt, n=2**14, r=8, p=1)
    return f"scrypt$16384$8$1${salt.hex()}${digest.hex()}"


def verify_password(password: str, encoded: str) -> bool:
    try:
        algorithm, n, r, p, salt_hex, digest_hex = encoded.split("$", 5)
        if algorithm != "scrypt":
            return False
        actual = hashlib.scrypt(
            password.encode("utf-8"), salt=bytes.fromhex(salt_hex), n=int(n), r=int(r), p=int(p)
        )
        return hmac.compare_digest(actual, bytes.fromhex(digest_hex))
    except (TypeError, ValueError):
        return False


def create_session(db: Session, user: UserRecord) -> tuple[str, UserSessionRecord]:
    token = secrets.token_urlsafe(48)
    now = datetime.utcnow()
    record = UserSessionRecord(
        user_id=str(user.id),
        token_hash=hashlib.sha256(token.encode("utf-8")).hexdigest(),
        expires_at=now + timedelta(days=SESSION_DAYS),
        last_seen_at=now,
    )
    db.add(record)
    db.flush()
    return token, record


def identity_for_token(db: Session, token: str | None) -> Identity | None:
    if not token:
        return None
    token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
    row = db.execute(
        select(UserSessionRecord, UserRecord)
        .join(UserRecord, UserRecord.id == UserSessionRecord.user_id)
        .where(UserSessionRecord.token_hash == token_hash)
    ).first()
    if row is None:
        return None
    session, user = row
    now = datetime.utcnow()
    if session.expires_at <= now or not user.enabled:
        db.delete(session)
        db.commit()
        return None
    session.last_seen_at = now
    db.commit()
    return Identity(str(user.id), str(user.tenant_id), user.username, normalize_role(user.role))


def revoke_session(db: Session, token: str | None) -> None:
    if not token:
        return
    token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
    db.execute(delete(UserSessionRecord).where(UserSessionRecord.token_hash == token_hash))
    db.commit()


def current_identity(request: Request) -> Identity:
    identity = getattr(request.state, "identity", None)
    if identity is None:
        raise HTTPException(status_code=401, detail="Authentication required")
    return identity


def require_admin(request: Request) -> Identity:
    identity = current_identity(request)
    if not identity.is_admin:
        raise HTTPException(status_code=403, detail="Administrator permission required")
    return identity


def normalize_role(value: str) -> str:
    return "admin" if str(value).strip().lower() == "admin" else "user"
