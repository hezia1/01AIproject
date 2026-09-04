from copy import deepcopy
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.db import get_db
from app.db_models import PlatformPolicyRecord
from app.services.auth import require_admin
from app.services.audit import record_audit
from app.services.platform_policy import DEFAULT_POLICY, validate_policy

router = APIRouter()


def response(record):
    return {"config": validate_policy({**DEFAULT_POLICY, **record.config}) if record else deepcopy(DEFAULT_POLICY), "version": record.version if record else 0,
            "actor": record.actor if record else None, "updated_at": record.updated_at if record else None}


@router.get("/maintenance-policy")
def read_policy(db: Session = Depends(get_db)):
    return response(db.get(PlatformPolicyRecord, "maintenance"))


@router.put("/maintenance-policy")
def save_policy(payload: dict, request: Request, db: Session = Depends(get_db)):
    identity = require_admin(request)
    try:
        config = validate_policy(payload.get("config", {}))
    except (ValueError, TypeError) as exc:
        raise HTTPException(400, str(exc)) from exc
    # Serializes initial insertion as well as concurrent updates across workers.
    db.execute(text("SELECT pg_advisory_xact_lock(202609040016)"))
    record = db.get(PlatformPolicyRecord, "maintenance")
    if payload.get("version") != (record.version if record else 0):
        raise HTTPException(409, "配置已被其他管理员修改，请刷新后重试")
    if record is None:
        record = PlatformPolicyRecord(id="maintenance", version=0)
        db.add(record)
    record.config = config
    record.version += 1
    record.actor = identity.username
    record.updated_at = datetime.utcnow()
    record_audit(db, tenant_id=identity.tenant_id, user_id=identity.user_id,
                 action="platform.maintenance_policy.update", outcome="completed",
                 detail={"version": record.version, "config": config})
    db.commit()
    return response(record)
