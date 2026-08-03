from __future__ import annotations

from typing import Any

from sqlalchemy.orm import Session

from app.db_models import AuditRecord


def record_audit(
    db: Session, *, tenant_id: str, action: str, outcome: str,
    user_id: str | None = None, project_id: str | None = None, detail: dict[str, Any] | None = None,
) -> None:
    db.add(AuditRecord(
        tenant_id=tenant_id, user_id=user_id, project_id=project_id,
        action=action[:160], outcome=outcome[:40], detail=detail or {},
    ))
