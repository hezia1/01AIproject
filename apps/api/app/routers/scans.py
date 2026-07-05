from datetime import datetime
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db import get_db
from app.db_models import ProjectRecord, ScanTaskRecord
from app.models import ScanCreate, ScanStatus, ScanTask
from app.repositories.mappers import scan_to_schema

router = APIRouter()


@router.get("", response_model=list[ScanTask])
def list_scans(
    project_id: UUID | None = None, db: Session = Depends(get_db)
) -> list[ScanTask]:
    statement = select(ScanTaskRecord).order_by(ScanTaskRecord.created_at.desc())
    if project_id is not None:
        statement = statement.where(ScanTaskRecord.project_id == str(project_id))
    records = db.scalars(statement).all()
    return [scan_to_schema(record) for record in records]


@router.post("", response_model=ScanTask, status_code=201)
def create_scan(payload: ScanCreate, db: Session = Depends(get_db)) -> ScanTask:
    if db.get(ProjectRecord, str(payload.project_id)) is None:
        raise HTTPException(status_code=404, detail="Project not found")

    record = ScanTaskRecord(
        project_id=str(payload.project_id),
        scan_type=payload.scan_type,
        status=ScanStatus.queued.value,
    )
    db.add(record)
    db.commit()
    db.refresh(record)
    return scan_to_schema(record)


@router.post("/{scan_id}/complete", response_model=ScanTask)
def complete_scan(scan_id: UUID, db: Session = Depends(get_db)) -> ScanTask:
    record = db.get(ScanTaskRecord, str(scan_id))
    if record is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    record.status = ScanStatus.completed.value
    record.finished_at = datetime.utcnow()
    db.commit()
    db.refresh(record)
    return scan_to_schema(record)
