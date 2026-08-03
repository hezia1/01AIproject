from datetime import datetime
from uuid import UUID

import os

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.db import get_db
from app.db_models import ProjectRecord, ScanTaskRecord
from app.models import ScanCreate, ScanProgressUpdate, ScanStatus, ScanTask
from app.repositories.mappers import scan_to_schema

router = APIRouter()


@router.get("", response_model=list[ScanTask])
def list_scans(
    request: Request, project_id: UUID | None = None, db: Session = Depends(get_db)
) -> list[ScanTask]:
    statement = select(ScanTaskRecord).join(ProjectRecord, ProjectRecord.id == ScanTaskRecord.project_id).order_by(ScanTaskRecord.created_at.desc())
    identity = getattr(request.state, "identity", None)
    if identity is not None:
        statement = statement.where(ProjectRecord.tenant_id == identity.tenant_id)
    if project_id is not None:
        statement = statement.where(ScanTaskRecord.project_id == str(project_id))
    records = db.scalars(statement).all()
    return [scan_to_schema(record) for record in records]


@router.post("", response_model=ScanTask, status_code=201)
def create_scan(payload: ScanCreate, db: Session = Depends(get_db)) -> ScanTask:
    if db.get(ProjectRecord, str(payload.project_id)) is None:
        raise HTTPException(status_code=404, detail="Project not found")

    active = db.scalar(select(ScanTaskRecord.id).where(ScanTaskRecord.project_id == str(payload.project_id), ScanTaskRecord.scan_type == payload.scan_type, ScanTaskRecord.status.in_([ScanStatus.queued.value, ScanStatus.running.value])))
    if active:
        raise HTTPException(status_code=409, detail="A scan of this type is already queued or running for the project")
    queued_count = db.scalar(select(func.count()).select_from(ScanTaskRecord).where(ScanTaskRecord.status == ScanStatus.queued.value))
    metadata = dict(payload.metadata)
    metadata.update({"progress": 0, "stage": "queued", "attempt": max(1, int(metadata.get("attempt") or 1)), "queue_position": int(queued_count or 0) + 1, "events": [{"at": datetime.utcnow().isoformat() + "Z", "stage": "queued", "detail": "Task created"}]})
    record = ScanTaskRecord(
        project_id=str(payload.project_id),
        scan_type=payload.scan_type,
        status=ScanStatus.queued.value,
        scan_metadata=metadata,
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
    update_task_metadata(record, progress=100, stage="completed", detail="Task completed")
    db.commit()
    db.refresh(record)
    return scan_to_schema(record)


@router.post("/{scan_id}/start", response_model=ScanTask)
def start_scan(scan_id: UUID, db: Session = Depends(get_db)) -> ScanTask:
    record = db.get(ScanTaskRecord, str(scan_id))
    if record is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    if record.status != ScanStatus.queued.value:
        raise HTTPException(status_code=409, detail="Only queued scans can be started")
    concurrency = max(1, int(os.getenv("AI_SECURITY_SCAN_CONCURRENCY", "2")))
    running = db.scalar(select(func.count()).select_from(ScanTaskRecord).where(ScanTaskRecord.status == ScanStatus.running.value))
    if int(running or 0) >= concurrency:
        raise HTTPException(status_code=409, detail=f"Concurrency limit reached ({concurrency}); keep this task queued")
    record.status = ScanStatus.running.value
    record.started_at = datetime.utcnow()
    update_task_metadata(record, progress=5, stage="started", detail="Task claimed by worker")
    db.commit()
    db.refresh(record)
    return scan_to_schema(record)


@router.patch("/{scan_id}/progress", response_model=ScanTask)
def update_scan_progress(scan_id: UUID, payload: ScanProgressUpdate, db: Session = Depends(get_db)) -> ScanTask:
    record = db.get(ScanTaskRecord, str(scan_id))
    if record is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    if record.status != ScanStatus.running.value:
        raise HTTPException(status_code=409, detail="Only running scans can report progress")
    update_task_metadata(record, progress=payload.progress, stage=payload.stage, detail=payload.detail or "Progress updated")
    db.commit()
    db.refresh(record)
    return scan_to_schema(record)


@router.post("/{scan_id}/cancel", response_model=ScanTask)
def cancel_scan(scan_id: UUID, db: Session = Depends(get_db)) -> ScanTask:
    record = db.get(ScanTaskRecord, str(scan_id))
    if record is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    if record.status not in {ScanStatus.queued.value, ScanStatus.running.value}:
        raise HTTPException(status_code=409, detail="Only queued or running scans can be cancelled")
    record.status = ScanStatus.cancelled.value
    record.finished_at = datetime.utcnow()
    update_task_metadata(record, progress=int((record.scan_metadata or {}).get("progress") or 0), stage="cancelled", detail="Cancellation requested")
    db.commit()
    db.refresh(record)
    return scan_to_schema(record)


@router.post("/{scan_id}/retry", response_model=ScanTask, status_code=201)
def retry_scan(scan_id: UUID, db: Session = Depends(get_db)) -> ScanTask:
    previous = db.get(ScanTaskRecord, str(scan_id))
    if previous is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    if previous.status not in {ScanStatus.failed.value, ScanStatus.cancelled.value}:
        raise HTTPException(status_code=409, detail="Only failed or cancelled scans can be retried")
    metadata = dict(previous.scan_metadata or {})
    metadata.pop("error", None)
    metadata["attempt"] = int(metadata.get("attempt") or 1) + 1
    metadata["progress"] = 0
    metadata["stage"] = "queued"
    metadata["queue_position"] = 0
    metadata["events"] = [*list(metadata.get("events") or []), {"at": datetime.utcnow().isoformat() + "Z", "stage": "queued", "detail": f"Retry of {previous.id}"}]
    record = ScanTaskRecord(project_id=str(previous.project_id), scan_type=previous.scan_type, status=ScanStatus.queued.value, commit_hash=previous.commit_hash, scan_metadata=metadata)
    db.add(record)
    db.commit()
    db.refresh(record)
    return scan_to_schema(record)


def update_task_metadata(record: ScanTaskRecord, *, progress: int, stage: str, detail: str) -> None:
    metadata = dict(record.scan_metadata or {})
    events = list(metadata.get("events") or [])[-49:]
    events.append({"at": datetime.utcnow().isoformat() + "Z", "stage": stage, "detail": detail[:1000], "progress": progress})
    metadata.update({"progress": progress, "stage": stage, "queue_position": None, "events": events})
    record.scan_metadata = metadata
