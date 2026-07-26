from datetime import datetime
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db import get_db
from app.db_models import ComponentRecord, FindingRecord, ProjectRecord
from app.models import (
    AiReview,
    Finding,
    FindingCreate,
    FindingGovernanceUpdate,
    FindingRetestComparison,
    FindingStatusUpdate,
)
from app.repositories.mappers import finding_to_schema
from app.services.finding_retest import (
    build_finding_retest_comparison,
    current_finding_records,
)

router = APIRouter()


@router.get("", response_model=list[Finding])
def list_findings(
    project_id: UUID | None = None,
    latest_only: bool = True,
    db: Session = Depends(get_db),
) -> list[Finding]:
    statement = select(FindingRecord).order_by(FindingRecord.created_at.desc())
    if project_id is not None:
        statement = statement.where(FindingRecord.project_id == str(project_id))
    records = db.scalars(statement).all()
    if latest_only and project_id is not None:
        records = current_finding_records(db, project_id, list(records))
    return [finding_to_schema(record) for record in records]


@router.get("/projects/{project_id}/retest-comparison", response_model=FindingRetestComparison)
def get_retest_comparison(
    project_id: UUID,
    source: str,
    db: Session = Depends(get_db),
) -> FindingRetestComparison:
    if db.get(ProjectRecord, str(project_id)) is None:
        raise HTTPException(status_code=404, detail="Project not found")
    try:
        return build_finding_retest_comparison(db, project_id, source)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("", response_model=Finding, status_code=201)
def create_finding(payload: FindingCreate, db: Session = Depends(get_db)) -> Finding:
    if db.get(ProjectRecord, str(payload.project_id)) is None:
        raise HTTPException(status_code=404, detail="Project not found")
    if payload.component_id is not None:
        component = db.get(ComponentRecord, str(payload.component_id))
        if component is None or component.project_id != str(payload.project_id):
            raise HTTPException(status_code=400, detail="component_id does not belong to this project")

    record = FindingRecord(
        project_id=str(payload.project_id),
        scan_task_id=str(payload.scan_task_id) if payload.scan_task_id else None,
        component_id=str(payload.component_id) if payload.component_id else None,
        source=payload.source,
        rule_id=payload.rule_id,
        title=payload.title,
        severity=payload.severity.value,
        file_path=payload.file_path,
        line_start=payload.line_start,
        line_end=payload.line_end,
        evidence=payload.evidence,
    )
    db.add(record)
    db.commit()
    db.refresh(record)
    return finding_to_schema(record)


@router.patch("/{finding_id}/status", response_model=Finding)
def update_finding_status(
    finding_id: UUID, payload: FindingStatusUpdate, db: Session = Depends(get_db)
) -> Finding:
    record = db.get(FindingRecord, str(finding_id))
    if record is None:
        raise HTTPException(status_code=404, detail="Finding not found")
    record.status = payload.status.value
    record.updated_at = datetime.utcnow()
    db.commit()
    db.refresh(record)
    return finding_to_schema(record)


@router.patch("/{finding_id}/governance", response_model=Finding)
def update_finding_governance(
    finding_id: UUID, payload: FindingGovernanceUpdate, db: Session = Depends(get_db)
) -> Finding:
    record = db.get(FindingRecord, str(finding_id))
    if record is None:
        raise HTTPException(status_code=404, detail="Finding not found")

    updates = payload.model_dump(exclude_unset=True)
    if "status" in updates and updates["status"] is not None:
        record.status = updates["status"].value
    if "remediation_owner" in updates:
        record.remediation_owner = updates["remediation_owner"]
    if "remediation_note" in updates:
        record.remediation_note = updates["remediation_note"]
    if "remediation_due_at" in updates:
        record.remediation_due_at = updates["remediation_due_at"]
    record.updated_at = datetime.utcnow()
    db.commit()
    db.refresh(record)
    return finding_to_schema(record)


@router.post("/{finding_id}/ai-review", response_model=Finding)
def mock_ai_review(finding_id: UUID, db: Session = Depends(get_db)) -> Finding:
    record = db.get(FindingRecord, str(finding_id))
    if record is None:
        raise HTTPException(status_code=404, detail="Finding not found")

    review = AiReview(
        summary=f"{record.title} 需要结合上下文确认调用链和输入来源。",
        false_positive_likelihood="medium",
        remediation="补充输入校验、最小权限控制，并在修复后执行复测。",
    )
    record.ai_review = review.model_dump()
    record.updated_at = datetime.utcnow()
    db.commit()
    db.refresh(record)
    return finding_to_schema(record)
