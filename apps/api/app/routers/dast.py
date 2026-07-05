from datetime import datetime
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db import get_db
from app.db_models import DastValidationRecord, FindingRecord, ProjectModuleRecord, ProjectRecord
from app.models import DastProbeRequest, DastValidation, DastValidationCreate, DastValidationUpdate, ModuleKey
from app.repositories.mappers import dast_validation_to_schema
from app.services.dast_probe import probe_target_url

router = APIRouter()


def ensure_dast_enabled(project_id: UUID, db: Session) -> None:
    if db.get(ProjectRecord, str(project_id)) is None:
        raise HTTPException(status_code=404, detail="Project not found")

    project_module = db.scalar(
        select(ProjectModuleRecord).where(
            ProjectModuleRecord.project_id == str(project_id),
            ProjectModuleRecord.module_key == ModuleKey.dast.value,
            ProjectModuleRecord.enabled.is_(True),
        )
    )
    if project_module is None:
        raise HTTPException(status_code=400, detail="DAST module is not enabled for this project")


def ensure_finding_belongs_to_project(project_id: UUID, finding_id: UUID | None, db: Session) -> None:
    if finding_id is None:
        return
    finding = db.get(FindingRecord, str(finding_id))
    if finding is None or finding.project_id != str(project_id):
        raise HTTPException(status_code=400, detail="finding_id does not belong to this project")


@router.post("/validations", response_model=DastValidation, status_code=201)
def create_validation(payload: DastValidationCreate, db: Session = Depends(get_db)) -> DastValidation:
    ensure_dast_enabled(payload.project_id, db)
    ensure_finding_belongs_to_project(payload.project_id, payload.finding_id, db)

    record = DastValidationRecord(
        project_id=str(payload.project_id),
        finding_id=str(payload.finding_id) if payload.finding_id else None,
        target_url=payload.target_url,
        verdict=payload.verdict.value,
        validator=payload.validator,
        evidence_summary=payload.evidence_summary,
        request_summary=payload.request_summary,
        response_summary=payload.response_summary,
        reproduction_steps=payload.reproduction_steps,
        remediation_hint=payload.remediation_hint,
    )
    db.add(record)
    db.commit()
    db.refresh(record)
    return dast_validation_to_schema(record)


@router.post("/probe", response_model=DastValidation, status_code=201)
def probe_target(payload: DastProbeRequest, db: Session = Depends(get_db)) -> DastValidation:
    ensure_dast_enabled(payload.project_id, db)
    ensure_finding_belongs_to_project(payload.project_id, payload.finding_id, db)

    try:
        probe = probe_target_url(payload.target_url)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    record = DastValidationRecord(
        project_id=str(payload.project_id),
        finding_id=str(payload.finding_id) if payload.finding_id else None,
        target_url=probe.target_url,
        verdict=probe.verdict.value,
        validator=payload.validator or "auto-dast",
        evidence_summary=probe.evidence_summary,
        request_summary=probe.request_summary,
        response_summary=probe.response_summary,
        reproduction_steps=probe.reproduction_steps,
        remediation_hint=probe.remediation_hint,
    )
    db.add(record)
    db.commit()
    db.refresh(record)
    return dast_validation_to_schema(record)


@router.get("/projects/{project_id}/validations", response_model=list[DastValidation])
def list_project_validations(project_id: UUID, db: Session = Depends(get_db)) -> list[DastValidation]:
    if db.get(ProjectRecord, str(project_id)) is None:
        raise HTTPException(status_code=404, detail="Project not found")

    records = db.scalars(
        select(DastValidationRecord)
        .where(DastValidationRecord.project_id == str(project_id))
        .order_by(DastValidationRecord.created_at.desc())
    ).all()
    return [dast_validation_to_schema(record) for record in records]


@router.patch("/validations/{validation_id}", response_model=DastValidation)
def update_validation(
    validation_id: UUID, payload: DastValidationUpdate, db: Session = Depends(get_db)
) -> DastValidation:
    record = db.get(DastValidationRecord, str(validation_id))
    if record is None:
        raise HTTPException(status_code=404, detail="DAST validation not found")

    updates = payload.model_dump(exclude_unset=True)
    for field, value in updates.items():
        if field == "verdict" and value is not None:
            setattr(record, field, value.value)
        else:
            setattr(record, field, value)
    record.updated_at = datetime.utcnow()
    db.commit()
    db.refresh(record)
    return dast_validation_to_schema(record)
