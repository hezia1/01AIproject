from datetime import datetime
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db import get_db
from app.db_models import ComponentRecord, DastValidationRecord, FindingRecord, ProjectModuleRecord, ProjectRecord
from app.models import (
    DastLinkSuggestionRequest,
    DastProbeRequest,
    DastValidation,
    DastValidationCreate,
    DastValidationUpdate,
    LinkSuggestion,
    ModuleKey,
)
from app.repositories.mappers import dast_validation_to_schema
from app.services.dast_probe import probe_target_url
from app.services.evidence_link_suggestions import build_dast_link_suggestions

router = APIRouter()


@router.post("/link-suggestions", response_model=list[LinkSuggestion])
def suggest_validation_links(
    payload: DastLinkSuggestionRequest,
    db: Session = Depends(get_db),
) -> list[LinkSuggestion]:
    if db.get(ProjectRecord, str(payload.project_id)) is None:
        raise HTTPException(status_code=404, detail="Project not found")
    findings = list(
        db.scalars(
            select(FindingRecord).where(FindingRecord.project_id == str(payload.project_id))
        ).all()
    )
    components = {
        str(item.id): item
        for item in db.scalars(
            select(ComponentRecord).where(ComponentRecord.project_id == str(payload.project_id))
        ).all()
    }
    return build_dast_link_suggestions(payload.target_url, findings, components)


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


def ensure_links_belong_to_project(
    project_id: UUID,
    finding_id: UUID | None,
    component_id: UUID | None,
    db: Session,
) -> None:
    if finding_id is None:
        finding = None
    else:
        finding = db.get(FindingRecord, str(finding_id))
        if finding is None or finding.project_id != str(project_id):
            raise HTTPException(status_code=400, detail="finding_id does not belong to this project")
    if component_id is not None:
        component = db.get(ComponentRecord, str(component_id))
        if component is None or component.project_id != str(project_id):
            raise HTTPException(status_code=400, detail="component_id does not belong to this project")
        if finding is not None and finding.component_id and finding.component_id != str(component_id):
            raise HTTPException(status_code=400, detail="finding_id and component_id refer to different components")


def link_metadata(
    finding_id: UUID | None,
    component_id: UUID | None,
    requested_source: str = "unlinked",
    requested_confidence: int = 0,
) -> tuple[str, int]:
    if finding_id is None and component_id is None:
        return "unlinked", 0
    return (
        requested_source if requested_source != "unlinked" else "explicit-selection",
        requested_confidence if requested_confidence > 0 else 100,
    )


@router.post("/validations", response_model=DastValidation, status_code=201)
def create_validation(payload: DastValidationCreate, db: Session = Depends(get_db)) -> DastValidation:
    ensure_dast_enabled(payload.project_id, db)
    ensure_links_belong_to_project(payload.project_id, payload.finding_id, payload.component_id, db)
    link_source, link_confidence = link_metadata(
        payload.finding_id,
        payload.component_id,
        payload.link_source,
        payload.link_confidence,
    )

    record = DastValidationRecord(
        project_id=str(payload.project_id),
        finding_id=str(payload.finding_id) if payload.finding_id else None,
        component_id=str(payload.component_id) if payload.component_id else None,
        link_source=link_source,
        link_confidence=link_confidence,
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
    ensure_links_belong_to_project(payload.project_id, payload.finding_id, payload.component_id, db)
    link_source, link_confidence = link_metadata(
        payload.finding_id,
        payload.component_id,
        payload.link_source,
        payload.link_confidence,
    )

    try:
        probe = probe_target_url(payload.target_url)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    record = DastValidationRecord(
        project_id=str(payload.project_id),
        finding_id=str(payload.finding_id) if payload.finding_id else None,
        component_id=str(payload.component_id) if payload.component_id else None,
        link_source=link_source,
        link_confidence=link_confidence,
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
    next_finding_id = updates.get("finding_id", record.finding_id)
    next_component_id = updates.get("component_id", record.component_id)
    ensure_links_belong_to_project(
        UUID(str(record.project_id)),
        UUID(str(next_finding_id)) if next_finding_id else None,
        UUID(str(next_component_id)) if next_component_id else None,
        db,
    )
    for field, value in updates.items():
        if field == "verdict" and value is not None:
            setattr(record, field, value.value)
        elif field in {"finding_id", "component_id"}:
            setattr(record, field, str(value) if value else None)
        else:
            setattr(record, field, value)
    if "finding_id" in updates or "component_id" in updates:
        record.link_source, record.link_confidence = link_metadata(
            UUID(str(record.finding_id)) if record.finding_id else None,
            UUID(str(record.component_id)) if record.component_id else None,
            record.link_source,
            record.link_confidence,
        )
    record.updated_at = datetime.utcnow()
    db.commit()
    db.refresh(record)
    return dast_validation_to_schema(record)
