from datetime import datetime
from uuid import UUID
from urllib.parse import urlparse

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db import get_db
from app.db_models import ComponentRecord, DastValidationRecord, FindingRecord, ProjectModuleRecord, ProjectRecord
from app.models import (
    DastLinkSuggestionRequest,
    DastProbeRequest,
    DastVerdict,
    DastVerificationStrategy,
    DastValidation,
    DastValidationCreate,
    DastValidationUpdate,
    LinkSuggestion,
    ModuleKey,
)
from app.repositories.mappers import dast_validation_to_schema
from app.services.dast_probe import probe_target_url
from app.services.evidence_link_suggestions import build_dast_link_suggestions
from app.services.verification_strategies import recommended_dast_strategies, resolve_dast_strategy

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


def ensure_dast_enabled(project_id: UUID, db: Session) -> ProjectRecord:
    project = db.get(ProjectRecord, str(project_id))
    if project is None:
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
    return project


def _origin(url: str) -> tuple[str, str, int] | None:
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password:
        return None
    try:
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
    except ValueError:
        return None
    return parsed.scheme.lower(), parsed.hostname.lower(), port


def confirm_probe_target(project: ProjectRecord, target_url: str, confirmation: str) -> None:
    if target_url != target_url.strip() or _origin(target_url) is None:
        raise HTTPException(status_code=400, detail="target_url must be a valid credential-free http or https URL")
    configured_origins = {
        origin
        for value in (project.runtime_url, project.api_base_url)
        if value and (origin := _origin(value)) is not None
    }
    if not configured_origins:
        raise HTTPException(status_code=400, detail="Configure a valid project runtime_url or api_base_url before DAST connects")
    if _origin(target_url) not in configured_origins:
        raise HTTPException(status_code=400, detail="target_url must use the same origin as the configured project runtime or API URL")
    expected = f"DAST_WEB_BASELINE:{target_url}"
    if confirmation != expected:
        raise HTTPException(status_code=400, detail=f"Enter the exact confirmation phrase: {expected}")


def ensure_manual_validation_record(record: DastValidationRecord) -> None:
    if record.validation_mode != "manual_validation":
        raise HTTPException(
            status_code=400,
            detail="Automated DAST baseline observations are read-only; create a manual validation record for review.",
        )


def build_dast_report(project_id: UUID, records: list[DastValidationRecord]) -> dict[str, object]:
    serialized_records = [dast_validation_to_schema(record).model_dump(mode="json") for record in records]
    automated_count = sum(record.validation_mode == "automated_web_baseline" for record in records)
    manual_count = sum(record.validation_mode == "manual_validation" for record in records)
    linked_count = sum(record.finding_id is not None or record.component_id is not None for record in records)
    verdict_counts = {
        verdict.value: sum(record.verdict == verdict.value for record in records)
        for verdict in DastVerdict
    }
    return {
        "schema": "ai-security-platform.dast-report/v1",
        "generated_at": datetime.utcnow().isoformat(),
        "project_id": str(project_id),
        "summary": {
            "record_count": len(records),
            "automated_baseline_count": automated_count,
            "manual_validation_count": manual_count,
            "linked_record_count": linked_count,
            "by_verdict": verdict_counts,
        },
        "records": serialized_records,
        "capability_boundaries": [
            "Automated baseline records capture only the observed unauthenticated HTTP GET result for the confirmed target URL.",
            "A baseline_clear result is not a non-exploitability conclusion and does not establish the absence of vulnerabilities.",
            "Manual verdicts document the reviewer-provided evidence and are limited to their recorded target, scope, and reproduction steps.",
            "This report is generated solely from stored DAST records and does not connect to targets or perform new tests.",
        ],
    }


@router.get("/projects/{project_id}/strategies", response_model=list[DastVerificationStrategy])
def list_verification_strategies(
    project_id: UUID,
    finding_id: UUID | None = None,
    db: Session = Depends(get_db),
) -> list[DastVerificationStrategy]:
    ensure_dast_enabled(project_id, db)
    finding = db.get(FindingRecord, str(finding_id)) if finding_id else None
    if finding_id and (finding is None or finding.project_id != str(project_id)):
        raise HTTPException(status_code=400, detail="finding_id does not belong to this project")
    return recommended_dast_strategies(finding)


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
    if payload.verdict not in {DastVerdict.exploitable, DastVerdict.uncertain, DastVerdict.not_exploitable}:
        raise HTTPException(status_code=400, detail="Manual DAST validation requires an explicit three-state verdict")
    if not (payload.evidence_summary or "").strip() or not (payload.reproduction_steps or "").strip():
        raise HTTPException(status_code=400, detail="Manual DAST validation requires evidence_summary and reproduction_steps")
    ensure_links_belong_to_project(payload.project_id, payload.finding_id, payload.component_id, db)
    link_source, link_confidence = link_metadata(
        payload.finding_id,
        payload.component_id,
        payload.link_source,
        payload.link_confidence,
    )

    finding = db.get(FindingRecord, str(payload.finding_id)) if payload.finding_id else None
    try:
        strategy = resolve_dast_strategy(payload.strategy_id, finding)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    record = DastValidationRecord(
        project_id=str(payload.project_id),
        finding_id=str(payload.finding_id) if payload.finding_id else None,
        component_id=str(payload.component_id) if payload.component_id else None,
        link_source=link_source,
        link_confidence=link_confidence,
        target_url=payload.target_url,
        verdict=payload.verdict.value,
        validator=payload.validator,
        strategy_id=strategy.id,
        strategy_name=payload.strategy_name or strategy.name,
        scope_summary=payload.scope_summary or strategy.scope_summary,
        limitations=payload.limitations or " ".join(strategy.limitations),
        evidence_summary=payload.evidence_summary,
        request_summary=payload.request_summary,
        response_summary=payload.response_summary,
        reproduction_steps=payload.reproduction_steps,
        remediation_hint=payload.remediation_hint,
        validation_mode="manual_validation",
        connection_confirmed=False,
    )
    db.add(record)
    db.commit()
    db.refresh(record)
    return dast_validation_to_schema(record)


@router.post("/probe", response_model=DastValidation, status_code=201)
def probe_target(payload: DastProbeRequest, db: Session = Depends(get_db)) -> DastValidation:
    project = ensure_dast_enabled(payload.project_id, db)
    confirm_probe_target(project, payload.target_url, payload.target_confirmation)
    ensure_links_belong_to_project(payload.project_id, payload.finding_id, payload.component_id, db)
    link_source, link_confidence = link_metadata(
        payload.finding_id,
        payload.component_id,
        payload.link_source,
        payload.link_confidence,
    )

    finding = db.get(FindingRecord, str(payload.finding_id)) if payload.finding_id else None
    try:
        strategy = resolve_dast_strategy(payload.strategy_id, finding)
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
        strategy_id=strategy.id,
        strategy_name=strategy.name,
        scope_summary=strategy.scope_summary,
        limitations=" ".join(strategy.limitations),
        evidence_summary=probe.evidence_summary,
        request_summary=probe.request_summary,
        response_summary=probe.response_summary,
        reproduction_steps=probe.reproduction_steps,
        remediation_hint=probe.remediation_hint,
        validation_mode="automated_web_baseline",
        connection_confirmed=True,
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


@router.get("/projects/{project_id}/report")
def get_project_dast_report(project_id: UUID, db: Session = Depends(get_db)) -> dict[str, object]:
    ensure_dast_enabled(project_id, db)
    records = db.scalars(
        select(DastValidationRecord)
        .where(DastValidationRecord.project_id == str(project_id))
        .order_by(DastValidationRecord.created_at.desc())
    ).all()
    return build_dast_report(project_id, records)


@router.patch("/validations/{validation_id}", response_model=DastValidation)
def update_validation(
    validation_id: UUID, payload: DastValidationUpdate, db: Session = Depends(get_db)
) -> DastValidation:
    record = db.get(DastValidationRecord, str(validation_id))
    if record is None:
        raise HTTPException(status_code=404, detail="DAST validation not found")
    ensure_manual_validation_record(record)

    updates = payload.model_dump(exclude_unset=True)
    if "verdict" in updates and updates["verdict"] not in {DastVerdict.exploitable, DastVerdict.uncertain, DastVerdict.not_exploitable}:
        raise HTTPException(status_code=400, detail="Manual DAST validation requires an explicit three-state verdict")
    if {"verdict", "evidence_summary", "reproduction_steps"} & updates.keys():
        next_evidence = updates.get("evidence_summary", record.evidence_summary)
        next_steps = updates.get("reproduction_steps", record.reproduction_steps)
        if not (next_evidence or "").strip() or not (next_steps or "").strip():
            raise HTTPException(status_code=400, detail="Manual DAST validation requires evidence_summary and reproduction_steps")
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
