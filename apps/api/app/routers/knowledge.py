from datetime import datetime
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.db import get_db
from app.db_models import (
    AuditRecord,
    DastValidationRecord,
    FindingRecord,
    KnowledgeEntryRecord,
    KnowledgeEntryVersionRecord,
    ProjectRecord,
    SandboxEvidenceRecord,
)
from app.models import (
    KnowledgeCandidateSubmit,
    KnowledgeEntry,
    KnowledgeEntryVersion,
    KnowledgeRecommendation,
    KnowledgeReview,
    KnowledgeRollback,
    KnowledgeWorkspace,
)
from app.services.finding_retest import current_finding_records
from app.services.knowledge_hub import (
    build_applicability,
    build_evidence_refs,
    default_summary,
    entry_publish_ready,
    entry_snapshot,
    infer_knowledge_type,
    recommendation_score,
    restore_snapshot,
)


router = APIRouter()


@router.get("/projects/{project_id}/workspace", response_model=KnowledgeWorkspace)
def get_knowledge_workspace(project_id: UUID, db: Session = Depends(get_db)) -> KnowledgeWorkspace:
    project = require_project(db, project_id)
    findings = current_finding_records(db, project_id)
    entries = list(db.scalars(
        select(KnowledgeEntryRecord)
        .where(KnowledgeEntryRecord.source_project_id == str(project_id))
        .order_by(KnowledgeEntryRecord.updated_at.desc())
    ).all())
    project_names = project_name_map(db, entries)
    published = list(db.scalars(
        select(KnowledgeEntryRecord)
        .where(
            KnowledgeEntryRecord.tenant_id == project.tenant_id,
            KnowledgeEntryRecord.status == "published",
            KnowledgeEntryRecord.source_project_id != str(project_id),
        )
        .order_by(KnowledgeEntryRecord.published_at.desc())
    ).all())
    project_names.update(project_name_map(db, published))
    recommendations: list[KnowledgeRecommendation] = []
    for entry in published:
        score, reasons, matched_ids = recommendation_score(entry, findings)
        if score == 0:
            continue
        recommendations.append(KnowledgeRecommendation(
            entry=entry_to_schema(entry, project_names.get(entry.source_project_id, "未知项目")),
            score=score,
            reasons=reasons,
            matched_finding_ids=[UUID(item) for item in matched_ids],
        ))
    recommendations.sort(key=lambda item: (-item.score, str(item.entry.title)))
    status_counts: dict[str, int] = {}
    for entry in entries:
        status_counts[entry.status] = status_counts.get(entry.status, 0) + 1
    enterprise_count = int(db.scalar(
        select(func.count()).select_from(KnowledgeEntryRecord).where(
            KnowledgeEntryRecord.tenant_id == project.tenant_id,
            KnowledgeEntryRecord.status == "published",
        )
    ) or 0)
    return KnowledgeWorkspace(
        project_id=project_id,
        project_name=project.name,
        entries=[entry_to_schema(entry, project.name) for entry in entries],
        recommendations=recommendations,
        enterprise_published_count=enterprise_count,
        status_counts=status_counts,
    )


@router.post("/projects/{project_id}/candidates/{finding_id}", response_model=KnowledgeEntry)
def submit_candidate(
    project_id: UUID,
    finding_id: UUID,
    payload: KnowledgeCandidateSubmit,
    db: Session = Depends(get_db),
) -> KnowledgeEntry:
    project = require_project(db, project_id)
    finding = db.get(FindingRecord, str(finding_id))
    if finding is None or finding.project_id != str(project_id):
        raise HTTPException(status_code=404, detail="Finding not found in project")
    validations = list(db.scalars(
        select(DastValidationRecord).where(
            DastValidationRecord.project_id == str(project_id),
            DastValidationRecord.finding_id == str(finding_id),
        )
    ).all())
    validation_ids = [str(item.id) for item in validations]
    evidence_link = SandboxEvidenceRecord.finding_id == str(finding_id)
    if validation_ids:
        evidence_link = evidence_link | SandboxEvidenceRecord.validation_id.in_(validation_ids)
    evidence = list(db.scalars(
        select(SandboxEvidenceRecord).where(
            SandboxEvidenceRecord.project_id == str(project_id),
            evidence_link,
        )
    ).all())
    entry = db.scalar(select(KnowledgeEntryRecord).where(
        KnowledgeEntryRecord.tenant_id == project.tenant_id,
        KnowledgeEntryRecord.source_finding_id == str(finding_id),
    ))
    now = datetime.utcnow()
    if entry is None:
        entry = KnowledgeEntryRecord(
            tenant_id=project.tenant_id,
            source_project_id=str(project_id),
            source_finding_id=str(finding_id),
            knowledge_type=infer_knowledge_type(finding, validations),
            title=finding.title,
            summary=(payload.summary or default_summary(finding)).strip(),
            rule_id=finding.rule_id,
            source_module=finding.source,
            severity=finding.severity,
            category=str((finding.ai_review or {}).get("category") or "uncategorized"),
            status="pending_review",
            applicability=build_applicability(project, finding),
            evidence_refs=build_evidence_refs(finding, validations, evidence),
            tags=[finding.source.lower(), finding.severity, finding.rule_id],
            version=1,
            submitted_by=payload.submitted_by,
            created_at=now,
            updated_at=now,
        )
        db.add(entry)
        db.flush()
        action = "submitted"
    else:
        if entry.status == "published":
            raise HTTPException(status_code=409, detail="Published knowledge must be changed through versioned review")
        entry.knowledge_type = infer_knowledge_type(finding, validations)
        entry.title = finding.title
        entry.summary = (payload.summary or default_summary(finding)).strip()
        entry.rule_id = finding.rule_id
        entry.source_module = finding.source
        entry.severity = finding.severity
        entry.category = str((finding.ai_review or {}).get("category") or "uncategorized")
        entry.status = "pending_review"
        entry.applicability = build_applicability(project, finding)
        entry.evidence_refs = build_evidence_refs(finding, validations, evidence)
        entry.tags = [finding.source.lower(), finding.severity, finding.rule_id]
        entry.submitted_by = payload.submitted_by
        entry.reviewer = None
        entry.review_note = None
        entry.reviewed_at = None
        entry.version += 1
        entry.updated_at = now
        action = "resubmitted"
    record_version(db, entry, action, payload.submitted_by, None)
    record_audit(db, entry, f"knowledge.{action}", payload.submitted_by, {"finding_id": str(finding_id)})
    db.commit()
    db.refresh(entry)
    return entry_to_schema(entry, project.name)


@router.post("/entries/{entry_id}/review", response_model=KnowledgeEntry)
def review_entry(entry_id: UUID, payload: KnowledgeReview, db: Session = Depends(get_db)) -> KnowledgeEntry:
    entry = require_entry(db, entry_id)
    if entry.status != "pending_review":
        raise HTTPException(status_code=409, detail="Only pending knowledge can be reviewed")
    if payload.decision == "publish" and not entry_publish_ready(entry):
        raise HTTPException(status_code=409, detail="Knowledge needs a DAST/SANDBOX or governed remediation conclusion before publication")
    now = datetime.utcnow()
    entry.status = "published" if payload.decision == "publish" else "rejected"
    entry.reviewer = payload.reviewer
    entry.review_note = payload.note
    entry.reviewed_at = now
    entry.published_at = now if payload.decision == "publish" else None
    entry.version += 1
    entry.updated_at = now
    action = "published" if payload.decision == "publish" else "rejected"
    record_version(db, entry, action, payload.reviewer, payload.note)
    record_audit(db, entry, f"knowledge.{action}", payload.reviewer, {"note": payload.note})
    db.commit()
    db.refresh(entry)
    project = db.get(ProjectRecord, entry.source_project_id)
    return entry_to_schema(entry, project.name if project else "未知项目")


@router.get("/entries/{entry_id}/versions", response_model=list[KnowledgeEntryVersion])
def list_versions(entry_id: UUID, db: Session = Depends(get_db)) -> list[KnowledgeEntryVersion]:
    require_entry(db, entry_id)
    records = db.scalars(
        select(KnowledgeEntryVersionRecord)
        .where(KnowledgeEntryVersionRecord.entry_id == str(entry_id))
        .order_by(KnowledgeEntryVersionRecord.version.desc())
    ).all()
    return [KnowledgeEntryVersion(
        entry_id=UUID(record.entry_id),
        version=record.version,
        snapshot=record.snapshot,
        change_action=record.change_action,
        changed_by=record.changed_by,
        change_note=record.change_note,
        created_at=record.created_at,
    ) for record in records]


@router.post("/entries/{entry_id}/rollback", response_model=KnowledgeEntry)
def rollback_entry(entry_id: UUID, payload: KnowledgeRollback, db: Session = Depends(get_db)) -> KnowledgeEntry:
    entry = require_entry(db, entry_id)
    target = db.scalar(select(KnowledgeEntryVersionRecord).where(
        KnowledgeEntryVersionRecord.entry_id == str(entry_id),
        KnowledgeEntryVersionRecord.version == payload.target_version,
    ))
    if target is None:
        raise HTTPException(status_code=404, detail="Knowledge version not found")
    previous_version = entry.version
    restore_snapshot(entry, target.snapshot)
    entry.version = previous_version + 1
    entry.updated_at = datetime.utcnow()
    if entry.status == "published":
        entry.published_at = datetime.utcnow()
    record_version(db, entry, "rolled_back", payload.reviewer, payload.note)
    record_audit(db, entry, "knowledge.rolled_back", payload.reviewer, {
        "target_version": payload.target_version,
        "new_version": entry.version,
        "note": payload.note,
    })
    db.commit()
    db.refresh(entry)
    project = db.get(ProjectRecord, entry.source_project_id)
    return entry_to_schema(entry, project.name if project else "未知项目")


def require_project(db: Session, project_id: UUID) -> ProjectRecord:
    project = db.get(ProjectRecord, str(project_id))
    if project is None:
        raise HTTPException(status_code=404, detail="Project not found")
    return project


def require_entry(db: Session, entry_id: UUID) -> KnowledgeEntryRecord:
    entry = db.get(KnowledgeEntryRecord, str(entry_id))
    if entry is None:
        raise HTTPException(status_code=404, detail="Knowledge entry not found")
    return entry


def project_name_map(db: Session, entries: list[KnowledgeEntryRecord]) -> dict[str, str]:
    ids = {entry.source_project_id for entry in entries}
    if not ids:
        return {}
    return {record.id: record.name for record in db.scalars(select(ProjectRecord).where(ProjectRecord.id.in_(ids))).all()}


def entry_to_schema(entry: KnowledgeEntryRecord, project_name: str) -> KnowledgeEntry:
    return KnowledgeEntry(
        id=UUID(entry.id),
        tenant_id=UUID(entry.tenant_id),
        source_project_id=UUID(entry.source_project_id),
        source_project_name=project_name,
        source_finding_id=UUID(entry.source_finding_id),
        knowledge_type=entry.knowledge_type,
        title=entry.title,
        summary=entry.summary,
        rule_id=entry.rule_id,
        source_module=entry.source_module,
        severity=entry.severity,
        category=entry.category,
        status=entry.status,
        applicability=entry.applicability or {},
        evidence_refs=entry.evidence_refs or [],
        tags=entry.tags or [],
        version=entry.version,
        submitted_by=entry.submitted_by,
        reviewer=entry.reviewer,
        review_note=entry.review_note,
        reviewed_at=entry.reviewed_at,
        published_at=entry.published_at,
        publish_ready=entry_publish_ready(entry),
        created_at=entry.created_at,
        updated_at=entry.updated_at,
    )


def record_version(
    db: Session,
    entry: KnowledgeEntryRecord,
    action: str,
    actor: str,
    note: str | None,
) -> None:
    db.add(KnowledgeEntryVersionRecord(
        entry_id=entry.id,
        version=entry.version,
        snapshot=entry_snapshot(entry),
        change_action=action,
        changed_by=actor,
        change_note=note,
    ))


def record_audit(
    db: Session,
    entry: KnowledgeEntryRecord,
    action: str,
    actor: str,
    detail: dict[str, object],
) -> None:
    db.add(AuditRecord(
        tenant_id=entry.tenant_id,
        project_id=entry.source_project_id,
        action=action,
        outcome="success",
        detail={"entry_id": entry.id, "actor": actor, **detail},
    ))
