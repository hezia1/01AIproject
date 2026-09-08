from datetime import datetime
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.db import get_db
from app.db_models import (ProjectRecord, SecuritySkillRecord, SecuritySkillRunRecord,
                           SecuritySkillVersionRecord)
from app.security_skill_models import (SecuritySkill, SecuritySkillCreate, SecuritySkillRun,
                                       SecuritySkillVersionCreate)
from app.services.audit import record_audit
from app.services.auth import current_identity, require_admin
from app.services.finding_retest import current_finding_records
from app.services.security_skill_registry import execute_manifest

router = APIRouter()


def audit_user_id(identity) -> str | None:
    """AUTH_DISABLED uses a non-persisted sentinel identity; never violate the audit FK."""
    return None if identity.user_id == "00000000-0000-0000-0000-000000000000" else identity.user_id


def skill_response(db: Session, skill: SecuritySkillRecord, include_unpublished: bool = True) -> SecuritySkill:
    version_query = select(SecuritySkillVersionRecord).where(SecuritySkillVersionRecord.skill_id == skill.id)
    if not include_unpublished:
        version_query = version_query.where(SecuritySkillVersionRecord.status == "published")
    versions = list(db.scalars(version_query.order_by(SecuritySkillVersionRecord.version.desc())).all())
    return SecuritySkill(**{column: getattr(skill, column) for column in (
        "id", "slug", "name", "description", "module", "status", "active_version",
        "created_by", "created_at", "updated_at")}, versions=versions)


def accessible_project(db: Session, project_id: UUID, tenant_id: str) -> ProjectRecord:
    project = db.get(ProjectRecord, str(project_id))
    if project is None or str(project.tenant_id) != tenant_id:
        raise HTTPException(404, "Project not found")
    return project


def accessible_skill(db: Session, skill_id: UUID, tenant_id: str) -> SecuritySkillRecord:
    skill = db.get(SecuritySkillRecord, str(skill_id))
    if skill is None or str(skill.tenant_id) != tenant_id:
        raise HTTPException(404, "Security Skill not found")
    return skill


@router.get("", response_model=list[SecuritySkill])
def list_skills(request: Request, include_drafts: bool = Query(False), db: Session = Depends(get_db)):
    identity = current_identity(request)
    if include_drafts and not identity.is_admin:
        raise HTTPException(403, "Administrator permission required")
    query = select(SecuritySkillRecord).where(SecuritySkillRecord.tenant_id == identity.tenant_id)
    if not include_drafts:
        query = query.where(SecuritySkillRecord.status == "published")
    skills = list(db.scalars(query.order_by(SecuritySkillRecord.updated_at.desc())).all())
    return [skill_response(db, item, include_unpublished=identity.is_admin and include_drafts) for item in skills]


@router.post("", response_model=SecuritySkill, status_code=201)
def create_skill(payload: SecuritySkillCreate, request: Request, db: Session = Depends(get_db)):
    identity = require_admin(request)
    if db.scalar(select(SecuritySkillRecord.id).where(
            SecuritySkillRecord.tenant_id == identity.tenant_id,
            SecuritySkillRecord.slug == payload.slug)):
        raise HTTPException(409, "Skill slug already exists in this tenant")
    now = datetime.utcnow()
    skill = SecuritySkillRecord(tenant_id=identity.tenant_id, slug=payload.slug, name=payload.name,
        description=payload.description, module=payload.module, status="draft", created_by=identity.username,
        created_at=now, updated_at=now)
    db.add(skill)
    db.flush()
    db.add(SecuritySkillVersionRecord(skill_id=skill.id, version=1,
        manifest=payload.manifest.model_dump(mode="json"), status="draft", change_note=payload.change_note,
        created_by=identity.username, created_at=now))
    record_audit(db, tenant_id=identity.tenant_id, user_id=audit_user_id(identity),
        action="security_skill.created", outcome="completed", detail={"skill_id": str(skill.id), "version": 1})
    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(409, "Skill could not be saved because a concurrent database constraint changed") from exc
    return skill_response(db, skill)


@router.post("/{skill_id}/versions", response_model=SecuritySkill, status_code=201)
def create_version(skill_id: UUID, payload: SecuritySkillVersionCreate, request: Request,
                   db: Session = Depends(get_db)):
    identity = require_admin(request)
    skill = accessible_skill(db, skill_id, identity.tenant_id)
    next_version = int(db.scalar(select(func.coalesce(func.max(SecuritySkillVersionRecord.version), 0)).where(
        SecuritySkillVersionRecord.skill_id == skill.id)) or 0) + 1
    db.add(SecuritySkillVersionRecord(skill_id=skill.id, version=next_version,
        manifest=payload.manifest.model_dump(mode="json"), status="draft", change_note=payload.change_note,
        created_by=identity.username))
    skill.updated_at = datetime.utcnow()
    record_audit(db, tenant_id=identity.tenant_id, user_id=audit_user_id(identity),
        action="security_skill.version_created", outcome="completed",
        detail={"skill_id": str(skill.id), "version": next_version})
    db.commit()
    return skill_response(db, skill)


@router.post("/{skill_id}/versions/{version}/publish", response_model=SecuritySkill)
def publish_version(skill_id: UUID, version: int, request: Request, db: Session = Depends(get_db)):
    identity = require_admin(request)
    skill = accessible_skill(db, skill_id, identity.tenant_id)
    target = db.scalar(select(SecuritySkillVersionRecord).where(
        SecuritySkillVersionRecord.skill_id == skill.id, SecuritySkillVersionRecord.version == version))
    if target is None:
        raise HTTPException(404, "Skill version not found")
    now = datetime.utcnow()
    for item in db.scalars(select(SecuritySkillVersionRecord).where(
            SecuritySkillVersionRecord.skill_id == skill.id)).all():
        if item.status == "published":
            item.status = "superseded"
    target.status = "published"
    target.published_at = now
    skill.status, skill.active_version, skill.updated_at = "published", version, now
    record_audit(db, tenant_id=identity.tenant_id, user_id=audit_user_id(identity),
        action="security_skill.published", outcome="completed",
        detail={"skill_id": str(skill.id), "version": version})
    db.commit()
    return skill_response(db, skill)


@router.post("/{skill_id}/projects/{project_id}/run", response_model=SecuritySkillRun)
def run_skill(skill_id: UUID, project_id: UUID, request: Request, db: Session = Depends(get_db)):
    identity = current_identity(request)
    skill = accessible_skill(db, skill_id, identity.tenant_id)
    accessible_project(db, project_id, identity.tenant_id)
    if skill.status != "published" or skill.active_version is None:
        raise HTTPException(409, "Only a published Skill version can be executed")
    version = db.scalar(select(SecuritySkillVersionRecord).where(
        SecuritySkillVersionRecord.skill_id == skill.id,
        SecuritySkillVersionRecord.version == skill.active_version,
        SecuritySkillVersionRecord.status == "published"))
    if version is None:
        raise HTTPException(409, "Published Skill version is unavailable")
    findings = current_finding_records(db, project_id)
    from app.security_skill_models import SecuritySkillManifest
    summary = execute_manifest(SecuritySkillManifest.model_validate(version.manifest), findings)
    now = datetime.utcnow()
    run = SecuritySkillRunRecord(skill_id=skill.id, skill_version_id=version.id, project_id=str(project_id),
        status="completed", matched_finding_ids=[item["id"] for item in summary["matched_findings"]],
        result_summary=summary, requested_by=identity.username, started_at=now, finished_at=now)
    db.add(run)
    record_audit(db, tenant_id=identity.tenant_id, user_id=audit_user_id(identity), project_id=str(project_id),
        action="security_skill.executed", outcome="completed",
        detail={"skill_id": str(skill.id), "version": version.version,
                "matched_count": summary["matched_count"], "current_finding_count": summary["current_finding_count"]})
    db.commit()
    return run_response(run, version.version)


@router.get("/projects/{project_id}/runs", response_model=list[SecuritySkillRun])
def list_runs(project_id: UUID, request: Request, db: Session = Depends(get_db)):
    identity = current_identity(request)
    accessible_project(db, project_id, identity.tenant_id)
    rows = db.execute(select(SecuritySkillRunRecord, SecuritySkillVersionRecord.version).join(
        SecuritySkillVersionRecord, SecuritySkillVersionRecord.id == SecuritySkillRunRecord.skill_version_id
    ).where(SecuritySkillRunRecord.project_id == str(project_id)).order_by(
        SecuritySkillRunRecord.started_at.desc()).limit(100)).all()
    return [run_response(run, version) for run, version in rows]


def run_response(run: SecuritySkillRunRecord, version: int) -> SecuritySkillRun:
    return SecuritySkillRun(id=run.id, skill_id=run.skill_id, skill_version=version,
        project_id=run.project_id, status=run.status, matched_finding_ids=run.matched_finding_ids,
        result_summary=run.result_summary, requested_by=run.requested_by,
        started_at=run.started_at, finished_at=run.finished_at)
