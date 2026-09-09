from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import ValidationError
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db_models import (FindingRecord, ProjectRecord, ScanTaskRecord, SecuritySkillRecord,
                           SecuritySkillRunRecord, SecuritySkillVersionRecord)
from app.security_skill_models import SecuritySkillManifest
from app.services.audit import record_audit
from app.services.finding_retest import current_finding_records


def execute_manifest(manifest: SecuritySkillManifest, findings: list[FindingRecord]) -> dict[str, Any]:
    selectors = manifest.selectors
    rule_ids = {value.casefold() for value in selectors.rule_ids}
    categories = {value.casefold() for value in selectors.categories}
    statuses = {value.casefold() for value in selectors.statuses}
    selected: list[FindingRecord] = []
    selector_matches = 0
    evidence_excluded = 0
    for finding in findings:
        category = str((finding.ai_review or {}).get("category", ""))
        checks = (
            not selectors.sources or finding.source.upper() in selectors.sources,
            not rule_ids or finding.rule_id.casefold() in rule_ids,
            not categories or category.casefold() in categories,
            not selectors.severities or finding.severity.lower() in selectors.severities,
            not statuses or finding.status.casefold() in statuses,
        )
        if not all(checks):
            continue
        selector_matches += 1
        evidence = {
            "finding_location": bool(finding.file_path and finding.line_start is not None),
            "finding_evidence": bool(finding.evidence),
            "ai_review": bool(finding.ai_review),
        }
        if not all(evidence[item] for item in manifest.evidence_required):
            evidence_excluded += 1
            continue
        selected.append(finding)

    return {
        "action": manifest.action,
        "current_finding_count": len(findings),
        "selector_match_count": selector_matches,
        "matched_count": len(selected),
        "evidence_excluded_count": evidence_excluded,
        "matched_findings": [{
            "id": str(item.id), "title": item.title, "source": item.source,
            "rule_id": item.rule_id, "severity": item.severity, "status": item.status,
            "file_path": item.file_path, "line_start": item.line_start,
            "evidence_refs": {
                "finding_location": bool(item.file_path and item.line_start is not None),
                "finding_evidence": bool(item.evidence), "ai_review": bool(item.ai_review),
            },
        } for item in selected],
        "limitations": [
            "仅复核项目最新已完成扫描所对应的现有 Finding，不会重新运行 SCA、SAST 或 AGENT。",
            "执行完成只表示筛选流程完成；零命中不代表项目无漏洞，命中也不等于动态复现成功。",
            "Skill 为声明式清单，不执行用户上传的 Python、Shell 或其他任意代码。",
        ],
    }


def executes_after_scan(skill: SecuritySkillRecord, scan_type: str) -> bool:
    return skill.status == "published" and scan_type in list(skill.auto_trigger_scan_types or [])


def execute_automatic_skills_for_scan(
    db: Session,
    scan: ScanTaskRecord,
    *,
    actor: str,
    user_id: str | None = None,
) -> dict[str, Any]:
    """Run tenant-wide published Skills once after a completed static scan."""
    if user_id == "00000000-0000-0000-0000-000000000000":
        user_id = None
    scan_type = str(scan.scan_type).lower()
    if scan_type not in {"sca", "sast", "agent"} or scan.status != "completed":
        return {"status": "not_applicable", "executed_count": 0, "failed_count": 0, "run_ids": []}
    project = db.get(ProjectRecord, str(scan.project_id))
    if project is None:
        return {"status": "failed", "detail": "Project not found for automatic Skill execution",
                "executed_count": 0, "failed_count": 0, "run_ids": []}
    skills = [item for item in db.scalars(select(SecuritySkillRecord).where(
        SecuritySkillRecord.tenant_id == project.tenant_id,
        SecuritySkillRecord.status == "published",
    )).all() if executes_after_scan(item, scan_type)]
    findings = current_finding_records(db, UUID(str(scan.project_id)))
    run_ids: list[str] = []
    failed_count = 0
    errors: list[dict[str, str]] = []
    for skill in skills:
        existing = db.scalar(select(SecuritySkillRunRecord.id).where(
            SecuritySkillRunRecord.skill_id == skill.id,
            SecuritySkillRunRecord.trigger_scan_task_id == scan.id,
        ))
        if existing:
            continue
        version = db.scalar(select(SecuritySkillVersionRecord).where(
            SecuritySkillVersionRecord.skill_id == skill.id,
            SecuritySkillVersionRecord.version == skill.active_version,
            SecuritySkillVersionRecord.status == "published",
        ))
        if version is None:
            failed_count += 1
            errors.append({"skill_id": str(skill.id), "detail": "Published Skill version is unavailable"})
            continue
        try:
            summary = execute_manifest(SecuritySkillManifest.model_validate(version.manifest), findings)
            status = "completed"
        except (ValidationError, ValueError) as exc:
            failed_count += 1
            status = "failed"
            summary = {
                "action": "review_existing_findings", "current_finding_count": len(findings),
                "matched_count": 0, "error": str(exc)[:1000],
                "limitations": ["Skill 清单无效或已发布版本不可用；本次自动复核失败，原扫描结果不受影响。"],
            }
        now = datetime.utcnow()
        run = SecuritySkillRunRecord(
            skill_id=skill.id, skill_version_id=version.id,
            project_id=str(scan.project_id), status=status, trigger="scan_completed",
            trigger_scan_task_id=str(scan.id),
            matched_finding_ids=[item["id"] for item in summary.get("matched_findings", [])],
            result_summary=summary, requested_by=actor, started_at=now, finished_at=now,
        )
        db.add(run)
        db.flush()
        run_ids.append(str(run.id))
        record_audit(db, tenant_id=str(project.tenant_id), user_id=user_id,
            project_id=str(project.id), action="security_skill.auto_executed", outcome=status,
            detail={"skill_id": str(skill.id), "version": version.version,
                    "scan_task_id": str(scan.id), "scan_type": scan_type,
                    "matched_count": summary.get("matched_count", 0)})
    result = {"status": "completed" if failed_count == 0 else "partial",
              "eligible_count": len(skills), "executed_count": len(run_ids),
              "failed_count": failed_count, "run_ids": run_ids, "errors": errors}
    scan.scan_metadata = {**dict(scan.scan_metadata or {}), "security_skill_automation": result}
    db.commit()
    return result


def trigger_automatic_skills_safely(
    db: Session, scan: ScanTaskRecord, *, actor: str, user_id: str | None = None,
) -> dict[str, Any]:
    """Keep enrichment failure separate from the already committed scanner result."""
    scan_id = str(scan.id)
    try:
        return execute_automatic_skills_for_scan(db, scan, actor=actor, user_id=user_id)
    except Exception as exc:
        db.rollback()
        result = {"status": "failed", "executed_count": 0, "failed_count": 0,
                  "run_ids": [], "detail": str(exc)[:1000]}
        try:
            persisted = db.get(ScanTaskRecord, scan_id)
            if persisted is not None:
                persisted.scan_metadata = {
                    **dict(persisted.scan_metadata or {}), "security_skill_automation": result,
                }
                db.commit()
        except Exception:
            db.rollback()
        return result
