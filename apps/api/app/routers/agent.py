from datetime import datetime
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from app.db import get_db
from app.db_models import FindingRecord, ProjectModuleRecord, ProjectRecord, ScanTaskRecord
from app.models import AgentScanRequest, AgentScanResult, Finding, ModuleKey, ScanStatus
from app.repositories.mappers import finding_to_schema
from app.services.agent_scanner import scan_agent_tree

router = APIRouter()


@router.post("/scan", response_model=AgentScanResult)
def run_agent_scan(payload: AgentScanRequest, db: Session = Depends(get_db)) -> AgentScanResult:
    if db.get(ProjectRecord, str(payload.project_id)) is None:
        raise HTTPException(status_code=404, detail="Project not found")

    project_module = db.scalar(
        select(ProjectModuleRecord).where(
            ProjectModuleRecord.project_id == str(payload.project_id),
            ProjectModuleRecord.module_key == ModuleKey.agent.value,
            ProjectModuleRecord.enabled.is_(True),
        )
    )
    if project_module is None:
        raise HTTPException(status_code=400, detail="AGENT module is not enabled for this project")

    scan = ScanTaskRecord(
        project_id=str(payload.project_id),
        scan_type="agent",
        status=ScanStatus.running.value,
        started_at=datetime.utcnow(),
    )
    db.add(scan)
    db.flush()

    try:
        parsed = scan_agent_tree(payload.source_path)
        if payload.clear_previous:
            db.execute(
                delete(FindingRecord).where(
                    FindingRecord.project_id == str(payload.project_id),
                    FindingRecord.source == "AGENT",
                )
            )

        records: list[FindingRecord] = []
        for finding in parsed.findings:
            record = FindingRecord(
                project_id=str(payload.project_id),
                scan_task_id=scan.id,
                source="AGENT",
                rule_id=finding.rule_id,
                title=finding.title,
                severity=finding.severity.value,
                file_path=finding.file_path,
                line_start=finding.line_start,
                line_end=finding.line_end,
                evidence=finding.evidence,
                ai_review={
                    "summary": finding.description,
                    "false_positive_likelihood": "medium",
                    "remediation": finding.remediation,
                    "category": finding.category,
                    "description": finding.description,
                    "trust_impact": finding.trust_impact,
                },
            )
            db.add(record)
            records.append(record)

        scan.status = ScanStatus.completed.value
        scan.finished_at = datetime.utcnow()
        db.commit()
        for record in records:
            db.refresh(record)
        db.refresh(scan)
    except ValueError as exc:
        scan.status = ScanStatus.failed.value
        scan.finished_at = datetime.utcnow()
        db.commit()
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception:
        scan.status = ScanStatus.failed.value
        scan.finished_at = datetime.utcnow()
        db.commit()
        raise

    return AgentScanResult(
        project_id=payload.project_id,
        scan_task_id=UUID(str(scan.id)),
        source_path=payload.source_path,
        scanned_files=parsed.scanned_files,
        finding_count=len(records),
        findings=[finding_to_schema(record) for record in records],
    )


@router.get("/projects/{project_id}/findings", response_model=list[Finding])
def list_project_agent_findings(project_id: UUID, db: Session = Depends(get_db)) -> list[Finding]:
    if db.get(ProjectRecord, str(project_id)) is None:
        raise HTTPException(status_code=404, detail="Project not found")

    records = db.scalars(
        select(FindingRecord)
        .where(FindingRecord.project_id == str(project_id), FindingRecord.source == "AGENT")
        .order_by(FindingRecord.created_at.desc())
    ).all()
    return [finding_to_schema(record) for record in records]
