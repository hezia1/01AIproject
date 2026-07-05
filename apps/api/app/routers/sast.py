from datetime import datetime
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from app.db import get_db
from app.db_models import FindingRecord, ProjectModuleRecord, ProjectRecord, ScanTaskRecord
from app.models import Finding, ModuleKey, SastScanRequest, SastScanResult, ScanStatus
from app.repositories.mappers import finding_to_schema
from app.services.sast_agent_orchestrator import run_sast_agent_pipeline
from app.services.sast_scanner import SastScanOutput, dedupe_findings, scan_source_tree
from app.services.semgrep_scanner import SemgrepUnavailable, scan_with_semgrep

router = APIRouter()


@router.post("/scan", response_model=SastScanResult)
def run_sast_scan(payload: SastScanRequest, db: Session = Depends(get_db)) -> SastScanResult:
    if db.get(ProjectRecord, str(payload.project_id)) is None:
        raise HTTPException(status_code=404, detail="Project not found")

    project_module = db.scalar(
        select(ProjectModuleRecord).where(
            ProjectModuleRecord.project_id == str(payload.project_id),
            ProjectModuleRecord.module_key == ModuleKey.sast.value,
            ProjectModuleRecord.enabled.is_(True),
        )
    )
    if project_module is None:
        raise HTTPException(status_code=400, detail="SAST module is not enabled for this project")

    scan = ScanTaskRecord(
        project_id=str(payload.project_id),
        scan_type="sast",
        status=ScanStatus.running.value,
        started_at=datetime.utcnow(),
    )
    db.add(scan)
    db.flush()

    try:
        parsed = run_sast_engines(payload)
        if payload.clear_previous:
            db.execute(
                delete(FindingRecord).where(
                    FindingRecord.project_id == str(payload.project_id),
                    FindingRecord.source == "SAST",
                )
            )

        records: list[FindingRecord] = []
        for finding in parsed.findings:
            record = FindingRecord(
                project_id=str(payload.project_id),
                scan_task_id=scan.id,
                source="SAST",
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
                    "cwe": finding.cwe,
                    "owasp": finding.owasp,
                    "language": finding.language,
                    "description": finding.description,
                },
            )
            record.ai_review = run_sast_agent_pipeline(record)
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

    return SastScanResult(
        project_id=payload.project_id,
        scan_task_id=UUID(str(scan.id)),
        source_path=payload.source_path,
        scanned_files=parsed.scanned_files,
        finding_count=len(records),
        findings=[finding_to_schema(record) for record in records],
    )


@router.get("/projects/{project_id}/findings", response_model=list[Finding])
def list_project_sast_findings(project_id: UUID, db: Session = Depends(get_db)) -> list[Finding]:
    if db.get(ProjectRecord, str(project_id)) is None:
        raise HTTPException(status_code=404, detail="Project not found")

    records = db.scalars(
        select(FindingRecord)
        .where(FindingRecord.project_id == str(project_id), FindingRecord.source == "SAST")
        .order_by(FindingRecord.created_at.desc())
    ).all()
    return [finding_to_schema(record) for record in records]


@router.post("/projects/{project_id}/agent-review", response_model=list[Finding])
def run_project_agent_review(project_id: UUID, db: Session = Depends(get_db)) -> list[Finding]:
    if db.get(ProjectRecord, str(project_id)) is None:
        raise HTTPException(status_code=404, detail="Project not found")

    records = db.scalars(
        select(FindingRecord)
        .where(FindingRecord.project_id == str(project_id), FindingRecord.source == "SAST")
        .order_by(FindingRecord.created_at.desc())
    ).all()
    for record in records:
        record.ai_review = run_sast_agent_pipeline(record)
        record.updated_at = datetime.utcnow()
    db.commit()
    for record in records:
        db.refresh(record)
    return [finding_to_schema(record) for record in records]


def run_sast_engines(payload: SastScanRequest) -> SastScanOutput:
    outputs: list[SastScanOutput] = []
    try:
        outputs.append(scan_with_semgrep(payload.source_path, payload.semgrep_config))
    except SemgrepUnavailable:
        pass

    if payload.include_local_rules or not outputs:
        outputs.append(scan_source_tree(payload.source_path))

    return SastScanOutput(
        findings=dedupe_findings([finding for output in outputs for finding in output.findings]),
        scanned_files=sorted({file_path for output in outputs for file_path in output.scanned_files}),
    )

