from datetime import datetime
from pathlib import Path
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db import get_db
from app.db_models import FindingRecord, ProjectModuleRecord, ProjectRecord, ScanTaskRecord
from app.models import (
    AgentAssetResult,
    AgentScanCoverage,
    AgentScanHistoryItem,
    AgentScanRequest,
    AgentScanResult,
    Finding,
    ModuleKey,
    ScanStatus,
)
from app.repositories.mappers import finding_to_schema
from app.services.agent_scanner import AgentAsset, scan_agent_tree

router = APIRouter()


@router.post("/scan", response_model=AgentScanResult)
def run_agent_scan(payload: AgentScanRequest, db: Session = Depends(get_db)) -> AgentScanResult:
    project = db.get(ProjectRecord, str(payload.project_id))
    if project is None:
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

    source_path = validate_agent_source_path(project, payload.source_path)
    scan = ScanTaskRecord(
        project_id=str(payload.project_id),
        scan_type="agent",
        status=ScanStatus.running.value,
        started_at=datetime.utcnow(),
        scan_metadata={"progress": 10, "stage": "discovering-agent-assets", "source_path": source_path},
    )
    db.add(scan)
    db.flush()

    try:
        parsed = scan_agent_tree(source_path)
        coverage = build_agent_coverage(parsed.assets, len(parsed.skipped_files))
        if payload.clear_previous:
            supersede_active_agent_findings(db, str(payload.project_id), str(scan.id))

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
                    "false_positive_likelihood": "not_reviewed",
                    "remediation": finding.remediation,
                    "category": finding.category,
                    "description": finding.description,
                    "trust_impact": finding.trust_impact,
                    "review_status": "not_reviewed",
                    "analysis_source": "local_rule",
                },
            )
            db.add(record)
            records.append(record)

        scan.status = ScanStatus.completed.value
        scan.finished_at = datetime.utcnow()
        scan.scan_metadata = {
            "progress": 100,
            "stage": "completed",
            "source_path": source_path,
            "rule_version": parsed.rule_version,
            "finding_count": len(records),
            "assets": [asset_to_dict(asset) for asset in parsed.assets],
            "coverage": coverage.model_dump(),
            "skipped_files": parsed.skipped_files,
        }
        db.commit()
        for record in records:
            db.refresh(record)
        db.refresh(scan)
    except ValueError as exc:
        mark_agent_scan_failed(scan, str(exc))
        db.commit()
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        mark_agent_scan_failed(scan, "Agent scan failed")
        db.commit()
        raise exc

    return AgentScanResult(
        project_id=payload.project_id,
        scan_task_id=UUID(str(scan.id)),
        source_path=source_path,
        scanned_files=parsed.scanned_files,
        finding_count=len(records),
        findings=[finding_to_schema(record) for record in records],
        assets=[AgentAssetResult(**asset_to_dict(asset)) for asset in parsed.assets],
        coverage=coverage,
        rule_version=parsed.rule_version,
    )


@router.get("/projects/{project_id}/findings", response_model=list[Finding])
def list_project_agent_findings(project_id: UUID, db: Session = Depends(get_db)) -> list[Finding]:
    if db.get(ProjectRecord, str(project_id)) is None:
        raise HTTPException(status_code=404, detail="Project not found")

    latest_scan = latest_completed_agent_scan(db, str(project_id))
    if latest_scan is None:
        return []
    records = db.scalars(
        select(FindingRecord)
        .where(
            FindingRecord.project_id == str(project_id),
            FindingRecord.source == "AGENT",
            FindingRecord.scan_task_id == latest_scan.id,
        )
        .order_by(FindingRecord.created_at.desc())
    ).all()
    return [finding_to_schema(record) for record in records]


@router.get("/projects/{project_id}/scan-history", response_model=list[AgentScanHistoryItem])
def list_project_agent_scan_history(project_id: UUID, db: Session = Depends(get_db)) -> list[AgentScanHistoryItem]:
    if db.get(ProjectRecord, str(project_id)) is None:
        raise HTTPException(status_code=404, detail="Project not found")
    scans = db.scalars(
        select(ScanTaskRecord)
        .where(ScanTaskRecord.project_id == str(project_id), ScanTaskRecord.scan_type == "agent")
        .order_by(ScanTaskRecord.created_at.desc())
        .limit(30)
    ).all()
    return [agent_scan_history_item(scan) for scan in scans]


def validate_agent_source_path(project: ProjectRecord, requested_path: str) -> str:
    if not project.source_path:
        raise HTTPException(status_code=400, detail="Project source path is not configured")
    project_root = Path(project.source_path).expanduser().resolve()
    requested = Path(requested_path).expanduser().resolve()
    if not project_root.exists() or not project_root.is_dir():
        raise HTTPException(status_code=400, detail="Configured project source path does not exist")
    if not requested.exists() or not requested.is_dir():
        raise HTTPException(status_code=400, detail="Requested AGENT source path does not exist")
    if requested != project_root and project_root not in requested.parents:
        raise HTTPException(status_code=400, detail="Requested AGENT source path must stay within the project source path")
    return str(requested)


def supersede_active_agent_findings(db: Session, project_id: str, new_scan_id: str) -> None:
    records = db.scalars(
        select(FindingRecord).where(
            FindingRecord.project_id == project_id,
            FindingRecord.source == "AGENT",
            FindingRecord.status.in_(["open", "pending", "confirmed"]),
        )
    ).all()
    for record in records:
        review = dict(record.ai_review or {})
        review["scan_lifecycle"] = "superseded"
        review["superseded_by_scan"] = new_scan_id
        record.status = "closed"
        record.ai_review = review
        record.updated_at = datetime.utcnow()


def latest_completed_agent_scan(db: Session, project_id: str) -> ScanTaskRecord | None:
    return db.scalar(
        select(ScanTaskRecord)
        .where(
            ScanTaskRecord.project_id == project_id,
            ScanTaskRecord.scan_type == "agent",
            ScanTaskRecord.status == ScanStatus.completed.value,
        )
        .order_by(ScanTaskRecord.created_at.desc())
        .limit(1)
    )


def build_agent_coverage(assets: list[AgentAsset], skipped_file_count: int = 0) -> AgentScanCoverage:
    asset_types: dict[str, int] = {}
    findings_by_asset_type: dict[str, int] = {}
    for asset in assets:
        asset_types[asset.asset_type] = asset_types.get(asset.asset_type, 0) + 1
        findings_by_asset_type[asset.asset_type] = findings_by_asset_type.get(asset.asset_type, 0) + asset.finding_count
    return AgentScanCoverage(
        discovered_asset_count=len(assets),
        parsed_asset_count=sum(asset.status == "parsed" for asset in assets),
        failed_asset_count=sum(asset.status == "failed" for asset in assets),
        skipped_file_count=skipped_file_count,
        findings_by_asset_type=findings_by_asset_type,
        asset_types=asset_types,
    )


def asset_to_dict(asset: AgentAsset) -> dict[str, object]:
    return {
        "path": asset.path,
        "asset_type": asset.asset_type,
        "format": asset.format,
        "parser": asset.parser,
        "status": asset.status,
        "checks": asset.checks,
        "finding_count": asset.finding_count,
        "detail": asset.detail,
    }


def agent_scan_history_item(scan: ScanTaskRecord) -> AgentScanHistoryItem:
    metadata = scan.scan_metadata or {}
    coverage = metadata.get("coverage") if isinstance(metadata.get("coverage"), dict) else {}
    return AgentScanHistoryItem(
        scan_task_id=UUID(str(scan.id)),
        status=scan.status,
        created_at=scan.created_at,
        started_at=scan.started_at,
        finished_at=scan.finished_at,
        source_path=metadata.get("source_path"),
        finding_count=int(metadata.get("finding_count") or 0),
        rule_version=metadata.get("rule_version"),
        coverage=AgentScanCoverage(**coverage),
    )


def mark_agent_scan_failed(scan: ScanTaskRecord, detail: str) -> None:
    metadata = dict(scan.scan_metadata or {})
    metadata.update({"stage": "failed", "detail": detail})
    scan.scan_metadata = metadata
    scan.status = ScanStatus.failed.value
    scan.finished_at = datetime.utcnow()
