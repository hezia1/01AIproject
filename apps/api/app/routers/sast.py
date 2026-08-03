from datetime import datetime
from pathlib import Path
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import JSONResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db import get_db
from app.db_models import FindingRecord, ProjectModuleRecord, ProjectRecord, ScanTaskRecord
from app.models import Finding, ModuleKey, SastScanRequest, SastScanResult, ScanStatus
from app.repositories.mappers import finding_to_schema
from app.services.sast_agent_orchestrator import run_sast_agent_pipeline
from app.services.sast_governance import (
    add_suppression,
    apply_suppressions,
    effective_sast_profile,
    update_sast_profile,
    update_suppression,
)
from app.services.sast_sarif import build_sast_sarif
from app.services.sast_scanner import SastScanOutput, dedupe_findings, sast_tool_health, scan_source_tree
from app.services.semgrep_scanner import SemgrepUnavailable, scan_with_semgrep

router = APIRouter()


@router.post("/scan", response_model=SastScanResult)
def run_sast_scan(payload: SastScanRequest, db: Session = Depends(get_db)) -> SastScanResult:
    project = ensure_project(db, payload.project_id)
    project_module = enabled_sast_module(db, payload.project_id)
    source_path = validate_sast_source_path(project, payload.source_path)
    profile = resolved_scan_profile(project_module.config, payload)
    clear_previous = payload.clear_previous if "clear_previous" in payload.model_fields_set else bool(profile["clear_previous"])

    scan = ScanTaskRecord(
        project_id=str(payload.project_id),
        scan_type="sast",
        status=ScanStatus.running.value,
        started_at=datetime.utcnow(),
    )
    db.add(scan)
    db.flush()

    try:
        parsed = run_sast_engines(source_path, profile)
        findings, suppressed = apply_suppressions(parsed.findings, profile.get("suppressions"))
        if clear_previous:
            supersede_active_sast_findings(db, str(payload.project_id), str(scan.id))

        records: list[FindingRecord] = []
        for finding in findings:
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
        scan.scan_metadata = {
            "sast_profile": profile,
            "engine_status": parsed.engine_status or {},
            "suppressed_findings": suppressed,
            "finding_snapshot": finding_snapshot(findings),
        }
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
        source_path=source_path,
        scanned_files=parsed.scanned_files,
        finding_count=len(records),
        findings=[finding_to_schema(record) for record in records],
        engine_status=parsed.engine_status or {},
        suppressed_count=len(suppressed),
    )


@router.get("/projects/{project_id}/findings", response_model=list[Finding])
def list_project_sast_findings(project_id: UUID, db: Session = Depends(get_db)) -> list[Finding]:
    ensure_project(db, project_id)
    records = db.scalars(
        select(FindingRecord)
        .where(FindingRecord.project_id == str(project_id), FindingRecord.source == "SAST")
        .order_by(FindingRecord.created_at.desc())
    ).all()
    return [finding_to_schema(record) for record in records]


@router.post("/projects/{project_id}/agent-review", response_model=list[Finding])
def run_project_agent_review(project_id: UUID, db: Session = Depends(get_db)) -> list[Finding]:
    ensure_project(db, project_id)
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


@router.get("/tool-health")
def get_sast_tool_health() -> dict[str, object]:
    return sast_tool_health()


@router.get("/projects/{project_id}/profile")
def get_sast_profile(project_id: UUID, db: Session = Depends(get_db)) -> dict[str, object]:
    return effective_sast_profile(sast_module(db, project_id).config)


@router.patch("/projects/{project_id}/profile")
def patch_sast_profile(project_id: UUID, payload: dict[str, object], db: Session = Depends(get_db)) -> dict[str, object]:
    module = sast_module(db, project_id)
    try:
        profile = update_sast_profile(module.config, payload)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    persist_sast_profile(module, profile)
    db.commit()
    return profile


@router.post("/projects/{project_id}/suppressions", status_code=201)
def create_sast_suppression(project_id: UUID, payload: dict[str, object], db: Session = Depends(get_db)) -> dict[str, object]:
    module = sast_module(db, project_id)
    try:
        profile = add_suppression(module.config, payload)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    persist_sast_profile(module, profile)
    db.commit()
    return profile


@router.patch("/projects/{project_id}/suppressions/{suppression_id}")
def patch_sast_suppression(project_id: UUID, suppression_id: str, payload: dict[str, object], db: Session = Depends(get_db)) -> dict[str, object]:
    module = sast_module(db, project_id)
    try:
        profile = update_suppression(module.config, suppression_id, payload)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    persist_sast_profile(module, profile)
    db.commit()
    return profile


@router.get("/projects/{project_id}/scan-history")
def sast_scan_history(project_id: UUID, db: Session = Depends(get_db)) -> list[dict[str, object]]:
    ensure_project(db, project_id)
    scans = db.scalars(
        select(ScanTaskRecord)
        .where(ScanTaskRecord.project_id == str(project_id), ScanTaskRecord.scan_type == "sast")
        .order_by(ScanTaskRecord.created_at.desc())
    ).all()
    return [sast_scan_history_item(item) for item in scans]


@router.get("/projects/{project_id}/scan-diff")
def sast_scan_diff(project_id: UUID, target_scan_id: UUID | None = None, db: Session = Depends(get_db)) -> dict[str, object]:
    ensure_project(db, project_id)
    scans = db.scalars(
        select(ScanTaskRecord)
        .where(ScanTaskRecord.project_id == str(project_id), ScanTaskRecord.scan_type == "sast", ScanTaskRecord.status == ScanStatus.completed.value)
        .order_by(ScanTaskRecord.created_at.desc())
    ).all()
    if not scans:
        raise HTTPException(status_code=400, detail="No completed SAST scans found")
    target = next((item for item in scans if str(item.id) == str(target_scan_id)), None) if target_scan_id else scans[0]
    if target is None:
        raise HTTPException(status_code=404, detail="SAST scan not found")
    previous = next((item for item in scans if item.created_at < target.created_at), None)
    return build_sast_scan_diff(target, previous, db)


@router.get("/projects/{project_id}/sarif")
def export_sast_sarif(project_id: UUID, scan_task_id: UUID | None = None, db: Session = Depends(get_db)) -> JSONResponse:
    ensure_project(db, project_id)
    selected_scan = db.get(ScanTaskRecord, str(scan_task_id)) if scan_task_id else latest_sast_scan(db, project_id)
    if selected_scan is None or selected_scan.project_id != str(project_id) or selected_scan.scan_type != "sast":
        raise HTTPException(status_code=400, detail="No matching completed SAST scan found")
    findings = db.scalars(
        select(FindingRecord)
        .where(FindingRecord.project_id == str(project_id), FindingRecord.source == "SAST", FindingRecord.scan_task_id == str(selected_scan.id))
        .order_by(FindingRecord.created_at.asc())
    ).all()
    return JSONResponse(
        build_sast_sarif(findings, str(selected_scan.id)),
        headers={"Content-Disposition": 'attachment; filename="sast-results.sarif"'},
    )


def run_sast_engines(source_path: str, profile: dict[str, object]) -> SastScanOutput:
    outputs: list[SastScanOutput] = []
    engine_status: dict[str, dict[str, object]] = {}
    if profile["semgrep_enabled"]:
        try:
            outputs.append(scan_with_semgrep(source_path, str(profile["semgrep_config"])))
            engine_status["semgrep"] = {"status": "completed", "config": profile["semgrep_config"]}
        except SemgrepUnavailable as exc:
            engine_status["semgrep"] = {"status": "degraded", "config": profile["semgrep_config"], "detail": str(exc)}
    else:
        engine_status["semgrep"] = {"status": "disabled", "config": profile["semgrep_config"]}
    if profile["include_local_rules"]:
        local_output = scan_source_tree(source_path)
        outputs.append(local_output)
        engine_status["local_rules"] = {"status": "completed", "scanned_files": len(local_output.scanned_files)}
    else:
        engine_status["local_rules"] = {"status": "disabled"}
    if not outputs:
        raise ValueError("No SAST engines completed; enable local rules or make Semgrep available")
    return SastScanOutput(
        findings=dedupe_findings([finding for output in outputs for finding in output.findings]),
        scanned_files=sorted({file_path for output in outputs for file_path in output.scanned_files}),
        engine_status=engine_status,
    )


def resolved_scan_profile(config: dict[str, object] | None, payload: SastScanRequest) -> dict[str, object]:
    profile = effective_sast_profile(config)
    overrides = payload.model_dump(include={"semgrep_config", "include_local_rules"}, exclude_unset=True)
    if overrides:
        profile = update_sast_profile({"sast_profile": profile}, overrides)
    return profile


def validate_sast_source_path(project: ProjectRecord, source_path: str) -> str:
    target = Path(source_path).expanduser().resolve()
    if not target.is_dir():
        raise HTTPException(status_code=400, detail="source_path must be an existing directory")
    if not project.source_path:
        return str(target)
    configured = Path(project.source_path).expanduser().resolve()
    if target != configured and configured not in target.parents:
        raise HTTPException(status_code=400, detail="source_path must be the configured project path or one of its subdirectories")
    return str(target)


def ensure_project(db: Session, project_id: UUID) -> ProjectRecord:
    project = db.get(ProjectRecord, str(project_id))
    if project is None:
        raise HTTPException(status_code=404, detail="Project not found")
    return project


def sast_module(db: Session, project_id: UUID) -> ProjectModuleRecord:
    ensure_project(db, project_id)
    module = db.scalar(select(ProjectModuleRecord).where(ProjectModuleRecord.project_id == str(project_id), ProjectModuleRecord.module_key == ModuleKey.sast.value))
    if module is None:
        raise HTTPException(status_code=400, detail="SAST module is not configured for this project")
    return module


def enabled_sast_module(db: Session, project_id: UUID) -> ProjectModuleRecord:
    module = sast_module(db, project_id)
    if not module.enabled:
        raise HTTPException(status_code=400, detail="SAST module is not enabled for this project")
    return module


def persist_sast_profile(module: ProjectModuleRecord, profile: dict[str, object]) -> None:
    config = dict(module.config or {})
    previous = effective_sast_profile(config)
    profile["profile_version"] = int(previous.get("profile_version") or 0) + 1
    config["sast_profile"] = profile
    module.config = config
    module.updated_at = datetime.utcnow()


def supersede_active_sast_findings(db: Session, project_id: str, new_scan_id: str) -> None:
    records = db.scalars(
        select(FindingRecord).where(
            FindingRecord.project_id == project_id,
            FindingRecord.source == "SAST",
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


def finding_snapshot(findings: list) -> list[dict[str, object]]:
    return [
        {
            "rule_id": item.rule_id,
            "title": item.title,
            "severity": item.severity.value,
            "file_path": item.file_path,
            "line_start": item.line_start,
            "line_end": item.line_end,
            "evidence": item.evidence,
            "category": item.category,
        }
        for item in findings
    ]


def sast_scan_history_item(scan: ScanTaskRecord) -> dict[str, object]:
    metadata = scan.scan_metadata or {}
    snapshot = metadata.get("finding_snapshot") if isinstance(metadata.get("finding_snapshot"), list) else []
    return {
        "scan_task_id": str(scan.id),
        "status": scan.status,
        "created_at": scan.created_at,
        "started_at": scan.started_at,
        "finished_at": scan.finished_at,
        "finding_count": len(snapshot),
        "suppressed_count": len(metadata.get("suppressed_findings") or []),
        "engine_status": metadata.get("engine_status") or {},
        "profile": metadata.get("sast_profile") or {},
    }


def latest_sast_scan(db: Session, project_id: UUID) -> ScanTaskRecord | None:
    return db.scalar(
        select(ScanTaskRecord)
        .where(ScanTaskRecord.project_id == str(project_id), ScanTaskRecord.scan_type == "sast", ScanTaskRecord.status == ScanStatus.completed.value)
        .order_by(ScanTaskRecord.created_at.desc())
    )


def build_sast_scan_diff(target: ScanTaskRecord, previous: ScanTaskRecord | None, db: Session) -> dict[str, object]:
    target_items = snapshot_for_scan(target, db)
    previous_items = snapshot_for_scan(previous, db) if previous else []
    target_map = {snapshot_key(item): item for item in target_items}
    previous_map = {snapshot_key(item): item for item in previous_items}
    added = [target_map[key] for key in target_map.keys() - previous_map.keys()]
    removed = [previous_map[key] for key in previous_map.keys() - target_map.keys()]
    severity_changed = [
        {"before": previous_map[key], "after": target_map[key]}
        for key in target_map.keys() & previous_map.keys()
        if target_map[key].get("severity") != previous_map[key].get("severity")
    ]
    return {
        "target_scan_id": str(target.id),
        "base_scan_id": str(previous.id) if previous else None,
        "summary": {"added": len(added), "removed": len(removed), "severity_changed": len(severity_changed), "unchanged": len(target_map.keys() & previous_map.keys())},
        "added": added,
        "removed": removed,
        "severity_changed": severity_changed,
    }


def snapshot_for_scan(scan: ScanTaskRecord | None, db: Session) -> list[dict[str, object]]:
    if scan is None:
        return []
    metadata = scan.scan_metadata or {}
    snapshot = metadata.get("finding_snapshot")
    if isinstance(snapshot, list):
        return [item for item in snapshot if isinstance(item, dict)]
    records = db.scalars(select(FindingRecord).where(FindingRecord.scan_task_id == str(scan.id), FindingRecord.source == "SAST")).all()
    return [
        {"rule_id": item.rule_id, "title": item.title, "severity": item.severity, "file_path": item.file_path, "line_start": item.line_start, "line_end": item.line_end, "evidence": item.evidence}
        for item in records
    ]


def snapshot_key(item: dict[str, object]) -> tuple[str, str, int, str]:
    return (str(item.get("rule_id") or ""), str(item.get("file_path") or ""), int(item.get("line_start") or 0), str(item.get("evidence") or ""))
