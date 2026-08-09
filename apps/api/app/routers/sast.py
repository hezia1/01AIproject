from datetime import datetime
from fnmatch import fnmatchcase
from html import escape
from pathlib import Path
import re
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db import get_db
from app.db_models import FindingRecord, ProjectModuleRecord, ProjectRecord, SastAgentRunRecord, ScanTaskRecord
from app.models import Finding, ModuleKey, SastScanRequest, SastScanResult, ScanStatus, ScanTask, Severity
from app.repositories.mappers import finding_to_schema, scan_to_schema
from app.services.sast_agent_orchestrator import infer_language, run_sast_agent_pipeline
from app.services.deepseek_client import DeepSeekClient, DeepSeekSettings, DeepSeekUnavailable, deepseek_health
from app.services.sast_ai_orchestrator import AGENT_ROLES, SastAiPipelineResult, finding_key, redact_text, run_deepseek_sast_pipeline
from app.services.sast_governance import (
    add_custom_rule,
    add_semgrep_rule,
    add_suppression,
    apply_suppressions,
    effective_sast_profile,
    update_custom_rule,
    update_semgrep_rule,
    update_sast_profile,
    update_suppression,
    validate_custom_rule_payload,
    validate_semgrep_rule_payload,
)
from app.services.sast_git import collect_git_context, git_history_secret_findings
from app.services.sast_sarif import build_sast_sarif
from app.services.sast_scanner import ParsedFinding, SastScanOutput, dedupe_findings, sast_tool_health, scan_source_tree
from app.services.sast_semgrep_rules import materialize_semgrep_rule_packs, semgrep_rule_preflight
from app.services.semgrep_scanner import DEFAULT_SEMGREP_IMAGE, SemgrepUnavailable, scan_with_semgrep
from app.services.audit import record_audit

router = APIRouter()


@router.post("/scan", response_model=SastScanResult)
def run_sast_scan(payload: SastScanRequest, request: Request, db: Session = Depends(get_db)) -> SastScanResult:
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
        git_context = collect_git_context(source_path, str(profile.get("git_baseline_ref") or ""), bool(profile.get("scan_git_history_secrets", True)))
        changed_files = git_context.get("changed_files") if profile.get("changed_files_only") else None
        if profile.get("changed_files_only") and not changed_files:
            raise ValueError("changed_files_only needs a resolvable git_baseline_ref with at least one changed file")
        parsed = run_sast_engines(source_path, profile, changed_files if isinstance(changed_files, list) else None)
        parsed = SastScanOutput(
            findings=dedupe_findings([*parsed.findings, *git_history_secret_findings(git_context)]),
            scanned_files=parsed.scanned_files,
            engine_status=parsed.engine_status,
        )
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

        db.flush()
        ai_summary: dict[str, object] = {"status": "disabled", "agent_roles": AGENT_ROLES}
        if profile.get("ai_enabled") and profile.get("ai_auto_scan"):
            ai_summary, ai_records, ai_suppressed = execute_deepseek_agents(
                db,
                project_id=str(payload.project_id),
                scan_task_id=str(scan.id),
                source_path=source_path,
                records=records,
                profile=profile,
                trigger="scan",
            )
            records.extend(ai_records)
            suppressed.extend(ai_suppressed)

        engine_status = dict(parsed.engine_status or {})
        engine_status["deepseek_agents"] = {
            "status": ai_summary.get("status", "disabled"),
            "agent_count": int(ai_summary.get("completed_agent_count") or 0),
            "expected_agent_count": int(ai_summary.get("expected_agent_count") or len(AGENT_ROLES)),
            "incomplete_roles": ai_summary.get("incomplete_roles") or [],
            "candidate_count": int(ai_summary.get("candidate_count") or 0),
            "confirmed_count": int(ai_summary.get("confirmed_count") or 0),
            "detail": ai_summary.get("error"),
        }

        scan.status = ScanStatus.completed.value
        scan.finished_at = datetime.utcnow()
        scan.scan_metadata = {
            "sast_profile": profile,
            "engine_status": engine_status,
            "suppressed_findings": suppressed,
            "finding_snapshot": finding_record_snapshot(records),
            "git_context": git_context,
            "branch": payload.branch,
            "deepseek_agents": ai_summary,
        }
        identity = getattr(request.state, "identity", None)
        if identity is not None:
            record_audit(db, tenant_id=identity.tenant_id, user_id=identity.user_id, project_id=str(payload.project_id), action="sast.scan", outcome="completed", detail={"scan_task_id": str(scan.id), "finding_count": len(records), "changed_files_only": bool(profile.get("changed_files_only"))})
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
        engine_status=engine_status,
        suppressed_count=len(suppressed),
    )


@router.post("/jobs", response_model=ScanTask, status_code=201)
def queue_sast_scan(payload: SastScanRequest, request: Request, db: Session = Depends(get_db)) -> ScanTask:
    project = ensure_project(db, payload.project_id)
    enabled_sast_module(db, payload.project_id)
    source_path = validate_sast_source_path(project, payload.source_path)
    active = db.scalar(select(ScanTaskRecord.id).where(ScanTaskRecord.project_id == str(payload.project_id), ScanTaskRecord.scan_type == "sast_job", ScanTaskRecord.status.in_([ScanStatus.queued.value, ScanStatus.running.value])))
    if active:
        raise HTTPException(status_code=409, detail="A SAST job is already queued or running for this project")
    metadata = {
        "task_kind": "sast_job", "payload": serialize_sast_job_payload(payload, source_path),
        "progress": 0, "stage": "queued", "attempt": 1,
        "events": [{"at": datetime.utcnow().isoformat() + "Z", "stage": "queued", "detail": "SAST job queued"}],
    }
    job = ScanTaskRecord(project_id=str(payload.project_id), scan_type="sast_job", status=ScanStatus.queued.value, scan_metadata=metadata)
    db.add(job)
    identity = getattr(request.state, "identity", None)
    if identity is not None:
        record_audit(db, tenant_id=identity.tenant_id, user_id=identity.user_id, project_id=str(payload.project_id), action="sast.job.queue", outcome="completed", detail={"job_id": str(job.id), "source_path": source_path})
    db.commit()
    db.refresh(job)
    return scan_to_schema(job)


@router.post("/jobs/{job_id}/run", response_model=SastScanResult)
def run_queued_sast_job(job_id: UUID, request: Request, db: Session = Depends(get_db)) -> SastScanResult:
    job = db.get(ScanTaskRecord, str(job_id))
    if job is None or job.scan_type != "sast_job":
        raise HTTPException(status_code=404, detail="SAST job not found")
    return execute_queued_sast_job(db, job, request)


def execute_queued_sast_job(db: Session, job: ScanTaskRecord, request: Request) -> SastScanResult:
    if job.status == ScanStatus.cancelled.value:
        raise HTTPException(status_code=409, detail="Cancelled SAST job cannot run")
    if job.status not in {ScanStatus.queued.value, ScanStatus.running.value}:
        raise HTTPException(status_code=409, detail="Only queued or running SAST jobs can run")
    metadata = dict(job.scan_metadata or {})
    raw_payload = metadata.get("payload")
    if not isinstance(raw_payload, dict):
        raise HTTPException(status_code=400, detail="SAST job has no valid payload")
    try:
        payload = SastScanRequest.model_validate(raw_payload)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="SAST job payload is invalid") from exc
    job.status = ScanStatus.running.value
    job.started_at = job.started_at or datetime.utcnow()
    update_sast_job_metadata(job, progress=10, stage="running", detail="Worker started SAST execution")
    db.commit()
    try:
        result = run_sast_scan(payload, request, db)
        db.refresh(job)
        metadata = dict(job.scan_metadata or {})
        metadata["result_scan_task_id"] = str(result.scan_task_id)
        job.scan_metadata = metadata
        if job.status == ScanStatus.cancelled.value:
            update_sast_job_metadata(job, progress=100, stage="cancelled", detail="SAST execution finished after cancellation; the result batch was retained for audit")
            db.commit()
            return result
        job.status = ScanStatus.completed.value
        job.finished_at = datetime.utcnow()
        update_sast_job_metadata(job, progress=100, stage="completed", detail="Worker completed SAST execution")
        db.commit()
        return result
    except Exception as exc:
        db.refresh(job)
        if job.status == ScanStatus.cancelled.value:
            update_sast_job_metadata(job, progress=int((job.scan_metadata or {}).get("progress") or 10), stage="cancelled", detail=f"Cancelled job stopped with: {exc}")
            db.commit()
            raise
        job.status = ScanStatus.failed.value
        job.finished_at = datetime.utcnow()
        update_sast_job_metadata(job, progress=int((job.scan_metadata or {}).get("progress") or 10), stage="failed", detail=str(exc))
        metadata = dict(job.scan_metadata or {})
        metadata["error"] = str(exc)[:1000]
        job.scan_metadata = metadata
        db.commit()
        raise


def update_sast_job_metadata(job: ScanTaskRecord, *, progress: int, stage: str, detail: str) -> None:
    metadata = dict(job.scan_metadata or {})
    events = list(metadata.get("events") or [])[-49:]
    events.append({"at": datetime.utcnow().isoformat() + "Z", "stage": stage, "detail": detail[:1000], "progress": progress})
    metadata.update({"progress": progress, "stage": stage, "queue_position": None, "events": events})
    job.scan_metadata = metadata


def serialize_sast_job_payload(payload: SastScanRequest, source_path: str) -> dict[str, object]:
    """Persist only caller-supplied overrides so a queued job keeps the project profile."""
    return {
        **payload.model_dump(mode="json", exclude_unset=True),
        "project_id": str(payload.project_id),
        "source_path": source_path,
    }


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
def run_project_agent_review(project_id: UUID, request: Request, db: Session = Depends(get_db)) -> list[Finding]:
    project = ensure_project(db, project_id)
    module = enabled_sast_module(db, project_id)
    profile = effective_sast_profile(module.config)
    latest_scan = latest_sast_scan(db, project_id)
    query = (
        select(FindingRecord)
        .where(FindingRecord.project_id == str(project_id), FindingRecord.source == "SAST")
        .order_by(FindingRecord.created_at.desc())
    )
    records = db.scalars(query).all()
    review_records = [item for item in records if latest_scan is None or str(item.scan_task_id or "") == str(latest_scan.id)][:100]
    if profile.get("ai_enabled"):
        if not project.source_path:
            raise HTTPException(status_code=400, detail="项目未配置 source_path，无法执行 DeepSeek 深度审计")
        summary, new_records, _suppressed = execute_deepseek_agents(
            db,
            project_id=str(project_id),
            scan_task_id=str(latest_scan.id) if latest_scan else None,
            source_path=validate_sast_source_path(project, project.source_path),
            records=review_records,
            profile=profile,
            trigger="manual_review",
        )
        records.extend(new_records)
        if latest_scan is not None:
            scan_metadata = dict(latest_scan.scan_metadata or {})
            batch_records = db.scalars(select(FindingRecord).where(FindingRecord.scan_task_id == str(latest_scan.id), FindingRecord.source == "SAST")).all()
            scan_metadata["finding_snapshot"] = finding_record_snapshot(batch_records)
            scan_metadata["deepseek_agents"] = summary
            latest_scan.scan_metadata = scan_metadata
    else:
        for record in review_records:
            record.ai_review = run_sast_agent_pipeline(record)
            record.updated_at = datetime.utcnow()
    audit_sast_mutation(db, request, str(project_id), "sast.agent_review", {"finding_count": len(records)})
    db.commit()
    refreshed = db.scalars(query).all()
    return [finding_to_schema(record) for record in refreshed]


@router.get("/tool-health")
def get_sast_tool_health() -> dict[str, object]:
    return sast_tool_health()


@router.get("/ai-health")
def get_sast_ai_health() -> dict[str, object]:
    return {**deepseek_health(), "agent_roles": AGENT_ROLES, "execution_mode": "seven_sequential_roles_with_local_fallback"}


@router.post("/ai-health/test")
def test_sast_ai_connection() -> dict[str, object]:
    client = DeepSeekClient()
    try:
        call = client.complete_json(
            role="connection_test",
            system_prompt="你是连接测试服务。只输出合法 JSON 对象，不输出 Markdown。",
            user_prompt='请输出 JSON：{"status":"ok","message":"DeepSeek SAST connection ready"}',
            max_tokens=256,
        )
    except DeepSeekUnavailable as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    return {
        "status": "ok",
        "provider": "deepseek",
        "model": call.model,
        "latency_ms": call.latency_ms,
        "prompt_tokens": call.prompt_tokens,
        "completion_tokens": call.completion_tokens,
    }


@router.get("/projects/{project_id}/agent-runs")
def list_sast_agent_runs(project_id: UUID, db: Session = Depends(get_db)) -> list[dict[str, object]]:
    ensure_project(db, project_id)
    records = db.scalars(
        select(SastAgentRunRecord)
        .where(SastAgentRunRecord.project_id == str(project_id))
        .order_by(SastAgentRunRecord.created_at.desc())
        .limit(30)
    ).all()
    return [serialize_agent_run(item) for item in records]


@router.post("/rules/validate")
def validate_sast_rule(payload: dict[str, object]) -> dict[str, object]:
    try:
        return validate_custom_rule_payload(payload)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/semgrep-rules/validate")
def validate_sast_semgrep_rule(payload: dict[str, object]) -> dict[str, object]:
    try:
        return validate_semgrep_rule_payload(payload)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/semgrep-rules/preflight")
def preflight_sast_semgrep_rule(payload: dict[str, object]) -> dict[str, object]:
    try:
        return semgrep_rule_preflight(payload.get("content"))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/projects/{project_id}/profile")
def get_sast_profile(project_id: UUID, db: Session = Depends(get_db)) -> dict[str, object]:
    return effective_sast_profile(sast_module(db, project_id).config)


@router.patch("/projects/{project_id}/profile")
def patch_sast_profile(project_id: UUID, payload: dict[str, object], request: Request, db: Session = Depends(get_db)) -> dict[str, object]:
    module = sast_module(db, project_id)
    try:
        profile = update_sast_profile(module.config, payload)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    persist_sast_profile(module, profile)
    audit_sast_mutation(db, request, str(project_id), "sast.profile.update", {"fields": sorted(payload)})
    db.commit()
    return profile


@router.get("/projects/{project_id}/rules")
def list_sast_rules(project_id: UUID, db: Session = Depends(get_db)) -> dict[str, object]:
    profile = effective_sast_profile(sast_module(db, project_id).config)
    return {
        "rule_pack_version": profile["rule_pack_version"],
        "custom_rules": profile["custom_rules"],
        "note": "Custom rules are project-scoped regular expressions. Built-in semantic checks provide bounded AST/data-flow taint analysis for Python and conservative JS/TS source-to-sink paths.",
    }


@router.post("/projects/{project_id}/rules", status_code=201)
def create_sast_rule(project_id: UUID, payload: dict[str, object], request: Request, db: Session = Depends(get_db)) -> dict[str, object]:
    module = sast_module(db, project_id)
    try:
        profile = add_custom_rule(module.config, payload)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    persist_sast_profile(module, profile)
    audit_sast_mutation(db, request, str(project_id), "sast.regex_rule.create", {"rule_id": payload.get("rule_id")})
    db.commit()
    return profile


@router.patch("/projects/{project_id}/rules/{rule_id}")
def patch_sast_rule(project_id: UUID, rule_id: str, payload: dict[str, object], request: Request, db: Session = Depends(get_db)) -> dict[str, object]:
    module = sast_module(db, project_id)
    try:
        profile = update_custom_rule(module.config, rule_id, payload)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    persist_sast_profile(module, profile)
    audit_sast_mutation(db, request, str(project_id), "sast.regex_rule.update", {"rule_id": rule_id, "fields": sorted(payload)})
    db.commit()
    return profile


@router.get("/projects/{project_id}/semgrep-rules")
def list_sast_semgrep_rules(project_id: UUID, db: Session = Depends(get_db)) -> dict[str, object]:
    profile = effective_sast_profile(sast_module(db, project_id).config)
    return {"rule_pack_version": profile["rule_pack_version"], "semgrep_rules": profile["semgrep_rules"], "execution": "Enabled packs are materialized below artifacts/sast-offline/runtime-rules and passed to the local CLI or preloaded Docker image."}


@router.post("/projects/{project_id}/semgrep-rules", status_code=201)
def create_sast_semgrep_rule(project_id: UUID, payload: dict[str, object], request: Request, db: Session = Depends(get_db)) -> dict[str, object]:
    module = sast_module(db, project_id)
    try:
        profile = add_semgrep_rule(module.config, payload)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    persist_sast_profile(module, profile)
    identity = getattr(request.state, "identity", None)
    if identity is not None:
        record_audit(db, tenant_id=identity.tenant_id, user_id=identity.user_id, project_id=str(project_id), action="sast.semgrep_rule.create", outcome="completed", detail={"name": payload.get("name")})
    db.commit()
    return profile


@router.patch("/projects/{project_id}/semgrep-rules/{rule_id}")
def patch_sast_semgrep_rule(project_id: UUID, rule_id: str, payload: dict[str, object], request: Request, db: Session = Depends(get_db)) -> dict[str, object]:
    module = sast_module(db, project_id)
    try:
        profile = update_semgrep_rule(module.config, rule_id, payload)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    persist_sast_profile(module, profile)
    identity = getattr(request.state, "identity", None)
    if identity is not None:
        record_audit(db, tenant_id=identity.tenant_id, user_id=identity.user_id, project_id=str(project_id), action="sast.semgrep_rule.update", outcome="completed", detail={"rule_id": rule_id, "fields": sorted(payload)})
    db.commit()
    return profile


@router.post("/projects/{project_id}/semgrep-rules/{rule_id}/publish")
def publish_sast_semgrep_rule(project_id: UUID, rule_id: str, request: Request, db: Session = Depends(get_db)) -> dict[str, object]:
    module = sast_module(db, project_id)
    identity = getattr(request.state, "identity", None)
    try:
        profile = update_semgrep_rule(module.config, rule_id, {"status": "published", "approved_by": identity.username if identity is not None else "local-worker"})
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    persist_sast_profile(module, profile)
    audit_sast_mutation(db, request, str(project_id), "sast.semgrep_rule.publish", {"rule_id": rule_id})
    db.commit()
    return profile


@router.post("/projects/{project_id}/suppressions", status_code=201)
def create_sast_suppression(project_id: UUID, payload: dict[str, object], request: Request, db: Session = Depends(get_db)) -> dict[str, object]:
    module = sast_module(db, project_id)
    try:
        profile = add_suppression(module.config, payload)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    persist_sast_profile(module, profile)
    audit_sast_mutation(db, request, str(project_id), "sast.suppression.create", {"rule_id": payload.get("rule_id"), "path_pattern": payload.get("path_pattern")})
    db.commit()
    return profile


@router.patch("/projects/{project_id}/suppressions/{suppression_id}")
def patch_sast_suppression(project_id: UUID, suppression_id: str, payload: dict[str, object], request: Request, db: Session = Depends(get_db)) -> dict[str, object]:
    module = sast_module(db, project_id)
    try:
        profile = update_suppression(module.config, suppression_id, payload)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    persist_sast_profile(module, profile)
    audit_sast_mutation(db, request, str(project_id), "sast.suppression.update", {"suppression_id": suppression_id, "fields": sorted(payload)})
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


@router.get("/projects/{project_id}/report")
def sast_report(project_id: UUID, scan_task_id: UUID | None = None, db: Session = Depends(get_db)) -> dict[str, object]:
    ensure_project(db, project_id)
    scan = db.get(ScanTaskRecord, str(scan_task_id)) if scan_task_id else latest_sast_scan(db, project_id)
    if scan is None or scan.project_id != str(project_id) or scan.scan_type != "sast":
        raise HTTPException(status_code=404, detail="No matching SAST scan found")
    findings = db.scalars(select(FindingRecord).where(FindingRecord.project_id == str(project_id), FindingRecord.source == "SAST", FindingRecord.scan_task_id == str(scan.id))).all()
    severity = {key: sum(1 for item in findings if item.severity == key) for key in ("critical", "high", "medium", "low", "info")}
    categories: dict[str, int] = {}
    for item in findings:
        category = str((item.ai_review or {}).get("category") or "uncategorized")
        categories[category] = categories.get(category, 0) + 1
    scans = db.scalars(select(ScanTaskRecord).where(ScanTaskRecord.project_id == str(project_id), ScanTaskRecord.scan_type == "sast", ScanTaskRecord.status == ScanStatus.completed.value).order_by(ScanTaskRecord.created_at.desc())).all()
    previous = next((item for item in scans if item.created_at < scan.created_at), None)
    metadata = scan.scan_metadata or {}
    profile = metadata.get("sast_profile") if isinstance(metadata.get("sast_profile"), dict) else effective_sast_profile(sast_module(db, project_id).config)
    return {"project_id": str(project_id), "scan": sast_scan_history_item(scan), "summary": {"finding_count": len(findings), "severity": severity, "categories": categories}, "trend": build_sast_scan_diff(scan, previous, db), "git": metadata.get("git_context") or {}, "quality_gate": sast_quality_gate(findings, profile, str(metadata.get("branch") or ""), scan, previous, db), "validation_suggestions": validation_suggestions(findings)}


@router.get("/projects/{project_id}/report.html", response_class=HTMLResponse)
def sast_report_html(project_id: UUID, scan_task_id: UUID | None = None, db: Session = Depends(get_db)) -> HTMLResponse:
    report = sast_report(project_id, scan_task_id, db)
    summary = report["summary"]
    severity = summary["severity"] if isinstance(summary, dict) else {}
    labels = {"critical": "严重", "high": "高危", "medium": "中危", "low": "低危", "info": "提示"}
    rows = "".join(f"<tr><td>{escape(labels.get(str(key), str(key)))}</td><td>{int(value)}</td></tr>" for key, value in severity.items())
    gate = report["quality_gate"] if isinstance(report["quality_gate"], dict) else {}
    scan = report.get("scan") if isinstance(report.get("scan"), dict) else {}
    html = f"""<!doctype html><html lang='zh-CN'><head><meta charset='utf-8'><title>SAST 扫描报告</title><style>body{{font-family:system-ui,sans-serif;max-width:960px;margin:40px auto;color:#172033}}table{{border-collapse:collapse;width:100%}}th,td{{border:1px solid #d9e0ec;padding:10px;text-align:left}}.meta{{background:#f5f7fb;padding:16px;border-radius:8px}}</style></head><body><h1>SAST 扫描报告</h1><div class='meta'><p>项目：{escape(str(project_id))}</p><p>扫描批次：{escape(str(scan.get('scan_task_id') or '-'))}</p><p>风险发现：{int(summary.get('finding_count', 0))}</p><p>质量门禁：{escape(str(gate.get('status', 'unknown')))}</p></div><h2>严重等级分布</h2><table><thead><tr><th>等级</th><th>数量</th></tr></thead><tbody>{rows}</tbody></table><p>本报告仅包含汇总信息和已脱敏证据。</p></body></html>"""
    return HTMLResponse(html, headers={"Content-Disposition": 'attachment; filename="sast-report.html"'})


@router.get("/projects/{project_id}/validation-suggestions")
def sast_validation_suggestions(project_id: UUID, db: Session = Depends(get_db)) -> list[dict[str, object]]:
    ensure_project(db, project_id)
    findings = db.scalars(select(FindingRecord).where(FindingRecord.project_id == str(project_id), FindingRecord.source == "SAST", FindingRecord.status.in_(["open", "pending", "confirmed"]))).all()
    return validation_suggestions(findings)


@router.get("/findings/{finding_id}/fix-draft")
def sast_fix_draft(finding_id: UUID, db: Session = Depends(get_db)) -> dict[str, object]:
    finding = db.get(FindingRecord, str(finding_id))
    if finding is None or finding.source != "SAST":
        raise HTTPException(status_code=404, detail="SAST finding not found")
    return build_fix_draft(finding)


@router.get("/projects/{project_id}/ci-config")
def get_sast_ci_config(project_id: UUID, db: Session = Depends(get_db)) -> dict[str, object]:
    profile = effective_sast_profile(sast_module(db, project_id).config)
    gate = profile["quality_gate"] if isinstance(profile.get("quality_gate"), dict) else {}
    return {
        "profile": profile,
        "environment": {
            "SAST_OFFLINE_ONLY": "true",
            "SAST_SEMGREP_IMAGE": DEFAULT_SEMGREP_IMAGE,
        },
        "command": "python scripts/sast_ci.py --source . --offline --profile sast-ci-config.json --json sast-result.json --sarif sast-result.sarif",
        "quality_gate": gate,
        "workflow": ".github/workflows/sast-local.yml",
        "offline_assets": "D:\\project\\PYproject\\AI网安项目\\artifacts\\sast-offline",
    }


def run_sast_engines(source_path: str, profile: dict[str, object], include_paths: list[str] | None = None) -> SastScanOutput:
    outputs: list[SastScanOutput] = []
    engine_status: dict[str, dict[str, object]] = {}
    if profile["semgrep_enabled"]:
        try:
            semgrep_rules = profile.get("semgrep_rules") if isinstance(profile.get("semgrep_rules"), list) else []
            extra_configs = materialize_semgrep_rule_packs(item for item in semgrep_rules if isinstance(item, dict))
            outputs.append(scan_with_semgrep(source_path, str(profile["semgrep_config"]), extra_configs=extra_configs, include_paths=include_paths))
            engine_status["semgrep"] = {"status": "completed", "config": profile["semgrep_config"], "custom_yaml_rule_packs": len(extra_configs), "scan_scope": "git-diff" if include_paths else "source-tree"}
        except SemgrepUnavailable as exc:
            engine_status["semgrep"] = {"status": "degraded", "config": profile["semgrep_config"], "detail": str(exc)}
    else:
        engine_status["semgrep"] = {"status": "disabled", "config": profile["semgrep_config"]}
    if profile["include_local_rules"]:
        custom_rules = profile.get("custom_rules") if isinstance(profile.get("custom_rules"), list) else []
        local_output = scan_source_tree(source_path, custom_rules=custom_rules, include_paths=include_paths)
        outputs.append(local_output)
        engine_status["local_rules"] = {
            "status": "completed",
            "scanned_files": len(local_output.scanned_files),
            "rule_pack_version": profile.get("rule_pack_version"),
            "custom_rule_count": len([item for item in custom_rules if isinstance(item, dict) and item.get("enabled", True)]),
            "semantic_analysis": "Python AST with bounded intraprocedural and direct local interprocedural source/sink/sanitizer tracking; JS/TS conservative local data-flow",
            "scan_scope": "git-diff" if include_paths else "source-tree",
        }
    else:
        engine_status["local_rules"] = {"status": "disabled"}
    if not outputs:
        raise ValueError("No SAST engines completed; enable local rules or make Semgrep available")
    completed_engines = [name for name in ("semgrep", "local_rules") if engine_status.get(name, {}).get("status") == "completed"]
    enabled_engines = [name for name in ("semgrep", "local_rules") if engine_status.get(name, {}).get("status") != "disabled"]
    execution_complete = bool(enabled_engines) and len(completed_engines) == len(enabled_engines)
    engine_status["assurance"] = {
        "status": "bounded" if execution_complete else "partial",
        "execution_status": "complete" if execution_complete else "partial",
        "confidence": "medium",
        "completed_engines": completed_engines,
        "enabled_engines": enabled_engines,
        "scan_scope": "git-diff" if include_paths else "source-tree",
        "statement": (
            "已启用的静态分析引擎均执行完成；结果仅代表当前规则和有限数据流范围内的证据，"
            "不表示项目不存在其他漏洞。"
            if execution_complete
            else "部分静态分析引擎未完整执行，当前结果不具备完整的已配置引擎覆盖。"
        ),
        "limitations": [
            "静态分析不能证明所有业务权限、CSRF 和运行时可利用性",
            "Python 仅支持有限本地跨函数数据流；JS/TS 为保守的文件内数据流",
            "未命中不等于不存在漏洞，关键结果需要人工或动态验证",
        ],
    }
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


def audit_sast_mutation(db: Session, request: Request, project_id: str, action: str, detail: dict[str, object]) -> None:
    identity = getattr(request.state, "identity", None)
    if identity is not None:
        record_audit(db, tenant_id=identity.tenant_id, user_id=identity.user_id, project_id=project_id, action=action, outcome="completed", detail=detail)


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


def execute_deepseek_agents(
    db: Session,
    *,
    project_id: str,
    scan_task_id: str | None,
    source_path: str,
    records: list[FindingRecord],
    profile: dict[str, object],
    trigger: str,
) -> tuple[dict[str, object], list[FindingRecord], list[dict[str, object]]]:
    try:
        settings = DeepSeekSettings.from_env()
    except DeepSeekUnavailable as exc:
        return {"status": "degraded", "error": str(exc), "agent_roles": AGENT_ROLES}, [], []
    run = SastAgentRunRecord(
        project_id=project_id,
        scan_task_id=scan_task_id,
        status="running",
        provider="deepseek",
        model=settings.model,
        review_model=settings.review_model,
        trigger=trigger,
        started_at=datetime.utcnow(),
    )
    db.add(run)
    db.flush()
    try:
        history = db.scalars(
            select(FindingRecord)
            .where(FindingRecord.project_id == project_id, FindingRecord.source == "SAST")
            .order_by(FindingRecord.created_at.desc())
            .limit(160)
        ).all()
        current_ids = {str(item.id) for item in records if item.id}
        historical = [item for item in history if str(item.id) not in current_ids][:80]
        pipeline = run_deepseek_sast_pipeline(source_path, records[:100], historical, profile, DeepSeekClient(settings))
        new_records, suppressed = apply_deepseek_pipeline_result(db, project_id, scan_task_id, records, pipeline, profile)
        summary = pipeline.audit_summary()
        summary["run_id"] = str(run.id)
        summary["outputs"] = pipeline.outputs
        summary["candidates"] = pipeline.candidates
        summary["confirmed_findings"] = pipeline.confirmed_findings
        summary["disagreements"] = pipeline.disagreements
        run.status = pipeline.status
        run.agent_steps = pipeline.agent_steps
        run.result_summary = summary
        run.token_usage = pipeline.token_usage
        run.error = pipeline.error
        run.finished_at = datetime.utcnow()
        return summary, new_records, suppressed
    except Exception as exc:
        detail = redact_text(str(exc))[:500]
        run.status = "degraded"
        run.error = detail
        run.result_summary = {"status": "degraded", "error": detail, "agent_roles": AGENT_ROLES, "run_id": str(run.id)}
        run.finished_at = datetime.utcnow()
        return run.result_summary, [], []


def apply_deepseek_pipeline_result(
    db: Session,
    project_id: str,
    scan_task_id: str | None,
    records: list[FindingRecord],
    pipeline: SastAiPipelineResult,
    profile: dict[str, object],
) -> tuple[list[FindingRecord], list[dict[str, object]]]:
    for record in records:
        update = pipeline.finding_updates.get(finding_key(record))
        if not update:
            continue
        review = dict(record.ai_review or {})
        review.update({key: value for key, value in update.items() if value not in {None, ""}})
        review["agent_pipeline"] = AGENT_ROLES
        review["ai_review_source"] = "deepseek_multi_agent"
        record.ai_review = review
        record.updated_at = datetime.utcnow()

    new_records: list[FindingRecord] = []
    suppressed: list[dict[str, object]] = []
    for candidate in pipeline.confirmed_findings:
        parsed = candidate_to_parsed_finding(candidate, bool(profile.get("ai_include_fix_drafts", True)))
        kept, applied = apply_suppressions([parsed], profile.get("suppressions"))
        if not kept:
            suppressed.extend(applied)
            continue
        duplicate = next(
            (
                item for item in [*records, *new_records]
                if str(item.file_path or "").replace("\\", "/") == parsed.file_path
                and abs(int(item.line_start or 0) - parsed.line_start) <= 2
                and str((item.ai_review or {}).get("category") or "") == parsed.category
            ),
            None,
        )
        if duplicate is not None:
            review = dict(duplicate.ai_review or {})
            discoveries = list(review.get("ai_discovery_candidates") or [])[-9:]
            discoveries.append({"candidate_id": candidate.get("candidate_id"), "confidence": candidate.get("confidence"), "verdict": candidate.get("verdict"), "evidence": parsed.evidence})
            review.update({"ai_discovery_candidates": discoveries, "ai_review_source": "deepseek_multi_agent", "agent_pipeline": AGENT_ROLES})
            duplicate.ai_review = review
            duplicate.updated_at = datetime.utcnow()
            continue
        record = FindingRecord(
            project_id=project_id,
            scan_task_id=scan_task_id,
            source="SAST",
            rule_id=parsed.rule_id,
            title=parsed.title,
            severity=parsed.severity.value,
            file_path=parsed.file_path,
            line_start=parsed.line_start,
            line_end=parsed.line_end,
            evidence=parsed.evidence,
            ai_review={
                "summary": parsed.description,
                "description": parsed.description,
                "category": parsed.category,
                "cwe": parsed.cwe,
                "owasp": parsed.owasp,
                "language": parsed.language,
                "remediation": parsed.remediation,
                "fix_strategy": parsed.remediation,
                "false_positive_likelihood": "low",
                "review_verdict": "confirmed",
                "priority": "P1" if parsed.severity in {Severity.critical, Severity.high} else "P2",
                "ai_provider": "deepseek",
                "ai_confidence": candidate.get("confidence"),
                "ai_candidate_id": candidate.get("candidate_id"),
                "ai_review_source": "deepseek_multi_agent",
                "agent_pipeline": AGENT_ROLES,
                "evidence_analysis": candidate.get("evidence_analysis") or {},
                "knowledge": candidate.get("knowledge") or {},
                "fix_draft": candidate.get("fix") or {},
                "independent_review": candidate.get("independent_review") or {},
            },
        )
        db.add(record)
        new_records.append(record)
    if new_records:
        db.flush()
    return new_records, suppressed


def candidate_to_parsed_finding(candidate: dict[str, object], include_patch: bool) -> ParsedFinding:
    category = str(candidate.get("category") or "security")[:120]
    candidate_id = re.sub(r"[^A-Za-z0-9_.-]+", "-", str(candidate.get("candidate_id") or "candidate"))[:80]
    review = candidate.get("review") if isinstance(candidate.get("review"), dict) else {}
    fix = dict(candidate.get("fix")) if isinstance(candidate.get("fix"), dict) else {}
    if not include_patch:
        fix.pop("patch", None)
    remediation = redact_text(str(fix.get("recommended_change") or "请人工复核该 AI 候选，完成最小修复并增加安全回归测试。"))[:2000]
    evidence = redact_text(str(candidate.get("evidence") or ""))[:1200]
    return ParsedFinding(
        rule_id=f"AI.DEEPSEEK.{re.sub(r'[^A-Za-z0-9]+', '_', category).upper()[:80]}.{candidate_id}"[:300],
        title=str(candidate.get("title") or "DeepSeek AI candidate")[:300],
        severity=Severity(str(candidate.get("severity") or "medium")),
        file_path=str(candidate.get("file_path") or "").replace("\\", "/")[:800],
        line_start=max(1, int(candidate.get("line_start") or 1)),
        line_end=max(1, int(candidate.get("line_end") or candidate.get("line_start") or 1)),
        evidence=evidence,
        category=category,
        cwe=str(review.get("cwe") or "-")[:120],
        owasp=str(review.get("owasp") or "-")[:120],
        description=f"DeepSeek 多 Agent 已通过独立复核，置信度 {int(candidate.get('confidence') or 0)}%。",
        remediation=remediation,
        language=infer_language(str(candidate.get("file_path") or "")),
    )


def finding_record_snapshot(records: list[FindingRecord]) -> list[dict[str, object]]:
    return [
        {
            "rule_id": item.rule_id,
            "title": item.title,
            "severity": item.severity,
            "file_path": item.file_path,
            "line_start": item.line_start,
            "line_end": item.line_end,
            "evidence": item.evidence,
            "category": str((item.ai_review or {}).get("category") or ""),
        }
        for item in records
    ]


def serialize_agent_run(record: SastAgentRunRecord) -> dict[str, object]:
    return {
        "id": str(record.id),
        "project_id": str(record.project_id),
        "scan_task_id": str(record.scan_task_id) if record.scan_task_id else None,
        "status": record.status,
        "provider": record.provider,
        "model": record.model,
        "review_model": record.review_model,
        "trigger": record.trigger,
        "agent_steps": record.agent_steps or [],
        "result_summary": record.result_summary or {},
        "token_usage": record.token_usage or {},
        "error": record.error,
        "started_at": record.started_at,
        "finished_at": record.finished_at,
        "created_at": record.created_at,
    }


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


def sast_quality_gate(
    findings: list[FindingRecord], profile: dict[str, object] | None = None, branch: str = "",
    target_scan: ScanTaskRecord | None = None, previous_scan: ScanTaskRecord | None = None, db: Session | None = None,
) -> dict[str, object]:
    gate = (profile or {}).get("quality_gate") if isinstance((profile or {}).get("quality_gate"), dict) else {}
    threshold = str(gate.get("threshold") or "high")
    enabled = bool(gate.get("enabled", True))
    patterns = gate.get("branch_patterns") if isinstance(gate.get("branch_patterns"), list) else ["*"]
    applies_to_branch = any(fnmatchcase(branch or "default", str(pattern)) for pattern in patterns)
    ranks = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "none": 99}
    excluded = {str(item) for item in gate.get("excluded_rule_ids", [])} if isinstance(gate.get("excluded_rule_ids"), list) else set()
    blocking = [item for item in findings if item.rule_id not in excluded and ranks.get(item.severity, 99) <= ranks.get(threshold, 1)]
    new_only = bool(gate.get("block_new_only", False))
    if new_only and target_scan is not None and db is not None:
        previous_keys = {snapshot_key(item) for item in snapshot_for_scan(previous_scan, db)} if previous_scan else set()
        blocking = [item for item in blocking if finding_record_key(item) not in previous_keys]
    maximum = int(gate.get("max_blocking_findings") or 0)
    over_maximum = maximum > 0 and len(blocking) > maximum
    threshold_breached = over_maximum if maximum > 0 else bool(blocking)
    blocked = enabled and applies_to_branch and threshold != "none" and threshold_breached
    return {
        "status": "block" if blocked else "pass",
        "enabled": enabled,
        "threshold": threshold,
        "branch": branch or "default",
        "branch_patterns": patterns,
        "block_new_only": new_only,
        "excluded_rule_ids": sorted(excluded),
        "max_blocking_findings": maximum,
        "blocking_finding_count": len(blocking),
        "blocking_rule_ids": sorted({item.rule_id for item in blocking}),
        "note": "The API reports a deterministic, branch-aware SAST quality gate. Repository CI must enforce the returned SARIF/exit code independently.",
    }


def finding_record_key(record: FindingRecord) -> tuple[str, str, int, str]:
    """Return the same stable value used by persisted finding snapshots."""
    return (record.rule_id, str(record.file_path or ""), int(record.line_start or 0), record.evidence or "")


def validation_suggestions(findings: list[FindingRecord]) -> list[dict[str, object]]:
    suggestions: list[dict[str, object]] = []
    for finding in findings:
        category = str((finding.ai_review or {}).get("category") or "")
        if finding.severity not in {"critical", "high"} and category not in {"ssrf", "rce", "command", "deserialize"}:
            continue
        if category in {"ssrf"}:
            next_step = "Create a DAST validation with an explicitly approved, non-production target and an allow-listed callback domain."
        elif category in {"rce", "command", "deserialize"}:
            next_step = "Create a SANDBOX evidence task using a harmless proof command and the default no-network isolation profile."
        else:
            next_step = "Review the code path, then create a scoped DAST validation only after target ownership and test authorization are recorded."
        suggestions.append({
            "finding_id": str(finding.id), "severity": finding.severity, "category": category or "unclassified",
            "recommended_module": "DAST" if category == "ssrf" else "SANDBOX" if category in {"rce", "command", "deserialize"} else "DAST",
            "next_step": next_step,
            "automatic_execution": False,
            "reason": "Cross-module actions are suggestions only; this API never launches network probes or sandbox commands automatically.",
        })
    return suggestions


def build_fix_draft(finding: FindingRecord) -> dict[str, object]:
    review = finding.ai_review or {}
    category = str(review.get("category") or "general")
    replacements = {
        "sql": "Use a parameterized query: cursor.execute(\"SELECT ... WHERE id = %s\", (trusted_id,))",
        "injection": "Pass untrusted data as a bound parameter instead of formatting it into a command or query.",
        "rce": "Replace dynamic execution with a fixed allow-list and structured API.",
        "command": "Replace shell execution with a fixed executable plus validated argument array; set shell=False.",
        "ssrf": "Parse the URL, enforce scheme/host/IP allow-lists, and reject private, loopback, link-local, and metadata addresses.",
        "path": "Resolve the candidate below a fixed root and reject traversal and absolute-path inputs before reading or writing.",
        "path-traversal": "Resolve the candidate below a fixed root and reject traversal and absolute-path inputs before reading or writing.",
        "deserialize": "Replace unsafe object deserialization with a safe typed format and restricted loader.",
        "secret": "Move the credential to a secret store or environment injection, rotate the exposed value, and add a regression test.",
    }
    replacement = replacements.get(category, str(review.get("remediation") or "Apply the remediation after code review and run a focused regression scan."))
    source_line = (finding.evidence or "<redacted source line>").replace("\n", " ")[:300]
    patch = "\n".join([
        f"--- a/{finding.file_path or 'source-file'}", f"+++ b/{finding.file_path or 'source-file'}",
        f"@@ -{finding.line_start or 1},1 +{finding.line_start or 1},2 @@",
        f"- {source_line}", f"+ # SECURITY DRAFT: {replacement}",
        "+ # Replace this comment with reviewed, language-appropriate code.",
    ])
    return {
        "finding_id": str(finding.id), "status": "draft_only", "category": category,
        "patch": patch, "recommended_change": replacement,
        "limitations": ["This draft is never applied automatically.", "It is a review aid, not a verified language-specific patch.", "Run tests and a focused SAST rescan after an approved change."],
        "regression_scan": {"endpoint": "POST /api/sast/scan", "required_fields": ["project_id", "source_path"], "recommended_options": {"clear_previous": False, "include_local_rules": True}},
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
