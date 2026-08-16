from datetime import datetime
from uuid import UUID
from hashlib import sha256
import re
from urllib.parse import urlparse

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db import get_db
from app.db_models import ComponentRecord, DastBusinessFlowRecord, DastBusinessRunRecord, DastBusinessSnapshotRecord, DastRunEvidenceRecord, DastValidationRecord, DastVerificationPlanRecord, DastVerificationRunRecord, FindingRecord, ProjectModuleRecord, ProjectRecord
from app.models import (
    DastLinkSuggestionRequest,
    DastBusinessCandidate,
    DastBusinessDraftRequest,
    DastBusinessFlow,
    DastBusinessFlowCreate,
    DastBusinessFlowUpdate,
    DastBusinessRun,
    DastBusinessRunCreate,
    DastBusinessRunVerdict,
    DastBusinessSnapshot,
    DastProbeRequest,
    DastRunEvidence,
    DastRunEvidenceCreate,
    DastVerdict,
    DastVerificationPlan,
    DastVerificationPlanCreate,
    DastVerificationPlanUpdate,
    DastVerificationRun,
    DastVerificationRunCreate,
    DastVerificationRunUpdate,
    DastVerificationStrategy,
    DastValidation,
    DastValidationCreate,
    DastValidationUpdate,
    LinkSuggestion,
    ModuleKey,
)
from app.repositories.mappers import dast_business_flow_to_schema, dast_business_run_to_schema, dast_business_snapshot_to_schema, dast_plan_to_schema, dast_run_evidence_to_schema, dast_run_to_schema, dast_validation_to_schema
from app.services.dast_business_flow import dry_run as dry_run_business_flow, execute_api_flow, redact as redact_business_value
from app.services.dast_deepseek import dast_deepseek_health, generate_business_flow_draft
from app.services.deepseek_client import DeepSeekUnavailable
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


def redact_evidence_summary(value: str) -> str:
    redacted = re.sub(r"(?i)(authorization\s*[:=]\s*bearer\s+)[^\s,;]+", r"\1[REDACTED]", value)
    redacted = re.sub(r"(?i)((?:api[_-]?key|token|password|secret)\s*[:=]\s*)[^\s,;]+", r"\1[REDACTED]", redacted)
    return redacted


def build_dast_report(
    project_id: UUID,
    records: list[DastValidationRecord],
    plans: list[DastVerificationPlanRecord] | None = None,
    runs: list[DastVerificationRunRecord] | None = None,
    evidence: list[DastRunEvidenceRecord] | None = None,
) -> dict[str, object]:
    plans = plans or []
    runs = runs or []
    evidence = evidence or []
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
            "verification_plan_count": len(plans),
            "approved_plan_count": sum(plan.approval_status == "approved" for plan in plans),
            "documentation_run_count": len(runs),
            "reviewed_run_count": sum(run.status == "reviewed" for run in runs),
            "evidence_item_count": len(evidence),
        },
        "records": serialized_records,
        "verification_plans": [dast_plan_to_schema(plan).model_dump(mode="json") for plan in plans],
        "verification_runs": [dast_run_to_schema(run).model_dump(mode="json") for run in runs],
        "evidence_index": [dast_run_evidence_to_schema(item).model_dump(mode="json") for item in evidence],
        "capability_boundaries": [
            "Automated baseline records capture only the observed unauthenticated HTTP GET result for the confirmed target URL.",
            "A baseline_clear result is not a non-exploitability conclusion and does not establish the absence of vulnerabilities.",
            "Manual verdicts document the reviewer-provided evidence and are limited to their recorded target, scope, and reproduction steps.",
            "This report is generated solely from stored DAST records and does not connect to targets or perform new tests.",
            "Verification runs in this release are documentation-only ledger entries; they do not execute HTTP requests, payloads, crawlers, or authenticated workflows.",
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


def business_candidate(record: FindingRecord, component: ComponentRecord | None = None) -> DastBusinessCandidate:
    review = record.ai_review if isinstance(record.ai_review, dict) else {}
    category = str(review.get("category") or review.get("cwe") or record.rule_id or "unknown").lower()
    if record.source == "SCA":
        vulnerability_type = "dependency_risk"
    elif "idor" in category or "access" in category or "authorization" in category:
        vulnerability_type = "access_control"
    elif "sql" in category:
        vulnerability_type = "sql_injection"
    elif "xss" in category or "cross-site" in category:
        vulnerability_type = "xss"
    elif "ssrf" in category:
        vulnerability_type = "ssrf"
    else:
        vulnerability_type = "unclassified"
    notes = [f"来源模块：{record.source}"]
    if component is not None:
        notes.append(f"受影响组件：{component.name} {component.version or 'unknown'}")
    return DastBusinessCandidate(
        id=UUID(str(record.id)), source=record.source, scan_task_id=UUID(str(record.scan_task_id)) if record.scan_task_id else None,
        rule_id=record.rule_id, title=record.title, severity=record.severity,
        vulnerability_type=vulnerability_type, cwe=str(review.get("cwe")) if review.get("cwe") else None,
        file_path=record.file_path, line_start=record.line_start, line_end=record.line_end,
        evidence=redact_business_value(record.evidence or ""),
        preconditions={"required_roles": [], "required_fixtures": [], "business_notes": notes},
        missing=["接口或页面地址", "HTTP 方法", "参数位置", "业务身份与前置测试数据"],
        requires_human_input=True,
    )


def ensure_business_flow(flow_id: UUID, db: Session) -> DastBusinessFlowRecord:
    record = db.get(DastBusinessFlowRecord, str(flow_id))
    if record is None:
        raise HTTPException(status_code=404, detail="DAST business flow not found")
    return record


def business_flow_target_confirmation(project: ProjectRecord, flow: DastBusinessFlowRecord, confirmation: str | None) -> None:
    confirm_probe_target(project, flow.target_url, f"DAST_WEB_BASELINE:{flow.target_url}")
    expected = f"DAST_BUSINESS_FLOW:{flow.id}:{flow.target_url}"
    if confirmation != expected:
        raise HTTPException(status_code=400, detail=f"Enter the exact confirmation phrase: {expected}")


def persist_business_snapshots(
    db: Session,
    flow: DastBusinessFlowRecord,
    run: DastBusinessRunRecord,
    snapshots: list[dict[str, object]],
) -> None:
    for snapshot in snapshots:
        payload = {
            "step_id": str(snapshot.get("step_id") or "unknown"),
            "step_kind": str(snapshot.get("step_kind") or "unknown"),
            "role_alias": snapshot.get("role_alias"),
            "status": str(snapshot.get("status") or "unknown"),
            "request_summary": redact_business_value(str(snapshot.get("request_summary") or "")) or None,
            "response_summary": redact_business_value(str(snapshot.get("response_summary") or "")) or None,
            "detail": snapshot.get("detail") if isinstance(snapshot.get("detail"), dict) else {},
        }
        evidence_hash = sha256(str(sorted(payload.items())).encode("utf-8")).hexdigest()
        db.add(DastBusinessSnapshotRecord(
            project_id=flow.project_id, flow_id=str(flow.id), run_id=str(run.id),
            step_id=payload["step_id"], step_kind=payload["step_kind"], role_alias=payload["role_alias"],
            status=payload["status"], request_summary=payload["request_summary"],
            response_summary=payload["response_summary"], detail=payload["detail"], evidence_hash=evidence_hash,
        ))


@router.get("/business-draft-health")
def business_draft_health() -> dict[str, object]:
    return dast_deepseek_health()


@router.post("/business-candidates/{finding_id}/ai-draft")
def generate_business_candidate_draft(
    finding_id: UUID, payload: DastBusinessDraftRequest, db: Session = Depends(get_db)
) -> dict[str, object]:
    finding = db.get(FindingRecord, str(finding_id))
    if finding is None or finding.source not in {"SCA", "SAST", "AGENT"}:
        raise HTTPException(status_code=404, detail="DAST business candidate not found")
    ensure_dast_enabled(UUID(str(finding.project_id)), db)
    expected = f"DAST_DEEPSEEK_DRAFT:{finding_id}"
    if payload.confirmation_phrase != expected:
        raise HTTPException(status_code=400, detail=f"Enter the exact confirmation phrase: {expected}")
    component = db.get(ComponentRecord, str(finding.component_id)) if finding.component_id else None
    normalized = business_candidate(finding, component)
    candidate = {
        "source": normalized.source,
        "rule_id": normalized.rule_id,
        "title": normalized.title,
        "severity": normalized.severity.value,
        "vulnerability_type": normalized.vulnerability_type,
        "cwe": normalized.cwe,
        "attack_surface": normalized.attack_surface,
        "preconditions": normalized.preconditions,
        "missing": normalized.missing,
    }
    try:
        return generate_business_flow_draft(candidate, redact_business_value(payload.business_description), redact_business_value(payload.target_description))
    except DeepSeekUnavailable as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/projects/{project_id}/business-candidates", response_model=list[DastBusinessCandidate])
def list_business_candidates(project_id: UUID, db: Session = Depends(get_db)) -> list[DastBusinessCandidate]:
    ensure_dast_enabled(project_id, db)
    findings = db.scalars(
        select(FindingRecord)
        .where(
            FindingRecord.project_id == str(project_id),
            FindingRecord.source.in_(["SCA", "SAST", "AGENT"]),
            FindingRecord.status.in_(["open", "pending", "confirmed"]),
        )
        .order_by(FindingRecord.created_at.desc())
    ).all()
    components = {str(item.id): item for item in db.scalars(select(ComponentRecord).where(ComponentRecord.project_id == str(project_id))).all()}
    return [business_candidate(item, components.get(str(item.component_id))) for item in findings]


@router.get("/projects/{project_id}/business-flows", response_model=list[DastBusinessFlow])
def list_business_flows(project_id: UUID, db: Session = Depends(get_db)) -> list[DastBusinessFlow]:
    ensure_dast_enabled(project_id, db)
    records = db.scalars(
        select(DastBusinessFlowRecord)
        .where(DastBusinessFlowRecord.project_id == str(project_id))
        .order_by(DastBusinessFlowRecord.created_at.desc())
    ).all()
    return [dast_business_flow_to_schema(record) for record in records]


@router.post("/business-flows", response_model=DastBusinessFlow, status_code=201)
def create_business_flow(payload: DastBusinessFlowCreate, db: Session = Depends(get_db)) -> DastBusinessFlow:
    ensure_dast_enabled(payload.project_id, db)
    if payload.flow_mode not in {"api", "browser", "hybrid"}:
        raise HTTPException(status_code=400, detail="flow_mode must be api, browser, or hybrid")
    if payload.strategy_source not in {"manual", "recorded", "template", "ai_draft"}:
        raise HTTPException(status_code=400, detail="strategy_source must be manual, recorded, template, or ai_draft")
    if payload.finding_id:
        finding = db.get(FindingRecord, str(payload.finding_id))
        if finding is None or finding.project_id != str(payload.project_id):
            raise HTTPException(status_code=400, detail="finding_id does not belong to this project")
    record = DastBusinessFlowRecord(
        project_id=str(payload.project_id), finding_id=str(payload.finding_id) if payload.finding_id else None,
        name=payload.name, target_url=payload.target_url, flow_mode=payload.flow_mode,
        strategy_source=payload.strategy_source, authorized_scope=payload.authorized_scope,
        allowed_paths=payload.allowed_paths, roles=payload.roles, steps=payload.steps,
        sufficiency_criteria=payload.sufficiency_criteria, requester=payload.requester, status="draft",
    )
    db.add(record)
    db.commit()
    db.refresh(record)
    return dast_business_flow_to_schema(record)


@router.patch("/business-flows/{flow_id}", response_model=DastBusinessFlow)
def update_business_flow(flow_id: UUID, payload: DastBusinessFlowUpdate, db: Session = Depends(get_db)) -> DastBusinessFlow:
    record = ensure_business_flow(flow_id, db)
    updates = payload.model_dump(exclude_unset=True)
    status = updates.get("status", record.status)
    if status not in {"draft", "approved", "archived"}:
        raise HTTPException(status_code=400, detail="status must be draft, approved, or archived")
    if status == "approved":
        reference = updates.get("approval_reference", record.approval_reference)
        approver = updates.get("approved_by", record.approved_by)
        if not (reference or "").strip() or not (approver or "").strip():
            raise HTTPException(status_code=400, detail="Approved business flows require approval_reference and approved_by")
        record.approved_at = datetime.utcnow()
    scope_fields = {"authorized_scope", "allowed_paths", "roles", "steps", "sufficiency_criteria"}
    if record.status == "approved" and scope_fields & updates.keys():
        if updates.get("status") == "approved":
            raise HTTPException(status_code=400, detail="Change business flow scope first, then record a separate approval")
        record.status, record.approval_reference, record.approved_by, record.approved_at = "draft", None, None, None
    for field, value in updates.items():
        setattr(record, field, value)
    record.updated_at = datetime.utcnow()
    db.commit()
    db.refresh(record)
    return dast_business_flow_to_schema(record)


@router.get("/business-flows/{flow_id}/runs", response_model=list[DastBusinessRun])
def list_business_runs(flow_id: UUID, db: Session = Depends(get_db)) -> list[DastBusinessRun]:
    ensure_business_flow(flow_id, db)
    records = db.scalars(select(DastBusinessRunRecord).where(DastBusinessRunRecord.flow_id == str(flow_id)).order_by(DastBusinessRunRecord.created_at.desc())).all()
    return [dast_business_run_to_schema(record) for record in records]


@router.get("/business-runs/{run_id}/snapshots", response_model=list[DastBusinessSnapshot])
def list_business_snapshots(run_id: UUID, db: Session = Depends(get_db)) -> list[DastBusinessSnapshot]:
    if db.get(DastBusinessRunRecord, str(run_id)) is None:
        raise HTTPException(status_code=404, detail="DAST business run not found")
    records = db.scalars(select(DastBusinessSnapshotRecord).where(DastBusinessSnapshotRecord.run_id == str(run_id)).order_by(DastBusinessSnapshotRecord.created_at.asc())).all()
    return [dast_business_snapshot_to_schema(record) for record in records]


@router.post("/business-flows/{flow_id}/runs", response_model=DastBusinessRun, status_code=201)
def run_business_flow(flow_id: UUID, payload: DastBusinessRunCreate, db: Session = Depends(get_db)) -> DastBusinessRun:
    flow = ensure_business_flow(flow_id, db)
    project = ensure_dast_enabled(UUID(str(flow.project_id)), db)
    if payload.execution_mode not in {"dry_run", "api_execution"}:
        raise HTTPException(status_code=400, detail="execution_mode must be dry_run or api_execution")
    if payload.execution_mode == "api_execution":
        if flow.status != "approved":
            raise HTTPException(status_code=400, detail="Only an approved business flow can connect to a target")
        business_flow_target_confirmation(project, flow, payload.target_confirmation)
    run = DastBusinessRunRecord(
        project_id=flow.project_id, flow_id=str(flow.id), status="running", execution_mode=payload.execution_mode,
        operator=payload.operator, started_at=datetime.utcnow(),
    )
    db.add(run)
    db.flush()
    if payload.execution_mode == "dry_run":
        snapshots, errors = dry_run_business_flow(flow)
        run.status = "blocked" if errors else "completed"
        run.verdict = "uncertain" if errors else None
        run.verdict_reason = "；".join(errors) if errors else "本地预执行校验通过；未连接目标。"
    else:
        snapshots, verdict, reason = execute_api_flow(flow)
        run.status = "completed" if verdict in {"exploitable", "not_exploitable"} else "blocked"
        run.verdict, run.verdict_reason = verdict, reason
    persist_business_snapshots(db, flow, run, snapshots)
    run.completed_at, run.updated_at = datetime.utcnow(), datetime.utcnow()
    db.commit()
    db.refresh(run)
    return dast_business_run_to_schema(run)


@router.patch("/business-runs/{run_id}/verdict", response_model=DastBusinessRun)
def set_business_run_verdict(run_id: UUID, payload: DastBusinessRunVerdict, db: Session = Depends(get_db)) -> DastBusinessRun:
    run = db.get(DastBusinessRunRecord, str(run_id))
    if run is None:
        raise HTTPException(status_code=404, detail="DAST business run not found")
    if payload.verdict not in {DastVerdict.exploitable, DastVerdict.not_exploitable, DastVerdict.uncertain}:
        raise HTTPException(status_code=400, detail="Business run requires an explicit three-state verdict")
    run.verdict, run.verdict_reason, run.updated_at = payload.verdict.value, payload.reason, datetime.utcnow()
    db.commit()
    db.refresh(run)
    return dast_business_run_to_schema(run)


def ensure_dast_plan(project_id: UUID, plan_id: UUID, db: Session) -> DastVerificationPlanRecord:
    plan = db.get(DastVerificationPlanRecord, str(plan_id))
    if plan is None or plan.project_id != str(project_id):
        raise HTTPException(status_code=404, detail="DAST verification plan not found")
    return plan


@router.get("/projects/{project_id}/plans", response_model=list[DastVerificationPlan])
def list_verification_plans(project_id: UUID, db: Session = Depends(get_db)) -> list[DastVerificationPlan]:
    ensure_dast_enabled(project_id, db)
    records = db.scalars(
        select(DastVerificationPlanRecord)
        .where(DastVerificationPlanRecord.project_id == str(project_id))
        .order_by(DastVerificationPlanRecord.created_at.desc())
    ).all()
    return [dast_plan_to_schema(record) for record in records]


@router.post("/plans", response_model=DastVerificationPlan, status_code=201)
def create_verification_plan(
    payload: DastVerificationPlanCreate, db: Session = Depends(get_db)
) -> DastVerificationPlan:
    ensure_dast_enabled(payload.project_id, db)
    ensure_links_belong_to_project(payload.project_id, payload.finding_id, payload.component_id, db)
    finding = db.get(FindingRecord, str(payload.finding_id)) if payload.finding_id else None
    try:
        strategy = resolve_dast_strategy(payload.strategy_id, finding)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    record = DastVerificationPlanRecord(
        project_id=str(payload.project_id),
        finding_id=str(payload.finding_id) if payload.finding_id else None,
        component_id=str(payload.component_id) if payload.component_id else None,
        title=payload.title,
        target_url=payload.target_url,
        authorized_scope=payload.authorized_scope,
        allowed_paths=payload.allowed_paths,
        allowed_methods=[method.upper() for method in payload.allowed_methods],
        strategy_id=strategy.id,
        strategy_name=strategy.name,
        limitations=payload.limitations or " ".join(strategy.limitations),
        requester=payload.requester,
        approval_status="draft",
    )
    db.add(record)
    db.commit()
    db.refresh(record)
    return dast_plan_to_schema(record)


@router.patch("/plans/{plan_id}", response_model=DastVerificationPlan)
def update_verification_plan(
    plan_id: UUID, payload: DastVerificationPlanUpdate, db: Session = Depends(get_db)
) -> DastVerificationPlan:
    record = db.get(DastVerificationPlanRecord, str(plan_id))
    if record is None:
        raise HTTPException(status_code=404, detail="DAST verification plan not found")
    updates = payload.model_dump(exclude_unset=True)
    next_status = updates.get("approval_status", record.approval_status)
    if next_status not in {"draft", "approved", "archived"}:
        raise HTTPException(status_code=400, detail="approval_status must be draft, approved, or archived")
    if next_status == "approved":
        approval_reference = updates.get("approval_reference", record.approval_reference)
        approved_by = updates.get("approved_by", record.approved_by)
        if not (approval_reference or "").strip() or not (approved_by or "").strip():
            raise HTTPException(status_code=400, detail="Approved DAST plans require approval_reference and approved_by")
        record.approved_at = datetime.utcnow()
    elif "approval_status" in updates:
        record.approved_at = None
    scope_fields = {"title", "authorized_scope", "allowed_paths", "allowed_methods", "limitations"}
    if record.approval_status == "approved" and scope_fields & updates.keys():
        if updates.get("approval_status") == "approved":
            raise HTTPException(status_code=400, detail="Change DAST scope first, then record a separate approval")
        record.approval_status = "draft"
        record.approval_reference = None
        record.approved_by = None
        record.approved_at = None
    for field, value in updates.items():
        if field == "allowed_methods" and value is not None:
            value = [method.upper() for method in value]
        setattr(record, field, value)
    record.updated_at = datetime.utcnow()
    db.commit()
    db.refresh(record)
    return dast_plan_to_schema(record)


@router.get("/plans/{plan_id}/runs", response_model=list[DastVerificationRun])
def list_verification_runs(plan_id: UUID, db: Session = Depends(get_db)) -> list[DastVerificationRun]:
    plan = db.get(DastVerificationPlanRecord, str(plan_id))
    if plan is None:
        raise HTTPException(status_code=404, detail="DAST verification plan not found")
    records = db.scalars(
        select(DastVerificationRunRecord)
        .where(DastVerificationRunRecord.plan_id == str(plan_id))
        .order_by(DastVerificationRunRecord.created_at.desc())
    ).all()
    return [dast_run_to_schema(record) for record in records]


@router.post("/plans/{plan_id}/runs", response_model=DastVerificationRun, status_code=201)
def create_verification_run(
    plan_id: UUID, payload: DastVerificationRunCreate, db: Session = Depends(get_db)
) -> DastVerificationRun:
    plan = db.get(DastVerificationPlanRecord, str(plan_id))
    if plan is None:
        raise HTTPException(status_code=404, detail="DAST verification plan not found")
    if plan.approval_status != "approved":
        raise HTTPException(status_code=400, detail="Only an approved DAST verification plan can create a run ledger entry")
    record = DastVerificationRunRecord(
        project_id=plan.project_id, plan_id=str(plan.id), operator=payload.operator,
        purpose=payload.purpose, status="prepared", execution_mode="documentation_only",
    )
    db.add(record)
    db.commit()
    db.refresh(record)
    return dast_run_to_schema(record)


@router.patch("/runs/{run_id}", response_model=DastVerificationRun)
def update_verification_run(
    run_id: UUID, payload: DastVerificationRunUpdate, db: Session = Depends(get_db)
) -> DastVerificationRun:
    record = db.get(DastVerificationRunRecord, str(run_id))
    if record is None:
        raise HTTPException(status_code=404, detail="DAST verification run not found")
    updates = payload.model_dump(exclude_unset=True)
    if "status" in updates and updates["status"] not in {"prepared", "evidence_recorded", "reviewed"}:
        raise HTTPException(status_code=400, detail="Run status must be prepared, evidence_recorded, or reviewed")
    if "validation_id" in updates and updates["validation_id"] is not None:
        validation = db.get(DastValidationRecord, str(updates["validation_id"]))
        if validation is None or validation.project_id != record.project_id:
            raise HTTPException(status_code=400, detail="validation_id does not belong to this DAST run project")
        ensure_manual_validation_record(validation)
        record.validation_id = str(validation.id)
    if updates.get("status") == "reviewed" and not record.validation_id:
        raise HTTPException(status_code=400, detail="A reviewed DAST run requires a linked manual validation verdict")
    if "status" in updates:
        record.status = updates["status"]
        record.completed_at = datetime.utcnow() if record.status == "reviewed" else None
    record.updated_at = datetime.utcnow()
    db.commit()
    db.refresh(record)
    return dast_run_to_schema(record)


@router.get("/runs/{run_id}/evidence", response_model=list[DastRunEvidence])
def list_run_evidence(run_id: UUID, db: Session = Depends(get_db)) -> list[DastRunEvidence]:
    run = db.get(DastVerificationRunRecord, str(run_id))
    if run is None:
        raise HTTPException(status_code=404, detail="DAST verification run not found")
    records = db.scalars(
        select(DastRunEvidenceRecord)
        .where(DastRunEvidenceRecord.run_id == str(run_id))
        .order_by(DastRunEvidenceRecord.created_at.desc())
    ).all()
    return [dast_run_evidence_to_schema(record) for record in records]


@router.post("/runs/{run_id}/evidence", response_model=DastRunEvidence, status_code=201)
def create_run_evidence(
    run_id: UUID, payload: DastRunEvidenceCreate, db: Session = Depends(get_db)
) -> DastRunEvidence:
    run = db.get(DastVerificationRunRecord, str(run_id))
    if run is None:
        raise HTTPException(status_code=404, detail="DAST verification run not found")
    summary = redact_evidence_summary(payload.content_summary)
    record = DastRunEvidenceRecord(
        project_id=run.project_id, plan_id=run.plan_id, run_id=str(run.id),
        evidence_type=payload.evidence_type, content_summary=summary,
        content_hash=sha256(summary.encode("utf-8")).hexdigest(),
        source_reference=redact_evidence_summary(payload.source_reference) if payload.source_reference else None,
        collected_by=payload.collected_by,
        redaction_applied=True,
    )
    run.status = "evidence_recorded"
    run.updated_at = datetime.utcnow()
    db.add(record)
    db.commit()
    db.refresh(record)
    return dast_run_evidence_to_schema(record)


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
    plans = db.scalars(
        select(DastVerificationPlanRecord)
        .where(DastVerificationPlanRecord.project_id == str(project_id))
        .order_by(DastVerificationPlanRecord.created_at.desc())
    ).all()
    runs = db.scalars(
        select(DastVerificationRunRecord)
        .where(DastVerificationRunRecord.project_id == str(project_id))
        .order_by(DastVerificationRunRecord.created_at.desc())
    ).all()
    evidence = db.scalars(
        select(DastRunEvidenceRecord)
        .where(DastRunEvidenceRecord.project_id == str(project_id))
        .order_by(DastRunEvidenceRecord.created_at.desc())
    ).all()
    return build_dast_report(project_id, records, plans, runs, evidence)


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
