from datetime import datetime
from uuid import UUID, uuid4
from types import SimpleNamespace
from hashlib import sha256
from secrets import compare_digest
import json
from html import escape
import re
from urllib.parse import urlparse

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import HTMLResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db import get_db
from app.db_models import ComponentRecord, DastAssetDiscoveryRecord, DastBusinessFlowRecord, DastBusinessRunRecord, DastBusinessSnapshotRecord, DastRunEvidenceRecord, DastValidationRecord, DastVerificationPlanRecord, DastVerificationRunRecord, FindingRecord, ProjectModuleRecord, ProjectRecord, SandboxTargetInstanceRecord
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
    DastSandboxRunCreate,
    DastSandboxResult,
    DastAssetDiscoveryRequest,
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
from app.services.dast_business_flow import dry_run as dry_run_business_flow, execute_api_flow_result, redact as redact_business_value
from app.services.dast_candidate_adapter import TEMPLATES, build_flow_blueprint, is_runtime_verifiable_finding, normalize_candidate
from app.services.dast_deepseek import dast_deepseek_health, generate_business_flow_draft
from app.services.dast_discovery import discover_assets
from app.services.dast_sandbox_contract import build_sandbox_handoff, callback_token_hash, execution_preflight, new_callback_token, required_capabilities, validate_flow_policy
from app.services.deepseek_client import DeepSeekUnavailable
from app.services.dast_probe import probe_target_url
from app.services.evidence_link_suggestions import build_dast_link_suggestions
from app.services.finding_retest import current_finding_records
from app.services.sandbox_orchestrator import enqueue_dast_handoff
from app.services.sandbox_identity import bootstrap_target_identities, roles_ready
from app.services.verification_strategies import recommended_dast_strategies, resolve_dast_strategy

router = APIRouter()
DAST_CANDIDATE_SOURCES = {"SAST", "AGENT"}
DAST_CANDIDATE_STATUSES = {"open", "pending", "confirmed"}
TRI_COLOR_VERDICTS = {"exploitable", "uncertain", "not_exploitable"}
ACTIVE_BUSINESS_RUN_STATUSES = {"queued", "prepared", "running", "awaiting_sandbox"}
FAILED_BUSINESS_RUN_STATUSES = {"blocked", "failed", "canceled", "cancelled"}


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
    redacted = re.sub(r"(?im)^(\s*(?:cookie|set-cookie|x-api-key)\s*:\s*).+$", r"\1[REDACTED]", redacted)
    redacted = re.sub(r"(?i)((?:api[_-]?key|token|password|secret|cookie)\s*[:=]\s*)[^\s,;]+", r"\1[REDACTED]", redacted)
    return redacted


def has_complete_runtime_evidence(
    run: DastBusinessRunRecord,
    snapshots: list[DastBusinessSnapshotRecord],
) -> bool:
    """Use the same evidence gate for queue state, reports, and tri-color verdicts."""
    return run.execution_mode == "sandbox_handoff" and any(
        item.step_kind == "sandbox_evidence"
        and isinstance(item.detail, dict)
        and bool(item.detail.get("complete"))
        and bool(item.detail.get("request_id"))
        for item in snapshots
    )


def build_dast_report(
    project_id: UUID,
    records: list[DastValidationRecord],
    plans: list[DastVerificationPlanRecord] | None = None,
    runs: list[DastVerificationRunRecord] | None = None,
    evidence: list[DastRunEvidenceRecord] | None = None,
    business_flows: list[DastBusinessFlowRecord] | None = None,
    business_runs: list[DastBusinessRunRecord] | None = None,
    business_snapshots: list[DastBusinessSnapshotRecord] | None = None,
    findings: list[FindingRecord] | None = None,
) -> dict[str, object]:
    plans = plans or []
    runs = runs or []
    evidence = evidence or []
    business_flows = business_flows or []
    business_runs = business_runs or []
    business_snapshots = business_snapshots or []
    findings = findings or []
    serialized_records = [dast_validation_to_schema(record).model_dump(mode="json") for record in records]
    automated_count = sum(record.validation_mode == "automated_web_baseline" for record in records)
    manual_count = sum(record.validation_mode == "manual_validation" for record in records)
    linked_count = sum(record.finding_id is not None or record.component_id is not None for record in records)
    verdict_counts = {
        verdict.value: sum(record.verdict == verdict.value for record in records)
        for verdict in DastVerdict
    }
    flow_map = {str(item.id): item for item in business_flows}
    finding_map = {str(item.id): item for item in findings}
    snapshot_map: dict[str, list[DastBusinessSnapshotRecord]] = {}
    for item in business_snapshots:
        snapshot_map.setdefault(str(item.run_id), []).append(item)
    active_finding_ids = {str(item.id) for item in findings}
    visible_flow_ids = {
        str(item.id) for item in business_flows
        if item.finding_id is not None and str(item.finding_id) in active_finding_ids
    }

    evidence_gated_runs = [
        item for item in business_runs
        if str(item.flow_id) in visible_flow_ids
        and item.status == "completed"
        and item.verdict in {"exploitable", "uncertain", "not_exploitable"}
        and has_complete_runtime_evidence(item, snapshot_map.get(str(item.id), []))
    ]
    latest_run_by_finding: dict[str, DastBusinessRunRecord] = {}
    for item in sorted(evidence_gated_runs, key=lambda run: (run.created_at, str(run.id)), reverse=True):
        flow = flow_map.get(str(item.flow_id))
        if flow is not None and flow.finding_id is not None:
            latest_run_by_finding.setdefault(str(flow.finding_id), item)
    tri_color_counts = {
        verdict: sum(item.verdict == verdict for item in latest_run_by_finding.values())
        for verdict in ("exploitable", "uncertain", "not_exploitable")
    }
    vulnerability_details: list[dict[str, object]] = []
    execution_logs: list[dict[str, object]] = []
    for run in business_runs:
        flow = flow_map.get(str(run.flow_id))
        snapshots_for_run = snapshot_map.get(str(run.id), [])
        runtime_evidence_complete = has_complete_runtime_evidence(run, snapshots_for_run)
        requests = [
            {
                "request_id": (item.detail or {}).get("request_id") if isinstance(item.detail, dict) else None,
                "step_id": item.step_id,
                "request": redact_business_value(item.request_summary or "") or None,
                "response": redact_business_value(item.response_summary or "") or None,
                "evidence_hash": item.evidence_hash,
            }
            for item in snapshots_for_run if item.step_kind in {"http_request", "login"}
        ]
        states = [
            (item.detail or {}).get("state") for item in snapshots_for_run
            if item.step_kind == "state_transition" and isinstance(item.detail, dict)
        ]
        finding = finding_map.get(str(flow.finding_id)) if flow and flow.finding_id else None
        review = finding.ai_review if finding is not None and isinstance(finding.ai_review, dict) else {}
        vulnerability_details.append({
            "finding_id": str(flow.finding_id) if flow and flow.finding_id else None,
            "strategy_id": str(flow.id) if flow else str(run.flow_id),
            "strategy_name": flow.name if flow else None,
            "task_id": str(run.id),
            "target_url": flow.target_url if flow else None,
            "verdict": run.verdict if runtime_evidence_complete and run.verdict else "unverified",
            "verdict_reason": redact_business_value(run.verdict_reason or ""),
            "evidence_summary": [redact_business_value(item.response_summary or "") for item in snapshots_for_run if item.response_summary and item.step_kind != "state_transition"],
            "key_requests": requests,
            "remediation_hint": next((record.remediation_hint for record in records if flow and record.finding_id == flow.finding_id and record.remediation_hint), None) or review.get("remediation") or review.get("fix_strategy"),
        })
        execution_logs.append({
            "task_id": str(run.id), "strategy_id": str(flow.id) if flow else str(run.flow_id),
            "status": run.status, "state_path": states, "request_ids": [item["request_id"] for item in requests if item["request_id"]],
            "started_at": run.started_at.isoformat() if run.started_at else None,
            "completed_at": run.completed_at.isoformat() if run.completed_at else None,
        })
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
            "business_flow_count": len(business_flows),
            "business_run_count": len(business_runs),
            "tri_color": {"total": sum(tri_color_counts.values()), **tri_color_counts},
            "unverified_count": max(0, len(active_finding_ids) - len(latest_run_by_finding)),
            "execution_status": {status: sum(item.status == status for item in business_runs) for status in ("prepared", "awaiting_sandbox", "completed", "blocked", "failed", "cancelled")},
            "evidence_coverage": {
                "http_exchange": sum(item.step_kind in {"http_request", "login"} for item in business_snapshots),
                "browser_or_media": sum(item.step_kind == "sandbox_evidence" and isinstance(item.detail, dict) and item.detail.get("evidence_type") in {"browser", "screenshot", "video", "har", "console"} for item in business_snapshots),
                "oast_callback": sum(item.step_kind == "sandbox_evidence" and isinstance(item.detail, dict) and item.detail.get("evidence_type") == "oast_callback" for item in business_snapshots),
                "timing": sum((item.step_kind in {"http_request", "login"} and isinstance(item.detail, dict) and isinstance(item.detail.get("exchange"), dict)) or (item.step_kind == "sandbox_evidence" and isinstance(item.detail, dict) and item.detail.get("evidence_type") == "timing") for item in business_snapshots),
                "environment": sum(item.step_kind == "sandbox_evidence" and isinstance(item.detail, dict) and item.detail.get("evidence_type") == "environment" for item in business_snapshots),
            },
        },
        "records": serialized_records,
        "verification_plans": [dast_plan_to_schema(plan).model_dump(mode="json") for plan in plans],
        "verification_runs": [dast_run_to_schema(run).model_dump(mode="json") for run in runs],
        "evidence_index": [dast_run_evidence_to_schema(item).model_dump(mode="json") for item in evidence],
        "vulnerability_details": vulnerability_details,
        "execution_log_summary": execution_logs,
        "capability_boundaries": [
            "Automated baseline records capture only the observed unauthenticated HTTP GET result for the confirmed target URL.",
            "A baseline_clear result is not a non-exploitability conclusion and does not establish the absence of vulnerabilities.",
            "Manual verdicts document the reviewer-provided evidence and are limited to their recorded target, scope, and reproduction steps.",
            "This report is generated solely from stored DAST records and does not connect to targets or perform new tests.",
            "Legacy verification-plan runs remain documentation-only; business-flow runs separately record approved, same-origin, bounded API execution and evidence snapshots.",
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


@router.get("/projects/{project_id}/strategy-library")
def list_strategy_library(project_id: UUID, db: Session = Depends(get_db)) -> dict[str, object]:
    ensure_dast_enabled(project_id, db)
    template_metadata = {item.id: item for item in TEMPLATES}
    builtins = [
        {**item.model_dump(mode="json"), "source": "builtin", "editable": False, "version": 1,
         "required_capabilities": list(template_metadata[item.id].required_capabilities) if item.id in template_metadata else []}
        for item in recommended_dast_strategies(None)
    ]
    learned_records = db.scalars(
        select(DastBusinessFlowRecord).where(
            DastBusinessFlowRecord.project_id == str(project_id),
            DastBusinessFlowRecord.strategy_source == "ai_draft",
            DastBusinessFlowRecord.status != "archived",
        ).order_by(DastBusinessFlowRecord.created_at.desc())
    ).all()
    learned = [
        {
            "id": str(item.id), "name": item.name, "description": "DeepSeek 生成并经项目审批保存的策略经验。",
            "scope_summary": item.authorized_scope, "check_items": [str(step.get("kind") or "step") for step in item.steps if isinstance(step, dict)],
            "limitations": ["复用到新目标前必须重新确认范围并审批。"], "source": "deepseek_local", "editable": True,
            "finding_id": str(item.finding_id) if item.finding_id else None,
            "vulnerability_type": (item.sufficiency_criteria or {}).get("vulnerability_type"),
            "version": int((item.sufficiency_criteria or {}).get("template_version") or 1),
            "approval_status": item.status,
        }
        for item in learned_records
    ]
    return {"project_id": str(project_id), "builtin": builtins, "learned": learned, "total": len(builtins) + len(learned)}


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


def business_candidate(record: FindingRecord, project: ProjectRecord, component: ComponentRecord | None = None, discovery: dict[str, object] | None = None) -> DastBusinessCandidate:
    normalized = normalize_candidate(record, project, component, discovery)
    return DastBusinessCandidate(
        id=UUID(str(record.id)), source=record.source, scan_task_id=UUID(str(record.scan_task_id)) if record.scan_task_id else None,
        rule_id=record.rule_id, title=record.title, severity=record.severity,
        vulnerability_type=str(normalized["vulnerability_type"]), cwe=normalized["cwe"],
        file_path=record.file_path, line_start=record.line_start, line_end=record.line_end,
        evidence=redact_business_value(record.evidence or ""),
        attack_surface=normalized["attack_surface"], preconditions=normalized["preconditions"],
        missing=normalized["missing"], requires_human_input=bool(normalized["requires_human_input"]),
        readiness=str(normalized["readiness"]), target_status=str(normalized["target_status"]),
        recommended_strategy_id=str(normalized["recommended_strategy_id"]),
        recommended_strategy_name=str(normalized["recommended_strategy_name"]),
        strategy_description=str(normalized["strategy_description"]),
        strategy_match=str(normalized.get("strategy_match") or "builtin"),
        evidence_requirements=normalized["evidence_requirements"], required_capabilities=normalized.get("required_capabilities", []),
        auto_filled=normalized["auto_filled"],
    )


def eligible_dast_candidate_records(records: list[FindingRecord]) -> list[FindingRecord]:
    """Keep the DAST queue aligned with the actionable findings shown by SAST and AGENT."""
    return [
        record
        for record in records
        if record.source in DAST_CANDIDATE_SOURCES and record.status in DAST_CANDIDATE_STATUSES and is_runtime_verifiable_finding(record)
    ]


def latest_project_discovery(db: Session, project_id: UUID | str) -> dict[str, object] | None:
    record = db.scalar(
        select(DastAssetDiscoveryRecord)
        .where(DastAssetDiscoveryRecord.project_id == str(project_id))
        .order_by(DastAssetDiscoveryRecord.created_at.desc())
    )
    return dict(record.result) if record is not None and isinstance(record.result, dict) else None


def enrich_business_candidates_with_validation(
    candidates: list[DastBusinessCandidate],
    flows: list[DastBusinessFlowRecord],
    runs: list[DastBusinessRunRecord],
    snapshots: list[DastBusinessSnapshotRecord],
) -> list[DastBusinessCandidate]:
    """Attach persisted, evidence-gated validation state to every queue item."""
    flows_by_finding: dict[str, list[DastBusinessFlowRecord]] = {}
    for flow in flows:
        if flow.finding_id is not None:
            flows_by_finding.setdefault(str(flow.finding_id), []).append(flow)
    runs_by_flow: dict[str, list[DastBusinessRunRecord]] = {}
    for run in runs:
        runs_by_flow.setdefault(str(run.flow_id), []).append(run)
    snapshots_by_run: dict[str, list[DastBusinessSnapshotRecord]] = {}
    for snapshot in snapshots:
        snapshots_by_run.setdefault(str(snapshot.run_id), []).append(snapshot)

    enriched: list[DastBusinessCandidate] = []
    for candidate in candidates:
        candidate_flows = flows_by_finding.get(str(candidate.id), [])
        candidate_runs = [run for flow in candidate_flows for run in runs_by_flow.get(str(flow.id), [])]
        candidate_runs.sort(key=lambda item: (item.created_at, str(item.id)), reverse=True)
        verified_runs = [
            run for run in candidate_runs
            if run.status == "completed"
            and run.verdict in TRI_COLOR_VERDICTS
            and has_complete_runtime_evidence(run, snapshots_by_run.get(str(run.id), []))
        ]
        verified_runs.sort(key=lambda item: (item.completed_at or item.created_at, str(item.id)), reverse=True)
        latest_verified = verified_runs[0] if verified_runs else None
        latest_run = candidate_runs[0] if candidate_runs else None
        displayed_run = latest_verified or latest_run
        if latest_verified is not None:
            validation_status = "verified"
        elif latest_run is not None and latest_run.status in ACTIVE_BUSINESS_RUN_STATUSES:
            validation_status = "verifying"
        elif latest_run is not None and latest_run.status in FAILED_BUSINESS_RUN_STATUSES:
            validation_status = "failed"
        else:
            validation_status = "unverified"
        flow_id = str(displayed_run.flow_id) if displayed_run is not None else None
        enriched.append(candidate.model_copy(update={
            "validation_status": validation_status,
            "validation_count": len(verified_runs),
            "latest_flow_id": UUID(flow_id) if flow_id else None,
            "latest_run_id": UUID(str(displayed_run.id)) if displayed_run is not None else None,
            "latest_run_status": displayed_run.status if displayed_run is not None else None,
            "latest_verdict": latest_verified.verdict if latest_verified is not None else None,
            "latest_verdict_reason": redact_business_value(latest_verified.verdict_reason or "") if latest_verified is not None else None,
            "latest_verified_at": (latest_verified.completed_at or latest_verified.created_at) if latest_verified is not None else None,
        }))
    return enriched


def unique_business_candidates(candidates: list[DastBusinessCandidate]) -> list[DastBusinessCandidate]:
    result: list[DastBusinessCandidate] = []
    seen: dict[tuple[object, ...], int] = {}
    validation_rank = {"unverified": 0, "failed": 1, "verifying": 2, "verified": 3}
    for candidate in candidates:
        surface = candidate.attack_surface
        key = (
            candidate.vulnerability_type,
            tuple(sorted(str(value) for value in surface.get("urls", []))),
            tuple(sorted(str(value) for value in surface.get("methods", []))),
            tuple(sorted(str(value) for value in surface.get("parameters", []))),
        )
        existing_index = seen.get(key)
        if existing_index is None:
            seen[key] = len(result)
            result.append(candidate)
        elif validation_rank.get(candidate.validation_status, 0) > validation_rank.get(result[existing_index].validation_status, 0):
            # A deduplicated scenario must retain its persisted verdict even when a
            # newer duplicate source finding has not been materialized yet.
            result[existing_index] = candidate
    return result


def visible_business_flow_records(records: list[DastBusinessFlowRecord], active_candidate_ids: set[str]) -> list[DastBusinessFlowRecord]:
    return [
        record for record in records
        if record.finding_id is None or str(record.finding_id) in active_candidate_ids
    ]


def project_with_active_sandbox_target(project: ProjectRecord, db: Session) -> ProjectRecord | SimpleNamespace:
    """Expose a running SANDBOX instance as the project's temporary DAST target.

    The project asset remains unchanged: stopping the instance makes the temporary
    target disappear automatically.
    """
    if project.runtime_url or project.api_base_url:
        return project
    target = db.scalar(
        select(SandboxTargetInstanceRecord)
        .where(
            SandboxTargetInstanceRecord.project_id == str(project.id),
            SandboxTargetInstanceRecord.status == "running",
        )
        .order_by(SandboxTargetInstanceRecord.created_at.desc())
    )
    if target is None:
        return project
    health_detail = getattr(target, "health_detail", None)
    stored_identity = (health_detail or {}).get("identity") if isinstance(health_detail, dict) else None
    if getattr(target, "mode", "") == "docker" and isinstance(stored_identity, dict) and stored_identity.get("status") == "ready" and not roles_ready(project.id, ["authenticated_user", "resource_owner", "peer_user", "reset_test_account"]):
        # The target can survive an API reload while the in-memory secret vault
        # intentionally cannot.  Recreate disposable accounts from the already
        # authorized Docker target before presenting DAST readiness.
        target.health_detail = {**(target.health_detail or {}), "identity": bootstrap_target_identities(target)}
        target.updated_at = datetime.utcnow()
        db.commit()
    return SimpleNamespace(
        id=project.id,
        runtime_url=target.runtime_url,
        api_base_url=None,
        sandbox_image=project.sandbox_image or target.image,
        sandbox_command=project.sandbox_command or target.command,
        source_path=project.source_path,
    )


def _retarget_object(value: object, old_target: str, new_target: str) -> object:
    if isinstance(value, str):
        return value.replace(old_target, new_target)
    if isinstance(value, list):
        return [_retarget_object(item, old_target, new_target) for item in value]
    if isinstance(value, dict):
        return {str(key): _retarget_object(item, old_target, new_target) for key, item in value.items()}
    return value


def ensure_business_flow(flow_id: UUID, db: Session) -> DastBusinessFlowRecord:
    record = db.get(DastBusinessFlowRecord, str(flow_id))
    if record is None:
        raise HTTPException(status_code=404, detail="DAST business flow not found")
    return record


def business_flow_target_confirmation(project: ProjectRecord, flow: DastBusinessFlowRecord, confirmation: str | None) -> None:
    expected = f"DAST_BUSINESS_FLOW:{flow.id}:{flow.target_url}"
    if confirmation != expected:
        raise HTTPException(status_code=400, detail=f"Enter the exact confirmation phrase: {expected}")
    configured_target = project.api_base_url or project.runtime_url
    configured_origin = _origin(configured_target) if configured_target else None
    flow_origin = _origin(flow.target_url)
    if flow_origin is None or configured_origin is None:
        raise HTTPException(status_code=400, detail="Configure a valid project runtime_url or api_base_url before DAST connects")
    if flow_origin != configured_origin and not (getattr(project, "sandbox_image", None) and getattr(project, "sandbox_command", None)):
        raise HTTPException(status_code=400, detail="target_url must use the same origin as the configured project runtime or API URL")


def business_flow_for_runtime(project: ProjectRecord, flow: DastBusinessFlowRecord) -> DastBusinessFlowRecord | SimpleNamespace:
    """Retarget an approved flow when the same project's SANDBOX loopback port changes.

    Only the origin is replaced. Approved paths, methods, roles and all other
    strategy content remain unchanged, and off-origin step URLs are never made
    eligible by this rewrite.
    """
    configured_target = project.api_base_url or project.runtime_url
    source_origin = _origin(flow.target_url)
    runtime_origin = _origin(configured_target) if configured_target else None
    if source_origin is None or runtime_origin is None or source_origin == runtime_origin:
        return flow
    if not (getattr(project, "sandbox_image", None) and getattr(project, "sandbox_command", None)):
        return flow

    runtime = urlparse(str(configured_target))

    def rewrite_url(value: object) -> str:
        text = str(value or "")
        parsed = urlparse(text)
        if _origin(text) != source_origin:
            return text
        return parsed._replace(scheme=runtime.scheme, netloc=runtime.netloc).geturl()

    steps = []
    for raw_step in flow.steps if isinstance(flow.steps, list) else []:
        step = dict(raw_step) if isinstance(raw_step, dict) else raw_step
        if isinstance(step, dict) and step.get("url"):
            step["url"] = rewrite_url(step["url"])
        steps.append(step)
    return SimpleNamespace(
        id=flow.id,
        project_id=flow.project_id,
        finding_id=flow.finding_id,
        target_url=rewrite_url(flow.target_url),
        allowed_paths=list(flow.allowed_paths or []),
        roles=list(flow.roles or []),
        steps=steps,
        sufficiency_criteria=dict(flow.sufficiency_criteria or {}),
    )


def persist_business_snapshots(
    db: Session,
    flow: DastBusinessFlowRecord,
    run: DastBusinessRunRecord,
    snapshots: list[dict[str, object]],
) -> None:
    for snapshot in snapshots:
        detail = dict(snapshot.get("detail")) if isinstance(snapshot.get("detail"), dict) else {}
        detail.setdefault("task_id", str(run.id))
        detail.setdefault("strategy_id", str(flow.id))
        detail.setdefault("log_id", str(uuid4()))
        if str(snapshot.get("step_kind") or "") in {"http_request", "login"}:
            detail.setdefault("request_id", str(uuid4()))
        payload = {
            "step_id": str(snapshot.get("step_id") or "unknown"),
            "step_kind": str(snapshot.get("step_kind") or "unknown"),
            "role_alias": snapshot.get("role_alias"),
            "status": str(snapshot.get("status") or "unknown"),
            "request_summary": redact_business_value(str(snapshot.get("request_summary") or "")) or None,
            "response_summary": redact_business_value(str(snapshot.get("response_summary") or "")) or None,
            "detail": detail,
        }
        evidence_hash = sha256(json.dumps(payload, sort_keys=True, ensure_ascii=False, default=str).encode("utf-8")).hexdigest()
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
    if finding is None or finding.source not in DAST_CANDIDATE_SOURCES:
        raise HTTPException(status_code=404, detail="DAST business candidate not found")
    ensure_dast_enabled(UUID(str(finding.project_id)), db)
    expected = f"DAST_DEEPSEEK_DRAFT:{finding_id}"
    if payload.confirmation_phrase != expected:
        raise HTTPException(status_code=400, detail=f"Enter the exact confirmation phrase: {expected}")
    component = db.get(ComponentRecord, str(finding.component_id)) if finding.component_id else None
    project = project_with_active_sandbox_target(ensure_dast_enabled(UUID(str(finding.project_id)), db), db)
    normalized = business_candidate(finding, project, component, latest_project_discovery(db, finding.project_id))
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
    project = project_with_active_sandbox_target(ensure_dast_enabled(project_id, db), db)
    records = list(db.scalars(
        select(FindingRecord)
        .where(
            FindingRecord.project_id == str(project_id),
            FindingRecord.source.in_(sorted(DAST_CANDIDATE_SOURCES)),
        )
        .order_by(FindingRecord.created_at.desc())
    ).all())
    findings = eligible_dast_candidate_records(current_finding_records(db, project_id, records))
    components = {str(item.id): item for item in db.scalars(select(ComponentRecord).where(ComponentRecord.project_id == str(project_id))).all()}
    discovery = latest_project_discovery(db, project_id)
    flows = list(db.scalars(select(DastBusinessFlowRecord).where(DastBusinessFlowRecord.project_id == str(project_id))).all())
    runs = list(db.scalars(select(DastBusinessRunRecord).where(DastBusinessRunRecord.project_id == str(project_id))).all())
    snapshots = list(db.scalars(select(DastBusinessSnapshotRecord).where(DastBusinessSnapshotRecord.project_id == str(project_id))).all())
    candidates = [business_candidate(item, project, components.get(str(item.component_id)), discovery) for item in findings]
    return unique_business_candidates(enrich_business_candidates_with_validation(candidates, flows, runs, snapshots))


@router.post("/projects/{project_id}/discover")
def discover_project_assets(project_id: UUID, payload: DastAssetDiscoveryRequest, db: Session = Depends(get_db)) -> dict[str, object]:
    project = project_with_active_sandbox_target(ensure_dast_enabled(project_id, db), db)
    confirm_probe_target(project, payload.target_url, f"DAST_WEB_BASELINE:{payload.target_url}")
    expected = f"DAST_DISCOVERY:{payload.target_url}"
    if payload.target_confirmation != expected:
        raise HTTPException(status_code=400, detail=f"Enter the exact confirmation phrase: {expected}")
    try:
        result = discover_assets(payload.target_url, max_pages=payload.max_pages, credential_ref=payload.credential_ref, allowed_paths=payload.allowed_paths)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    record = DastAssetDiscoveryRecord(project_id=str(project_id), target_url=payload.target_url, status=str(result.get("status") or "unknown"), result=result)
    db.add(record)
    db.commit()
    return result


@router.get("/projects/{project_id}/discoveries/latest")
def get_latest_project_discovery(project_id: UUID, db: Session = Depends(get_db)) -> dict[str, object] | None:
    ensure_dast_enabled(project_id, db)
    return latest_project_discovery(db, project_id)


@router.post("/business-candidates/{finding_id}/materialize", response_model=DastBusinessFlow, status_code=201)
def materialize_business_candidate(finding_id: UUID, db: Session = Depends(get_db)) -> DastBusinessFlow:
    finding = db.get(FindingRecord, str(finding_id))
    if finding is None or finding.source not in DAST_CANDIDATE_SOURCES:
        raise HTTPException(status_code=404, detail="DAST business candidate not found")
    project = project_with_active_sandbox_target(ensure_dast_enabled(UUID(str(finding.project_id)), db), db)
    component = db.get(ComponentRecord, str(finding.component_id)) if finding.component_id else None
    candidate = business_candidate(finding, project, component, latest_project_discovery(db, finding.project_id)).model_dump(mode="json")
    existing = db.scalar(
        select(DastBusinessFlowRecord).where(
            DastBusinessFlowRecord.project_id == str(finding.project_id),
            DastBusinessFlowRecord.finding_id == str(finding_id),
            DastBusinessFlowRecord.status != "archived",
        ).order_by(DastBusinessFlowRecord.created_at.desc())
    )
    try:
        blueprint = build_flow_blueprint(candidate, finding_id=str(finding_id))
    except ValueError as exc:
        if existing is not None and existing.strategy_source in {"template", "learned_template"}:
            existing.status = "archived"
            existing.updated_at = datetime.utcnow()
            db.commit()
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    if existing is not None:
        existing_criteria = existing.sufficiency_criteria or {}
        next_criteria = blueprint["sufficiency_criteria"]
        mapping_is_current = (
            existing_criteria.get("adapter_version") == next_criteria.get("adapter_version")
            and existing_criteria.get("mapping_fingerprint") == next_criteria.get("mapping_fingerprint")
        )
        if existing.strategy_source not in {"template", "learned_template"} or mapping_is_current:
            return dast_business_flow_to_schema(existing)
        existing.status = "archived"
        existing.updated_at = datetime.utcnow()
    vulnerability_type = str(candidate.get("vulnerability_type") or "unclassified")
    learned_candidates = db.scalars(
        select(DastBusinessFlowRecord).where(
            DastBusinessFlowRecord.project_id == str(finding.project_id),
            DastBusinessFlowRecord.strategy_source == "ai_draft",
            DastBusinessFlowRecord.status == "approved",
        ).order_by(DastBusinessFlowRecord.created_at.desc())
    ).all()
    learned = next((item for item in learned_candidates if (item.sufficiency_criteria or {}).get("vulnerability_type") == vulnerability_type), None)
    if learned is not None:
        target_url = str((candidate.get("attack_surface") or {}).get("urls", [project.api_base_url or project.runtime_url])[0])
        blueprint.update({
            "name": f"{finding.title} · 复用本地审核策略",
            "target_url": target_url,
            "flow_mode": learned.flow_mode,
            "strategy_source": "learned_template",
            "roles": learned.roles,
            "steps": _retarget_object(learned.steps, learned.target_url, target_url),
            "sufficiency_criteria": {**(learned.sufficiency_criteria or {}), **blueprint["sufficiency_criteria"], "reused_from_strategy_id": str(learned.id), "template_version": int((learned.sufficiency_criteria or {}).get("template_version") or 1)},
        })
    elif vulnerability_type == "unclassified":
        raise HTTPException(status_code=409, detail="No approved local strategy matches this vulnerability type; generate and approve a DeepSeek draft first")
    record = DastBusinessFlowRecord(
        project_id=str(finding.project_id), finding_id=str(finding_id), name=blueprint["name"],
        target_url=blueprint["target_url"], flow_mode=blueprint["flow_mode"], strategy_source=blueprint["strategy_source"],
        authorized_scope=blueprint["authorized_scope"], allowed_paths=blueprint["allowed_paths"],
        roles=blueprint["roles"], steps=blueprint["steps"], sufficiency_criteria=blueprint["sufficiency_criteria"],
        requester=blueprint["requester"], status="draft",
    )
    db.add(record)
    db.commit()
    db.refresh(record)
    return dast_business_flow_to_schema(record)


@router.get("/projects/{project_id}/business-flows", response_model=list[DastBusinessFlow])
def list_business_flows(project_id: UUID, db: Session = Depends(get_db)) -> list[DastBusinessFlow]:
    ensure_dast_enabled(project_id, db)
    active_candidate_ids = {str(candidate.id) for candidate in list_business_candidates(project_id, db)}
    records = db.scalars(
        select(DastBusinessFlowRecord)
        .where(
            DastBusinessFlowRecord.project_id == str(project_id),
            DastBusinessFlowRecord.status != "archived",
        )
        .order_by(DastBusinessFlowRecord.created_at.desc())
    ).all()
    # Keep historical strategies in the ledger, but do not offer a strategy for
    # a finding that is no longer part of the current, deduplicated DAST queue.
    # This prevents old false mappings from reappearing after the adapter improves.
    visible_records = visible_business_flow_records(records, active_candidate_ids)
    return [dast_business_flow_to_schema(record) for record in visible_records]


@router.post("/business-flows", response_model=DastBusinessFlow, status_code=201)
def create_business_flow(payload: DastBusinessFlowCreate, db: Session = Depends(get_db)) -> DastBusinessFlow:
    ensure_dast_enabled(payload.project_id, db)
    if payload.flow_mode not in {"api", "browser", "hybrid"}:
        raise HTTPException(status_code=400, detail="flow_mode must be api, browser, or hybrid")
    if payload.strategy_source not in {"manual", "recorded", "template", "ai_draft", "learned_template"}:
        raise HTTPException(status_code=400, detail="strategy_source must be manual, recorded, template, ai_draft, or learned_template")
    if payload.finding_id:
        finding = db.get(FindingRecord, str(payload.finding_id))
        if finding is None or finding.project_id != str(payload.project_id):
            raise HTTPException(status_code=400, detail="finding_id does not belong to this project")
    criteria = dict(payload.sufficiency_criteria)
    if payload.finding_id and payload.strategy_source == "ai_draft":
        finding = db.get(FindingRecord, str(payload.finding_id))
        project = project_with_active_sandbox_target(ensure_dast_enabled(payload.project_id, db), db)
        component = db.get(ComponentRecord, str(finding.component_id)) if finding and finding.component_id else None
        if finding:
            normalized = business_candidate(finding, project, component, latest_project_discovery(db, finding.project_id))
            criteria.setdefault("vulnerability_type", normalized.vulnerability_type)
            criteria.setdefault("template_version", 1)
            criteria.setdefault("required_capabilities", normalized.required_capabilities)
    record = DastBusinessFlowRecord(
        project_id=str(payload.project_id), finding_id=str(payload.finding_id) if payload.finding_id else None,
        name=payload.name, target_url=payload.target_url, flow_mode=payload.flow_mode,
        strategy_source=payload.strategy_source, authorized_scope=payload.authorized_scope,
        allowed_paths=payload.allowed_paths, roles=payload.roles, steps=payload.steps,
        sufficiency_criteria=criteria, requester=payload.requester, status="draft",
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
    if record.status == "approved":
        policy_issues = validate_flow_policy(record)
        if policy_issues:
            raise HTTPException(status_code=400, detail={"message": "Business flow violates DAST safety policy", "issues": policy_issues})
    record.updated_at = datetime.utcnow()
    db.commit()
    db.refresh(record)
    return dast_business_flow_to_schema(record)


@router.get("/business-flows/{flow_id}/runs", response_model=list[DastBusinessRun])
def list_business_runs(flow_id: UUID, db: Session = Depends(get_db)) -> list[DastBusinessRun]:
    ensure_business_flow(flow_id, db)
    records = db.scalars(select(DastBusinessRunRecord).where(DastBusinessRunRecord.flow_id == str(flow_id)).order_by(DastBusinessRunRecord.created_at.desc())).all()
    return [dast_business_run_to_schema(record) for record in records]


@router.get("/business-flows/{flow_id}/preflight")
def get_business_flow_preflight(flow_id: UUID, db: Session = Depends(get_db)) -> dict[str, object]:
    flow = ensure_business_flow(flow_id, db)
    project = project_with_active_sandbox_target(ensure_dast_enabled(UUID(str(flow.project_id)), db), db)
    return execution_preflight(project, flow)


@router.get("/business-runs/{run_id}/snapshots", response_model=list[DastBusinessSnapshot])
def list_business_snapshots(run_id: UUID, db: Session = Depends(get_db)) -> list[DastBusinessSnapshot]:
    if db.get(DastBusinessRunRecord, str(run_id)) is None:
        raise HTTPException(status_code=404, detail="DAST business run not found")
    records = db.scalars(select(DastBusinessSnapshotRecord).where(DastBusinessSnapshotRecord.run_id == str(run_id)).order_by(DastBusinessSnapshotRecord.created_at.asc())).all()
    return [dast_business_snapshot_to_schema(record) for record in records]


@router.post("/business-flows/{flow_id}/runs", response_model=DastBusinessRun, status_code=201)
def run_business_flow(flow_id: UUID, payload: DastBusinessRunCreate, db: Session = Depends(get_db)) -> DastBusinessRun:
    flow = ensure_business_flow(flow_id, db)
    project = project_with_active_sandbox_target(ensure_dast_enabled(UUID(str(flow.project_id)), db), db)
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
    state_snapshots: list[dict[str, object]] = [
        _workflow_state("PENDING", 1, "任务已创建并绑定策略。"),
        _workflow_state("RUNNING", 2, "执行器开始处理已审批范围内的步骤。" if payload.execution_mode == "api_execution" else "开始本地预执行校验。"),
    ]
    if payload.execution_mode == "dry_run":
        snapshots, errors = dry_run_business_flow(flow)
        if errors:
            run.status, run.verdict = "blocked", None
            run.verdict_reason = "；".join(errors)
            terminal_states = [_workflow_state("BLOCKED", 3, run.verdict_reason)]
        else:
            run.status, run.verdict = "prepared", None
            run.verdict_reason = "本地预执行校验通过；未连接目标，因此不形成漏洞裁决。"
            terminal_states = [_workflow_state("READY", 3, run.verdict_reason)]
    else:
        execution_flow = business_flow_for_runtime(project, flow)
        result = execute_api_flow_result(execution_flow, task_id=str(run.id))
        snapshots, run.verdict, run.verdict_reason = result.snapshots, result.verdict, result.reason
        if result.terminal_status == "completed" and result.verdict:
            run.status = "completed"
            terminal_states = [
                _workflow_state("ANALYZING", 3, "请求与断言结果已进入证据分析。"),
                _workflow_state("VERDICTED", 4, result.reason, verdict=result.verdict),
                _workflow_state("REPORTED", 5, "运行摘要、证据索引和状态日志已归档。"),
            ]
        else:
            run.status, run.verdict = result.terminal_status, None
            terminal_states = [_workflow_state(result.terminal_status.upper(), 3, result.reason)]
    persist_business_snapshots(db, flow, run, [*state_snapshots, *snapshots, *terminal_states])
    run.completed_at, run.updated_at = datetime.utcnow(), datetime.utcnow()
    db.commit()
    db.refresh(run)
    return dast_business_run_to_schema(run)


@router.post("/business-flows/{flow_id}/sandbox-runs", status_code=201)
def create_sandbox_business_run(flow_id: UUID, payload: DastSandboxRunCreate, db: Session = Depends(get_db)) -> dict[str, object]:
    flow = ensure_business_flow(flow_id, db)
    project = project_with_active_sandbox_target(ensure_dast_enabled(UUID(str(flow.project_id)), db), db)
    preflight = execution_preflight(project, flow)
    if preflight["status"] == "blocked":
        raise HTTPException(status_code=400, detail={"message": "DAST execution preflight is blocked", "preflight": preflight})
    if not preflight["can_handoff_sandbox"]:
        raise HTTPException(status_code=400, detail="This strategy does not require SANDBOX capabilities")
    token = new_callback_token()
    run = DastBusinessRunRecord(
        project_id=flow.project_id, flow_id=str(flow.id), status="awaiting_sandbox", execution_mode="sandbox_handoff",
        operator=payload.operator, started_at=datetime.utcnow(),
        verdict_reason="已生成隔离执行合同，等待 SANDBOX 回传原始事实证据。",
    )
    db.add(run)
    db.flush()
    handoff = build_sandbox_handoff(project, flow, str(run.id), token)
    sandbox_task = enqueue_dast_handoff(db, handoff)
    persist_business_snapshots(db, flow, run, [
        _workflow_state("PENDING", 1, "任务已创建并绑定策略。"),
        _workflow_state("WAITING_SANDBOX", 2, "已生成隔离执行合同，等待 SANDBOX 接管。"),
        {"step_id": "sandbox-handoff", "step_kind": "sandbox_handoff", "status": "completed", "request_summary": None, "response_summary": "SANDBOX 执行合同已生成。", "detail": {"callback_token_sha256": callback_token_hash(token), "required_capabilities": preflight["required_capabilities"], "allowed_request_ids": [str(step.get("request_id")) for step in handoff["steps"] if isinstance(step, dict) and step.get("request_id")], "schema": handoff["schema"]}},
    ])
    db.commit()
    db.refresh(run)
    safe_handoff = dict(handoff)
    safe_handoff["callback"] = {"path": str((handoff.get("callback") or {}).get("path") or "")}
    return {"run": dast_business_run_to_schema(run).model_dump(mode="json"), "preflight": preflight, "handoff": safe_handoff, "sandbox_task_id": str(sandbox_task.id)}


@router.post("/business-runs/{run_id}/sandbox-result", response_model=DastBusinessRun)
def ingest_sandbox_business_result(run_id: UUID, payload: DastSandboxResult, db: Session = Depends(get_db)) -> DastBusinessRun:
    run = db.get(DastBusinessRunRecord, str(run_id))
    if run is None or run.execution_mode != "sandbox_handoff":
        raise HTTPException(status_code=404, detail="DAST SANDBOX run not found")
    if run.status != "awaiting_sandbox":
        raise HTTPException(status_code=409, detail="DAST SANDBOX run already reached a terminal state")
    flow = ensure_business_flow(UUID(str(run.flow_id)), db)
    if str(payload.task_id) != str(run.id) or str(payload.strategy_id) != str(flow.id):
        raise HTTPException(status_code=400, detail="SANDBOX result identifiers do not match the DAST task and strategy")
    handoff_snapshot = db.scalar(select(DastBusinessSnapshotRecord).where(DastBusinessSnapshotRecord.run_id == str(run.id), DastBusinessSnapshotRecord.step_kind == "sandbox_handoff"))
    expected_hash = str((handoff_snapshot.detail or {}).get("callback_token_sha256") or "") if handoff_snapshot else ""
    if not expected_hash or not compare_digest(expected_hash, callback_token_hash(payload.callback_token)):
        raise HTTPException(status_code=403, detail="Invalid or expired SANDBOX callback token")
    if payload.status not in {"completed", "blocked", "failed", "cancelled"}:
        raise HTTPException(status_code=400, detail="Unsupported SANDBOX result status")
    missing_capabilities = sorted(set(required_capabilities(flow)) - set(payload.capabilities))
    if payload.status == "completed" and missing_capabilities:
        raise HTTPException(status_code=400, detail=f"SANDBOX result is missing required capabilities: {', '.join(missing_capabilities)}")
    allowed_request_ids = set((handoff_snapshot.detail or {}).get("allowed_request_ids") or []) if handoff_snapshot else set()
    returned_request_ids = {str(item.get("request_id")) for item in payload.evidence if item.get("request_id")}
    if not returned_request_ids.issubset(allowed_request_ids):
        raise HTTPException(status_code=400, detail="SANDBOX evidence contains a request_id that was not issued by DAST")
    if any(item.get("artifact_sha256") and not re.fullmatch(r"[0-9a-f]{64}", str(item.get("artifact_sha256"))) for item in payload.evidence):
        raise HTTPException(status_code=400, detail="SANDBOX evidence contains an invalid artifact_sha256")
    evidence_snapshots = _sandbox_evidence_snapshots(payload)
    complete_bound_evidence = [
        item for item in payload.evidence
        if bool(item.get("complete")) and bool(item.get("request_id"))
    ]
    if payload.status == "completed" and evidence_snapshots and complete_bound_evidence:
        verdict, reason = _adjudicate_sandbox_result(payload)
        run.status, run.verdict, run.verdict_reason = "completed", verdict, reason
        states = [
            _workflow_state("RUNNING", 3, f"SANDBOX 执行 {payload.execution_id} 已回传。"),
            _workflow_state("ANALYZING", 4, "DAST 正在依据结构化事实证据执行裁决规则。"),
            _workflow_state("VERDICTED", 5, reason, verdict=verdict),
            _workflow_state("REPORTED", 6, "运行摘要、证据索引和状态日志已归档。"),
        ]
    else:
        run.status, run.verdict = payload.status if payload.status != "completed" else "blocked", None
        run.verdict_reason = payload.verdict_reason or "SANDBOX 未返回足以形成漏洞裁决的事实证据，本次任务未验证。"
        states = [_workflow_state(run.status.upper(), 3, run.verdict_reason)]
    combined_snapshots = [*states[:2], *evidence_snapshots, *states[2:]] if len(states) > 1 else [*evidence_snapshots, *states]
    persist_business_snapshots(db, flow, run, combined_snapshots)
    run.completed_at, run.updated_at = datetime.utcnow(), datetime.utcnow()
    db.commit()
    db.refresh(run)
    return dast_business_run_to_schema(run)


def _sandbox_evidence_snapshots(payload: DastSandboxResult) -> list[dict[str, object]]:
    allowed_types = {"http_exchange", "browser", "screenshot", "video", "oast_callback", "timing", "environment", "runtime_trace", "authorization", "differential", "coverage", "har", "console"}
    snapshots: list[dict[str, object]] = []
    for index, raw in enumerate(payload.evidence, start=1):
        evidence_type = str(raw.get("type") or "").strip()
        if evidence_type not in allowed_types:
            evidence_type = "runtime_trace"
        evidence_id = str(raw.get("evidence_id") or uuid4())
        detail = {
            "evidence_id": evidence_id,
            "execution_id": payload.execution_id,
            "evidence_type": evidence_type,
            "confirmed": bool(raw.get("confirmed")),
            "facts": redact_business_value(str(raw.get("facts") or raw.get("summary") or "")),
            "artifact_reference": redact_business_value(str(raw.get("artifact_reference") or "")) or None,
            "artifact_sha256": str(raw.get("artifact_sha256") or "") or None,
            "mime_type": str(raw.get("mime_type") or "") or None,
            "size_bytes": int(raw.get("size_bytes") or 0),
            "request_id": str(raw.get("request_id") or "") or None,
            "duration_ms": raw.get("duration_ms"),
            "complete": bool(raw.get("complete")),
            "probe_count": int(raw.get("probe_count") or 0),
            "expected_probe_count": int(raw.get("expected_probe_count") or 0),
            "negative_conclusion_supported": bool(raw.get("negative_conclusion_supported")),
            "exchange": _redact_evidence_object(raw.get("exchange")) if isinstance(raw.get("exchange"), dict) else None,
            "timing": _redact_evidence_object(raw.get("timing")) if isinstance(raw.get("timing"), dict) else None,
            "environment": _redact_evidence_object(raw.get("environment")) if isinstance(raw.get("environment"), dict) else None,
        }
        snapshots.append({
            "step_id": f"sandbox-evidence-{index}", "step_kind": "sandbox_evidence", "role_alias": None,
            "status": "confirmed" if detail["confirmed"] else "recorded", "request_summary": None,
            "response_summary": f"SANDBOX {evidence_type} 证据已脱敏归档。", "detail": detail,
        })
    return snapshots


def _redact_evidence_object(value: object, *, depth: int = 0) -> object:
    if depth > 8:
        return "[TRUNCATED]"
    if isinstance(value, str):
        return redact_business_value(value[:65536])
    if isinstance(value, list):
        return [_redact_evidence_object(item, depth=depth + 1) for item in value[:200]]
    if isinstance(value, dict):
        secret_keys = {"authorization", "proxy-authorization", "cookie", "set-cookie", "token", "password", "secret", "api_key", "apikey"}
        return {
            str(key): "[REDACTED]" if str(key).lower() in secret_keys else _redact_evidence_object(item, depth=depth + 1)
            for key, item in list(value.items())[:200]
        }
    return value


def _adjudicate_sandbox_result(payload: DastSandboxResult) -> tuple[str, str]:
    strong_types = {"browser", "oast_callback", "runtime_trace", "authorization", "differential"}
    confirmed = [item for item in payload.evidence if bool(item.get("confirmed")) and str(item.get("type") or "") in strong_types and bool(item.get("request_id"))]
    confirmed_timing = [
        item for item in payload.evidence
        if str(item.get("type") or "") == "timing"
        and bool(item.get("confirmed"))
        and bool(item.get("complete"))
        and bool(item.get("request_id"))
        and int(item.get("expected_probe_count") or 0) >= 6
        and int(item.get("probe_count") or 0) >= int(item.get("expected_probe_count") or 0)
        and isinstance(item.get("timing"), dict)
        and len((item.get("timing") or {}).get("samples_ms") or []) >= 6
    ]
    confirmed.extend(confirmed_timing)
    coverage = [
        item for item in payload.evidence
        if str(item.get("type") or "") == "coverage"
        and bool(item.get("complete"))
        and bool(item.get("negative_conclusion_supported"))
        and int(item.get("expected_probe_count") or 0) >= 1
        and int(item.get("probe_count") or 0) >= int(item.get("expected_probe_count") or 0)
    ]
    requested = payload.verdict_signal.value if payload.verdict_signal else "uncertain"
    if requested == "exploitable" and confirmed:
        return "exploitable", payload.verdict_reason or "SANDBOX 返回了与任务、策略和请求关联的明确触发证据，DAST 规则确认可利用。"
    if requested == "not_exploitable" and coverage and not confirmed:
        return "not_exploitable", payload.verdict_reason or "授权范围内的预期探针已完整执行，且对应的阴性判定条件全部满足。"
    if requested == "exploitable":
        return "uncertain", "SANDBOX 建议可利用，但缺少浏览器、外带、运行轨迹、授权差分、稳定差分或完整多轮时延样本中的明确确认事实。"
    if requested == "not_exploitable":
        return "uncertain", "SANDBOX 建议不可利用，但缺少声明了预期数量和阴性判定条件的完整覆盖证据。"
    return "uncertain", payload.verdict_reason or "已获得部分运行异常或观察结果，但证据不足以确认可利用性。"


def _workflow_state(state: str, sequence: int, message: str, *, verdict: str | None = None) -> dict[str, object]:
    detail: dict[str, object] = {"state": state, "sequence": sequence, "message": message}
    if verdict:
        detail["verdict"] = verdict
    return {
        "step_id": f"state-{sequence}-{state.lower()}", "step_kind": "state_transition", "role_alias": None,
        "status": "completed", "request_summary": None, "response_summary": message, "detail": detail,
    }


@router.patch("/business-runs/{run_id}/verdict", response_model=DastBusinessRun)
def set_business_run_verdict(run_id: UUID, payload: DastBusinessRunVerdict, db: Session = Depends(get_db)) -> DastBusinessRun:
    run = db.get(DastBusinessRunRecord, str(run_id))
    if run is None:
        raise HTTPException(status_code=404, detail="DAST business run not found")
    raise HTTPException(
        status_code=409,
        detail="Business-run verdicts are evidence-gated and can only be produced by a completed DAST executor or an authenticated SANDBOX evidence callback",
    )


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
    project = project_with_active_sandbox_target(ensure_dast_enabled(project_id, db), db)
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
    all_findings = list(db.scalars(select(FindingRecord).where(FindingRecord.project_id == str(project_id))).all())
    eligible_findings = eligible_dast_candidate_records(current_finding_records(db, project_id, all_findings))
    all_flows = list(db.scalars(select(DastBusinessFlowRecord).where(DastBusinessFlowRecord.project_id == str(project_id)).order_by(DastBusinessFlowRecord.created_at.desc())).all())
    all_business_runs = list(db.scalars(select(DastBusinessRunRecord).where(DastBusinessRunRecord.project_id == str(project_id)).order_by(DastBusinessRunRecord.created_at.desc())).all())
    all_snapshots = list(db.scalars(select(DastBusinessSnapshotRecord).where(DastBusinessSnapshotRecord.project_id == str(project_id)).order_by(DastBusinessSnapshotRecord.created_at.asc())).all())
    components = {str(item.id): item for item in db.scalars(select(ComponentRecord).where(ComponentRecord.project_id == str(project_id))).all()}
    discovery = latest_project_discovery(db, project_id)
    normalized_candidates = [business_candidate(item, project, components.get(str(item.component_id)), discovery) for item in eligible_findings]
    active_candidates = unique_business_candidates(enrich_business_candidates_with_validation(normalized_candidates, all_flows, all_business_runs, all_snapshots))
    active_finding_ids = {str(item.id) for item in active_candidates}
    findings = [item for item in eligible_findings if str(item.id) in active_finding_ids]
    business_flows = [item for item in all_flows if item.finding_id is not None and str(item.finding_id) in active_finding_ids]
    flow_ids = {str(item.id) for item in business_flows}
    business_runs = [item for item in all_business_runs if str(item.flow_id) in flow_ids]
    run_ids = {str(item.id) for item in business_runs}
    business_snapshots = [item for item in all_snapshots if str(item.run_id) in run_ids]
    return build_dast_report(project_id, records, plans, runs, evidence, business_flows, business_runs, business_snapshots, findings)


@router.get("/projects/{project_id}/report.html", response_class=HTMLResponse)
def get_project_dast_html_report(project_id: UUID, db: Session = Depends(get_db)) -> HTMLResponse:
    report = get_project_dast_report(project_id, db)
    summary = report.get("summary") if isinstance(report.get("summary"), dict) else {}
    tri = summary.get("tri_color") if isinstance(summary.get("tri_color"), dict) else {}
    details = report.get("vulnerability_details") if isinstance(report.get("vulnerability_details"), list) else []
    rows = "".join(
        "<tr>"
        f"<td><code>{escape(str(item.get('task_id') or ''))}</code></td>"
        f"<td>{escape(str(item.get('strategy_name') or ''))}</td>"
        f"<td>{escape(str(item.get('verdict') or 'unverified'))}</td>"
        f"<td>{escape(str(item.get('verdict_reason') or ''))}</td>"
        f"<td>{escape(str(item.get('remediation_hint') or '未提供'))}</td>"
        "</tr>"
        for item in details if isinstance(item, dict)
    ) or "<tr><td colspan='5'>暂无动态验证任务</td></tr>"
    html = f"""<!doctype html><html lang='zh-CN'><head><meta charset='utf-8'><title>DAST 动态验证报告</title>
<style>body{{font-family:system-ui,sans-serif;margin:32px;color:#13213a}}h1{{margin-bottom:4px}}.meta{{color:#66758f}}.cards{{display:flex;gap:12px;flex-wrap:wrap;margin:24px 0}}.card{{padding:14px 18px;border:1px solid #dbe3ef;border-radius:12px;min-width:120px}}.card b{{display:block;font-size:26px}}table{{width:100%;border-collapse:collapse}}th,td{{padding:10px;border:1px solid #dbe3ef;text-align:left;vertical-align:top}}th{{background:#f3f6fa}}code{{word-break:break-all}}footer{{margin-top:24px;color:#66758f}}</style></head><body>
<h1>DAST 动态验证报告</h1><div class='meta'>项目 {escape(str(project_id))} · 生成时间 {escape(str(report.get('generated_at') or ''))}</div>
<div class='cards'><div class='card'><b>{int(tri.get('total') or 0)}</b>三色裁决</div><div class='card'><b>{int(tri.get('exploitable') or 0)}</b>可利用</div><div class='card'><b>{int(tri.get('uncertain') or 0)}</b>不确定</div><div class='card'><b>{int(tri.get('not_exploitable') or 0)}</b>不可利用</div><div class='card'><b>{int(summary.get('unverified_count') or 0)}</b>未验证</div></div>
<h2>漏洞验证详情</h2><table><thead><tr><th>任务 ID</th><th>策略</th><th>结论</th><th>裁决依据</th><th>修复建议</th></tr></thead><tbody>{rows}</tbody></table>
<h2>执行日志摘要</h2><pre>{escape(json.dumps(report.get('execution_log_summary') or [], ensure_ascii=False, indent=2))}</pre>
<footer>报告仅基于已归档证据生成，不会在导出时连接目标。</footer></body></html>"""
    return HTMLResponse(html)


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
