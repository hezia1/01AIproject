from datetime import datetime
import hmac
import json
import subprocess
from hashlib import sha256
from pathlib import Path
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db import get_db
from app.db_models import FindingRecord, ProjectModuleRecord, ProjectRecord, ScanTaskRecord
from app.models import (
    AgentAssetDiffItem,
    AgentAssetResult,
    AgentPermissionDiffItem,
    AgentPermissionResult,
    AgentScanDiff,
    AgentScanDiffSummary,
    AgentOfflineAuditDiff,
    AgentScanCoverage,
    AgentScanHistoryItem,
    AgentScanRequest,
    AgentScanResult,
    AgentScanSnapshot,
    AgentRuntimePreflightRequest,
    AgentStagingBuildRequest,
    AgentFixtureRuntimeRequest,
    AgentMcpProbeRuntimeRequest,
    AgentRemoteMcpProbeRuntimeRequest,
    AgentTargetRuntimeRequest,
    Finding,
    ModuleKey,
    ScanStatus,
)
from app.repositories.mappers import finding_to_schema
from app.services.agent_governance import (
    add_agent_exception,
    build_agent_html_report,
    build_agent_sarif,
    decide_agent_exception,
    effective_agent_profile,
    evaluate_agent_quality_gate,
    filter_agent_findings,
    finding_governance_status,
    finding_identity,
    permission_identity as governance_permission_identity,
    persist_agent_profile_config,
    update_agent_profile,
)
from app.services.agent_scanner import AgentAsset, AgentFinding, AgentPermission, scan_agent_tree
from app.services.agent_intelligence import analyze_agent_intelligence
from app.services.agent_dataflow import analyze_agent_dataflow
from app.services.agent_audit import build_agent_offline_audit, compare_agent_offline_audits
from app.services.agent_runtime_validation import build_agent_runtime_plan, staging_workspace_path
from app.services.agent_trust import calculate_agent_trust_score
from app.services.agent_staging import build_filtered_staging
from app.services.agent_fixture_runtime import (
    FixtureRuntimeRejected,
    list_fixture_evidence,
    list_local_fixture_images,
    run_harmless_fixture_validation,
)
from app.services.agent_target_runtime import (
    TargetRuntimeRejected,
    list_target_evidence,
    list_target_runtime_status,
    run_target_agent_validation,
)
from app.services.agent_mcp_probe_runtime import (
    list_mcp_probe_evidence,
    list_mcp_probe_status,
    run_mcp_probe_validation,
)
from app.services.agent_remote_mcp_probe_runtime import (
    list_remote_mcp_probe_evidence,
    list_remote_mcp_probe_status,
    run_remote_mcp_probe_validation,
)

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
    profile = effective_agent_profile(project_module.config)
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
        previous_scan = latest_completed_agent_scan(db, str(payload.project_id))
        parsed = scan_agent_tree(source_path, list(profile.get("excluded_paths") or []))
        intelligence_output = analyze_agent_intelligence(parsed.assets)
        dataflow_output = analyze_agent_dataflow(
            parsed.assets,
            [*parsed.findings, *intelligence_output.findings],
            profile,
        )
        sandbox_module = db.scalar(
            select(ProjectModuleRecord).where(
                ProjectModuleRecord.project_id == str(payload.project_id),
                ProjectModuleRecord.module_key == ModuleKey.sandbox.value,
                ProjectModuleRecord.enabled.is_(True),
            )
        )
        runtime_validation = build_agent_runtime_plan(
            project_id=str(payload.project_id),
            source_path=source_path,
            command=project.sandbox_command,
            image=project.sandbox_image,
            dataflow=dataflow_output.report,
            sandbox_enabled=sandbox_module is not None,
        )
        governed_findings = filter_agent_findings(
            [*parsed.findings, *intelligence_output.findings, *dataflow_output.findings], profile
        )
        coverage = build_agent_coverage(parsed.assets, len(parsed.skipped_files))
        asset_payloads = governed_asset_payloads(parsed.assets, governed_findings)
        coverage.findings_by_asset_type = findings_by_asset_type(asset_payloads)
        if payload.clear_previous:
            supersede_active_agent_findings(db, str(payload.project_id), str(scan.id))

        records: list[FindingRecord] = []
        finding_payloads: list[dict[str, object]] = []
        suppressed_count = 0
        for finding in governed_findings:
            governance_status, exception_id, disposition = finding_governance_status(finding, profile)
            if governance_status != "open":
                suppressed_count += 1
            review = {
                "summary": finding.description,
                "false_positive_likelihood": "not_reviewed",
                "remediation": finding.remediation,
                "category": finding.category,
                "description": finding.description,
                "trust_impact": finding.trust_impact,
                "review_status": "not_reviewed",
                "analysis_source": (
                    "local_intelligence" if finding.rule_id.startswith("AGENT.INTEL.")
                    else "local_dataflow" if finding.rule_id.startswith("AGENT.FLOW.")
                    else "local_rule"
                ),
                "governance_exception_id": exception_id,
                "governance_disposition": disposition,
            }
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
                status=governance_status,
                ai_review=review,
            )
            db.add(record)
            records.append(record)
            finding_payloads.append(agent_finding_payload(finding, governance_status))

        previous_finding_identities = scan_finding_identities(db, previous_scan)
        current_finding_identities = {finding_identity(item) for item in finding_payloads}
        previous_permissions = metadata_dict_list(previous_scan.scan_metadata or {}, "permissions") if previous_scan else []
        previous_permission_identities = {governance_permission_identity(item) for item in previous_permissions}
        current_permission_identities = {governance_permission_identity(item) for item in parsed.permissions}
        previous_assets = metadata_dict_list(previous_scan.scan_metadata or {}, "assets") if previous_scan else []
        previous_asset_map = {asset_identity(item): item for item in previous_assets}
        asset_changes = compare_agent_assets(previous_assets, asset_payloads) if previous_scan else []
        changed_integrity_identities = {
            item.identity for item in asset_changes
            if item.change_type == "changed" and any(field in {
                "file_sha256", "directory_sha256", "integrity_status", "integrity_issues",
            } for field in item.changes)
            and bool(previous_asset_map.get(item.identity, {}).get("file_sha256") or previous_asset_map.get(item.identity, {}).get("directory_sha256"))
        }
        changed_source_identities = {
            item.identity for item in asset_changes
            if item.change_type == "changed" and "provenance" in item.changes
            and "provenance" in previous_asset_map.get(item.identity, {})
        }
        trust_score = calculate_agent_trust_score(
            assets=asset_payloads,
            permissions=parsed.permissions,
            findings=finding_payloads,
            coverage=coverage.model_dump(),
            intelligence=intelligence_output.report,
            dataflow=dataflow_output.report,
            runtime_validation=runtime_validation,
        )
        audit = build_agent_offline_audit(
            assets=asset_payloads,
            findings=finding_payloads,
            coverage=coverage.model_dump(),
            intelligence=intelligence_output.report,
            dataflow=dataflow_output.report,
            trust_score=trust_score,
        )
        quality_gate = evaluate_agent_quality_gate(
            findings=finding_payloads,
            permissions=parsed.permissions,
            assets=asset_payloads,
            coverage=coverage.model_dump(),
            profile=profile,
            new_finding_identities=current_finding_identities - previous_finding_identities,
            expanded_permission_identities=current_permission_identities - previous_permission_identities,
            changed_integrity_identities=changed_integrity_identities,
            changed_source_identities=changed_source_identities,
            intelligence=intelligence_output.report,
            dataflow=dataflow_output.report,
            trust_score=trust_score,
        )

        scan.status = ScanStatus.completed.value
        scan.finished_at = datetime.utcnow()
        scan.scan_metadata = {
            "progress": 100,
            "stage": "completed",
            "source_path": source_path,
            "rule_version": parsed.rule_version,
            "finding_count": len(records),
            "suppressed_count": suppressed_count,
            "assets": asset_payloads,
            "permissions": [permission_to_dict(permission) for permission in parsed.permissions],
            "coverage": coverage.model_dump(),
            "skipped_files": parsed.skipped_files,
            "agent_profile": profile,
            "quality_gate": quality_gate,
            "intelligence": intelligence_output.report,
            "dataflow": dataflow_output.report,
            "audit": audit,
            "runtime_validation": runtime_validation,
            "trust_score": trust_score,
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
        assets=[AgentAssetResult(**item) for item in asset_payloads],
        permissions=[AgentPermissionResult(**permission_to_dict(permission)) for permission in parsed.permissions],
        coverage=coverage,
        rule_version=parsed.rule_version,
        suppressed_count=suppressed_count,
        quality_gate=quality_gate,
        intelligence=intelligence_output.report,
        dataflow=dataflow_output.report,
        audit=audit,
        runtime_validation=runtime_validation,
        trust_score=trust_score,
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


@router.get("/projects/{project_id}/profile")
def get_project_agent_profile(project_id: UUID, db: Session = Depends(get_db)) -> dict[str, object]:
    return effective_agent_profile(enabled_agent_module(db, project_id).config)


@router.patch("/projects/{project_id}/profile")
def patch_project_agent_profile(
    project_id: UUID,
    payload: dict[str, object],
    request: Request,
    db: Session = Depends(get_db),
) -> dict[str, object]:
    module = enabled_agent_module(db, project_id)
    actor = mutation_actor(request, payload)
    clean_payload = {key: value for key, value in payload.items() if key != "actor"}
    try:
        profile = update_agent_profile(module.config, clean_payload, actor=actor)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    module.config = persist_agent_profile_config(module.config, profile)
    module.updated_at = datetime.utcnow()
    db.commit()
    return profile


@router.post("/projects/{project_id}/exceptions", status_code=201)
def create_project_agent_exception(
    project_id: UUID,
    payload: dict[str, object],
    request: Request,
    db: Session = Depends(get_db),
) -> dict[str, object]:
    module = enabled_agent_module(db, project_id)
    actor = mutation_actor(request, payload)
    clean_payload = {key: value for key, value in payload.items() if key != "actor"}
    try:
        profile, item = add_agent_exception(module.config, clean_payload, actor=actor)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    module.config = persist_agent_profile_config(module.config, profile)
    module.updated_at = datetime.utcnow()
    db.commit()
    return item


@router.patch("/projects/{project_id}/exceptions/{exception_id}")
def decide_project_agent_exception(
    project_id: UUID,
    exception_id: str,
    payload: dict[str, object],
    request: Request,
    db: Session = Depends(get_db),
) -> dict[str, object]:
    module = enabled_agent_module(db, project_id)
    actor = mutation_actor(request, payload)
    clean_payload = {key: value for key, value in payload.items() if key != "actor"}
    try:
        profile, item = decide_agent_exception(module.config, exception_id, clean_payload, actor=actor)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    module.config = persist_agent_profile_config(module.config, profile)
    module.updated_at = datetime.utcnow()
    db.commit()
    return item


@router.get("/projects/{project_id}/snapshot", response_model=AgentScanSnapshot)
def get_project_agent_snapshot(project_id: UUID, db: Session = Depends(get_db)) -> AgentScanSnapshot:
    if db.get(ProjectRecord, str(project_id)) is None:
        raise HTTPException(status_code=404, detail="Project not found")
    scan = latest_completed_agent_scan(db, str(project_id))
    if scan is None:
        raise HTTPException(status_code=404, detail="No completed AGENT scan found")
    return agent_scan_snapshot(project_id, scan)


@router.post("/projects/{project_id}/runtime-preflight")
def preflight_project_agent_runtime(
    project_id: UUID,
    payload: AgentRuntimePreflightRequest,
    db: Session = Depends(get_db),
) -> dict[str, object]:
    project = db.get(ProjectRecord, str(project_id))
    if project is None:
        raise HTTPException(status_code=404, detail="Project not found")
    enabled_agent_module(db, project_id)
    sandbox_module = db.scalar(
        select(ProjectModuleRecord).where(
            ProjectModuleRecord.project_id == str(project_id),
            ProjectModuleRecord.module_key == ModuleKey.sandbox.value,
            ProjectModuleRecord.enabled.is_(True),
        )
    )
    scan = latest_completed_agent_scan(db, str(project_id))
    metadata = scan.scan_metadata if scan and isinstance(scan.scan_metadata, dict) else {}
    dataflow = metadata.get("dataflow") if isinstance(metadata.get("dataflow"), dict) else {}
    return build_agent_runtime_plan(
        project_id=str(project_id),
        source_path=project.source_path,
        command=payload.command if payload.command is not None else project.sandbox_command,
        image=payload.image if payload.image is not None else project.sandbox_image,
        dataflow=dataflow,
        sandbox_enabled=sandbox_module is not None,
        operator_confirmed=payload.operator_confirmed,
        timeout_seconds=payload.timeout_seconds,
    )


@router.post("/projects/{project_id}/runtime-staging", status_code=201)
def build_project_agent_runtime_staging(
    project_id: UUID,
    payload: AgentStagingBuildRequest,
    db: Session = Depends(get_db),
) -> dict[str, object]:
    project = db.get(ProjectRecord, str(project_id))
    if project is None:
        raise HTTPException(status_code=404, detail="Project not found")
    enabled_agent_module(db, project_id)
    sandbox_module = db.scalar(
        select(ProjectModuleRecord).where(
            ProjectModuleRecord.project_id == str(project_id),
            ProjectModuleRecord.module_key == ModuleKey.sandbox.value,
            ProjectModuleRecord.enabled.is_(True),
        )
    )
    scan = latest_completed_agent_scan(db, str(project_id))
    metadata = scan.scan_metadata if scan and isinstance(scan.scan_metadata, dict) else {}
    dataflow = metadata.get("dataflow") if isinstance(metadata.get("dataflow"), dict) else {}
    selected_command = payload.command if payload.command is not None else project.sandbox_command
    selected_image = payload.image if payload.image is not None else project.sandbox_image
    plan = build_agent_runtime_plan(
        project_id=str(project_id),
        source_path=project.source_path,
        command=selected_command,
        image=selected_image,
        dataflow=dataflow,
        sandbox_enabled=sandbox_module is not None,
        operator_confirmed=payload.operator_confirmed,
        timeout_seconds=payload.timeout_seconds,
    )
    if not payload.operator_confirmed:
        raise HTTPException(status_code=400, detail="Explicit confirmation is required to create a filtered D-drive copy.")
    if not hmac.compare_digest(str(plan.get("plan_sha256") or ""), payload.plan_sha256):
        raise HTTPException(status_code=409, detail="The preflight plan changed; run preflight again before creating staging.")
    required_checks = {
        "sandbox-module", "source-directory", "source-link-boundary", "explicit-command",
        "command-policy", "explicit-image", "image-reference-policy", "digest-pinned-image",
        "operator-confirmation",
    }
    blocking = [
        str(item.get("id") or "") for item in plan.get("checks", [])
        if isinstance(item, dict) and item.get("id") in required_checks and item.get("status") != "pass"
    ]
    if blocking:
        raise HTTPException(status_code=400, detail=f"Required staging checks did not pass: {', '.join(blocking)}")
    if not project.source_path:
        raise HTTPException(status_code=400, detail="Project source directory is not configured")
    try:
        staging = build_filtered_staging(
            source_path=project.source_path,
            project_id=str(project_id),
            destination_root=staging_workspace_path(str(project_id)),
            binding={
                "scan_task_id": str(scan.id),
                "plan_sha256": str(plan.get("plan_sha256") or ""),
                "command_sha256": sha256(str(selected_command or "").strip().encode("utf-8")).hexdigest(),
                "image": str(selected_image or "").strip(),
                "timeout_seconds": payload.timeout_seconds,
            } if scan is not None else None,
        )
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {
        "schema": staging.get("schema"),
        "status": staging.get("status"),
        "execution_enabled": False,
        "runtime_status": "not_run",
        "plan_sha256": plan.get("plan_sha256"),
        "staging": staging,
        "next_action": "Review the staging manifest and digest. Agent execution remains disabled and requires separate approval.",
    }


@router.get("/projects/{project_id}/runtime-fixture-status")
def get_project_agent_fixture_status(
    project_id: UUID,
    db: Session = Depends(get_db),
) -> dict[str, object]:
    require_agent_fixture_modules(db, project_id)
    try:
        return list_local_fixture_images()
    except FixtureRuntimeRejected as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/projects/{project_id}/runtime-fixture-evidence")
def get_project_agent_fixture_evidence(
    project_id: UUID,
    db: Session = Depends(get_db),
) -> list[dict[str, object]]:
    require_agent_fixture_modules(db, project_id)
    try:
        return list_fixture_evidence(str(project_id))
    except FixtureRuntimeRejected as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/projects/{project_id}/runtime-fixture-validation", status_code=201)
def validate_project_agent_runtime_fixture(
    project_id: UUID,
    payload: AgentFixtureRuntimeRequest,
    db: Session = Depends(get_db),
) -> dict[str, object]:
    require_agent_fixture_modules(db, project_id)
    if not payload.operator_confirmed:
        raise HTTPException(status_code=400, detail="Explicit confirmation is required to run the bundled harmless fixture.")
    try:
        return run_harmless_fixture_validation(
            project_id=str(project_id),
            image=payload.image,
            timeout_seconds=payload.timeout_seconds,
        )
    except FixtureRuntimeRejected as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/projects/{project_id}/runtime-target-status")
def get_project_agent_target_runtime_status(
    project_id: UUID,
    db: Session = Depends(get_db),
) -> dict[str, object]:
    require_agent_fixture_modules(db, project_id)
    module = enabled_agent_module(db, project_id)
    profile = effective_agent_profile(module.config)
    try:
        status = list_target_runtime_status(
            str(project_id), bool(profile.get("target_runtime_execution_enabled"))
        )
        scan = latest_completed_agent_scan(db, str(project_id))
        current_scan_id = str(scan.id) if scan is not None else None
        builds = status.get("builds") if isinstance(status.get("builds"), list) else []
        status["current_scan_task_id"] = current_scan_id
        status["builds"] = [
            item for item in builds
            if isinstance(item, dict) and str(item.get("scan_task_id") or "") == current_scan_id
        ]
        return status
    except TargetRuntimeRejected as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/projects/{project_id}/runtime-target-evidence")
def get_project_agent_target_runtime_evidence(
    project_id: UUID,
    db: Session = Depends(get_db),
) -> list[dict[str, object]]:
    require_agent_fixture_modules(db, project_id)
    try:
        return list_target_evidence(str(project_id))
    except TargetRuntimeRejected as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/projects/{project_id}/runtime-mcp-probe-status")
def get_project_agent_mcp_probe_status(
    project_id: UUID,
    db: Session = Depends(get_db),
) -> dict[str, object]:
    require_agent_fixture_modules(db, project_id)
    module = enabled_agent_module(db, project_id)
    profile = effective_agent_profile(module.config)
    scan = latest_completed_agent_scan(db, str(project_id))
    try:
        return list_mcp_probe_status(
            str(project_id), str(scan.id) if scan is not None else None,
            bool(profile.get("target_runtime_execution_enabled")),
        )
    except TargetRuntimeRejected as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/projects/{project_id}/runtime-mcp-probe-evidence")
def get_project_agent_mcp_probe_evidence(
    project_id: UUID,
    db: Session = Depends(get_db),
) -> list[dict[str, object]]:
    require_agent_fixture_modules(db, project_id)
    try:
        return list_mcp_probe_evidence(str(project_id))
    except TargetRuntimeRejected as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/projects/{project_id}/runtime-mcp-probe-validation", status_code=201)
def validate_project_agent_mcp_probe(
    project_id: UUID,
    payload: AgentMcpProbeRuntimeRequest,
    db: Session = Depends(get_db),
) -> dict[str, object]:
    require_agent_fixture_modules(db, project_id)
    module = enabled_agent_module(db, project_id)
    profile = effective_agent_profile(module.config)
    if not profile.get("target_runtime_execution_enabled"):
        raise HTTPException(status_code=403, detail="MCP server probing is disabled by the project target runtime policy.")
    scan = latest_completed_agent_scan(db, str(project_id))
    if scan is None:
        raise HTTPException(status_code=400, detail="A completed AGENT scan is required before MCP probing.")
    metadata = scan.scan_metadata if isinstance(scan.scan_metadata, dict) else {}
    try:
        evidence = run_mcp_probe_validation(
            project_id=str(project_id), scan_task_id=str(scan.id), image=payload.image,
            timeout_seconds=payload.timeout_seconds, plan_sha256=payload.plan_sha256,
            staging_build_id=payload.staging_build_id, staging_sha256=payload.staging_sha256,
            manifest_sha256=payload.manifest_sha256, candidate_id=payload.candidate_id,
            authorization_phrase=payload.authorization_phrase,
            operator_confirmed=payload.operator_confirmed,
        )
    except subprocess.TimeoutExpired as exc:
        raise HTTPException(status_code=400, detail="A Docker control command timed out during MCP probing.") from exc
    except (TargetRuntimeRejected, OSError, ValueError, json.JSONDecodeError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    runtime_validation = (
        dict(metadata.get("runtime_validation"))
        if isinstance(metadata.get("runtime_validation"), dict)
        else {}
    )
    runtime_validation["mcp_probe_evidence"] = evidence
    findings = db.scalars(
        select(FindingRecord)
        .where(FindingRecord.scan_task_id == scan.id, FindingRecord.source == "AGENT")
        .order_by(FindingRecord.created_at.asc())
    ).all()
    trust_score = calculate_agent_trust_score(
        assets=metadata_dict_list(metadata, "assets"),
        permissions=metadata_dict_list(metadata, "permissions"),
        findings=[finding_record_report_payload(item) for item in findings],
        coverage=metadata.get("coverage") if isinstance(metadata.get("coverage"), dict) else {},
        intelligence=metadata.get("intelligence") if isinstance(metadata.get("intelligence"), dict) else {},
        dataflow=metadata.get("dataflow") if isinstance(metadata.get("dataflow"), dict) else {},
        runtime_validation=runtime_validation,
    )
    scan.scan_metadata = {
        **metadata, "runtime_validation": runtime_validation, "trust_score": trust_score,
    }
    db.commit()
    return {**evidence, "trust_score": trust_score}


@router.get("/projects/{project_id}/runtime-remote-mcp-probe-status")
def get_project_agent_remote_mcp_probe_status(
    project_id: UUID,
    db: Session = Depends(get_db),
) -> dict[str, object]:
    require_agent_fixture_modules(db, project_id)
    module = enabled_agent_module(db, project_id)
    profile = effective_agent_profile(module.config)
    scan = latest_completed_agent_scan(db, str(project_id))
    try:
        return list_remote_mcp_probe_status(
            str(project_id), str(scan.id) if scan is not None else None,
            bool(profile.get("target_runtime_execution_enabled")),
        )
    except TargetRuntimeRejected as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/projects/{project_id}/runtime-remote-mcp-probe-evidence")
def get_project_agent_remote_mcp_probe_evidence(
    project_id: UUID,
    db: Session = Depends(get_db),
) -> list[dict[str, object]]:
    require_agent_fixture_modules(db, project_id)
    try:
        return list_remote_mcp_probe_evidence(str(project_id))
    except TargetRuntimeRejected as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/projects/{project_id}/runtime-remote-mcp-probe-validation", status_code=201)
def validate_project_agent_remote_mcp_probe(
    project_id: UUID,
    payload: AgentRemoteMcpProbeRuntimeRequest,
    db: Session = Depends(get_db),
) -> dict[str, object]:
    require_agent_fixture_modules(db, project_id)
    module = enabled_agent_module(db, project_id)
    profile = effective_agent_profile(module.config)
    if not profile.get("target_runtime_execution_enabled"):
        raise HTTPException(status_code=403, detail="Remote MCP probing is disabled by the project target runtime policy.")
    scan = latest_completed_agent_scan(db, str(project_id))
    if scan is None:
        raise HTTPException(status_code=400, detail="A completed AGENT scan is required before remote MCP probing.")
    metadata = scan.scan_metadata if isinstance(scan.scan_metadata, dict) else {}
    try:
        evidence = run_remote_mcp_probe_validation(
            project_id=str(project_id), scan_task_id=str(scan.id), image=payload.image,
            timeout_seconds=payload.timeout_seconds, plan_sha256=payload.plan_sha256,
            staging_build_id=payload.staging_build_id, staging_sha256=payload.staging_sha256,
            manifest_sha256=payload.manifest_sha256, candidate_id=payload.candidate_id,
            authorization_phrase=payload.authorization_phrase,
            operator_confirmed=payload.operator_confirmed,
        )
    except subprocess.TimeoutExpired as exc:
        raise HTTPException(status_code=400, detail="A Docker control command timed out during remote MCP probing.") from exc
    except (TargetRuntimeRejected, OSError, ValueError, json.JSONDecodeError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    runtime_validation = (
        dict(metadata.get("runtime_validation"))
        if isinstance(metadata.get("runtime_validation"), dict)
        else {}
    )
    runtime_validation["remote_mcp_probe_evidence"] = evidence
    findings = db.scalars(
        select(FindingRecord)
        .where(FindingRecord.scan_task_id == scan.id, FindingRecord.source == "AGENT")
        .order_by(FindingRecord.created_at.asc())
    ).all()
    trust_score = calculate_agent_trust_score(
        assets=metadata_dict_list(metadata, "assets"),
        permissions=metadata_dict_list(metadata, "permissions"),
        findings=[finding_record_report_payload(item) for item in findings],
        coverage=metadata.get("coverage") if isinstance(metadata.get("coverage"), dict) else {},
        intelligence=metadata.get("intelligence") if isinstance(metadata.get("intelligence"), dict) else {},
        dataflow=metadata.get("dataflow") if isinstance(metadata.get("dataflow"), dict) else {},
        runtime_validation=runtime_validation,
    )
    scan.scan_metadata = {
        **metadata, "runtime_validation": runtime_validation, "trust_score": trust_score,
    }
    db.commit()
    return {**evidence, "trust_score": trust_score}


@router.post("/projects/{project_id}/runtime-target-validation", status_code=201)
def validate_project_agent_runtime_target(
    project_id: UUID,
    payload: AgentTargetRuntimeRequest,
    db: Session = Depends(get_db),
) -> dict[str, object]:
    require_agent_fixture_modules(db, project_id)
    module = enabled_agent_module(db, project_id)
    profile = effective_agent_profile(module.config)
    if not profile.get("target_runtime_execution_enabled"):
        raise HTTPException(
            status_code=403,
            detail="Target Agent execution is disabled by the project policy.",
        )
    scan = latest_completed_agent_scan(db, str(project_id))
    if scan is None:
        raise HTTPException(status_code=400, detail="A completed AGENT scan is required before target validation.")
    metadata = scan.scan_metadata if isinstance(scan.scan_metadata, dict) else {}
    dataflow = metadata.get("dataflow") if isinstance(metadata.get("dataflow"), dict) else {}
    try:
        evidence = run_target_agent_validation(
            project_id=str(project_id),
            scan_task_id=str(scan.id),
            command=payload.command,
            image=payload.image,
            timeout_seconds=payload.timeout_seconds,
            plan_sha256=payload.plan_sha256,
            staging_build_id=payload.staging_build_id,
            staging_sha256=payload.staging_sha256,
            manifest_sha256=payload.manifest_sha256,
            authorization_phrase=payload.authorization_phrase,
            operator_confirmed=payload.operator_confirmed,
            dataflow=dataflow,
        )
    except subprocess.TimeoutExpired as exc:
        raise HTTPException(status_code=400, detail="A Docker control command timed out; the target was not approved as completed.") from exc
    except (TargetRuntimeRejected, OSError, ValueError, json.JSONDecodeError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    runtime_validation = (
        dict(metadata.get("runtime_validation"))
        if isinstance(metadata.get("runtime_validation"), dict)
        else {}
    )
    runtime_validation["evidence"] = evidence
    assets = metadata_dict_list(metadata, "assets")
    permissions = metadata_dict_list(metadata, "permissions")
    findings = db.scalars(
        select(FindingRecord)
        .where(FindingRecord.scan_task_id == scan.id, FindingRecord.source == "AGENT")
        .order_by(FindingRecord.created_at.asc())
    ).all()
    trust_score = calculate_agent_trust_score(
        assets=assets,
        permissions=permissions,
        findings=[finding_record_report_payload(item) for item in findings],
        coverage=metadata.get("coverage") if isinstance(metadata.get("coverage"), dict) else {},
        intelligence=metadata.get("intelligence") if isinstance(metadata.get("intelligence"), dict) else {},
        dataflow=dataflow,
        runtime_validation=runtime_validation,
    )
    scan.scan_metadata = {
        **metadata,
        "runtime_validation": runtime_validation,
        "trust_score": trust_score,
    }
    db.commit()
    return {**evidence, "trust_score": trust_score}


@router.get("/projects/{project_id}/scan-diff", response_model=AgentScanDiff)
def get_project_agent_scan_diff(
    project_id: UUID,
    target_scan_id: UUID | None = None,
    db: Session = Depends(get_db),
) -> AgentScanDiff:
    if db.get(ProjectRecord, str(project_id)) is None:
        raise HTTPException(status_code=404, detail="Project not found")
    target = resolve_agent_scan(db, str(project_id), target_scan_id)
    if target is None:
        raise HTTPException(status_code=404, detail="No completed AGENT scan found")
    base = db.scalar(
        select(ScanTaskRecord)
        .where(
            ScanTaskRecord.project_id == str(project_id),
            ScanTaskRecord.scan_type == "agent",
            ScanTaskRecord.status == ScanStatus.completed.value,
            ScanTaskRecord.created_at < target.created_at,
        )
        .order_by(ScanTaskRecord.created_at.desc())
        .limit(1)
    )
    return build_agent_scan_diff(project_id, target, base)


@router.get("/projects/{project_id}/audit-diff", response_model=AgentOfflineAuditDiff)
def get_project_agent_audit_diff(
    project_id: UUID,
    target_scan_id: UUID | None = None,
    db: Session = Depends(get_db),
) -> AgentOfflineAuditDiff:
    if db.get(ProjectRecord, str(project_id)) is None:
        raise HTTPException(status_code=404, detail="Project not found")
    target = resolve_agent_scan(db, str(project_id), target_scan_id)
    if target is None:
        raise HTTPException(status_code=404, detail="No completed AGENT scan found")
    base = previous_completed_agent_scan(db, project_id, target)
    return build_agent_audit_diff(project_id, target, base)


@router.get("/projects/{project_id}/gate")
def get_project_agent_gate(project_id: UUID, db: Session = Depends(get_db)) -> dict[str, object]:
    if db.get(ProjectRecord, str(project_id)) is None:
        raise HTTPException(status_code=404, detail="Project not found")
    scan = latest_completed_agent_scan(db, str(project_id))
    if scan is None:
        raise HTTPException(status_code=404, detail="No completed AGENT scan found")
    metadata = scan.scan_metadata or {}
    gate = metadata.get("quality_gate") if isinstance(metadata.get("quality_gate"), dict) else {}
    return {"project_id": str(project_id), "scan_task_id": str(scan.id), **gate}


@router.get("/projects/{project_id}/report")
def get_project_agent_report(
    project_id: UUID,
    scan_task_id: UUID | None = None,
    db: Session = Depends(get_db),
) -> dict[str, object]:
    scan = resolve_agent_scan(db, str(project_id), scan_task_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="No completed AGENT scan found")
    return build_agent_report(project_id, scan, db)


@router.get("/projects/{project_id}/sarif")
def get_project_agent_sarif(
    project_id: UUID,
    scan_task_id: UUID | None = None,
    db: Session = Depends(get_db),
) -> JSONResponse:
    report = get_project_agent_report(project_id, scan_task_id, db)
    payload = build_agent_sarif(report["findings"], str(report["scan_task_id"]))
    return JSONResponse(payload, headers={"Content-Disposition": 'attachment; filename="agent-results.sarif"'})


@router.get("/projects/{project_id}/report.html", response_class=HTMLResponse)
def get_project_agent_report_html(
    project_id: UUID,
    scan_task_id: UUID | None = None,
    db: Session = Depends(get_db),
) -> HTMLResponse:
    report = get_project_agent_report(project_id, scan_task_id, db)
    return HTMLResponse(
        build_agent_html_report(report),
        headers={"Content-Disposition": 'attachment; filename="agent-report.html"'},
    )


@router.get("/projects/{project_id}/ci-config")
def get_project_agent_ci_config(project_id: UUID, db: Session = Depends(get_db)) -> dict[str, object]:
    profile = effective_agent_profile(enabled_agent_module(db, project_id).config)
    return {
        "project_id": str(project_id),
        "profile": profile,
        "command": "python scripts/agent_ci.py --source . --profile agent-ci-config.json --json agent-result.json --sarif agent-result.sarif --html agent-report.html --fail-on-block",
        "offline": True,
        "exit_codes": {"0": "gate passed", "1": "gate blocked", "2": "configuration or scan error"},
        "limitations": "The local CI scanner performs static analysis only and does not connect to or execute Agent, MCP, plugin, or tool code.",
    }


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
    adapter_coverage: dict[str, dict[str, object]] = {}
    for asset in assets:
        asset_types[asset.asset_type] = asset_types.get(asset.asset_type, 0) + 1
        findings_by_asset_type[asset.asset_type] = findings_by_asset_type.get(asset.asset_type, 0) + asset.finding_count
        adapter = asset.metadata.get("config_adapter") if isinstance(asset.metadata, dict) else None
        adapter = adapter if isinstance(adapter, dict) else {}
        adapter_id = str(adapter.get("id") or "unclassified")
        item = adapter_coverage.setdefault(adapter_id, {
            "asset_count": 0,
            "parsed_asset_count": 0,
            "failed_asset_count": 0,
            "label": str(adapter.get("label") or "未分类配置"),
            "validation_level": str(adapter.get("validation_level") or "unknown"),
            "status": str(adapter.get("status") or "unknown"),
            "schema_reference_count": 0,
            "schema_references_not_validated": 0,
            "limitation": str(adapter.get("limitation") or "未记录"),
        })
        item["asset_count"] = int(item["asset_count"]) + 1
        item["parsed_asset_count"] = int(item["parsed_asset_count"]) + int(asset.status == "parsed")
        item["failed_asset_count"] = int(item["failed_asset_count"]) + int(asset.status == "failed")
        schema_declared = adapter.get("schema_reference_declared") is True
        schema_not_validated = adapter.get("schema_reference_validation") == "not-fetched"
        item["schema_reference_count"] = int(item["schema_reference_count"]) + int(schema_declared)
        item["schema_references_not_validated"] = int(item["schema_references_not_validated"]) + int(schema_not_validated)
    return AgentScanCoverage(
        discovered_asset_count=len(assets),
        parsed_asset_count=sum(asset.status == "parsed" for asset in assets),
        failed_asset_count=sum(asset.status == "failed" for asset in assets),
        skipped_file_count=skipped_file_count,
        findings_by_asset_type=findings_by_asset_type,
        asset_types=asset_types,
        adapter_coverage=adapter_coverage,
        generic_parser_asset_count=sum(
            int(item.get("asset_count") or 0)
            for item in adapter_coverage.values()
            if item.get("status") == "generic"
        ),
        schema_references_not_validated=sum(
            int(item.get("schema_references_not_validated") or 0)
            for item in adapter_coverage.values()
        ),
    )


def governed_asset_payloads(assets: list[AgentAsset], findings: list[AgentFinding]) -> list[dict[str, object]]:
    finding_counts: dict[str, int] = {}
    for finding in findings:
        finding_counts[finding.file_path] = finding_counts.get(finding.file_path, 0) + 1
    payloads: list[dict[str, object]] = []
    for asset in assets:
        item = asset_to_dict(asset)
        item["finding_count"] = finding_counts.get(asset.path, 0)
        payloads.append(item)
    return payloads


def findings_by_asset_type(assets: list[dict[str, object]]) -> dict[str, int]:
    result: dict[str, int] = {}
    for asset in assets:
        asset_type = str(asset.get("asset_type") or "unknown")
        result[asset_type] = result.get(asset_type, 0) + int(asset.get("finding_count") or 0)
    return result


def agent_finding_payload(finding: AgentFinding, status: str) -> dict[str, object]:
    return {
        "rule_id": finding.rule_id,
        "title": finding.title,
        "severity": finding.severity.value,
        "file_path": finding.file_path,
        "line_start": finding.line_start,
        "line_end": finding.line_end,
        "evidence": finding.evidence,
        "category": finding.category,
        "description": finding.description,
        "remediation": finding.remediation,
        "trust_impact": finding.trust_impact,
        "status": status,
    }


def scan_finding_identities(db: Session, scan: ScanTaskRecord | None) -> set[str]:
    if scan is None:
        return set()
    records = db.scalars(
        select(FindingRecord).where(FindingRecord.scan_task_id == scan.id, FindingRecord.source == "AGENT")
    ).all()
    return {
        finding_identity({
            "rule_id": item.rule_id,
            "file_path": item.file_path,
            "line_start": item.line_start,
            "title": item.title,
        })
        for item in records
    }


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
        "name": asset.name,
        "version": asset.version,
        "publisher": asset.publisher,
        "transport": asset.transport,
        "entrypoint": asset.entrypoint,
        "declared_tools": asset.declared_tools,
        "declared_resources": asset.declared_resources,
        "declared_prompts": asset.declared_prompts,
        "permission_count": len(asset.permissions),
        "provenance": [provenance_to_dict(item) for item in asset.provenance],
        "file_sha256": asset.file_sha256,
        "directory_sha256": asset.directory_sha256,
        "integrity_status": asset.integrity_status,
        "integrity_issues": asset.integrity_issues,
        "metadata": asset.metadata,
    }


def provenance_to_dict(item) -> dict[str, object]:
    return {
        "subject": item.subject,
        "package_name": item.package_name,
        "package_version": item.package_version,
        "source_type": item.source_type,
        "source_ref": item.source_ref,
        "installation_method": item.installation_method,
        "version_status": item.version_status,
        "publisher_claim": item.publisher_claim,
        "publisher_status": item.publisher_status,
        "source_visibility": item.source_visibility,
        "authentication_status": item.authentication_status,
        "onboarding_status": item.onboarding_status,
        "connection_status": item.connection_status,
        "issues": item.issues,
    }


def permission_to_dict(permission: AgentPermission) -> dict[str, str]:
    return {
        "asset_path": permission.asset_path,
        "subject": permission.subject,
        "capability": permission.capability,
        "access": permission.access,
        "resource_type": permission.resource_type,
        "scope": permission.scope,
        "approval": permission.approval,
        "risk_level": permission.risk_level,
        "source": permission.source,
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
        gate_decision=(metadata.get("quality_gate") or {}).get("decision") if isinstance(metadata.get("quality_gate"), dict) else None,
        audit_summary=audit_history_summary(metadata.get("audit")),
    )


def agent_scan_snapshot(project_id: UUID, scan: ScanTaskRecord) -> AgentScanSnapshot:
    metadata = scan.scan_metadata or {}
    assets = metadata.get("assets") if isinstance(metadata.get("assets"), list) else []
    permissions = metadata.get("permissions") if isinstance(metadata.get("permissions"), list) else []
    skipped_files = metadata.get("skipped_files") if isinstance(metadata.get("skipped_files"), list) else []
    return AgentScanSnapshot(
        project_id=project_id,
        scan_task_id=UUID(str(scan.id)),
        created_at=scan.finished_at or scan.created_at,
        source_path=metadata.get("source_path"),
        rule_version=metadata.get("rule_version"),
        assets=[AgentAssetResult(**item) for item in assets if isinstance(item, dict)],
        permissions=[AgentPermissionResult(**item) for item in permissions if isinstance(item, dict)],
        skipped_files=[item for item in skipped_files if isinstance(item, dict)],
        quality_gate=metadata.get("quality_gate") if isinstance(metadata.get("quality_gate"), dict) else {},
        intelligence=metadata.get("intelligence") if isinstance(metadata.get("intelligence"), dict) else {},
        dataflow=metadata.get("dataflow") if isinstance(metadata.get("dataflow"), dict) else {},
        audit=metadata.get("audit") if isinstance(metadata.get("audit"), dict) else {},
        runtime_validation=metadata.get("runtime_validation") if isinstance(metadata.get("runtime_validation"), dict) else {},
        trust_score=metadata.get("trust_score") if isinstance(metadata.get("trust_score"), dict) else {},
    )


def resolve_agent_scan(db: Session, project_id: str, scan_id: UUID | None) -> ScanTaskRecord | None:
    if scan_id is None:
        return latest_completed_agent_scan(db, project_id)
    scan = db.get(ScanTaskRecord, str(scan_id))
    if (
        scan is None
        or scan.project_id != project_id
        or scan.scan_type != "agent"
        or scan.status != ScanStatus.completed.value
    ):
        raise HTTPException(status_code=404, detail="Completed AGENT scan not found")
    return scan


def build_agent_scan_diff(
    project_id: UUID,
    target: ScanTaskRecord,
    base: ScanTaskRecord | None,
) -> AgentScanDiff:
    target_metadata = target.scan_metadata or {}
    target_assets = metadata_dict_list(target_metadata, "assets")
    target_permissions = metadata_dict_list(target_metadata, "permissions")
    if base is None:
        return AgentScanDiff(
            project_id=project_id,
            target_scan_id=UUID(str(target.id)),
            has_comparison=False,
        )

    base_metadata = base.scan_metadata or {}
    base_assets = metadata_dict_list(base_metadata, "assets")
    base_permissions = metadata_dict_list(base_metadata, "permissions")
    asset_changes = compare_agent_assets(base_assets, target_assets)
    permission_changes = compare_agent_permissions(base_permissions, target_permissions)
    return AgentScanDiff(
        project_id=project_id,
        target_scan_id=UUID(str(target.id)),
        base_scan_id=UUID(str(base.id)),
        has_comparison=True,
        summary=AgentScanDiffSummary(
            assets_added=sum(item.change_type == "added" for item in asset_changes),
            assets_removed=sum(item.change_type == "removed" for item in asset_changes),
            assets_changed=sum(item.change_type == "changed" for item in asset_changes),
            permissions_added=sum(item.change_type == "added" for item in permission_changes),
            permissions_removed=sum(item.change_type == "removed" for item in permission_changes),
            permissions_changed=sum(item.change_type == "changed" for item in permission_changes),
            source_changes=sum("provenance" in item.changes for item in asset_changes),
            integrity_changes=sum(any(field in {
                "file_sha256", "directory_sha256", "integrity_status", "integrity_issues",
            } for field in item.changes) for item in asset_changes),
        ),
        assets=asset_changes,
        permissions=permission_changes,
    )


def previous_completed_agent_scan(
    db: Session, project_id: UUID, target: ScanTaskRecord,
) -> ScanTaskRecord | None:
    return db.scalar(
        select(ScanTaskRecord)
        .where(
            ScanTaskRecord.project_id == str(project_id),
            ScanTaskRecord.scan_type == "agent",
            ScanTaskRecord.status == ScanStatus.completed.value,
            ScanTaskRecord.created_at < target.created_at,
        )
        .order_by(ScanTaskRecord.created_at.desc())
        .limit(1)
    )


def build_agent_audit_diff(
    project_id: UUID,
    target: ScanTaskRecord,
    base: ScanTaskRecord | None,
) -> AgentOfflineAuditDiff:
    target_metadata = target.scan_metadata or {}
    base_metadata = base.scan_metadata or {} if base else {}
    comparison = compare_agent_offline_audits(
        base_metadata.get("audit") if isinstance(base_metadata.get("audit"), dict) else None,
        target_metadata.get("audit") if isinstance(target_metadata.get("audit"), dict) else None,
    )
    return AgentOfflineAuditDiff(
        project_id=project_id,
        target_scan_id=UUID(str(target.id)),
        base_scan_id=UUID(str(base.id)) if base else None,
        **comparison,
    )


def audit_history_summary(value: object) -> dict[str, object]:
    audit = value if isinstance(value, dict) else {}
    summary = audit.get("summary") if isinstance(audit.get("summary"), dict) else {}
    available = audit.get("schema") == "ai-security-platform.agent-offline-audit/v1"
    return {
        "available": available,
        "schema": audit.get("schema") if available else None,
        "mode": audit.get("mode") if available else None,
        "model_status": audit.get("model_status") if available else None,
        "external_model_invoked": audit.get("external_model_invoked") is True if available else False,
        "review_item_count": int(summary.get("review_item_count") or 0) if available else 0,
        "active_finding_count": int(summary.get("active_finding_count") or 0) if available else 0,
    }


def metadata_dict_list(metadata: dict, key: str) -> list[dict[str, object]]:
    value = metadata.get(key)
    return [item for item in value if isinstance(item, dict)] if isinstance(value, list) else []


def compare_agent_assets(
    base_assets: list[dict[str, object]],
    target_assets: list[dict[str, object]],
) -> list[AgentAssetDiffItem]:
    base_map = {asset_identity(item): item for item in base_assets}
    target_map = {asset_identity(item): item for item in target_assets}
    results: list[AgentAssetDiffItem] = []
    for identity in sorted(base_map.keys() | target_map.keys()):
        previous = base_map.get(identity)
        current = target_map.get(identity)
        sample = current or previous or {}
        if previous is None:
            change_type = "added"
            changes = ["asset-added"]
        elif current is None:
            change_type = "removed"
            changes = ["asset-removed"]
        else:
            changes = changed_asset_fields(previous, current)
            if not changes:
                continue
            change_type = "changed"
        results.append(AgentAssetDiffItem(
            identity=identity,
            change_type=change_type,
            path=str(sample.get("path") or ""),
            asset_type=str(sample.get("asset_type") or "unknown"),
            changes=changes,
        ))
    return results


def changed_asset_fields(previous: dict[str, object], current: dict[str, object]) -> list[str]:
    fields = (
        "status",
        "parser",
        "version",
        "publisher",
        "transport",
        "entrypoint",
        "declared_tools",
        "declared_resources",
        "declared_prompts",
        "permission_count",
        "provenance",
        "file_sha256",
        "directory_sha256",
        "integrity_status",
        "integrity_issues",
    )
    return [field for field in fields if previous.get(field) != current.get(field)]


def compare_agent_permissions(
    base_permissions: list[dict[str, object]],
    target_permissions: list[dict[str, object]],
) -> list[AgentPermissionDiffItem]:
    base_map = {permission_identity(item): item for item in base_permissions}
    target_map = {permission_identity(item): item for item in target_permissions}
    results: list[AgentPermissionDiffItem] = []
    for identity in sorted(base_map.keys() & target_map.keys()):
        previous = base_map[identity]
        current = target_map[identity]
        if previous == current:
            continue
        permission = AgentPermissionResult(**current)
        results.append(AgentPermissionDiffItem(
            identity=identity,
            change_type="changed",
            direction=permission_change_direction(previous, current),
            permission=permission,
        ))
    for identity in sorted(target_map.keys() - base_map.keys()):
        permission = AgentPermissionResult(**target_map[identity])
        results.append(AgentPermissionDiffItem(
            identity=identity,
            change_type="added",
            direction="expanded",
            permission=permission,
        ))
    for identity in sorted(base_map.keys() - target_map.keys()):
        permission = AgentPermissionResult(**base_map[identity])
        results.append(AgentPermissionDiffItem(
            identity=identity,
            change_type="removed",
            direction="reduced",
            permission=permission,
        ))
    return results


def asset_identity(asset: dict[str, object]) -> str:
    return f"{asset.get('asset_type') or 'unknown'}::{asset.get('path') or ''}"


def permission_identity(permission: dict[str, object]) -> str:
    fields = (
        "asset_path",
        "subject",
        "capability",
        "access",
        "resource_type",
        "scope",
    )
    return "::".join(str(permission.get(field) or "") for field in fields)


def permission_change_direction(previous: dict[str, object], current: dict[str, object]) -> str:
    approval_rank = {"not-required": 0, "unknown": 1, "required": 2}
    previous_approval = str(previous.get("approval") or "unknown")
    current_approval = str(current.get("approval") or "unknown")
    if approval_rank.get(current_approval, 1) > approval_rank.get(previous_approval, 1):
        return "reduced"
    if approval_rank.get(current_approval, 1) < approval_rank.get(previous_approval, 1):
        return "expanded"
    return "changed"


def enabled_agent_module(db: Session, project_id: UUID) -> ProjectModuleRecord:
    if db.get(ProjectRecord, str(project_id)) is None:
        raise HTTPException(status_code=404, detail="Project not found")
    module = db.scalar(
        select(ProjectModuleRecord).where(
            ProjectModuleRecord.project_id == str(project_id),
            ProjectModuleRecord.module_key == ModuleKey.agent.value,
            ProjectModuleRecord.enabled.is_(True),
        )
    )
    if module is None:
        raise HTTPException(status_code=400, detail="AGENT module is not enabled for this project")
    return module


def require_agent_fixture_modules(db: Session, project_id: UUID) -> None:
    enabled_agent_module(db, project_id)
    sandbox = db.scalar(
        select(ProjectModuleRecord).where(
            ProjectModuleRecord.project_id == str(project_id),
            ProjectModuleRecord.module_key == ModuleKey.sandbox.value,
            ProjectModuleRecord.enabled.is_(True),
        )
    )
    if sandbox is None:
        raise HTTPException(status_code=400, detail="SANDBOX module is not enabled for this project")


def mutation_actor(request: Request, payload: dict[str, object]) -> str:
    identity = getattr(request.state, "identity", None)
    if identity is not None and getattr(identity, "username", None):
        return str(identity.username)[:120]
    header_actor = request.headers.get("X-Actor")
    return str(header_actor or payload.get("actor") or "local-operator").strip()[:120] or "local-operator"


def build_agent_report(project_id: UUID, scan: ScanTaskRecord, db: Session) -> dict[str, object]:
    if scan.project_id != str(project_id) or scan.scan_type != "agent":
        raise HTTPException(status_code=404, detail="Matching AGENT scan not found")
    metadata = scan.scan_metadata or {}
    findings = db.scalars(
        select(FindingRecord)
        .where(FindingRecord.project_id == str(project_id), FindingRecord.source == "AGENT", FindingRecord.scan_task_id == scan.id)
        .order_by(FindingRecord.created_at.asc())
    ).all()
    finding_payloads = [finding_record_report_payload(item) for item in findings]
    assets = metadata_dict_list(metadata, "assets")
    permissions = metadata_dict_list(metadata, "permissions")
    provenance_count = sum(
        len(item.get("provenance")) if isinstance(item.get("provenance"), list) else 0
        for item in assets
    )
    severity = {key: sum(1 for item in findings if item.severity == key) for key in ("critical", "high", "medium", "low", "info")}
    status = {}
    for item in findings:
        status[item.status] = status.get(item.status, 0) + 1
    base = db.scalar(
        select(ScanTaskRecord)
        .where(
            ScanTaskRecord.project_id == str(project_id),
            ScanTaskRecord.scan_type == "agent",
            ScanTaskRecord.status == ScanStatus.completed.value,
            ScanTaskRecord.created_at < scan.created_at,
        )
        .order_by(ScanTaskRecord.created_at.desc())
        .limit(1)
    )
    runtime_metadata = metadata.get("runtime_validation") if isinstance(metadata.get("runtime_validation"), dict) else {}
    target_evidence_present = isinstance(runtime_metadata.get("evidence"), dict)
    return {
        "project_id": str(project_id),
        "scan_task_id": str(scan.id),
        "generated_at": datetime.utcnow().isoformat(),
        "source_path": metadata.get("source_path"),
        "rule_version": metadata.get("rule_version"),
        "summary": {
            "asset_count": len(assets),
            "provenance_count": provenance_count,
            "integrity_recorded_count": sum(item.get("integrity_status") == "recorded" for item in assets),
            "integrity_partial_count": sum(item.get("integrity_status") == "partial" for item in assets),
            "permission_count": len(permissions),
            "finding_count": len(findings),
            "suppressed_count": int(metadata.get("suppressed_count") or 0),
            "severity": severity,
            "status": status,
            "coverage": metadata.get("coverage") or {},
            "dataflow": (
                (metadata.get("dataflow") or {}).get("summary", {})
                if isinstance(metadata.get("dataflow"), dict)
                else {}
            ),
        },
        "assets": assets,
        "permissions": permissions,
        "findings": finding_payloads,
        "quality_gate": metadata.get("quality_gate") or {},
        "intelligence": metadata.get("intelligence") or {},
        "dataflow": metadata.get("dataflow") or {},
        "audit": metadata.get("audit") or {},
        "audit_comparison": build_agent_audit_diff(project_id, scan, base).model_dump(mode="json"),
        "runtime_validation": metadata.get("runtime_validation") or {},
        "trust_score": metadata.get("trust_score") or {},
        "semantic_diff": build_agent_scan_diff(project_id, scan, base).model_dump(mode="json"),
        "profile": report_profile_summary(metadata.get("agent_profile")),
        "skipped_files": metadata.get("skipped_files") or [],
        "capability_boundaries": [
            "The scan is generated from local static configuration and instruction analysis; target execution is a separate explicitly confirmed action.",
            (
                "This report includes one separately confirmed target runtime evidence record with explicitly limited telemetry."
                if target_evidence_present
                else "No project Agent, MCP server, plugin or tool was executed for this report."
            ),
            "Approved exceptions and allowlists are governance decisions and remain visible in finding status and profile audit history.",
            "SHA-256 values prove only that local bytes were stable between scans; they do not authenticate a publisher or remote package.",
            "Offline intelligence results are limited to configured local sources; checked-no-match is not proof that a package is vulnerability-free.",
            "Data-flow paths are static, confidence-labelled relationships and are not proof of observed runtime execution.",
            "The offline audit is a local rule-based review draft. It does not invoke an external model or change findings, governance decisions, quality gates, or trust scores.",
            "Audit comparison is limited to local static review candidates. A not-current-candidate label is not proof of remediation, safety, runtime absence, or non-exploitability.",
            "The Agent runtime plan remains preflight-only; any target evidence is separately bound to an exact D-drive staging digest and uses --pull=never.",
        ],
    }


def finding_record_report_payload(record: FindingRecord) -> dict[str, object]:
    review = record.ai_review or {}
    return {
        "id": str(record.id),
        "rule_id": record.rule_id,
        "title": record.title,
        "severity": record.severity,
        "file_path": record.file_path,
        "line_start": record.line_start,
        "line_end": record.line_end,
        "evidence": record.evidence,
        "status": record.status,
        "category": review.get("category"),
        "description": review.get("description") or review.get("summary"),
        "remediation": review.get("remediation"),
        "trust_impact": review.get("trust_impact"),
        "governance_exception_id": review.get("governance_exception_id"),
        "governance_disposition": review.get("governance_disposition"),
    }


def report_profile_summary(value: object) -> dict[str, object]:
    profile = value if isinstance(value, dict) else {}
    return {
        "profile_version": profile.get("profile_version"),
        "rule_version": profile.get("rule_version"),
        "disabled_rule_ids": profile.get("disabled_rule_ids") or [],
        "excluded_paths": profile.get("excluded_paths") or [],
        "permission_allowlist": profile.get("permission_allowlist") or [],
        "required_approval_capabilities": profile.get("required_approval_capabilities") or [],
        "target_runtime_execution_enabled": bool(profile.get("target_runtime_execution_enabled")),
        "quality_gate": profile.get("quality_gate") or {},
        "exceptions": profile.get("exceptions") or [],
        "audit_log": profile.get("audit_log") or [],
    }


def mark_agent_scan_failed(scan: ScanTaskRecord, detail: str) -> None:
    metadata = dict(scan.scan_metadata or {})
    metadata.update({"stage": "failed", "detail": detail})
    scan.scan_metadata = metadata
    scan.status = ScanStatus.failed.value
    scan.finished_at = datetime.utcnow()
