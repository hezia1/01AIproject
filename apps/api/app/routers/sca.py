from datetime import datetime
from dataclasses import replace
from html import escape
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import HTMLResponse
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from app.db import get_db
from app.db_models import (
    ComponentRecord,
    FindingRecord,
    ProjectModuleRecord,
    ProjectRecord,
    ScanTaskRecord,
    ScaPolicyAuditRecord,
    ScaPolicyExceptionRecord,
    ScaPolicyOverrideRecord,
    ScaVexStatementRecord,
)
from app.services.sca_license_policy import load_license_policies
from app.services.sca_osv_mirror import import_osv_mirror, osv_mirror_status
from app.services.sca_intelligence import import_intelligence_entries, intelligence_status
from app.services.sca_gate_policy import effective_gate_policy, validate_gate_config
from app.services.sca_policy_overrides import effective_license_policies, effective_vulnerability_rules
from app.services.sca_vulnerability_rules import load_vulnerability_rules
from app.models import (
    Component,
    ModuleKey,
    ScaReport,
    ScaReportComponent,
    ScaScanDiffItem,
    ScaScanDiffResult,
    ScaScanDiffSummary,
    ScaScanHistoryItem,
    ScaScanRequest,
    ScaScanResult,
    ScaToolHealth,
    ScaToolHealthCheck,
    ScaToolStatus,
    ScanStatus,
)
from app.repositories.mappers import component_to_schema
from app.services.sca_parser import ParsedComponent, dedupe_components, parse_dependency_tree
from app.services.sca_risk_analyzer import analyze_components
from app.services.sca_dependency_graph import build_dependency_graph, dependency_snapshot_edges
from app.services.sca_native_tree import native_dependency_source_summary
from app.services.sca_python_environment import environment_metadata, inspect_python_environment
from app.services.sca_artifacts import collect_artifact_hashes
from app.services.sca_sbom import build_cyclonedx_sbom, build_spdx_sbom
from app.services.sca_tool_scanner import ToolScanResult, check_syft_grype_health, scan_with_syft_grype

router = APIRouter()


@router.get("/policies")
def list_sca_policies(project_id: UUID | None = None, db: Session = Depends(get_db)) -> dict[str, object]:
    if project_id is not None and db.get(ProjectRecord, str(project_id)) is None:
        raise HTTPException(status_code=404, detail="Project not found")
    overrides = scoped_policy_overrides(db, project_id)
    vulnerability_rules = effective_vulnerability_rules(load_vulnerability_rules(), overrides)
    license_policies = effective_license_policies(load_license_policies(), overrides)
    gate_policy = effective_gate_policy(overrides)
    return {
        "scope": "project" if project_id else "platform",
        "vulnerability_rules": [
            {
                "id": item.vulnerability_id,
                "ecosystem": item.ecosystem,
                "package": item.package,
                "enabled": item.enabled,
                "severity": item.severity.value,
                "affected": item.affected,
                "fixed_version": item.fixed_version,
                "source": policy_source(item.vulnerability_id, "vulnerability", overrides),
            }
            for item in vulnerability_rules
        ],
        "license_policies": [
            {
                "id": item.policy_id,
                "policy": item.policy,
                "keywords": list(item.keywords),
                "approval_required": item.approval_required,
                "enabled": bool(item.keywords),
                "source": policy_source(item.policy_id, "license", overrides),
            }
            for item in license_policies
        ],
        "gate_policy": {**gate_policy, "source": policy_source("default", "gate", overrides)},
        "override_count": len(overrides),
    }


@router.post("/policies/overrides", status_code=201)
def create_policy_override(payload: dict[str, object], db: Session = Depends(get_db)) -> dict[str, object]:
    project_id = parse_optional_project_id(payload.get("project_id"), db)
    policy_kind = str(payload.get("policy_kind") or "").strip().lower()
    policy_id = str(payload.get("policy_id") or "").strip()
    if policy_kind not in {"vulnerability", "license", "gate"} or not policy_id:
        raise HTTPException(status_code=400, detail="policy_kind (vulnerability|license|gate) and policy_id are required")
    config = payload.get("config")
    if config is not None and not isinstance(config, dict):
        raise HTTPException(status_code=400, detail="config must be an object")
    item = ScaPolicyOverrideRecord(
        project_id=project_id,
        policy_kind=policy_kind,
        policy_id=policy_id,
        enabled=bool(payload.get("enabled", True)),
        config=config or {},
        actor=string_or_none(payload.get("actor")),
        change_note=string_or_none(payload.get("change_note")),
    )
    try:
        validate_policy_override(item, [*scoped_policy_overrides(db, UUID(project_id) if project_id else None), item])
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    db.add(item)
    db.flush()
    record_policy_audit(db, item, "policy_override_created")
    db.commit()
    db.refresh(item)
    return policy_override_payload(item)


@router.patch("/policies/overrides/{override_id}")
def update_policy_override(override_id: UUID, payload: dict[str, object], db: Session = Depends(get_db)) -> dict[str, object]:
    item = db.get(ScaPolicyOverrideRecord, str(override_id))
    if item is None:
        raise HTTPException(status_code=404, detail="SCA policy override not found")
    if "enabled" in payload:
        item.enabled = bool(payload["enabled"])
    if "config" in payload:
        if not isinstance(payload["config"], dict):
            raise HTTPException(status_code=400, detail="config must be an object")
        item.config = dict(payload["config"])
    if "actor" in payload:
        item.actor = string_or_none(payload.get("actor"))
    if "change_note" in payload:
        item.change_note = string_or_none(payload.get("change_note"))
    item.updated_at = datetime.utcnow()
    try:
        validate_policy_override(item, scoped_policy_overrides(db, UUID(item.project_id) if item.project_id else None))
    except ValueError as exc:
        db.rollback()
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    record_policy_audit(db, item, "policy_override_updated")
    db.commit()
    db.refresh(item)
    return policy_override_payload(item)


@router.get("/projects/{project_id}/policy-audit")
def list_policy_audit(project_id: UUID, db: Session = Depends(get_db)) -> list[dict[str, object]]:
    if db.get(ProjectRecord, str(project_id)) is None:
        raise HTTPException(status_code=404, detail="Project not found")
    records = db.scalars(
        select(ScaPolicyAuditRecord)
        .where(or_(ScaPolicyAuditRecord.project_id.is_(None), ScaPolicyAuditRecord.project_id == str(project_id)))
        .order_by(ScaPolicyAuditRecord.created_at.desc())
        .limit(100)
    ).all()
    return [
        {
            "id": str(record.id),
            "event_type": record.event_type,
            "actor": record.actor,
            "details": record.details or {},
            "created_at": record.created_at,
        }
        for record in records
    ]


@router.get("/osv-mirror/status")
def get_osv_mirror_status() -> dict[str, object]:
    return osv_mirror_status()


@router.post("/osv-mirror/import", status_code=201)
def import_local_osv_mirror(payload: dict[str, object]) -> dict[str, object]:
    entries = payload.get("entries")
    if not isinstance(entries, list):
        raise HTTPException(status_code=400, detail="entries must be a JSON array")
    try:
        return import_osv_mirror(entries, string_or_none(payload.get("source")))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/intelligence/status")
def get_sca_intelligence_status() -> dict[str, object]:
    return intelligence_status()


@router.post("/intelligence/import", status_code=201)
def import_sca_intelligence(payload: dict[str, object]) -> dict[str, object]:
    entries = payload.get("entries")
    if not isinstance(entries, list):
        raise HTTPException(status_code=400, detail="entries must be a JSON array")
    try:
        return import_intelligence_entries(entries, string_or_none(payload.get("source")))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/projects/{project_id}/exceptions")
def list_policy_exceptions(project_id: UUID, db: Session = Depends(get_db)) -> list[dict[str, object]]:
    if db.get(ProjectRecord, str(project_id)) is None:
        raise HTTPException(status_code=404, detail="Project not found")
    return [exception_payload(item) for item in db.scalars(select(ScaPolicyExceptionRecord).where(ScaPolicyExceptionRecord.project_id == str(project_id)).order_by(ScaPolicyExceptionRecord.created_at.desc())).all()]


@router.post("/projects/{project_id}/exceptions", status_code=201)
def create_policy_exception(project_id: UUID, payload: dict[str, object], db: Session = Depends(get_db)) -> dict[str, object]:
    if db.get(ProjectRecord, str(project_id)) is None:
        raise HTTPException(status_code=404, detail="Project not found")
    required = ("ecosystem", "package_name", "exception_type", "reason")
    if any(not str(payload.get(key) or "").strip() for key in required):
        raise HTTPException(status_code=400, detail="ecosystem, package_name, exception_type and reason are required")
    item = ScaPolicyExceptionRecord(
        project_id=str(project_id), ecosystem=str(payload["ecosystem"]), package_name=str(payload["package_name"]),
        package_version=str(payload.get("package_version") or "") or None, exception_type=str(payload["exception_type"]),
        reason=str(payload["reason"]), requester=string_or_none(payload.get("requester")),
        requester_role=exception_role(payload.get("requester_role")), expires_at=parse_exception_date(payload.get("expires_at")),
        approval_history=[{"status": "pending", "actor": string_or_none(payload.get("requester")), "role": exception_role(payload.get("requester_role")), "at": datetime.utcnow().isoformat()}],
    )
    db.add(item); db.commit(); db.refresh(item)
    return exception_payload(item)


@router.patch("/exceptions/{exception_id}")
def update_policy_exception(exception_id: UUID, payload: dict[str, object], db: Session = Depends(get_db)) -> dict[str, object]:
    item = db.get(ScaPolicyExceptionRecord, str(exception_id))
    if item is None:
        raise HTTPException(status_code=404, detail="SCA policy exception not found")
    new_status = str(payload.get("status") or item.status)
    if new_status not in {"pending", "approved", "rejected", "revoked"}:
        raise HTTPException(status_code=400, detail="Unsupported exception status")
    actor_role = exception_role(payload.get("approver_role"))
    if new_status != item.status:
        validate_exception_transition(item.status, new_status, actor_role)
        history = list(item.approval_history or [])
        history.append({"status": new_status, "actor": string_or_none(payload.get("approver")), "role": actor_role, "note": string_or_none(payload.get("approval_note")), "at": datetime.utcnow().isoformat()})
        item.approval_history = history
        item.status = new_status
    for field in ("approver", "approval_note"):
        if field in payload: setattr(item, field, str(payload[field]) if payload[field] is not None else None)
    if "approver_role" in payload:
        item.approver_role = actor_role
    if "expires_at" in payload: item.expires_at = parse_exception_date(payload.get("expires_at"))
    item.updated_at = datetime.utcnow(); db.commit(); db.refresh(item)
    return exception_payload(item)


@router.get("/projects/{project_id}/vex")
def list_sca_vex(project_id: UUID, db: Session = Depends(get_db)) -> list[dict[str, object]]:
    if db.get(ProjectRecord, str(project_id)) is None:
        raise HTTPException(status_code=404, detail="Project not found")
    return [vex_payload(item) for item in db.scalars(select(ScaVexStatementRecord).where(ScaVexStatementRecord.project_id == str(project_id)).order_by(ScaVexStatementRecord.updated_at.desc())).all()]


@router.post("/projects/{project_id}/vex", status_code=201)
def create_sca_vex(project_id: UUID, payload: dict[str, object], db: Session = Depends(get_db)) -> dict[str, object]:
    if db.get(ProjectRecord, str(project_id)) is None:
        raise HTTPException(status_code=404, detail="Project not found")
    required = ("ecosystem", "package_name", "vulnerability_id", "status")
    if any(not string_or_none(payload.get(key)) for key in required):
        raise HTTPException(status_code=400, detail="ecosystem, package_name, vulnerability_id and status are required")
    status = str(payload["status"])
    if status not in {"not_affected", "affected", "fixed", "under_investigation"}:
        raise HTTPException(status_code=400, detail="Unsupported VEX status")
    item = ScaVexStatementRecord(
        project_id=str(project_id), ecosystem=str(payload["ecosystem"]), package_name=str(payload["package_name"]),
        package_version=string_or_none(payload.get("package_version")), vulnerability_id=str(payload["vulnerability_id"]), status=status,
        justification=string_or_none(payload.get("justification")), action_statement=string_or_none(payload.get("action_statement")),
        evidence=string_or_none(payload.get("evidence")), actor=string_or_none(payload.get("actor")), expires_at=parse_exception_date(payload.get("expires_at")),
    )
    db.add(item); db.commit(); db.refresh(item)
    return vex_payload(item)


@router.patch("/vex/{vex_id}")
def update_sca_vex(vex_id: UUID, payload: dict[str, object], db: Session = Depends(get_db)) -> dict[str, object]:
    item = db.get(ScaVexStatementRecord, str(vex_id))
    if item is None:
        raise HTTPException(status_code=404, detail="SCA VEX statement not found")
    if "status" in payload:
        status = str(payload["status"])
        if status not in {"not_affected", "affected", "fixed", "under_investigation"}:
            raise HTTPException(status_code=400, detail="Unsupported VEX status")
        item.status = status
    for field in ("justification", "action_statement", "evidence", "actor"):
        if field in payload:
            setattr(item, field, string_or_none(payload[field]))
    if "expires_at" in payload:
        item.expires_at = parse_exception_date(payload.get("expires_at"))
    item.updated_at = datetime.utcnow(); db.commit(); db.refresh(item)
    return vex_payload(item)


@router.get("/tool-health", response_model=ScaToolHealth)
def get_sca_tool_health() -> ScaToolHealth:
    health = check_syft_grype_health()
    return ScaToolHealth(
        status=health.status,
        recommended_grype_input=health.recommended_grype_input,
        checks=[
            ScaToolHealthCheck(
                name=check.name,
                status=check.status,
                detail=check.detail,
                remediation=check.remediation,
            )
            for check in health.checks
        ],
    )


@router.post("/scan", response_model=ScaScanResult)
def run_sca_scan(payload: ScaScanRequest, db: Session = Depends(get_db)) -> ScaScanResult:
    project = db.get(ProjectRecord, str(payload.project_id))
    if project is None:
        raise HTTPException(status_code=404, detail="Project not found")

    project_module = db.scalar(
        select(ProjectModuleRecord).where(
            ProjectModuleRecord.project_id == str(payload.project_id),
            ProjectModuleRecord.module_key == ModuleKey.sca.value,
            ProjectModuleRecord.enabled.is_(True),
        )
    )
    if project_module is None:
        raise HTTPException(status_code=400, detail="SCA module is not enabled for this project")

    scan = ScanTaskRecord(
        project_id=str(payload.project_id),
        scan_type="sca",
        status=ScanStatus.running.value,
        started_at=datetime.utcnow(),
    )
    db.add(scan)
    db.flush()

    try:
        parsed = parse_dependency_tree(payload.source_path)
        python_environment = inspect_python_environment(payload.source_path)
        tool_scan = scan_with_syft_grype(payload.source_path) if payload.enable_tool_scan else None
        tool_status = build_tool_status(payload.enable_tool_scan, tool_scan)
        parsed_components = merge_tool_components([*parsed.components, *python_environment.components], tool_scan)
        policy_overrides = scoped_policy_overrides(db, payload.project_id)
        vulnerability_rules = effective_vulnerability_rules(load_vulnerability_rules(), policy_overrides)
        license_policies = effective_license_policies(load_license_policies(), policy_overrides)
        gate_policy = effective_gate_policy(policy_overrides)
        analyzed_components = apply_tool_vulnerabilities(
            analyze_components(parsed_components, vulnerability_rules, license_policies),
            tool_scan,
        )
        records: list[ComponentRecord] = []
        for component in analyzed_components:
            record = ComponentRecord(
                project_id=str(payload.project_id),
                scan_task_id=scan.id,
                ecosystem=component.ecosystem,
                name=component.name,
                version=component.version,
                dependency_type=component.dependency_type,
                source_file=component.source_file,
                package_manager=component.package_manager,
                license=component.license,
                risk_status=component.risk_status,
                vulnerability_ids=component.vulnerability_ids or [],
                severity=component.severity,
                risk_summary=component.risk_summary,
                remediation=component.remediation,
                license_risk=component.license_risk,
                risk_source=component.risk_source,
                osv_checked=component.osv_checked,
                osv_error=component.osv_error,
                risk_metadata=component.risk_metadata or {},
            )
            db.add(record)
            records.append(record)
        db.flush()
        apply_approved_exceptions(db, str(payload.project_id), records)
        apply_active_vex_statements(db, str(payload.project_id), records)
        create_sca_findings(db, str(payload.project_id), scan.id, records)
        dependency_graph = build_dependency_graph(project, records)
        scan.scan_metadata = {
            "sca_tool_scan": tool_status.model_dump(),
            "python_environment": environment_metadata(python_environment),
            "osv_lookup": osv_lookup_metadata(analyzed_components),
            "osv_mirror": osv_mirror_status(),
            "intelligence": intelligence_status(),
            "artifact_hashes": collect_artifact_hashes(payload.source_path, parsed_components),
            "native_dependency_sources": native_dependency_source_summary(payload.source_path, dependency_graph["edges"]),
            "policy_snapshot": policy_snapshot(vulnerability_rules, license_policies, policy_overrides, gate_policy),
            "dependency_snapshot": {
                "captured_at": datetime.utcnow().isoformat(),
                "edges": dependency_graph["edges"],
                "summary": dependency_graph["summary"],
            },
        }

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

    return ScaScanResult(
        project_id=payload.project_id,
        scan_task_id=UUID(str(scan.id)),
        source_path=payload.source_path,
        scanned_files=parsed.scanned_files,
        component_count=len(records),
        components=[component_to_schema(record) for record in records],
        tool_status=tool_status,
    )


@router.get("/projects/{project_id}/components", response_model=list[Component])
def list_project_components(
    project_id: UUID,
    scan_task_id: UUID | None = None,
    db: Session = Depends(get_db),
) -> list[Component]:
    if db.get(ProjectRecord, str(project_id)) is None:
        raise HTTPException(status_code=404, detail="Project not found")

    records = load_project_components(db, project_id, scan_task_id)
    return [component_to_schema(record) for record in records]


@router.get("/projects/{project_id}/scan-history", response_model=list[ScaScanHistoryItem])
def list_project_sca_scan_history(project_id: UUID, db: Session = Depends(get_db)) -> list[ScaScanHistoryItem]:
    if db.get(ProjectRecord, str(project_id)) is None:
        raise HTTPException(status_code=404, detail="Project not found")

    scans = db.scalars(
        select(ScanTaskRecord)
        .where(ScanTaskRecord.project_id == str(project_id), ScanTaskRecord.scan_type == "sca")
        .order_by(ScanTaskRecord.created_at.desc())
    ).all()
    if not scans:
        return []

    component_counts = {
        scan_id: count
        for scan_id, count in db.execute(
            select(ComponentRecord.scan_task_id, func.count(ComponentRecord.id))
            .where(ComponentRecord.project_id == str(project_id), ComponentRecord.scan_task_id.is_not(None))
            .group_by(ComponentRecord.scan_task_id)
        ).all()
    }

    history: list[ScaScanHistoryItem] = []
    for scan in scans:
        components = load_project_components(db, project_id, UUID(str(scan.id)))
        history.append(
            ScaScanHistoryItem(
                scan_task_id=UUID(str(scan.id)),
                status=scan.status,
                started_at=scan.started_at,
                finished_at=scan.finished_at,
                created_at=scan.created_at,
                component_count=int(component_counts.get(scan.id, 0)),
                direct_dependency_count=sum(1 for component in components if component.dependency_type != "transitive"),
                transitive_dependency_count=sum(1 for component in components if component.dependency_type == "transitive"),
                critical_count=sum(1 for component in components if component.severity == "critical"),
                high_count=sum(1 for component in components if component.severity == "high"),
                vulnerable_count=sum(1 for component in components if component.risk_status == "vulnerable"),
                license_risk_count=sum(1 for component in components if component.license_risk in {"restricted", "review_required", "unknown"}),
                tool_status=scan_tool_status(scan),
                osv_status=osv_lookup_status(scan),
                osv_error_count=osv_lookup_error_count(scan),
            )
        )
    return history


@router.get("/projects/{project_id}/scan-diff", response_model=ScaScanDiffResult)
def get_project_sca_scan_diff(
    project_id: UUID,
    target_scan_id: UUID | None = None,
    base_scan_id: UUID | None = None,
    db: Session = Depends(get_db),
) -> ScaScanDiffResult:
    if db.get(ProjectRecord, str(project_id)) is None:
        raise HTTPException(status_code=404, detail="Project not found")

    scans = load_completed_sca_scans(db, project_id)
    if not scans:
        raise HTTPException(status_code=400, detail="No completed SCA scans found.")

    resolved_target = target_scan_id or UUID(str(scans[0].id))
    resolved_base = base_scan_id or previous_sca_scan_id(scans, resolved_target)
    if resolved_base is None:
        return ScaScanDiffResult(
            project_id=project_id,
            target_scan_id=resolved_target,
            has_comparison=False,
        )

    base_components = load_project_components(db, project_id, resolved_base)
    target_components = load_project_components(db, project_id, resolved_target)
    changes = build_scan_diff_items(base_components, target_components)
    return ScaScanDiffResult(
        project_id=project_id,
        base_scan_id=resolved_base,
        target_scan_id=resolved_target,
        has_comparison=True,
        summary=build_scan_diff_summary(changes),
        changes=changes,
    )


@router.get("/projects/{project_id}/report", response_model=ScaReport)
def export_project_sca_report(
    project_id: UUID,
    scan_task_id: UUID | None = None,
    db: Session = Depends(get_db),
) -> ScaReport:
    project = db.get(ProjectRecord, str(project_id))
    if project is None:
        raise HTTPException(status_code=404, detail="Project not found")

    resolved_scan_id = scan_task_id or latest_sca_scan_id(db, project_id)
    if resolved_scan_id is None:
        raise HTTPException(status_code=400, detail="No completed SCA scans found. Run SCA scan before exporting report.")

    scan = db.get(ScanTaskRecord, str(resolved_scan_id))
    components = load_project_components(db, project_id, resolved_scan_id)
    if not components:
        raise HTTPException(status_code=400, detail="No SCA components found for selected scan.")

    return ScaReport(
        project=project_report(project),
        scan=scan_report(scan, resolved_scan_id),
        tool_status=scan_tool_status(scan),
        summary=report_summary(components),
        distributions=report_distributions(components),
        top_risk_components=top_risk_components(components),
        trend=build_scan_diff_result(db, project_id, resolved_scan_id),
        recommendations=report_recommendations(components),
        evidence={
            "artifact_hashes": scan_metadata_value(scan, "artifact_hashes") or {},
            "python_environment": scan_metadata_value(scan, "python_environment") or {},
            "osv_lookup": scan_metadata_value(scan, "osv_lookup") or {},
            "osv_mirror": scan_metadata_value(scan, "osv_mirror") or {},
            "native_dependency_sources": scan_metadata_value(scan, "native_dependency_sources") or {},
            "policy_snapshot": scan_metadata_value(scan, "policy_snapshot") or {},
            "dependency_snapshot": scan_metadata_value(scan, "dependency_snapshot") or {},
        },
    )


@router.get("/projects/{project_id}/sbom")
def export_project_sbom(
    project_id: UUID,
    format: str = Query(default="cyclonedx", pattern="^(cyclonedx|CycloneDX|spdx|SPDX)$"),
    scan_task_id: UUID | None = None,
    db: Session = Depends(get_db),
) -> dict[str, object]:
    project = db.get(ProjectRecord, str(project_id))
    if project is None:
        raise HTTPException(status_code=404, detail="Project not found")

    records = load_project_components(db, project_id, scan_task_id)
    if not records:
        raise HTTPException(status_code=400, detail="No SCA components found. Run SCA scan before exporting SBOM.")

    if format.lower() == "cyclonedx":
        return build_cyclonedx_sbom(project, records)
    if format.lower() == "spdx":
        return build_spdx_sbom(project, records)
    raise HTTPException(status_code=400, detail="Unsupported SBOM format")


@router.get("/projects/{project_id}/dependency-graph")
def get_project_dependency_graph(
    project_id: UUID,
    scan_task_id: UUID | None = None,
    db: Session = Depends(get_db),
) -> dict[str, object]:
    project = db.get(ProjectRecord, str(project_id))
    if project is None:
        raise HTTPException(status_code=404, detail="Project not found")

    records = load_project_components(db, project_id, scan_task_id)
    if not records:
        raise HTTPException(status_code=400, detail="No SCA components found. Run SCA scan before building graph.")

    resolved_scan_id = scan_task_id or latest_sca_scan_id(db, project_id)
    snapshot = db.get(ScanTaskRecord, str(resolved_scan_id)) if resolved_scan_id else None
    return build_dependency_graph(
        project,
        records,
        dependency_edges=dependency_snapshot_edges((snapshot.scan_metadata or {}).get("dependency_snapshot")) if snapshot else None,
    )


@router.get("/projects/{project_id}/gate")
def sca_gate(project_id: UUID, scan_task_id: UUID | None = None, db: Session = Depends(get_db)) -> dict[str, object]:
    if db.get(ProjectRecord, str(project_id)) is None:
        raise HTTPException(status_code=404, detail="Project not found")
    components = load_project_components(db, project_id, scan_task_id)
    resolved_scan_id = scan_task_id or latest_sca_scan_id(db, project_id)
    scan = db.get(ScanTaskRecord, str(resolved_scan_id)) if resolved_scan_id else None
    return build_sca_gate_result(project_id, resolved_scan_id, components, scan, effective_gate_policy(scoped_policy_overrides(db, project_id)))


@router.get("/projects/{project_id}/evidence")
def get_sca_evidence(project_id: UUID, scan_task_id: UUID | None = None, db: Session = Depends(get_db)) -> dict[str, object]:
    if db.get(ProjectRecord, str(project_id)) is None:
        raise HTTPException(status_code=404, detail="Project not found")
    resolved_scan_id = scan_task_id or latest_sca_scan_id(db, project_id)
    if resolved_scan_id is None:
        raise HTTPException(status_code=400, detail="No completed SCA scans found")
    scan = db.get(ScanTaskRecord, str(resolved_scan_id))
    components = load_project_components(db, project_id, resolved_scan_id)
    return {
        "scan_task_id": str(resolved_scan_id),
        "artifact_hashes": scan_metadata_value(scan, "artifact_hashes") or {},
        "osv_mirror": scan_metadata_value(scan, "osv_mirror") or {},
        "intelligence": scan_metadata_value(scan, "intelligence") or {},
        "native_dependency_sources": scan_metadata_value(scan, "native_dependency_sources") or {},
        "policy_snapshot": scan_metadata_value(scan, "policy_snapshot") or {},
        "gate": build_sca_gate_result(project_id, resolved_scan_id, components, scan, effective_gate_policy(scoped_policy_overrides(db, project_id))),
    }


@router.get("/projects/{project_id}/report.html", response_class=HTMLResponse)
def export_sca_report_html(
    project_id: UUID,
    scan_task_id: UUID | None = None,
    db: Session = Depends(get_db),
) -> str:
    report = export_project_sca_report(project_id, scan_task_id=scan_task_id, db=db)
    rows = "".join(
        "<tr>"
        f"<td>{escape(item.name)}</td>"
        f"<td>{escape(item.version or '-')}</td>"
        f"<td>{escape(item.severity or '-')}</td>"
        f"<td>{escape(item.risk_status)}</td>"
        f"<td>{escape(', '.join(item.vulnerability_ids))}</td>"
        "</tr>"
        for item in report.top_risk_components
    )
    recommendations = "".join(f"<li>{escape(item)}</li>" for item in report.recommendations)
    return (
        "<!doctype html><html lang='zh-CN'><meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width,initial-scale=1'>"
        "<title>SCA 报告</title>"
        "<style>body{font:14px Arial,sans-serif;margin:32px;color:#172b4d}"
        "table{border-collapse:collapse;width:100%;margin:12px 0}"
        "td,th{border:1px solid #c7d2e0;padding:8px;text-align:left;vertical-align:top}"
        "th{background:#eef3fa}h1{margin-bottom:4px}h2{margin-top:28px}"
        "@media print{body{margin:16px}}</style>"
        f"<h1>{escape(str(report.project['name']))} · SCA 供应链风险报告</h1>"
        f"<p>扫描批次：{escape(str(report.scan['scan_task_id']))}；"
        f"风险组件：{report.summary.get('risky_component_count', 0)}</p>"
        f"<p>门禁结论：{escape(str(sca_gate(project_id, scan_task_id, db)['decision']))}</p>"
        "<h2>高风险组件</h2>"
        "<table><tr><th>组件</th><th>版本</th><th>等级</th><th>状态</th><th>漏洞</th></tr>"
        f"{rows}</table><h2>修复建议</h2><ul>{recommendations}</ul></html>"
    )


def scoped_policy_overrides(db: Session, project_id: UUID | None) -> list[ScaPolicyOverrideRecord]:
    conditions = [ScaPolicyOverrideRecord.project_id.is_(None)]
    if project_id is not None:
        conditions.append(ScaPolicyOverrideRecord.project_id == str(project_id))
    return db.scalars(
        select(ScaPolicyOverrideRecord)
        .where(or_(*conditions))
        .order_by(ScaPolicyOverrideRecord.created_at.asc())
    ).all()


def parse_optional_project_id(value: object, db: Session) -> str | None:
    if value in {None, ""}:
        return None
    try:
        project_id = UUID(str(value))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="project_id must be a UUID") from exc
    if db.get(ProjectRecord, str(project_id)) is None:
        raise HTTPException(status_code=404, detail="Project not found")
    return str(project_id)


def string_or_none(value: object) -> str | None:
    normalized = str(value or "").strip()
    return normalized or None


def validate_policy_override(item: ScaPolicyOverrideRecord, overrides: list[ScaPolicyOverrideRecord]) -> None:
    if item.policy_kind == "vulnerability":
        effective_vulnerability_rules(load_vulnerability_rules(), overrides)
    elif item.policy_kind == "license":
        effective_license_policies(load_license_policies(), overrides)
    elif item.policy_kind == "gate":
        if item.policy_id != "default":
            raise ValueError("The only supported gate policy id is default")
        validate_gate_config(item.config or {})
    else:
        raise ValueError("Unsupported SCA policy kind")


def policy_source(policy_id: str, kind: str, overrides: list[ScaPolicyOverrideRecord]) -> str:
    matched = [item for item in overrides if item.policy_kind == kind and item.policy_id == policy_id]
    if not matched:
        return "packaged"
    effective = sorted(
        matched,
        key=lambda item: (item.project_id is not None, item.updated_at or item.created_at),
    )[-1]
    return "project_override" if effective.project_id else "platform_override"


def policy_override_payload(item: ScaPolicyOverrideRecord) -> dict[str, object]:
    return {
        "id": str(item.id),
        "project_id": item.project_id,
        "policy_kind": item.policy_kind,
        "policy_id": item.policy_id,
        "enabled": item.enabled,
        "config": item.config or {},
        "actor": item.actor,
        "change_note": item.change_note,
        "created_at": item.created_at,
        "updated_at": item.updated_at,
    }


def record_policy_audit(db: Session, item: ScaPolicyOverrideRecord, event_type: str) -> None:
    db.add(
        ScaPolicyAuditRecord(
            project_id=item.project_id,
            policy_override_id=item.id,
            event_type=event_type,
            actor=item.actor,
            details={
                "policy_kind": item.policy_kind,
                "policy_id": item.policy_id,
                "enabled": item.enabled,
                "change_note": item.change_note,
            },
        )
    )


def policy_snapshot(vulnerability_rules, license_policies, overrides: list[ScaPolicyOverrideRecord], gate_policy: dict[str, object]) -> dict[str, object]:
    return {
        "vulnerability_rule_count": len(vulnerability_rules),
        "enabled_vulnerability_rule_count": sum(1 for rule in vulnerability_rules if rule.enabled),
        "license_policy_count": len(license_policies),
        "enabled_license_policy_count": sum(1 for policy in license_policies if policy.keywords),
        "override_count": len(overrides),
        "override_ids": [str(item.id) for item in overrides],
        "gate_policy": gate_policy,
    }


def build_sca_gate_result(
    project_id: UUID,
    scan_task_id: UUID | None,
    components: list[ComponentRecord],
    scan: ScanTaskRecord | None,
    policy: dict[str, object],
) -> dict[str, object]:
    block_reasons: list[dict[str, object]] = []
    exempt_statuses = {"accepted-risk", "not_affected", "fixed"}
    active = [item for item in components if item.risk_status not in exempt_statuses]
    severities = set(policy.get("block_severities", []))
    license_policies = set(policy.get("block_license_policies", []))
    min_score = int(policy.get("min_risk_score", 0))
    for item in active:
        metadata = item.risk_metadata or {}
        reasons: list[str] = []
        if item.severity in severities:
            reasons.append(f"severity:{item.severity}")
        if item.license_risk in license_policies:
            reasons.append(f"license:{item.license_risk}")
        if int(metadata.get("risk_score") or 0) >= min_score and min_score > 0:
            reasons.append(f"risk_score:{metadata.get('risk_score')}")
        if policy.get("block_kev") and metadata.get("kev"):
            reasons.append("kev")
        if policy.get("require_intelligence_for_critical") and item.severity == "critical" and not metadata.get("advisories"):
            reasons.append("critical_without_intelligence")
        if reasons:
            block_reasons.append({"component": item, "reasons": reasons})
    stale = False
    max_age = int(policy.get("max_scan_age_hours", 0))
    if max_age and scan and scan.finished_at:
        stale = (datetime.now() - scan.finished_at).total_seconds() > max_age * 3600
    if scan is None:
        stale = True
    if stale:
        block_reasons.append({"component": None, "reasons": ["scan_stale_or_missing"]})
    if not bool(policy.get("enabled", True)):
        block_reasons = []
    blocked = [item for item in block_reasons if item["component"] is not None]
    accepted = [item for item in components if item.risk_status == "accepted-risk"]
    decision = "block" if block_reasons else "pass"
    return {
        "project_id": str(project_id),
        "scan_task_id": str(scan_task_id) if scan_task_id else None,
        "decision": decision,
        "exit_code": 2 if decision == "block" else 0,
        "blocked_component_count": len(blocked),
        "accepted_risk_count": len(accepted),
        "reason": "SCA 门禁策略命中阻断条件" if block_reasons else "未命中已启用的 SCA 门禁阻断条件",
        "policy": policy,
        "scan_stale_or_missing": stale,
        "blocked_components": [
            {
                "name": record["component"].name,
                "version": record["component"].version,
                "ecosystem": record["component"].ecosystem,
                "severity": record["component"].severity,
                "vulnerability_ids": record["component"].vulnerability_ids or [],
                "reasons": record["reasons"],
            }
            for record in blocked[:50]
        ],
        "ci_usage": "GET /api/sca/projects/{project_id}/gate?scan_task_id={scan_task_id}; exit_code 为 0 代表 pass，2 代表 block。",
    }


def build_tool_status(enabled: bool, tool_scan: ToolScanResult | None) -> ScaToolStatus:
    if not enabled:
        return ScaToolStatus(enabled=False, status="disabled")
    if tool_scan is None:
        return ScaToolStatus(enabled=True, status="failed", errors=["tool scan did not run"])
    if not tool_scan.errors:
        status = "success"
    elif tool_scan.components or tool_scan.vulnerabilities:
        status = "partial_failed"
    else:
        status = "failed"
    return ScaToolStatus(
        enabled=True,
        status=status,
        syft_component_count=len(tool_scan.components),
        grype_vulnerability_count=len(tool_scan.vulnerabilities),
        grype_input=tool_scan.grype_input,
        trivy_vulnerability_count=tool_scan.trivy_vulnerabilities,
        errors=tool_scan.errors,
    )


def scan_tool_status(scan: ScanTaskRecord | None) -> ScaToolStatus | None:
    if scan is None:
        return None
    metadata = scan.scan_metadata or {}
    value = metadata.get("sca_tool_scan") if isinstance(metadata, dict) else None
    if not isinstance(value, dict):
        return None
    return ScaToolStatus(**value)


def osv_lookup_metadata(components: list[ParsedComponent]) -> dict[str, object]:
    errors = [component.osv_error for component in components if component.osv_error]
    checked_count = sum(1 for component in components if component.osv_checked)
    mirror_checked_count = sum(1 for component in components if component.risk_source == "osv_mirror")
    if errors:
        status = "offline_degraded"
    elif mirror_checked_count:
        status = "mirror_used"
    elif checked_count:
        status = "available"
    else:
        status = "not_used"
    return {
        "status": status,
        "checked_component_count": checked_count,
        "mirror_checked_component_count": mirror_checked_count,
        "error_count": len(errors),
    }


def osv_lookup_status(scan: ScanTaskRecord) -> str:
    value = scan_metadata_value(scan, "osv_lookup")
    return str(value.get("status") or "not_checked") if value else "not_checked"


def osv_lookup_error_count(scan: ScanTaskRecord) -> int:
    value = scan_metadata_value(scan, "osv_lookup")
    return int(value.get("error_count") or 0) if value else 0


def scan_metadata_value(scan: ScanTaskRecord, key: str) -> dict | None:
    metadata = scan.scan_metadata or {}
    value = metadata.get(key) if isinstance(metadata, dict) else None
    return value if isinstance(value, dict) else None


def parse_exception_date(value: object) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00")).replace(tzinfo=None)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="expires_at must be ISO-8601") from exc


def exception_payload(item: ScaPolicyExceptionRecord) -> dict[str, object]:
    return {"id": item.id, "project_id": item.project_id, "ecosystem": item.ecosystem, "package_name": item.package_name, "package_version": item.package_version, "exception_type": item.exception_type, "reason": item.reason, "status": item.status, "requester": item.requester, "requester_role": item.requester_role, "approver": item.approver, "approver_role": item.approver_role, "expires_at": item.expires_at, "approval_note": item.approval_note, "approval_history": item.approval_history or [], "created_at": item.created_at, "updated_at": item.updated_at}


def exception_role(value: object) -> str | None:
    role = string_or_none(value)
    if role is None:
        return None
    normalized = role.lower().replace("-", "_")
    if normalized not in {"developer", "security", "legal", "release_manager", "admin"}:
        raise HTTPException(status_code=400, detail="Unsupported SCA governance role")
    return normalized


def validate_exception_transition(current: str, target: str, actor_role: str | None) -> None:
    allowed = {"pending": {"approved", "rejected", "revoked"}, "approved": {"revoked"}, "rejected": {"pending", "revoked"}, "revoked": {"pending"}}
    if target not in allowed.get(current, set()):
        raise HTTPException(status_code=400, detail=f"Invalid exception transition: {current} -> {target}")
    if target in {"approved", "rejected", "revoked"} and actor_role not in {"security", "legal", "admin"}:
        raise HTTPException(status_code=403, detail="SCA exception approval requires security, legal, or admin role")


def vex_payload(item: ScaVexStatementRecord) -> dict[str, object]:
    return {
        "id": str(item.id), "project_id": str(item.project_id), "ecosystem": item.ecosystem,
        "package_name": item.package_name, "package_version": item.package_version,
        "vulnerability_id": item.vulnerability_id, "status": item.status, "justification": item.justification,
        "action_statement": item.action_statement, "evidence": item.evidence, "actor": item.actor,
        "expires_at": item.expires_at, "created_at": item.created_at, "updated_at": item.updated_at,
    }


def apply_approved_exceptions(db: Session, project_id: str, components: list[ComponentRecord]) -> None:
    now = datetime.utcnow()
    allowed = db.scalars(select(ScaPolicyExceptionRecord).where(ScaPolicyExceptionRecord.project_id == project_id, ScaPolicyExceptionRecord.status == "approved")).all()
    for component in components:
        matched = next((item for item in allowed if item.ecosystem.lower() in {"unknown", component.ecosystem.lower()} and item.package_name.lower() == component.name.lower() and (not item.package_version or item.package_version == component.version) and (item.expires_at is None or item.expires_at > now)), None)
        if matched:
            component.risk_status = "accepted-risk"
            component.risk_summary = f"{component.risk_summary or ''} 已批准例外：{matched.reason}".strip()


def apply_active_vex_statements(db: Session, project_id: str, components: list[ComponentRecord]) -> None:
    now = datetime.utcnow()
    statements = db.scalars(
        select(ScaVexStatementRecord).where(
            ScaVexStatementRecord.project_id == project_id,
            ScaVexStatementRecord.status.in_(("not_affected", "fixed")),
        )
    ).all()
    for component in components:
        matched = [
            item for item in statements
            if item.ecosystem.lower() == component.ecosystem.lower()
            and item.package_name.lower() == component.name.lower()
            and (not item.package_version or item.package_version == component.version)
            and item.vulnerability_id in (component.vulnerability_ids or [])
            and (item.expires_at is None or item.expires_at > now)
        ]
        if not matched:
            continue
        metadata = dict(component.risk_metadata or {})
        metadata["vex"] = [vex_payload(item) for item in matched]
        component.risk_metadata = metadata
        final_status = "not_affected" if any(item.status == "not_affected" for item in matched) else "fixed"
        component.risk_status = final_status
        component.risk_summary = f"{component.risk_summary or ''} VEX 结论：{final_status}（保留原始漏洞证据）。".strip()


def create_sca_findings(
    db: Session,
    project_id: str,
    scan_task_id: str,
    components: list[ComponentRecord],
) -> None:
    existing_rule_ids = set(
        db.scalars(
            select(FindingRecord.rule_id).where(
                FindingRecord.project_id == project_id,
                FindingRecord.scan_task_id == scan_task_id,
                FindingRecord.source == "SCA",
            )
        ).all()
    )
    for component in components:
        if component.risk_status in {"accepted-risk", "not_affected", "fixed"}:
            continue
        for finding in sca_findings_for_component(project_id, scan_task_id, component):
            if finding.rule_id in existing_rule_ids:
                continue
            db.add(finding)
            existing_rule_ids.add(finding.rule_id)


def sca_findings_for_component(
    project_id: str,
    scan_task_id: str,
    component: ComponentRecord,
) -> list[FindingRecord]:
    findings: list[FindingRecord] = []
    for vulnerability_id in component.vulnerability_ids or []:
        findings.append(
            FindingRecord(
                project_id=project_id,
                scan_task_id=scan_task_id,
                component_id=component.id,
                source="SCA",
                rule_id=f"SCA:{component.ecosystem}:{component.name}:{vulnerability_id}",
                title=f"SCA 漏洞组件：{component.name} {vulnerability_id}",
                severity=sca_finding_severity(component),
                file_path=component.source_file,
                evidence=sca_finding_evidence(component),
            )
        )
    if component.license_risk in {"restricted", "review_required", "unknown"}:
        findings.append(
            FindingRecord(
                project_id=project_id,
                scan_task_id=scan_task_id,
                component_id=component.id,
                source="SCA",
                rule_id=f"SCA-LICENSE:{component.ecosystem}:{component.name}:{component.license_risk}",
                title=f"SCA 许可证风险：{component.name} {component.license_risk}",
                severity="medium" if component.license_risk == "restricted" else "low",
                file_path=component.source_file,
                evidence=sca_finding_evidence(component),
            )
        )
    if component.risk_status == "review-required" and component.version is None:
        findings.append(
            FindingRecord(
                project_id=project_id,
                scan_task_id=scan_task_id,
                component_id=component.id,
                source="SCA",
                rule_id=f"SCA-VERSION:{component.ecosystem}:{component.name}",
                title=f"SCA 组件版本缺失：{component.name}",
                severity="low",
                file_path=component.source_file,
                evidence=sca_finding_evidence(component),
            )
        )
    if not findings and component.severity in {"critical", "high"} and component.risk_status == "vulnerable":
        findings.append(
            FindingRecord(
                project_id=project_id,
                scan_task_id=scan_task_id,
                component_id=component.id,
                source="SCA",
                rule_id=f"SCA-RISK:{component.ecosystem}:{component.name}:{component.version or 'unknown'}",
                title=f"SCA 高风险组件：{component.name}",
                severity=sca_finding_severity(component),
                file_path=component.source_file,
                evidence=sca_finding_evidence(component),
            )
        )
    return findings


def sca_finding_severity(component: ComponentRecord) -> str:
    if component.severity in {"critical", "high", "medium", "low", "info"}:
        return component.severity
    if component.risk_status == "vulnerable":
        return "medium"
    if component.license_risk == "restricted":
        return "medium"
    return "low"


def sca_finding_evidence(component: ComponentRecord) -> str:
    details = [
        f"组件：{component.ecosystem}/{component.name}",
        f"版本：{component.version or '-'}",
        f"依赖类型：{component.dependency_type}",
        f"来源文件：{component.source_file}",
        f"风险来源：{component.risk_source or '-'}",
    ]
    if component.vulnerability_ids:
        details.append("漏洞编号：" + ", ".join(str(item) for item in component.vulnerability_ids))
    if component.license or component.license_risk:
        details.append(f"许可证：{component.license or '-'} / 策略：{component.license_risk or '-'}")
    if component.remediation:
        details.append(f"修复建议：{component.remediation}")
    elif component.risk_summary:
        details.append(f"风险摘要：{component.risk_summary}")
    return "；".join(details)


def merge_tool_components(
    base_components: list[ParsedComponent],
    tool_scan: ToolScanResult | None,
) -> list[ParsedComponent]:
    if tool_scan is None or not tool_scan.components:
        return base_components
    return dedupe_components([*base_components, *tool_scan.components])


def apply_tool_vulnerabilities(
    components: list[ParsedComponent],
    tool_scan: ToolScanResult | None,
) -> list[ParsedComponent]:
    if tool_scan is None or not tool_scan.vulnerabilities:
        return components

    vulnerabilities_by_exact: dict[tuple[str, str, str | None], list] = {}
    vulnerabilities_by_name: dict[tuple[str, str], list] = {}
    for vulnerability in tool_scan.vulnerabilities:
        exact_key = (vulnerability.ecosystem, vulnerability.name.lower(), vulnerability.version)
        name_key = (vulnerability.ecosystem, vulnerability.name.lower())
        vulnerabilities_by_exact.setdefault(exact_key, []).append(vulnerability)
        vulnerabilities_by_name.setdefault(name_key, []).append(vulnerability)

    updated: list[ParsedComponent] = []
    for component in components:
        exact_matches = vulnerabilities_by_exact.get((component.ecosystem, component.name.lower(), component.version), [])
        name_matches = vulnerabilities_by_name.get((component.ecosystem, component.name.lower()), [])
        matches = exact_matches or name_matches
        if not matches:
            updated.append(component)
            continue

        vulnerability_ids = sorted({*(component.vulnerability_ids or []), *(match.vulnerability_id for match in matches)})
        highest_severity = highest_component_severity([component.severity, *(match.severity for match in matches)])
        remediation = component.remediation or first_value(match.remediation for match in matches)
        risk_summary = component.risk_summary or first_value(match.summary for match in matches)
        updated.append(
            replace(
                component,
                risk_status="vulnerable",
                vulnerability_ids=vulnerability_ids,
                severity=highest_severity,
                risk_summary=risk_summary,
                remediation=remediation,
                risk_source=merge_risk_source(component.risk_source, matches[0].tool),
            )
        )
    return updated


def highest_component_severity(values) -> str | None:
    severities = [value for value in values if value]
    if not severities:
        return None
    return max(severities, key=severity_weight)


def first_value(values) -> str | None:
    for value in values:
        if value:
            return value
    return None


def merge_risk_source(existing: str | None, source: str) -> str:
    if not existing or existing in {"clean", "not_supported"}:
        return source
    if source in existing.split("+"):
        return existing
    return f"{existing}+{source}"


def load_project_components(
    db: Session,
    project_id: UUID,
    scan_task_id: UUID | None = None,
) -> list[ComponentRecord]:
    resolved_scan_id = scan_task_id or latest_sca_scan_id(db, project_id)
    statement = select(ComponentRecord).where(ComponentRecord.project_id == str(project_id))
    if resolved_scan_id is not None:
        statement = statement.where(ComponentRecord.scan_task_id == str(resolved_scan_id))
    statement = statement.order_by(ComponentRecord.ecosystem, ComponentRecord.name)
    return db.scalars(statement).all()


def latest_sca_scan_id(db: Session, project_id: UUID) -> UUID | None:
    scan = db.scalar(
        select(ScanTaskRecord)
        .where(
            ScanTaskRecord.project_id == str(project_id),
            ScanTaskRecord.scan_type == "sca",
            ScanTaskRecord.status == ScanStatus.completed.value,
        )
        .order_by(ScanTaskRecord.finished_at.desc().nullslast(), ScanTaskRecord.created_at.desc())
    )
    return UUID(str(scan.id)) if scan else None


def load_completed_sca_scans(db: Session, project_id: UUID) -> list[ScanTaskRecord]:
    return db.scalars(
        select(ScanTaskRecord)
        .where(
            ScanTaskRecord.project_id == str(project_id),
            ScanTaskRecord.scan_type == "sca",
            ScanTaskRecord.status == ScanStatus.completed.value,
        )
        .order_by(ScanTaskRecord.finished_at.desc().nullslast(), ScanTaskRecord.created_at.desc())
    ).all()


def build_scan_diff_result(db: Session, project_id: UUID, target_scan_id: UUID) -> ScaScanDiffResult:
    scans = load_completed_sca_scans(db, project_id)
    resolved_base = previous_sca_scan_id(scans, target_scan_id)
    if resolved_base is None:
        return ScaScanDiffResult(project_id=project_id, target_scan_id=target_scan_id, has_comparison=False)

    base_components = load_project_components(db, project_id, resolved_base)
    target_components = load_project_components(db, project_id, target_scan_id)
    changes = build_scan_diff_items(base_components, target_components)
    return ScaScanDiffResult(
        project_id=project_id,
        base_scan_id=resolved_base,
        target_scan_id=target_scan_id,
        has_comparison=True,
        summary=build_scan_diff_summary(changes),
        changes=changes,
    )


def previous_sca_scan_id(scans: list[ScanTaskRecord], target_scan_id: UUID) -> UUID | None:
    for index, scan in enumerate(scans):
        if str(scan.id) != str(target_scan_id):
            continue
        if index + 1 >= len(scans):
            return None
        return UUID(str(scans[index + 1].id))
    return UUID(str(scans[1].id)) if len(scans) > 1 else None


def build_scan_diff_items(
    base_components: list[ComponentRecord],
    target_components: list[ComponentRecord],
) -> list[ScaScanDiffItem]:
    base_map = {component_key(component): component for component in base_components}
    target_map = {component_key(component): component for component in target_components}
    changes: list[ScaScanDiffItem] = []
    for key in sorted(set(base_map) | set(target_map)):
        base = base_map.get(key)
        target = target_map.get(key)
        if base is None and target is not None:
            changes.append(diff_item(None, target, "added", f"新增组件 {target.name} {target.version or ''}".strip()))
            continue
        if target is None and base is not None:
            changes.append(diff_item(base, None, "removed", f"移除组件 {base.name} {base.version or ''}".strip()))
            continue
        if base is None or target is None:
            continue
        if base.version != target.version:
            changes.append(diff_item(base, target, "version_changed", f"版本从 {base.version or '-'} 变为 {target.version or '-'}"))
        if component_risk_key(base) != component_risk_key(target):
            changes.append(diff_item(base, target, risk_change_type(base, target), "风险状态、漏洞编号或严重等级发生变化"))
        if base.license_risk != target.license_risk:
            changes.append(diff_item(base, target, "license_risk_changed", f"许可证策略从 {base.license_risk or '-'} 变为 {target.license_risk or '-'}"))
    return changes


def diff_item(
    base: ComponentRecord | None,
    target: ComponentRecord | None,
    change_type: str,
    summary: str,
) -> ScaScanDiffItem:
    component = target or base
    assert component is not None
    return ScaScanDiffItem(
        ecosystem=component.ecosystem,
        name=component.name,
        change_type=change_type,
        base_version=base.version if base else None,
        target_version=target.version if target else None,
        base_risk_status=base.risk_status if base else None,
        target_risk_status=target.risk_status if target else None,
        base_severity=base.severity if base else None,
        target_severity=target.severity if target else None,
        base_license_risk=base.license_risk if base else None,
        target_license_risk=target.license_risk if target else None,
        base_vulnerability_ids=base.vulnerability_ids or [] if base else [],
        target_vulnerability_ids=target.vulnerability_ids or [] if target else [],
        summary=summary,
    )


def build_scan_diff_summary(changes: list[ScaScanDiffItem]) -> ScaScanDiffSummary:
    return ScaScanDiffSummary(
        added_components=sum(1 for item in changes if item.change_type == "added"),
        removed_components=sum(1 for item in changes if item.change_type == "removed"),
        version_changes=sum(1 for item in changes if item.change_type == "version_changed"),
        risk_added=sum(1 for item in changes if item.change_type == "risk_added"),
        risk_removed=sum(1 for item in changes if item.change_type == "risk_removed"),
        license_risk_changes=sum(1 for item in changes if item.change_type == "license_risk_changed"),
        total_changes=len(changes),
    )


def component_key(component: ComponentRecord) -> tuple[str, str]:
    return (component.ecosystem, component.name)


def component_risk_key(component: ComponentRecord) -> tuple[str | None, str | None, tuple[str, ...]]:
    return (
        component.risk_status,
        component.severity,
        tuple(sorted(str(item) for item in component.vulnerability_ids or [])),
    )


def risk_change_type(base: ComponentRecord, target: ComponentRecord) -> str:
    if not is_risky_for_diff(base) and is_risky_for_diff(target):
        return "risk_added"
    if is_risky_for_diff(base) and not is_risky_for_diff(target):
        return "risk_removed"
    return "risk_changed"


def is_risky_for_diff(component: ComponentRecord) -> bool:
    return component.risk_status in {"vulnerable", "license-risk", "review-required"} or bool(component.vulnerability_ids) or component.severity in {"critical", "high"}


def project_report(project: ProjectRecord) -> dict[str, object | None]:
    return {
        "id": str(project.id),
        "name": project.name,
        "business_owner": project.business_owner,
        "security_owner": project.security_owner,
        "repository_url": project.repository_url,
        "source_path": project.source_path,
        "default_branch": project.default_branch,
        "runtime_url": project.runtime_url,
        "api_base_url": project.api_base_url,
    }


def scan_report(scan: ScanTaskRecord | None, scan_task_id: UUID) -> dict[str, object | None]:
    return {
        "scan_task_id": str(scan_task_id),
        "status": scan.status if scan else None,
        "started_at": scan.started_at.isoformat() if scan and scan.started_at else None,
        "finished_at": scan.finished_at.isoformat() if scan and scan.finished_at else None,
        "created_at": scan.created_at.isoformat() if scan else None,
    }


def report_summary(components: list[ComponentRecord]) -> dict[str, object]:
    risky_components = [component for component in components if is_report_risky(component)]
    return {
        "component_count": len(components),
        "direct_dependency_count": sum(1 for component in components if component.dependency_type != "transitive"),
        "transitive_dependency_count": sum(1 for component in components if component.dependency_type == "transitive"),
        "risky_component_count": len(risky_components),
        "critical_count": sum(1 for component in components if component.severity == "critical"),
        "high_count": sum(1 for component in components if component.severity == "high"),
        "vulnerability_count": sum(len(component.vulnerability_ids or []) for component in components),
        "license_risk_count": sum(1 for component in components if component.license_risk in {"restricted", "review_required", "unknown"}),
        "osv_checked_count": sum(1 for component in components if component.osv_checked),
        "osv_error_count": sum(1 for component in components if component.osv_error),
    }


def report_distributions(components: list[ComponentRecord]) -> dict[str, dict[str, int]]:
    return {
        "ecosystem": count_component_values(components, "ecosystem"),
        "dependency_type": count_component_values(components, "dependency_type"),
        "risk_status": count_component_values(components, "risk_status"),
        "severity": count_component_values(components, "severity"),
        "license_risk": count_component_values(components, "license_risk"),
        "risk_source": count_component_values(components, "risk_source"),
    }


def count_component_values(components: list[ComponentRecord], field: str) -> dict[str, int]:
    counts: dict[str, int] = {}
    for component in components:
        value = getattr(component, field) or "unknown"
        counts[str(value)] = counts.get(str(value), 0) + 1
    return counts


def top_risk_components(components: list[ComponentRecord], limit: int = 10) -> list[ScaReportComponent]:
    sorted_components = sorted(
        [component for component in components if is_report_risky(component)],
        key=lambda component: (
            severity_weight(component.severity),
            len(component.vulnerability_ids or []),
            1 if component.license_risk in {"restricted", "review_required", "unknown"} else 0,
        ),
        reverse=True,
    )
    return [
        ScaReportComponent(
            ecosystem=component.ecosystem,
            name=component.name,
            version=component.version,
            dependency_type=component.dependency_type,
            risk_status=component.risk_status,
            severity=component.severity,
            vulnerability_ids=component.vulnerability_ids or [],
            license=component.license,
            license_risk=component.license_risk,
            risk_source=component.risk_source,
            remediation=component.remediation or component.risk_summary,
        )
        for component in sorted_components[:limit]
    ]


def report_recommendations(components: list[ComponentRecord]) -> list[str]:
    recommendations: list[str] = []
    if any(component.severity in {"critical", "high"} for component in components):
        recommendations.append("优先修复严重和高危组件，确认修复版本后重新执行 SCA 扫描。")
    if any(component.dependency_type == "transitive" and is_report_risky(component) for component in components):
        recommendations.append("存在风险传递依赖，优先查看升级杠杆并升级其上游直接依赖。")
    if any(component.license_risk in {"restricted", "review_required", "unknown"} for component in components):
        recommendations.append("存在许可证风险或未知许可证，建议发起合规复核并记录例外审批结论。")
    if any(component.osv_error for component in components):
        recommendations.append("部分组件 OSV 查询失败，建议在网络恢复后复扫或补充离线漏洞库。")
    if not recommendations:
        recommendations.append("当前批次未发现高优先级 SCA 风险，建议保留 SBOM 并持续跟踪后续扫描趋势。")
    return recommendations


def is_report_risky(component: ComponentRecord) -> bool:
    return is_risky_for_diff(component) or component.license_risk in {"restricted", "review_required", "unknown"}


def severity_weight(severity: str | None) -> int:
    return {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}.get(severity or "", 0)



