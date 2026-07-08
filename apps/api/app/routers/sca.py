from datetime import datetime
from dataclasses import replace
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.db import get_db
from app.db_models import ComponentRecord, ProjectModuleRecord, ProjectRecord, ScanTaskRecord
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
    ScanStatus,
)
from app.repositories.mappers import component_to_schema
from app.services.sca_parser import ParsedComponent, dedupe_components, parse_dependency_tree
from app.services.sca_risk_analyzer import analyze_components
from app.services.sca_dependency_graph import build_dependency_graph
from app.services.sca_sbom import build_cyclonedx_sbom, build_spdx_sbom
from app.services.sca_tool_scanner import ToolScanResult, scan_with_syft_grype

router = APIRouter()


@router.post("/scan", response_model=ScaScanResult)
def run_sca_scan(payload: ScaScanRequest, db: Session = Depends(get_db)) -> ScaScanResult:
    if db.get(ProjectRecord, str(payload.project_id)) is None:
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
        tool_scan = scan_with_syft_grype(payload.source_path) if payload.enable_tool_scan else None
        parsed_components = merge_tool_components(parsed.components, tool_scan)
        analyzed_components = apply_tool_vulnerabilities(analyze_components(parsed_components), tool_scan)
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

    return ScaScanResult(
        project_id=payload.project_id,
        scan_task_id=UUID(str(scan.id)),
        source_path=payload.source_path,
        scanned_files=parsed.scanned_files,
        component_count=len(records),
        components=[component_to_schema(record) for record in records],
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
        summary=report_summary(components),
        distributions=report_distributions(components),
        top_risk_components=top_risk_components(components),
        trend=build_scan_diff_result(db, project_id, resolved_scan_id),
        recommendations=report_recommendations(components),
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

    return build_dependency_graph(project, records)


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
                risk_source=merge_risk_source(component.risk_source, "grype"),
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



