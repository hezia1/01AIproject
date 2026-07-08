from datetime import datetime
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.db import get_db
from app.db_models import ComponentRecord, ProjectModuleRecord, ProjectRecord, ScanTaskRecord
from app.models import (
    Component,
    ModuleKey,
    ScaScanDiffItem,
    ScaScanDiffResult,
    ScaScanDiffSummary,
    ScaScanHistoryItem,
    ScaScanRequest,
    ScaScanResult,
    ScanStatus,
)
from app.repositories.mappers import component_to_schema
from app.services.sca_parser import parse_dependency_tree
from app.services.sca_risk_analyzer import analyze_components
from app.services.sca_dependency_graph import build_dependency_graph
from app.services.sca_sbom import build_cyclonedx_sbom, build_spdx_sbom

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
        analyzed_components = analyze_components(parsed.components)
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



