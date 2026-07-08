from datetime import datetime
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from app.db import get_db
from app.db_models import ComponentRecord, ProjectModuleRecord, ProjectRecord, ScanTaskRecord
from app.models import Component, ModuleKey, ScaScanRequest, ScaScanResult, ScanStatus
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
        if payload.clear_previous:
            db.execute(delete(ComponentRecord).where(ComponentRecord.project_id == str(payload.project_id)))

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
def list_project_components(project_id: UUID, db: Session = Depends(get_db)) -> list[Component]:
    if db.get(ProjectRecord, str(project_id)) is None:
        raise HTTPException(status_code=404, detail="Project not found")

    records = db.scalars(
        select(ComponentRecord)
        .where(ComponentRecord.project_id == str(project_id))
        .order_by(ComponentRecord.ecosystem, ComponentRecord.name)
    ).all()
    return [component_to_schema(record) for record in records]


@router.get("/projects/{project_id}/sbom")
def export_project_sbom(
    project_id: UUID,
    format: str = Query(default="cyclonedx", pattern="^(cyclonedx|CycloneDX|spdx|SPDX)$"),
    db: Session = Depends(get_db),
) -> dict[str, object]:
    project = db.get(ProjectRecord, str(project_id))
    if project is None:
        raise HTTPException(status_code=404, detail="Project not found")

    records = db.scalars(
        select(ComponentRecord)
        .where(ComponentRecord.project_id == str(project_id))
        .order_by(ComponentRecord.ecosystem, ComponentRecord.name)
    ).all()
    if not records:
        raise HTTPException(status_code=400, detail="No SCA components found. Run SCA scan before exporting SBOM.")

    if format.lower() == "cyclonedx":
        return build_cyclonedx_sbom(project, records)
    if format.lower() == "spdx":
        return build_spdx_sbom(project, records)
    raise HTTPException(status_code=400, detail="Unsupported SBOM format")


@router.get("/projects/{project_id}/dependency-graph")
def get_project_dependency_graph(project_id: UUID, db: Session = Depends(get_db)) -> dict[str, object]:
    project = db.get(ProjectRecord, str(project_id))
    if project is None:
        raise HTTPException(status_code=404, detail="Project not found")

    records = db.scalars(
        select(ComponentRecord)
        .where(ComponentRecord.project_id == str(project_id))
        .order_by(ComponentRecord.ecosystem, ComponentRecord.name)
    ).all()
    if not records:
        raise HTTPException(status_code=400, detail="No SCA components found. Run SCA scan before building graph.")

    return build_dependency_graph(project, records)



