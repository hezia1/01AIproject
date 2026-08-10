from datetime import datetime
from pathlib import Path
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
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
    AgentScanCoverage,
    AgentScanHistoryItem,
    AgentScanRequest,
    AgentScanResult,
    AgentScanSnapshot,
    Finding,
    ModuleKey,
    ScanStatus,
)
from app.repositories.mappers import finding_to_schema
from app.services.agent_scanner import AgentAsset, AgentPermission, scan_agent_tree

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
            "permissions": [permission_to_dict(permission) for permission in parsed.permissions],
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
        permissions=[AgentPermissionResult(**permission_to_dict(permission)) for permission in parsed.permissions],
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


@router.get("/projects/{project_id}/snapshot", response_model=AgentScanSnapshot)
def get_project_agent_snapshot(project_id: UUID, db: Session = Depends(get_db)) -> AgentScanSnapshot:
    if db.get(ProjectRecord, str(project_id)) is None:
        raise HTTPException(status_code=404, detail="Project not found")
    scan = latest_completed_agent_scan(db, str(project_id))
    if scan is None:
        raise HTTPException(status_code=404, detail="No completed AGENT scan found")
    return agent_scan_snapshot(project_id, scan)


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
        "name": asset.name,
        "version": asset.version,
        "publisher": asset.publisher,
        "transport": asset.transport,
        "entrypoint": asset.entrypoint,
        "declared_tools": asset.declared_tools,
        "declared_resources": asset.declared_resources,
        "declared_prompts": asset.declared_prompts,
        "permission_count": len(asset.permissions),
        "metadata": asset.metadata,
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
        ),
        assets=asset_changes,
        permissions=permission_changes,
    )


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


def mark_agent_scan_failed(scan: ScanTaskRecord, detail: str) -> None:
    metadata = dict(scan.scan_metadata or {})
    metadata.update({"stage": "failed", "detail": detail})
    scan.scan_metadata = metadata
    scan.status = ScanStatus.failed.value
    scan.finished_at = datetime.utcnow()
