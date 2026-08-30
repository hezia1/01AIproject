from pathlib import Path
from uuid import UUID, uuid4

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from app.db import get_db
from app.db_models import (
    AuditRecord,
    ComponentRecord,
    DastAssetDiscoveryRecord,
    DastBusinessFlowRecord,
    DastBusinessRunRecord,
    DastBusinessSnapshotRecord,
    DastRunEvidenceRecord,
    DastValidationRecord,
    DastVerificationPlanRecord,
    DastVerificationRunRecord,
    FindingRecord,
    KnowledgeEntryRecord,
    KnowledgeEntryVersionRecord,
    ProjectModuleRecord,
    ProjectMembershipRecord,
    ProjectRecord,
    SandboxTargetInstanceRecord,
    SandboxEvidenceRecord,
    SandboxTaskEventRecord,
    SandboxTaskRecord,
    SastAgentRunRecord,
    ScaPolicyAuditRecord,
    ScaPolicyExceptionRecord,
    ScaPolicyOverrideRecord,
    ScaVexStatementRecord,
    ScanTaskRecord,
    TenantRecord,
)
from app.models import (
    ModuleKey,
    Project,
    ProjectAssetProbe,
    ProjectCreate,
    ProjectImportRequest,
    ProjectImportResult,
    ProjectReadiness,
    ProjectUpdate,
)
from app.module_registry import get_module
from app.repositories.mappers import project_to_schema
from app.services.project_onboarding import (
    MAX_ZIP_BYTES,
    ProjectOnboardingError,
    build_project_readiness,
    cleanup_managed_destination,
    clone_git_repository,
    extract_zip_archive,
    import_local_directory,
    inspect_project_assets,
    managed_import_root,
)

router = APIRouter()

@router.get("", response_model=list[Project])
def list_projects(db: Session = Depends(get_db)) -> list[Project]:
    records = db.scalars(select(ProjectRecord).order_by(ProjectRecord.created_at.desc())).all()
    return [project_to_schema(record) for record in records]


@router.post("", response_model=Project, status_code=201)
def create_project(payload: ProjectCreate, db: Session = Depends(get_db)) -> Project:
    tenant_id = ensure_legacy_tenant(db)
    record = ProjectRecord(**payload.model_dump(), tenant_id=tenant_id)
    db.add(record)
    db.flush()
    db.commit()
    db.refresh(record)
    return project_to_schema(record)


@router.post("/import", response_model=ProjectImportResult, status_code=201)
def import_project(payload: ProjectImportRequest, db: Session = Depends(get_db)) -> ProjectImportResult:
    try:
        if payload.import_mode.value == "git":
            source_path = clone_git_repository(payload.source, payload.default_branch)
            repository_url = payload.source
            managed_source = True
        else:
            source_path = import_local_directory(payload.source)
            repository_url = None
            managed_source = False
    except ProjectOnboardingError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return persist_imported_project(
        db,
        name=payload.name,
        source_path=source_path,
        repository_url=repository_url,
        business_owner=payload.business_owner,
        security_owner=payload.security_owner,
        runtime_url=payload.runtime_url,
        api_base_url=payload.api_base_url,
        sandbox_command=payload.sandbox_command,
        sandbox_image=payload.sandbox_image,
        default_branch=payload.default_branch,
        import_mode=payload.import_mode.value,
        managed_source=managed_source,
    )


@router.post("/import/zip", response_model=ProjectImportResult, status_code=201)
async def import_project_zip(
    request: Request,
    name: str = Query(min_length=1, max_length=120),
    default_branch: str = Query(default="main", min_length=1, max_length=200),
    business_owner: str | None = Query(default=None, max_length=200),
    security_owner: str | None = Query(default=None, max_length=200),
    runtime_url: str | None = Query(default=None, max_length=1000),
    api_base_url: str | None = Query(default=None, max_length=1000),
    sandbox_command: str | None = Query(default=None, max_length=1000),
    sandbox_image: str | None = Query(default=None, max_length=300),
    db: Session = Depends(get_db),
) -> ProjectImportResult:
    upload_path = managed_import_root() / f".upload-{uuid4().hex}.zip"
    received = 0
    try:
        with upload_path.open("wb") as output:
            async for chunk in request.stream():
                received += len(chunk)
                if received > MAX_ZIP_BYTES:
                    raise ProjectOnboardingError("ZIP 文件超过 500 MiB 接入上限")
                output.write(chunk)
        if received == 0:
            raise ProjectOnboardingError("未收到 ZIP 文件内容")
        source_path = extract_zip_archive(upload_path, name)
        return persist_imported_project(
            db,
            name=name,
            source_path=source_path,
            repository_url=None,
            business_owner=business_owner,
            security_owner=security_owner,
            runtime_url=runtime_url,
            api_base_url=api_base_url,
            sandbox_command=sandbox_command,
            sandbox_image=sandbox_image,
            default_branch=default_branch,
            import_mode="zip",
            managed_source=True,
        )
    except ProjectOnboardingError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    finally:
        upload_path.unlink(missing_ok=True)


@router.get("/{project_id}/readiness", response_model=ProjectReadiness)
def get_project_readiness(project_id: UUID, db: Session = Depends(get_db)) -> ProjectReadiness:
    record = db.get(ProjectRecord, str(project_id))
    if record is None:
        raise HTTPException(status_code=404, detail="Project not found")
    return ProjectReadiness.model_validate(build_project_readiness(record, inspect_project_assets(record.source_path)))


@router.get("/{project_id}", response_model=Project)
def get_project(project_id: UUID, db: Session = Depends(get_db)) -> Project:
    record = db.get(ProjectRecord, str(project_id))
    if record is None:
        raise HTTPException(status_code=404, detail="Project not found")
    return project_to_schema(record)


@router.patch("/{project_id}", response_model=Project)
def update_project(project_id: UUID, payload: ProjectUpdate, db: Session = Depends(get_db)) -> Project:
    record = db.get(ProjectRecord, str(project_id))
    if record is None:
        raise HTTPException(status_code=404, detail="Project not found")

    updates = payload.model_dump(exclude_unset=True)
    for field, value in updates.items():
        setattr(record, field, value)
    db.commit()
    db.refresh(record)
    return project_to_schema(record)


@router.delete("/{project_id}", status_code=204)
def delete_project(project_id: UUID, db: Session = Depends(get_db)) -> None:
    project_key = str(project_id)
    record = db.get(ProjectRecord, project_key)
    if record is None:
        raise HTTPException(status_code=404, detail="Project not found")
    source_path = Path(record.source_path).resolve() if record.source_path else None

    task_ids = select(SandboxTaskRecord.id).where(SandboxTaskRecord.project_id == project_key)
    entry_ids = select(KnowledgeEntryRecord.id).where(KnowledgeEntryRecord.source_project_id == project_key)
    db.execute(delete(SandboxTaskEventRecord).where(SandboxTaskEventRecord.task_id.in_(task_ids)))
    db.execute(delete(SandboxTaskRecord).where(SandboxTaskRecord.project_id == project_key))
    db.execute(delete(SandboxTargetInstanceRecord).where(SandboxTargetInstanceRecord.project_id == project_key))
    db.execute(delete(SandboxEvidenceRecord).where(SandboxEvidenceRecord.project_id == project_key))
    db.execute(delete(DastBusinessSnapshotRecord).where(DastBusinessSnapshotRecord.project_id == project_key))
    db.execute(delete(DastBusinessRunRecord).where(DastBusinessRunRecord.project_id == project_key))
    db.execute(delete(DastBusinessFlowRecord).where(DastBusinessFlowRecord.project_id == project_key))
    db.execute(delete(DastRunEvidenceRecord).where(DastRunEvidenceRecord.project_id == project_key))
    db.execute(delete(DastVerificationRunRecord).where(DastVerificationRunRecord.project_id == project_key))
    db.execute(delete(DastVerificationPlanRecord).where(DastVerificationPlanRecord.project_id == project_key))
    db.execute(delete(DastValidationRecord).where(DastValidationRecord.project_id == project_key))
    db.execute(delete(DastAssetDiscoveryRecord).where(DastAssetDiscoveryRecord.project_id == project_key))
    db.execute(delete(KnowledgeEntryVersionRecord).where(KnowledgeEntryVersionRecord.entry_id.in_(entry_ids)))
    db.execute(delete(KnowledgeEntryRecord).where(KnowledgeEntryRecord.source_project_id == project_key))
    db.execute(delete(SastAgentRunRecord).where(SastAgentRunRecord.project_id == project_key))
    db.execute(delete(ScaPolicyAuditRecord).where(ScaPolicyAuditRecord.project_id == project_key))
    db.execute(delete(ScaPolicyExceptionRecord).where(ScaPolicyExceptionRecord.project_id == project_key))
    db.execute(delete(ScaPolicyOverrideRecord).where(ScaPolicyOverrideRecord.project_id == project_key))
    db.execute(delete(ScaVexStatementRecord).where(ScaVexStatementRecord.project_id == project_key))
    db.execute(delete(FindingRecord).where(FindingRecord.project_id == project_key))
    db.execute(delete(ComponentRecord).where(ComponentRecord.project_id == project_key))
    db.execute(delete(ScanTaskRecord).where(ScanTaskRecord.project_id == project_key))
    db.execute(delete(ProjectModuleRecord).where(ProjectModuleRecord.project_id == project_key))
    db.execute(delete(AuditRecord).where(AuditRecord.project_id == project_key))
    db.execute(delete(ProjectMembershipRecord).where(ProjectMembershipRecord.project_id == project_key))
    db.delete(record)
    db.commit()
    if source_path is not None:
        cleanup_managed_destination(source_path)


@router.get("/{project_id}/asset-probe", response_model=ProjectAssetProbe)
def probe_project_assets(project_id: UUID, db: Session = Depends(get_db)) -> ProjectAssetProbe:
    record = db.get(ProjectRecord, str(project_id))
    if record is None:
        raise HTTPException(status_code=404, detail="Project not found")

    inventory = inspect_project_assets(record.source_path)
    return ProjectAssetProbe(
        project_id=project_id,
        source_path=inventory.source_path,
        path_exists=inventory.path_exists,
        sca_files=inventory.sca_files,
        source_files=inventory.source_files,
        agent_files=inventory.agent_files,
        recommended_tasks=inventory.recommended_tasks,
        message=inventory.message,
    )


def persist_imported_project(
    db: Session,
    *,
    name: str,
    source_path: Path,
    repository_url: str | None,
    business_owner: str | None,
    security_owner: str | None,
    runtime_url: str | None,
    api_base_url: str | None,
    sandbox_command: str | None,
    sandbox_image: str | None,
    default_branch: str,
    import_mode: str,
    managed_source: bool,
) -> ProjectImportResult:
    tenant_id = ensure_legacy_tenant(db)
    record = ProjectRecord(
        tenant_id=tenant_id,
        name=name.strip(),
        business_owner=business_owner,
        security_owner=security_owner,
        repository_url=repository_url,
        source_path=str(source_path.resolve()),
        runtime_url=runtime_url,
        api_base_url=api_base_url,
        sandbox_command=sandbox_command,
        sandbox_image=sandbox_image,
        default_branch=default_branch,
    )
    db.add(record)
    db.flush()
    inventory = inspect_project_assets(record.source_path)
    enabled = [ModuleKey.sca, ModuleKey.sast, ModuleKey.aspm]
    if inventory.agent_file_count:
        enabled.append(ModuleKey.agent)
    for module_key in enabled:
        module = get_module(module_key)
        db.add(ProjectModuleRecord(project_id=str(record.id), module_key=module_key.value, enabled=True, config=dict(module.default_config if module else {})))
    db.commit()
    db.refresh(record)
    readiness = ProjectReadiness.model_validate(build_project_readiness(record, inventory))
    return ProjectImportResult(
        project=project_to_schema(record),
        readiness=readiness,
        import_mode=import_mode,
        managed_source=managed_source,
    )


def ensure_legacy_tenant(db: Session) -> str:
    tenant_id = "00000000-0000-0000-0000-000000000001"
    if db.get(TenantRecord, tenant_id) is None:
        db.add(TenantRecord(id=tenant_id, name="Legacy Workspace"))
        db.flush()
    return tenant_id
