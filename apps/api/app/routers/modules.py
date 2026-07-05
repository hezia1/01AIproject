from datetime import datetime
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db import get_db
from app.db_models import ProjectModuleRecord, ProjectRecord
from app.models import (
    ModuleKey,
    ProjectModule,
    ProjectModuleCreate,
    ProjectModuleUpdate,
    SecurityModule,
)
from app.module_registry import get_module, list_modules
from app.repositories.mappers import project_module_to_schema

router = APIRouter()


@router.get("", response_model=list[SecurityModule])
def get_modules() -> list[SecurityModule]:
    return list_modules()


@router.get("/projects/{project_id}", response_model=list[ProjectModule])
def list_project_modules(
    project_id: UUID, db: Session = Depends(get_db)
) -> list[ProjectModule]:
    if db.get(ProjectRecord, str(project_id)) is None:
        raise HTTPException(status_code=404, detail="Project not found")

    records = db.scalars(
        select(ProjectModuleRecord).where(ProjectModuleRecord.project_id == str(project_id))
    ).all()
    return [project_module_to_schema(record) for record in records]


@router.post("/projects/{project_id}", response_model=ProjectModule, status_code=201)
def enable_project_module(
    project_id: UUID, payload: ProjectModuleCreate, db: Session = Depends(get_db)
) -> ProjectModule:
    if db.get(ProjectRecord, str(project_id)) is None:
        raise HTTPException(status_code=404, detail="Project not found")

    module = get_module(payload.module_key)
    if module is None:
        raise HTTPException(status_code=404, detail="Module not found")

    record = db.scalar(
        select(ProjectModuleRecord).where(
            ProjectModuleRecord.project_id == str(project_id),
            ProjectModuleRecord.module_key == payload.module_key.value,
        )
    )
    config = module.default_config | payload.config

    if record is None:
        record = ProjectModuleRecord(
            project_id=str(project_id),
            module_key=payload.module_key.value,
            enabled=payload.enabled,
            config=config,
        )
        db.add(record)
    else:
        record.enabled = payload.enabled
        record.config = config
        record.updated_at = datetime.utcnow()

    db.commit()
    db.refresh(record)
    return project_module_to_schema(record)


@router.patch(
    "/projects/{project_id}/{module_key}",
    response_model=ProjectModule,
)
def update_project_module(
    project_id: UUID,
    module_key: ModuleKey,
    payload: ProjectModuleUpdate,
    db: Session = Depends(get_db),
) -> ProjectModule:
    record = db.scalar(
        select(ProjectModuleRecord).where(
            ProjectModuleRecord.project_id == str(project_id),
            ProjectModuleRecord.module_key == module_key.value,
        )
    )
    if record is None:
        raise HTTPException(status_code=404, detail="Project module not found")

    if payload.enabled is not None:
        record.enabled = payload.enabled
    if payload.config is not None:
        record.config = record.config | payload.config
    record.updated_at = datetime.utcnow()

    db.commit()
    db.refresh(record)
    return project_module_to_schema(record)


@router.get("/{module_key}", response_model=SecurityModule)
def get_module_detail(module_key: ModuleKey) -> SecurityModule:
    module = get_module(module_key)
    if module is None:
        raise HTTPException(status_code=404, detail="Module not found")
    return module
