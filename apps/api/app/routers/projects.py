from pathlib import Path
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from app.db import get_db
from app.db_models import (
    ComponentRecord,
    DastValidationRecord,
    FindingRecord,
    ProjectModuleRecord,
    ProjectRecord,
    SandboxEvidenceRecord,
    ScanTaskRecord,
)
from app.models import Project, ProjectAssetProbe, ProjectCreate, ProjectUpdate
from app.repositories.mappers import project_to_schema

router = APIRouter()

SCA_MANIFESTS = {"package.json", "requirements.txt", "pom.xml", "go.mod"}
AGENT_FILES = {"AGENTS.md", "CLAUDE.md", "mcp.json", "plugin.json"}
SOURCE_SUFFIXES = {
    ".py",
    ".js",
    ".jsx",
    ".ts",
    ".tsx",
    ".java",
    ".go",
    ".cs",
    ".php",
    ".rb",
    ".rs",
    ".kt",
    ".swift",
}


@router.get("", response_model=list[Project])
def list_projects(db: Session = Depends(get_db)) -> list[Project]:
    records = db.scalars(select(ProjectRecord).order_by(ProjectRecord.created_at.desc())).all()
    return [project_to_schema(record) for record in records]


@router.post("", response_model=Project, status_code=201)
def create_project(payload: ProjectCreate, db: Session = Depends(get_db)) -> Project:
    record = ProjectRecord(**payload.model_dump())
    db.add(record)
    db.commit()
    db.refresh(record)
    return project_to_schema(record)


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

    db.execute(delete(DastValidationRecord).where(DastValidationRecord.project_id == project_key))
    db.execute(delete(SandboxEvidenceRecord).where(SandboxEvidenceRecord.project_id == project_key))
    db.execute(delete(ComponentRecord).where(ComponentRecord.project_id == project_key))
    db.execute(delete(FindingRecord).where(FindingRecord.project_id == project_key))
    db.execute(delete(ScanTaskRecord).where(ScanTaskRecord.project_id == project_key))
    db.execute(delete(ProjectModuleRecord).where(ProjectModuleRecord.project_id == project_key))
    db.delete(record)
    db.commit()


@router.get("/{project_id}/asset-probe", response_model=ProjectAssetProbe)
def probe_project_assets(project_id: UUID, db: Session = Depends(get_db)) -> ProjectAssetProbe:
    record = db.get(ProjectRecord, str(project_id))
    if record is None:
        raise HTTPException(status_code=404, detail="Project not found")

    if not record.source_path:
        return ProjectAssetProbe(project_id=project_id, message="当前项目未配置本地源码路径")

    root = Path(record.source_path).expanduser()
    if not root.exists() or not root.is_dir():
        return ProjectAssetProbe(
            project_id=project_id,
            source_path=record.source_path,
            message="本地源码路径不存在或不是目录",
        )

    sca_files: list[str] = []
    source_files: list[str] = []
    agent_files: list[str] = []
    ignored_dirs = {".git", "node_modules", ".venv", "venv", "dist", "build", "__pycache__"}
    for path in root.rglob("*"):
        if len(sca_files) >= 20 and len(source_files) >= 20 and len(agent_files) >= 20:
            break
        if any(part in ignored_dirs for part in path.relative_to(root).parts):
            continue
        if not path.is_file():
            continue

        relative = str(path.relative_to(root))
        if path.name in SCA_MANIFESTS and len(sca_files) < 20:
            sca_files.append(relative)
        if path.suffix.lower() in SOURCE_SUFFIXES and len(source_files) < 20:
            source_files.append(relative)
        if (
            path.name in AGENT_FILES
            or path.suffix.lower() in {".md", ".yaml", ".yml", ".json", ".toml"}
        ) and len(agent_files) < 20:
            agent_files.append(relative)

    recommended_tasks: list[str] = []
    if sca_files:
        recommended_tasks.append("sca")
    if source_files:
        recommended_tasks.append("sast")
    if agent_files:
        recommended_tasks.append("agent")

    return ProjectAssetProbe(
        project_id=project_id,
        source_path=record.source_path,
        path_exists=True,
        sca_files=sca_files,
        source_files=source_files,
        agent_files=agent_files,
        recommended_tasks=recommended_tasks,
        message="已完成本地源码路径探测",
    )
