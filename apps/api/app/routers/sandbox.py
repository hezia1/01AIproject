from datetime import datetime
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db import get_db
from app.db_models import FindingRecord, ProjectModuleRecord, ProjectRecord, SandboxEvidenceRecord
from app.models import ModuleKey, SandboxCommandTemplate, SandboxEvidence, SandboxEvidenceCreate, SandboxEvidenceUpdate, SandboxRunRequest
from app.repositories.mappers import sandbox_evidence_to_schema
from app.services.sandbox_runner import SandboxCommandRejected, run_sandbox_command
from app.services.sandbox_templates import discover_sandbox_templates

router = APIRouter()


@router.post("/evidence", response_model=SandboxEvidence, status_code=201)
def create_evidence(payload: SandboxEvidenceCreate, db: Session = Depends(get_db)) -> SandboxEvidence:
    _require_sandbox_project(db, payload.project_id)
    _validate_finding(db, payload.project_id, payload.finding_id)

    record = SandboxEvidenceRecord(
        project_id=str(payload.project_id),
        finding_id=str(payload.finding_id) if payload.finding_id else None,
        run_command=payload.run_command,
        runtime_profile=payload.runtime_profile,
        network_policy=payload.network_policy,
        filesystem_policy=payload.filesystem_policy,
        observed_files=payload.observed_files,
        observed_network=payload.observed_network,
        observed_processes=payload.observed_processes,
        observed_tool_calls=payload.observed_tool_calls,
        evidence_summary=payload.evidence_summary,
        operator=payload.operator,
    )
    db.add(record)
    db.commit()
    db.refresh(record)
    return sandbox_evidence_to_schema(record)


@router.post("/run", response_model=SandboxEvidence, status_code=201)
def run_evidence(payload: SandboxRunRequest, db: Session = Depends(get_db)) -> SandboxEvidence:
    project = _require_sandbox_project(db, payload.project_id)
    _validate_finding(db, payload.project_id, payload.finding_id)

    try:
        result = run_sandbox_command(payload.run_command, project.source_path, payload.timeout_seconds, payload.image)
    except SandboxCommandRejected as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    observed_process = {
        "command": result.command,
        "cwd": result.cwd,
        "image": result.image,
        "exit_code": result.exit_code,
        "elapsed_ms": result.elapsed_ms,
        "timed_out": result.timed_out,
        "stdout": result.stdout,
        "stderr": result.stderr,
    }
    record = SandboxEvidenceRecord(
        project_id=str(payload.project_id),
        finding_id=str(payload.finding_id) if payload.finding_id else None,
        run_command=result.command,
        runtime_profile=result.runtime_profile,
        network_policy="docker-network-none",
        filesystem_policy="readonly-source-mount",
        observed_files=[],
        observed_network=[{"policy": "none", "allowed": False}],
        observed_processes=[observed_process],
        observed_tool_calls=[
            {
                "tool": "docker",
                "arguments": result.command,
                "image": result.image,
                "resource_limits": {"cpus": "1", "memory": "512m", "pids_limit": 128},
                "mount": {"source": result.cwd, "target": "/workspace", "mode": "ro"},
            }
        ],
        evidence_summary=result.evidence_summary,
        operator=payload.operator or "sandbox-runner",
    )
    db.add(record)
    db.commit()
    db.refresh(record)
    return sandbox_evidence_to_schema(record)


@router.get("/projects/{project_id}/templates", response_model=list[SandboxCommandTemplate])
def list_project_templates(project_id: UUID, db: Session = Depends(get_db)) -> list[SandboxCommandTemplate]:
    project = _require_sandbox_project(db, project_id)
    return discover_sandbox_templates(project.source_path)


@router.get("/projects/{project_id}/evidence", response_model=list[SandboxEvidence])
def list_project_evidence(project_id: UUID, db: Session = Depends(get_db)) -> list[SandboxEvidence]:
    if db.get(ProjectRecord, str(project_id)) is None:
        raise HTTPException(status_code=404, detail="Project not found")

    records = db.scalars(
        select(SandboxEvidenceRecord)
        .where(SandboxEvidenceRecord.project_id == str(project_id))
        .order_by(SandboxEvidenceRecord.created_at.desc())
    ).all()
    return [sandbox_evidence_to_schema(record) for record in records]


@router.patch("/evidence/{evidence_id}", response_model=SandboxEvidence)
def update_evidence(
    evidence_id: UUID, payload: SandboxEvidenceUpdate, db: Session = Depends(get_db)
) -> SandboxEvidence:
    record = db.get(SandboxEvidenceRecord, str(evidence_id))
    if record is None:
        raise HTTPException(status_code=404, detail="SANDBOX evidence not found")

    updates = payload.model_dump(exclude_unset=True)
    for field, value in updates.items():
        setattr(record, field, value)
    record.updated_at = datetime.utcnow()
    db.commit()
    db.refresh(record)
    return sandbox_evidence_to_schema(record)


def _require_sandbox_project(db: Session, project_id: UUID) -> ProjectRecord:
    project = db.get(ProjectRecord, str(project_id))
    if project is None:
        raise HTTPException(status_code=404, detail="Project not found")

    project_module = db.scalar(
        select(ProjectModuleRecord).where(
            ProjectModuleRecord.project_id == str(project_id),
            ProjectModuleRecord.module_key == ModuleKey.sandbox.value,
            ProjectModuleRecord.enabled.is_(True),
        )
    )
    if project_module is None:
        raise HTTPException(status_code=400, detail="SANDBOX module is not enabled for this project")
    return project


def _validate_finding(db: Session, project_id: UUID, finding_id: UUID | None) -> None:
    if finding_id is None:
        return
    finding = db.get(FindingRecord, str(finding_id))
    if finding is None or finding.project_id != str(project_id):
        raise HTTPException(status_code=400, detail="finding_id does not belong to this project")
