from datetime import datetime
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db import get_db
from app.db_models import ComponentRecord, DastValidationRecord, FindingRecord, ProjectModuleRecord, ProjectRecord, SandboxEvidenceRecord
from app.models import (
    LinkSuggestion,
    ModuleKey,
    SandboxCommandTemplate,
    SandboxEvidence,
    SandboxEvidenceCreate,
    SandboxEvidenceUpdate,
    SandboxLinkSuggestionRequest,
    SandboxRunRequest,
)
from app.repositories.mappers import sandbox_evidence_to_schema
from app.services.evidence_link_suggestions import build_sandbox_link_suggestions
from app.services.sandbox_runner import SandboxCommandRejected, run_sandbox_command
from app.services.sandbox_templates import discover_sandbox_templates

router = APIRouter()


@router.post("/link-suggestions", response_model=list[LinkSuggestion])
def suggest_evidence_links(
    payload: SandboxLinkSuggestionRequest,
    db: Session = Depends(get_db),
) -> list[LinkSuggestion]:
    if db.get(ProjectRecord, str(payload.project_id)) is None:
        raise HTTPException(status_code=404, detail="Project not found")
    project_key = str(payload.project_id)
    findings = list(
        db.scalars(select(FindingRecord).where(FindingRecord.project_id == project_key)).all()
    )
    components = {
        str(item.id): item
        for item in db.scalars(
            select(ComponentRecord).where(ComponentRecord.project_id == project_key)
        ).all()
    }
    validations = list(
        db.scalars(
            select(DastValidationRecord)
            .where(DastValidationRecord.project_id == project_key)
            .order_by(DastValidationRecord.created_at.desc())
        ).all()
    )
    return build_sandbox_link_suggestions(
        payload.run_command,
        findings,
        components,
        validations,
        str(payload.finding_id) if payload.finding_id else None,
        str(payload.component_id) if payload.component_id else None,
    )


@router.post("/evidence", response_model=SandboxEvidence, status_code=201)
def create_evidence(payload: SandboxEvidenceCreate, db: Session = Depends(get_db)) -> SandboxEvidence:
    _require_sandbox_project(db, payload.project_id)
    finding_id, component_id, validation_id = _validate_links(
        db,
        payload.project_id,
        payload.finding_id,
        payload.component_id,
        payload.validation_id,
    )
    link_source, link_confidence = _link_metadata(
        finding_id,
        component_id,
        validation_id,
        payload.link_source,
        payload.link_confidence,
    )

    record = SandboxEvidenceRecord(
        project_id=str(payload.project_id),
        finding_id=finding_id,
        component_id=component_id,
        validation_id=validation_id,
        link_source=link_source,
        link_confidence=link_confidence,
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
        strategy_name=payload.strategy_name,
        purpose=payload.purpose,
        limitations=payload.limitations,
    )
    db.add(record)
    db.commit()
    db.refresh(record)
    return sandbox_evidence_to_schema(record)


@router.post("/run", response_model=SandboxEvidence, status_code=201)
def run_evidence(payload: SandboxRunRequest, db: Session = Depends(get_db)) -> SandboxEvidence:
    project = _require_sandbox_project(db, payload.project_id)
    finding_id, component_id, validation_id = _validate_links(
        db,
        payload.project_id,
        payload.finding_id,
        payload.component_id,
        payload.validation_id,
    )
    link_source, link_confidence = _link_metadata(
        finding_id,
        component_id,
        validation_id,
        payload.link_source,
        payload.link_confidence,
    )

    try:
        result = run_sandbox_command(payload.run_command, project.source_path, payload.timeout_seconds, payload.image)
    except SandboxCommandRejected as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    observed_process = build_process_event(result, payload.timeout_seconds)
    execution_policy = build_execution_policy(result)
    record = SandboxEvidenceRecord(
        project_id=str(payload.project_id),
        finding_id=finding_id,
        component_id=component_id,
        validation_id=validation_id,
        link_source=link_source,
        link_confidence=link_confidence,
        run_command=result.command,
        runtime_profile=result.runtime_profile,
        network_policy="docker-network-none",
        filesystem_policy="readonly-source-mount",
        observed_files=[
            {
                "event_type": "mount",
                "path": "/workspace",
                "source": result.cwd,
                "mode": "readonly",
                "purpose": "source-code",
            }
        ],
        observed_network=[
            {
                "event_type": "network_policy",
                "policy": "none",
                "allowed": False,
                "scope": "container",
                "evidence": "Docker run uses --network none.",
            }
        ],
        observed_processes=[observed_process],
        observed_tool_calls=[
            {
                "tool": "docker",
                "arguments": result.command,
                "image": result.image,
                "event_type": "container_run",
                "resource_limits": execution_policy["resource_limits"],
                "security_options": execution_policy["security_options"],
                "mount": execution_policy["mount"],
                "tmpfs": execution_policy["tmpfs"],
                "network": execution_policy["network"],
            }
        ],
        evidence_summary=result.evidence_summary,
        operator=payload.operator or "sandbox-runner",
        strategy_name=payload.strategy_name or "隔离受控执行",
        purpose=payload.purpose or "在禁网、只读的容器中执行选定命令，补充运行时执行结果和隔离策略证据。",
        limitations=payload.limitations or "命令执行成功不等于漏洞成立；当前不采集真实文件访问、网络连接或完整进程树。",
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
    next_finding_id = updates.get("finding_id", record.finding_id)
    next_component_id = updates.get("component_id", record.component_id)
    next_validation_id = updates.get("validation_id", record.validation_id)
    finding_id, component_id, validation_id = _validate_links(
        db,
        UUID(str(record.project_id)),
        UUID(str(next_finding_id)) if next_finding_id else None,
        UUID(str(next_component_id)) if next_component_id else None,
        UUID(str(next_validation_id)) if next_validation_id else None,
    )
    for field, value in updates.items():
        if field in {"finding_id", "component_id", "validation_id"}:
            setattr(record, field, str(value) if value else None)
        else:
            setattr(record, field, value)
    if {"finding_id", "component_id", "validation_id"} & updates.keys():
        record.finding_id = finding_id
        record.component_id = component_id
        record.validation_id = validation_id
        record.link_source, record.link_confidence = _link_metadata(
            finding_id,
            component_id,
            validation_id,
            record.link_source,
            record.link_confidence,
        )
    record.updated_at = datetime.utcnow()
    db.commit()
    db.refresh(record)
    return sandbox_evidence_to_schema(record)


def build_process_event(result, timeout_seconds: int) -> dict[str, object]:
    return {
        "event_type": "process_execution",
        "command": result.command,
        "cwd": result.cwd,
        "image": result.image,
        "exit_code": result.exit_code,
        "elapsed_ms": result.elapsed_ms,
        "timed_out": result.timed_out,
        "stdout": result.stdout,
        "stderr": result.stderr,
        "execution": {
            "command": result.command,
            "image": result.image,
            "working_directory": "/workspace",
            "source_directory": result.cwd,
            "exit_code": result.exit_code,
            "elapsed_ms": result.elapsed_ms,
            "timeout_seconds": timeout_seconds,
            "timed_out": result.timed_out,
        },
        "output": {
            "stdout_summary": first_nonempty_line(result.stdout),
            "stderr_summary": first_nonempty_line(result.stderr),
            "stdout_truncated": result.stdout_truncated,
            "stderr_truncated": result.stderr_truncated,
            "redacted": True,
        },
        "timeline": build_timeline(result),
    }


def build_execution_policy(result) -> dict[str, object]:
    return {
        "network": {"mode": "none", "egress_allowed": False},
        "filesystem": {"root": "read-only", "workspace_mount": "read-only"},
        "resource_limits": {"cpus": "1", "memory": "512m", "pids_limit": 128},
        "security_options": ["no-new-privileges", "read-only-rootfs"],
        "tmpfs": {"path": "/tmp", "mode": "rw,noexec,nosuid", "size": "128m"},
        "mount": {"source": result.cwd, "target": "/workspace", "mode": "ro"},
    }


def build_timeline(result) -> list[dict[str, object]]:
    final_stage = "timeout" if result.timed_out else "completed"
    final_detail = "Command timed out before completion." if result.timed_out else f"Process exited with code {result.exit_code}."
    return [
        {
            "stage": "prepared",
            "status": "completed",
            "detail": f"Resolved image {result.image or '-'} and mounted source as readonly workspace.",
        },
        {
            "stage": "executed",
            "status": "completed",
            "detail": "Docker container ran with no network, read-only root filesystem, and resource limits.",
        },
        {
            "stage": final_stage,
            "status": "timeout" if result.timed_out else "completed",
            "detail": final_detail,
            "elapsed_ms": result.elapsed_ms,
        },
    ]


def first_nonempty_line(value: str) -> str:
    for line in value.splitlines():
        stripped = line.strip()
        if stripped:
            return stripped[:240]
    return ""


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


def _validate_links(
    db: Session,
    project_id: UUID,
    finding_id: UUID | None,
    component_id: UUID | None,
    validation_id: UUID | None,
) -> tuple[str | None, str | None, str | None]:
    project_key = str(project_id)
    finding = db.get(FindingRecord, str(finding_id)) if finding_id else None
    component = db.get(ComponentRecord, str(component_id)) if component_id else None
    validation = db.get(DastValidationRecord, str(validation_id)) if validation_id else None
    if finding_id and (finding is None or finding.project_id != project_key):
        raise HTTPException(status_code=400, detail="finding_id does not belong to this project")
    if component_id and (component is None or component.project_id != project_key):
        raise HTTPException(status_code=400, detail="component_id does not belong to this project")
    if validation_id and (validation is None or validation.project_id != project_key):
        raise HTTPException(status_code=400, detail="validation_id does not belong to this project")

    resolved_finding_id = str(finding_id) if finding_id else validation.finding_id if validation else None
    resolved_component_id = str(component_id) if component_id else validation.component_id if validation else None
    if validation and validation.finding_id and resolved_finding_id and validation.finding_id != resolved_finding_id:
        raise HTTPException(status_code=400, detail="validation_id and finding_id refer to different risks")
    if validation and validation.component_id and resolved_component_id and validation.component_id != resolved_component_id:
        raise HTTPException(status_code=400, detail="validation_id and component_id refer to different components")
    if finding and finding.component_id and resolved_component_id and finding.component_id != resolved_component_id:
        raise HTTPException(status_code=400, detail="finding_id and component_id refer to different components")
    return resolved_finding_id, resolved_component_id, str(validation_id) if validation_id else None


def _link_metadata(
    finding_id: str | None,
    component_id: str | None,
    validation_id: str | None,
    requested_source: str = "unlinked",
    requested_confidence: int = 0,
) -> tuple[str, int]:
    if not any((finding_id, component_id, validation_id)):
        return "unlinked", 0
    return (
        requested_source if requested_source != "unlinked" else "explicit-selection",
        requested_confidence if requested_confidence > 0 else 100,
    )
