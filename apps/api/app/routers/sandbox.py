from datetime import datetime
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db import get_db
from app.db_models import ComponentRecord, DastValidationRecord, FindingRecord, ProjectModuleRecord, ProjectRecord, SandboxEvidenceRecord, SandboxTargetInstanceRecord, SandboxTaskEventRecord, SandboxTaskRecord
from app.models import (
    DastSandboxResult,
    LinkSuggestion,
    ModuleKey,
    SandboxCommandTemplate,
    SandboxEvidence,
    SandboxEvidenceCreate,
    SandboxEvidenceUpdate,
    SandboxLinkSuggestionRequest,
    SandboxRunRequest,
    SandboxTargetCreate,
    SandboxTargetInstance,
    SandboxTask,
    SandboxTaskCancel,
    SandboxTaskEvent,
    SandboxTaskExecute,
)
from app.repositories.mappers import sandbox_evidence_to_schema
from app.services.evidence_link_suggestions import build_sandbox_link_suggestions
from app.services.sandbox_runner import SandboxCommandRejected, run_sandbox_command
from app.services.sandbox_templates import discover_sandbox_templates
from app.services.sandbox_identity import bootstrap_target_identities
from app.services.sandbox_launch_planner import build_launch_plan
from app.services.sandbox_orchestrator import (
    SandboxOrchestrationError,
    capability_health,
    check_target_health,
    diagnose_startup_failure,
    event_to_dict,
    execute_task,
    persist_task_evidence_record,
    record_event,
    register_external_target,
    start_docker_target,
    stop_target,
    target_to_dict,
    task_to_dict,
)

router = APIRouter()


@router.get("/capabilities")
def get_capability_health() -> dict[str, object]:
    return capability_health()


@router.get("/projects/{project_id}/launch-plan")
def get_project_launch_plan(project_id: UUID, use_ai: bool = True, db: Session = Depends(get_db)) -> dict[str, object]:
    project = _require_sandbox_project(db, project_id)
    return build_launch_plan(project, use_ai=use_ai)


@router.get("/projects/{project_id}/targets", response_model=list[SandboxTargetInstance])
def list_targets(project_id: UUID, db: Session = Depends(get_db)) -> list[SandboxTargetInstance]:
    _require_sandbox_project(db, project_id)
    records = db.scalars(
        select(SandboxTargetInstanceRecord)
        .where(SandboxTargetInstanceRecord.project_id == str(project_id))
        .order_by(SandboxTargetInstanceRecord.created_at.desc())
    ).all()
    return [SandboxTargetInstance(**target_to_dict(record)) for record in records]


@router.post("/projects/{project_id}/targets", response_model=SandboxTargetInstance, status_code=201)
def create_target(project_id: UUID, payload: SandboxTargetCreate, db: Session = Depends(get_db)) -> SandboxTargetInstance:
    project = _require_sandbox_project(db, project_id)
    try:
        if payload.mode == "external":
            runtime_url = payload.runtime_url or project.runtime_url or project.api_base_url
            if not runtime_url:
                raise SandboxOrchestrationError("项目没有可注册的 runtime_url/api_base_url")
            record = register_external_target(db, project, runtime_url, payload.health_path, payload.operator, payload.operator_confirmed)
        else:
            image = payload.image or project.sandbox_image or ""
            command = payload.command or project.sandbox_command or ""
            container_port = payload.container_port
            health_path = payload.health_path
            launch_candidates: list[dict[str, object]] = []
            if image and command:
                launch_candidates.append({"image": image, "command": command, "container_port": container_port or 8000, "health_path": health_path or "/"})
            plan = build_launch_plan(project, use_ai=True)
            for item in plan.get("candidates") if isinstance(plan.get("candidates"), list) else []:
                if isinstance(item, dict) and item.get("approved") and item.get("image") and item.get("command"):
                    matching = next((value for value in launch_candidates if value["image"] == item["image"] and value["command"] == item["command"]), None)
                    if matching is not None:
                        matching.update({"services": list(item.get("services") or []), "source_subdir": str(item.get("source_subdir") or ".")})
                    else:
                        launch_candidates.append(item)
            if not launch_candidates:
                raise SandboxOrchestrationError(str(plan.get("message") or "无法生成安全的项目启动方案"))
            failures: list[dict[str, object]] = []
            record = None
            for candidate in launch_candidates:
                image, command = str(candidate.get("image") or ""), str(candidate.get("command") or "")
                container_port = int(candidate.get("container_port") or 8000)
                health_path = str(candidate.get("health_path") or "/")
                try:
                    attempt = start_docker_target(
                        db, project, image=image, command=command,
                        container_port=container_port, health_path=health_path,
                        operator=payload.operator, confirmed=payload.operator_confirmed,
                        services=list(candidate.get("services") or []), source_subdir=str(candidate.get("source_subdir") or "."),
                    )
                    if attempt.status != "running":
                        diagnostic = diagnose_startup_failure(str((attempt.health_detail or {}).get("error") or "HTTP healthcheck failed"), stage="healthcheck")
                        failures.append({"image": image, "command": command, "source_subdir": str(candidate.get("source_subdir") or "."), "diagnostic": diagnostic})
                        stop_target(attempt)
                        db.rollback()
                        project = _require_sandbox_project(db, project_id)
                        continue
                    record = attempt
                    break
                except SandboxOrchestrationError as exc:
                    failures.append({"image": image, "command": command, "source_subdir": str(candidate.get("source_subdir") or "."), "diagnostic": exc.diagnostic})
                    db.rollback()
                    project = _require_sandbox_project(db, project_id)
            if record is None:
                primary = failures[0].get("diagnostic") if failures and isinstance(failures[0].get("diagnostic"), dict) else diagnose_startup_failure("所有候选失败")
                summary = str(primary.get("title") or "所有候选失败") + "。" + str(primary.get("remediation") or "")
                raise SandboxOrchestrationError("所有安全启动候选均未通过试运行：" + summary, stage="candidate_fallback", diagnostic={"stage": "candidate_fallback", "code": "all_candidates_failed", "title": "所有启动候选均失败", "detail": summary, "remediation": primary.get("remediation"), "attempts": failures, "redacted": True})
            record.policy = {
                **(record.policy or {}),
                "launch_attempt_count": len(failures) + 1,
                "failed_launch_candidates": failures,
                "browser_session_id": str(payload.browser_session_id) if payload.browser_session_id else None,
            }
            if record.status == "running" and (not project.sandbox_image or not project.sandbox_command):
                project.sandbox_image, project.sandbox_command = image, command
        record.health_detail = {**(record.health_detail or {}), "identity": bootstrap_target_identities(record)}
        db.commit()
        db.refresh(record)
        return SandboxTargetInstance(**target_to_dict(record))
    except SandboxOrchestrationError as exc:
        db.rollback()
        raise HTTPException(status_code=400, detail=exc.to_detail()) from exc


@router.post("/targets/{target_id}/health", response_model=SandboxTargetInstance)
def refresh_target_health(target_id: UUID, db: Session = Depends(get_db)) -> SandboxTargetInstance:
    record = db.get(SandboxTargetInstanceRecord, str(target_id))
    if record is None:
        raise HTTPException(status_code=404, detail="SANDBOX target not found")
    check_target_health(record)
    if record.status == "running":
        record.health_detail = {**(record.health_detail or {}), "identity": bootstrap_target_identities(record)}
    db.commit()
    db.refresh(record)
    return SandboxTargetInstance(**target_to_dict(record))


@router.post("/targets/{target_id}/identities/bootstrap", response_model=SandboxTargetInstance)
def bootstrap_target_identity(target_id: UUID, db: Session = Depends(get_db)) -> SandboxTargetInstance:
    record = db.get(SandboxTargetInstanceRecord, str(target_id))
    if record is None:
        raise HTTPException(status_code=404, detail="SANDBOX target not found")
    if record.status != "running":
        raise HTTPException(status_code=409, detail="目标尚未通过健康检查，不能初始化测试身份")
    record.health_detail = {**(record.health_detail or {}), "identity": bootstrap_target_identities(record)}
    record.updated_at = datetime.utcnow()
    db.commit()
    db.refresh(record)
    return SandboxTargetInstance(**target_to_dict(record))


@router.post("/targets/{target_id}/stop", response_model=SandboxTargetInstance)
def stop_target_instance(target_id: UUID, db: Session = Depends(get_db)) -> SandboxTargetInstance:
    record = db.get(SandboxTargetInstanceRecord, str(target_id))
    if record is None:
        raise HTTPException(status_code=404, detail="SANDBOX target not found")
    try:
        stop_target(record)
        db.commit()
        db.refresh(record)
        return SandboxTargetInstance(**target_to_dict(record))
    except SandboxOrchestrationError as exc:
        db.rollback()
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.post("/projects/{project_id}/browser-sessions/{session_id}/stop")
def stop_browser_session_targets(project_id: UUID, session_id: UUID, db: Session = Depends(get_db)) -> dict[str, object]:
    """Best-effort unload cleanup scoped to Docker targets created by one browser page."""
    _require_sandbox_project(db, project_id)
    records = list(db.scalars(
        select(SandboxTargetInstanceRecord).where(
            SandboxTargetInstanceRecord.project_id == str(project_id),
            SandboxTargetInstanceRecord.mode == "docker",
            SandboxTargetInstanceRecord.status != "stopped",
        )
    ).all())
    target_ids = browser_session_target_ids(records, session_id)
    stopped: list[str] = []
    failed: list[dict[str, str]] = []
    for target_id in target_ids:
        record = db.get(SandboxTargetInstanceRecord, target_id)
        if record is None or record.status == "stopped":
            continue
        try:
            stop_target(record)
            db.commit()
            stopped.append(target_id)
        except SandboxOrchestrationError as exc:
            db.rollback()
            failed.append({"target_id": target_id, "detail": str(exc)})
    return {"session_id": str(session_id), "stopped_target_ids": stopped, "failed": failed}


def browser_session_target_ids(records: list[SandboxTargetInstanceRecord], session_id: UUID | str) -> list[str]:
    return [
        str(record.id) for record in records
        if record.mode == "docker"
        and record.status != "stopped"
        and str((record.policy or {}).get("browser_session_id") or "") == str(session_id)
    ]


@router.get("/projects/{project_id}/tasks", response_model=list[SandboxTask])
def list_tasks(project_id: UUID, db: Session = Depends(get_db)) -> list[SandboxTask]:
    _require_sandbox_project(db, project_id)
    records = db.scalars(
        select(SandboxTaskRecord).where(SandboxTaskRecord.project_id == str(project_id))
        .order_by(SandboxTaskRecord.created_at.desc())
    ).all()
    return [SandboxTask(**task_to_dict(record)) for record in records]


@router.get("/tasks/{task_id}/events", response_model=list[SandboxTaskEvent])
def list_task_events(task_id: UUID, db: Session = Depends(get_db)) -> list[SandboxTaskEvent]:
    if db.get(SandboxTaskRecord, str(task_id)) is None:
        raise HTTPException(status_code=404, detail="SANDBOX task not found")
    records = db.scalars(
        select(SandboxTaskEventRecord).where(SandboxTaskEventRecord.task_id == str(task_id))
        .order_by(SandboxTaskEventRecord.created_at.asc())
    ).all()
    return [SandboxTaskEvent(**event_to_dict(record)) for record in records]


@router.post("/tasks/{task_id}/execute", response_model=SandboxTask)
def execute_queued_task(task_id: UUID, payload: SandboxTaskExecute, db: Session = Depends(get_db)) -> SandboxTask:
    task = db.get(SandboxTaskRecord, str(task_id))
    if task is None:
        raise HTTPException(status_code=404, detail="SANDBOX task not found")
    target = db.get(SandboxTargetInstanceRecord, str(payload.target_instance_id)) if payload.target_instance_id else db.scalar(
        select(SandboxTargetInstanceRecord).where(
            SandboxTargetInstanceRecord.project_id == str(task.project_id), SandboxTargetInstanceRecord.status == "running",
        ).order_by(SandboxTargetInstanceRecord.created_at.desc())
    )
    if target is None:
        raise HTTPException(status_code=400, detail="当前项目没有健康的 SANDBOX 目标实例")
    try:
        result = execute_task(db, task, target, payload.operator)
        if str(result.get("status")) == "blocked":
            # A missing local adapter/image is retryable.  Keep the one-time DAST
            # callback token intact and leave the upstream run awaiting SANDBOX.
            db.commit()
            db.refresh(task)
            return SandboxTask(**task_to_dict(task))
        callback_payload = DastSandboxResult(
            task_id=UUID(str(task.source_task_id)), strategy_id=UUID(str(task.strategy_id)),
            callback_token=task.callback_token, execution_id=str(result["execution_id"]),
            status=str(result["status"]), capabilities=list(result.get("capabilities") or []),
            evidence=list(result.get("evidence") or []), verdict_signal=result.get("verdict_signal"),
            verdict_reason=str(result.get("verdict_reason") or "") or None,
        )
        from app.routers.dast import ingest_sandbox_business_result
        ingest_sandbox_business_result(UUID(str(task.source_task_id)), callback_payload, db)
        if task.status == "completed" and task.evidence:
            persist_task_evidence_record(db, task, target)
        task.callback_token = "consumed:" + task.callback_token[-32:]
        reported_message = (
            "完整事实证据已回传 DAST，并完成独立三色裁决。"
            if task.status == "completed" and bool(task.evidence)
            else "执行失败状态已同步 DAST；未产生事实证据，本次任务未形成三色裁决。"
        )
        record_event(db, task, "REPORTED", task.status, {"message": reported_message})
        db.commit()
        db.refresh(task)
        return SandboxTask(**task_to_dict(task))
    except SandboxOrchestrationError as exc:
        task.status, task.error, task.updated_at = "failed", str(exc), datetime.utcnow()
        record_event(db, task, "FAILED", "failed", {"message": str(exc)})
        callback_payload = DastSandboxResult(
            task_id=UUID(str(task.source_task_id)), strategy_id=UUID(str(task.strategy_id)), callback_token=task.callback_token,
            execution_id=task.execution_id or f"failed-{task.id}", status="failed", capabilities=[], evidence=[], verdict_reason=str(exc),
        )
        from app.routers.dast import ingest_sandbox_business_result
        ingest_sandbox_business_result(UUID(str(task.source_task_id)), callback_payload, db)
        task.callback_token = "consumed:" + task.callback_token[-32:]
        db.commit()
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/tasks/{task_id}/cancel", response_model=SandboxTask)
def cancel_task(task_id: UUID, payload: SandboxTaskCancel, db: Session = Depends(get_db)) -> SandboxTask:
    task = db.get(SandboxTaskRecord, str(task_id))
    if task is None:
        raise HTTPException(status_code=404, detail="SANDBOX task not found")
    if task.status not in {"queued", "blocked"}:
        raise HTTPException(status_code=409, detail=f"任务状态 {task.status} 不允许取消")
    task.status, task.operator, task.error = "cancelled", payload.operator, payload.reason
    task.completed_at = task.updated_at = datetime.utcnow()
    record_event(db, task, "CANCELLED", "cancelled", {"message": payload.reason})
    callback_payload = DastSandboxResult(
        task_id=UUID(str(task.source_task_id)), strategy_id=UUID(str(task.strategy_id)), callback_token=task.callback_token,
        execution_id=f"cancelled-{task.id}", status="cancelled", capabilities=[], evidence=[], verdict_reason=payload.reason,
    )
    from app.routers.dast import ingest_sandbox_business_result
    ingest_sandbox_business_result(UUID(str(task.source_task_id)), callback_payload, db)
    task.callback_token = "consumed:" + task.callback_token[-32:]
    db.commit()
    db.refresh(task)
    return SandboxTask(**task_to_dict(task))


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
