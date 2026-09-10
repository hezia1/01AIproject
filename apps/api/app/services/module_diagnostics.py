from __future__ import annotations

from dataclasses import asdict
from datetime import datetime
from typing import Callable

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db_models import (
    DastBusinessRunRecord,
    DastVerificationRunRecord,
    ProjectModuleRecord,
    ProjectRecord,
    SandboxTargetInstanceRecord,
    SandboxTaskRecord,
    SastAgentRunRecord,
    ScanTaskRecord,
)
from app.services.dast_deepseek import dast_deepseek_health
from app.services.deepseek_client import deepseek_health
from app.services.diagnostic_contract import bounded_positive_int, freshness, utc_now
from app.services.project_onboarding import inspect_project_assets
from app.services.sca_intelligence import intelligence_status
from app.services.sca_osv_mirror import osv_mirror_status
from app.services.sca_tool_scanner import grype_database_status
from app.services.scan_status import execution_diagnostic, scan_task_diagnostic


GOOD_CHECK_STATES = {"ok", "current", "ready", "succeeded", "not_required", "not_applicable"}


def project_module_diagnostics(
    db: Session,
    project: ProjectRecord,
    *,
    now: datetime | None = None,
    grype_status_provider: Callable[[], object] = grype_database_status,
    sast_model_provider: Callable[[], dict[str, object]] = deepseek_health,
    dast_model_provider: Callable[[], dict[str, object]] = dast_deepseek_health,
) -> dict[str, object]:
    checked_at = now or utc_now()
    project_id = str(project.id)
    configured_modules = db.scalars(
        select(ProjectModuleRecord).where(ProjectModuleRecord.project_id == project_id)
    ).all()
    module_records = {record.module_key: record for record in configured_modules}
    latest_scans = {
        key: db.scalar(
            select(ScanTaskRecord)
            .where(ScanTaskRecord.project_id == project_id, ScanTaskRecord.scan_type == key)
            .order_by(ScanTaskRecord.created_at.desc())
        )
        for key in ("sca", "sast", "agent")
    }
    latest_ai_run = db.scalar(
        select(SastAgentRunRecord)
        .where(SastAgentRunRecord.project_id == project_id)
        .order_by(SastAgentRunRecord.created_at.desc())
    )
    latest_target = db.scalar(
        select(SandboxTargetInstanceRecord)
        .where(SandboxTargetInstanceRecord.project_id == project_id)
        .order_by(SandboxTargetInstanceRecord.updated_at.desc())
    )
    latest_sandbox_task = db.scalar(
        select(SandboxTaskRecord)
        .where(SandboxTaskRecord.project_id == project_id)
        .order_by(SandboxTaskRecord.updated_at.desc())
    )
    business_run = db.scalar(
        select(DastBusinessRunRecord)
        .where(DastBusinessRunRecord.project_id == project_id)
        .order_by(DastBusinessRunRecord.updated_at.desc())
    )
    verification_run = db.scalar(
        select(DastVerificationRunRecord)
        .where(DastVerificationRunRecord.project_id == project_id)
        .order_by(DastVerificationRunRecord.updated_at.desc())
    )
    latest_dast_run = _newest_record(business_run, verification_run)

    try:
        agent_asset_count = inspect_project_assets(project.source_path).agent_file_count
    except (OSError, ValueError):
        agent_asset_count = None

    live_sources = _sca_sources(grype_status_provider)
    sast_health = _safe_model_health(sast_model_provider, "SAST DeepSeek")
    dast_health = _safe_model_health(dast_model_provider, "DAST DeepSeek")
    modules = [
        _sca_diagnostics(module_records.get("sca"), latest_scans["sca"], live_sources, checked_at),
        _sast_diagnostics(module_records.get("sast"), latest_scans["sast"], latest_ai_run, sast_health, checked_at),
        _agent_diagnostics(module_records.get("agent"), latest_scans["agent"], agent_asset_count, sast_health, checked_at),
        _dast_diagnostics(module_records.get("dast"), latest_dast_run, latest_target, dast_health, checked_at),
        _sandbox_diagnostics(module_records.get("sandbox"), latest_sandbox_task, latest_target, checked_at),
    ]
    active_statuses = [item["status"] for item in modules if item["status"] not in {"disabled", "not_applicable"}]
    overall = (
        "unavailable" if "unavailable" in active_statuses
        else "degraded" if any(status != "ok" for status in active_statuses)
        else "ok" if active_statuses
        else "unknown"
    )
    return {
        "project_id": project_id,
        "status": overall,
        "checked_at": checked_at.isoformat(),
        "state_contract": {
            "succeeded": "任务完成且现有执行元数据未显示范围、引擎或依赖缺口；不等于无漏洞。",
            "partial": "任务有结果，但范围、引擎、情报、模型或证据不完整。",
            "stale": "最近结果超过时效上限，不能代表当前代码或依赖状态。",
            "failed": "任务执行失败，不能将零结果解释为无漏洞。",
            "not_run": "模块没有任务记录。",
        },
        "modules": modules,
        "limitations": [
            "诊断聚合现有配置、任务元数据和已保存健康证据，不主动访问任意外部被测地址。",
            "模型配置存在不等于服务连通；只有显式连接测试或已保存成功调用可证明最近一次调用成功。",
            "succeeded 只表示已配置执行路径完成，不表示项目不存在未覆盖漏洞。",
        ],
    }


def _sca_sources(provider: Callable[[], object]) -> dict[str, object]:
    try:
        grype = provider()
        grype = asdict(grype) if hasattr(grype, "__dataclass_fields__") else dict(grype)
    except Exception as exc:
        grype = {"status": "unavailable", "detail": f"Grype 数据库状态读取失败：{type(exc).__name__}"}
    return {"grype": grype, "osv_mirror": osv_mirror_status(), "intelligence": intelligence_status()}


def _sca_diagnostics(record: object, scan: object, sources: dict[str, object], now: datetime) -> dict[str, object]:
    enabled = _enabled(record)
    task = scan_task_diagnostic(scan, now=now) if scan else _not_run_task()
    metadata = getattr(scan, "scan_metadata", {}) if scan else {}
    metadata = metadata if isinstance(metadata, dict) else {}
    osv_run = metadata.get("osv_lookup") if isinstance(metadata.get("osv_lookup"), dict) else {}
    grype = sources["grype"]
    mirror = sources["osv_mirror"]
    intel = sources["intelligence"]
    mirror_required = osv_run.get("status") == "offline_degraded"
    tool_required = bool((metadata.get("sca_tool_scan") or {}).get("enabled")) if isinstance(metadata.get("sca_tool_scan"), dict) else False
    checks = [
        _task_check(task, required=enabled),
        _check("online_osv", "本次在线 OSV", _osv_run_state(osv_run), _osv_run_detail(osv_run), required=enabled),
        _check("osv_mirror", "本地 OSV 镜像", _source_state(mirror), _source_detail(mirror), required=mirror_required, observed_at=_source_observed_at(mirror)),
        _check("supplemental_intelligence", "补充漏洞情报", _source_state(intel), _source_detail(intel), required=False, observed_at=_source_observed_at(intel)),
        _check("grype_database", "Grype 漏洞数据库", _grype_state(grype), str(grype.get("detail") or "已读取 Grype 数据库状态。"), required=tool_required, observed_at=grype.get("built_at")),
    ]
    return _module("sca", "SCA 供应链风险分析", enabled, task, checks)


def _sast_diagnostics(record: object, scan: object, ai_run: object, health: dict[str, object], now: datetime) -> dict[str, object]:
    enabled = _enabled(record)
    task = scan_task_diagnostic(scan, now=now) if scan else _not_run_task()
    config = getattr(record, "config", {}) if record else {}
    metadata = getattr(scan, "scan_metadata", {}) if scan else {}
    profile = metadata.get("sast_profile") if isinstance(metadata, dict) and isinstance(metadata.get("sast_profile"), dict) else config or {}
    model_required = bool(profile.get("ai_enabled") and profile.get("ai_auto_scan"))
    model = _model_check("sast_model", "SAST 模型服务", health, ai_run, required=model_required)
    engines = metadata.get("engine_status") if isinstance(metadata, dict) and isinstance(metadata.get("engine_status"), dict) else {}
    semgrep = engines.get("semgrep") if isinstance(engines.get("semgrep"), dict) else {}
    semgrep_state = "not_run" if not semgrep else "ok" if semgrep.get("status") == "completed" else str(semgrep.get("status") or "unknown")
    checks = [
        _task_check(task, required=enabled),
        _check("semgrep_execution", "本次 Semgrep", semgrep_state, str(semgrep.get("detail") or f"执行状态：{semgrep_state}"), required=bool(profile.get("semgrep_enabled"))),
        model,
    ]
    return _module("sast", "SAST 智能静态审计", enabled, task, checks)


def _agent_diagnostics(record: object, scan: object, asset_count: int | None, health: dict[str, object], now: datetime) -> dict[str, object]:
    enabled = _enabled(record)
    if enabled and asset_count == 0 and scan is None:
        task = {**_not_run_task(), "status": "not_applicable", "reasons": ["源码盘点未识别到 Agent、MCP 或插件配置。"]}
    else:
        task = scan_task_diagnostic(scan, now=now) if scan else _not_run_task()
    metadata = getattr(scan, "scan_metadata", {}) if scan else {}
    ai_review = metadata.get("ai_review") if isinstance(metadata, dict) and isinstance(metadata.get("ai_review"), dict) else None
    model = _model_check("agent_model", "AGENT 模型服务", health, None, required=False, stored_result=ai_review)
    intelligence = metadata.get("intelligence") if isinstance(metadata, dict) and isinstance(metadata.get("intelligence"), dict) else {}
    intel_status = str(intelligence.get("status") or "not_run")
    checks = [
        _task_check(task, required=enabled and task["status"] != "not_applicable"),
        _check("agent_intelligence", "AGENT 本地情报", intel_status, str(intelligence.get("detail") or f"状态：{intel_status}"), required=False),
        model,
    ]
    return _module("agent", "AGENT 供应链安全", enabled, task, checks, not_applicable=task["status"] == "not_applicable")


def _dast_diagnostics(record: object, run: object, target: object, health: dict[str, object], now: datetime) -> dict[str, object]:
    enabled = _enabled(record)
    task = _execution_task(run, now) if run else _not_run_task()
    checks = [
        _task_check(task, required=enabled),
        _target_check(target, required=enabled),
        _model_check("dast_model", "DAST 流程草案模型", health, None, required=False),
    ]
    return _module("dast", "DAST 动态验证", enabled, task, checks)


def _sandbox_diagnostics(record: object, task_record: object, target: object, now: datetime) -> dict[str, object]:
    enabled = _enabled(record)
    task = (
        execution_diagnostic(task_record.status, task_record.completed_at or task_record.updated_at, error=task_record.error, now=now)
        if task_record else _not_run_task()
    )
    checks = [_task_check(task, required=enabled), _target_check(target, required=enabled)]
    return _module("sandbox", "SANDBOX 动态证据", enabled, task, checks)


def _module(key: str, name: str, enabled: bool, task: dict[str, object], checks: list[dict[str, object]], *, not_applicable: bool = False) -> dict[str, object]:
    if not enabled:
        status = "disabled"
    elif not_applicable:
        status = "not_applicable"
    elif task["status"] in {"failed"} or any(item["required"] and item["status"] in {"failed", "unavailable", "invalid"} for item in checks):
        status = "unavailable"
    elif task["status"] == "succeeded" and all((not item["required"]) or item["status"] in GOOD_CHECK_STATES for item in checks):
        status = "ok"
    else:
        status = "degraded"
    return {"key": key, "name": name, "enabled": enabled, "status": status, "latest_task": task, "checks": checks}


def _task_check(task: dict[str, object], *, required: bool) -> dict[str, object]:
    reasons = task.get("reasons") if isinstance(task.get("reasons"), list) else []
    detail = "；".join(str(item) for item in reasons) or f"派生任务状态：{task['status']}。"
    return _check("latest_task", "最近任务", str(task["status"]), detail, required=required, observed_at=task.get("observed_at"))


def _target_check(target: object, *, required: bool) -> dict[str, object]:
    if target is None:
        return _check("target", "被测目标", "not_configured", "没有已注册并保存健康证据的动态目标。", required=required)
    health = getattr(target, "health_detail", {}) or {}
    persisted = str(getattr(target, "status", "unknown") or "unknown")
    if persisted == "running" and health.get("reachable") is True:
        status = "ready"
    elif persisted == "stopped":
        status = "stopped"
    elif persisted in {"unhealthy", "failed"} or health.get("reachable") is False:
        status = "unavailable"
    else:
        status = "unknown"
    detail = (
        f"目标状态 {persisted}；最近 HTTP 状态 {health.get('status_code', 'unknown')}。"
        if health else f"目标状态 {persisted}，没有健康检查详情。"
    )
    return _check("target", "被测目标", status, detail, required=required, observed_at=health.get("checked_at") or getattr(target, "updated_at", None), metadata={"mode": getattr(target, "mode", None), "runtime_url": getattr(target, "runtime_url", None)})


def _model_check(key: str, name: str, health: dict[str, object], run: object, *, required: bool, stored_result: dict[str, object] | None = None) -> dict[str, object]:
    configured = bool(health.get("configured"))
    configuration_status = str(health.get("status") or "unknown")
    observed_at = None
    last_status = None
    detail = str(health.get("detail") or "")
    if run is not None:
        last_status = str(getattr(run, "status", "unknown"))
        observed_at = getattr(run, "finished_at", None) or getattr(run, "started_at", None)
        detail = str(getattr(run, "error", None) or f"最近一次模型运行状态：{last_status}。")
    elif stored_result:
        last_status = str(stored_result.get("status") or "unknown")
        detail = str(stored_result.get("detail") or stored_result.get("summary") or f"最近一次模型运行状态：{last_status}。")
    call_freshness = freshness(
        observed_at,
        max_age_hours=bounded_positive_int("MODEL_DIAGNOSTIC_MAX_AGE_HOURS", 168),
    )
    if configuration_status in {"invalid_configuration", "unavailable", "error"}:
        status = "unavailable" if required else "degraded"
        detail = detail or f"模型配置状态：{configuration_status}。"
    elif last_status in {"completed", "success", "succeeded"} and observed_at is not None:
        status = "ok" if call_freshness["status"] == "current" else "stale"
        if status == "stale":
            detail = f"最近一次模型调用成功，但证据已过期；{call_freshness['detail']}"
    elif last_status in {"failed", "error", "partial"}:
        status = "unavailable" if required else "degraded"
    elif configured:
        status = "configured_unverified"
        detail = detail or "模型已配置，但没有保存的成功连接或调用证据。"
    else:
        status = "not_configured"
        detail = detail or "未配置模型密钥；本地确定性能力仍可独立运行。"
    return _check(key, name, status, detail, required=required, observed_at=observed_at, metadata={"provider": health.get("provider"), "model": health.get("model"), "configured": configured, "last_call_status": last_status})


def _safe_model_health(provider: Callable[[], dict[str, object]], label: str) -> dict[str, object]:
    try:
        return provider()
    except Exception as exc:
        return {"configured": False, "provider": "unknown", "status": "unavailable", "detail": f"{label} 配置读取失败：{type(exc).__name__}"}


def _execution_task(record: object, now: datetime) -> dict[str, object]:
    observed_at = getattr(record, "completed_at", None) or getattr(record, "updated_at", None) or getattr(record, "started_at", None)
    return execution_diagnostic(getattr(record, "status", "unknown"), observed_at, now=now)


def _not_run_task() -> dict[str, object]:
    return {"status": "not_run", "persisted_status": None, "result_complete": False, "stale": False, "observed_at": None, "age_hours": None, "max_age_hours": None, "reasons": ["没有任务记录。"]}


def _enabled(record: object) -> bool:
    return bool(record is not None and getattr(record, "enabled", False))


def _newest_record(left: object, right: object) -> object:
    candidates = [item for item in (left, right) if item is not None]
    if not candidates:
        return None
    return max(candidates, key=lambda item: getattr(item, "updated_at", None) or getattr(item, "created_at", datetime.min))


def _check(key: str, name: str, status: str, detail: str, *, required: bool, observed_at: object = None, metadata: dict[str, object] | None = None) -> dict[str, object]:
    value = observed_at.isoformat() if isinstance(observed_at, datetime) else observed_at
    return {"key": key, "name": name, "status": status, "required": required, "detail": detail, "observed_at": value, "metadata": metadata or {}}


def _source_state(source: dict[str, object]) -> str:
    status = str(source.get("status") or "unknown")
    if status in {"available", "current"}:
        freshness_state = str((source.get("freshness") or {}).get("status") or "unknown") if isinstance(source.get("freshness"), dict) else "unknown"
        return "current" if freshness_state == "current" else freshness_state
    return status


def _source_detail(source: dict[str, object]) -> str:
    freshness_value = source.get("freshness") if isinstance(source.get("freshness"), dict) else {}
    if source.get("status") in {"not_configured", "invalid", "unavailable"}:
        return str(source.get("detail") or freshness_value.get("detail") or f"状态：{source.get('status', 'unknown')}。")
    return str(freshness_value.get("detail") or source.get("detail") or f"状态：{source.get('status', 'unknown')}。")


def _source_observed_at(source: dict[str, object]) -> object:
    freshness_value = source.get("freshness") if isinstance(source.get("freshness"), dict) else {}
    return freshness_value.get("observed_at") or source.get("updated_at")


def _grype_state(source: dict[str, object]) -> str:
    status = str(source.get("status") or "unknown")
    return "current" if status == "current" else status


def _osv_run_state(source: dict[str, object]) -> str:
    status = str(source.get("status") or "not_run")
    return "ok" if status == "available" else "degraded" if status in {"offline_degraded", "mirror_used"} else status


def _osv_run_detail(source: dict[str, object]) -> str:
    if not source:
        return "最近扫描没有在线 OSV 查询状态。"
    return f"状态 {source.get('status')}；已检查 {int(source.get('checked_component_count') or 0)} 个组件，错误 {int(source.get('error_count') or 0)} 个。"
