from __future__ import annotations

from datetime import datetime

from app.services.diagnostic_contract import bounded_positive_int, freshness


TERMINAL_SUCCESS = {"completed", "reviewed", "success", "succeeded"}


def scan_task_diagnostic(
    scan: object,
    *,
    now: datetime | None = None,
    max_age_hours: int | None = None,
) -> dict[str, object]:
    persisted = str(getattr(scan, "status", "unknown") or "unknown").lower()
    scan_type = str(getattr(scan, "scan_type", "unknown") or "unknown").lower()
    metadata = getattr(scan, "scan_metadata", None)
    metadata = metadata if isinstance(metadata, dict) else {}
    observed_at = getattr(scan, "finished_at", None) or getattr(scan, "started_at", None) or getattr(scan, "created_at", None)
    age = freshness(
        observed_at,
        max_age_hours=max_age_hours or bounded_positive_int("SCAN_DIAGNOSTIC_MAX_AGE_HOURS", 168),
        now=now,
    )
    reasons: list[str] = []

    direct = {
        "queued": "queued",
        "pending": "queued",
        "running": "running",
        "failed": "failed",
        "error": "failed",
        "cancelled": "cancelled",
        "canceled": "cancelled",
    }
    if persisted in direct:
        status = direct[persisted]
        error = metadata.get("error") or metadata.get("detail")
        if status == "failed" and error:
            reasons.append(str(error)[:500])
    elif persisted in TERMINAL_SUCCESS:
        reasons.extend(_incomplete_reasons(scan_type, metadata))
        status = "partial" if reasons else "succeeded"
        if age["status"] == "stale":
            status = "stale"
            reasons.insert(0, str(age["detail"]))
    else:
        status = "unknown"
        reasons.append(f"未识别的持久化任务状态：{persisted}")

    return {
        "status": status,
        "persisted_status": persisted,
        "result_complete": status == "succeeded",
        "stale": status == "stale",
        "observed_at": age["observed_at"],
        "age_hours": age["age_hours"],
        "max_age_hours": age["max_age_hours"],
        "reasons": reasons,
    }


def execution_diagnostic(
    status: object,
    observed_at: object,
    *,
    error: object = None,
    now: datetime | None = None,
    max_age_hours: int | None = None,
) -> dict[str, object]:
    record = type("Execution", (), {
        "status": str(status or "unknown"),
        "scan_type": "execution",
        "scan_metadata": {"error": error} if error else {},
        "finished_at": observed_at,
        "started_at": None,
        "created_at": observed_at,
    })()
    return scan_task_diagnostic(record, now=now, max_age_hours=max_age_hours)


def _incomplete_reasons(scan_type: str, metadata: dict[str, object]) -> list[str]:
    reasons: list[str] = []
    if scan_type in {"sca", "sast", "agent"} and not metadata:
        reasons.append("完成记录缺少执行元数据，不能证明结果完整。")
    if metadata.get("error"):
        reasons.append(f"任务元数据仍包含错误：{str(metadata['error'])[:400]}")
    scope = metadata.get("scope_limit") if isinstance(metadata.get("scope_limit"), dict) else {}
    if scope.get("truncated"):
        reasons.append(str(scope.get("reason") or "扫描达到有界范围，覆盖不完整。"))

    if scan_type == "sca":
        assurance = metadata.get("assurance") if isinstance(metadata.get("assurance"), dict) else {}
        if assurance.get("status") == "partial":
            stated = assurance.get("reasons") if isinstance(assurance.get("reasons"), list) else []
            reasons.extend(str(item) for item in stated if str(item).strip())
            if not stated:
                reasons.append("SCA 保证状态为 partial。")
        tools = metadata.get("sca_tool_scan") if isinstance(metadata.get("sca_tool_scan"), dict) else {}
        if tools.get("enabled") and tools.get("status") in {"failed", "partial_failed"}:
            reasons.append(f"SCA 增强工具状态为 {tools.get('status')}。")
        osv = metadata.get("osv_lookup") if isinstance(metadata.get("osv_lookup"), dict) else {}
        if osv.get("status") == "offline_degraded":
            reasons.append(f"在线 OSV 查询降级，错误组件数 {int(osv.get('error_count') or 0)}。")
    elif scan_type == "sast":
        engines = metadata.get("engine_status") if isinstance(metadata.get("engine_status"), dict) else {}
        assurance = engines.get("assurance") if isinstance(engines.get("assurance"), dict) else {}
        if assurance and assurance.get("execution_status") != "complete":
            reasons.append(str(assurance.get("statement") or "已配置的 SAST 引擎未完整执行。"))
        profile = metadata.get("sast_profile") if isinstance(metadata.get("sast_profile"), dict) else {}
        ai = metadata.get("deepseek_agents") if isinstance(metadata.get("deepseek_agents"), dict) else {}
        if profile.get("ai_enabled") and profile.get("ai_auto_scan") and ai.get("status") not in {"completed", "success"}:
            reasons.append(f"已要求的 SAST 模型复核状态为 {ai.get('status') or 'missing'}。")
    elif scan_type == "agent":
        skipped = metadata.get("skipped_files") if isinstance(metadata.get("skipped_files"), list) else []
        if skipped:
            reasons.append(f"AGENT 扫描跳过 {len(skipped)} 个文件。")
        coverage = metadata.get("coverage") if isinstance(metadata.get("coverage"), dict) else {}
        if coverage.get("status") in {"partial", "failed"}:
            reasons.append(f"AGENT 覆盖状态为 {coverage.get('status')}。")
    return list(dict.fromkeys(reasons))
