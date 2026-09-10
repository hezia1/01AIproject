from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

from app.services.diagnostic_contract import freshness
from app.services.module_diagnostics import _model_check, _source_state, _target_check
from app.services.scan_status import execution_diagnostic, scan_task_diagnostic


NOW = datetime(2026, 9, 10, 0, 0, tzinfo=timezone.utc)


def scan(scan_type: str, status: str = "completed", metadata: dict | None = None, age_hours: int = 1):
    finished = NOW - timedelta(hours=age_hours)
    return SimpleNamespace(
        scan_type=scan_type,
        status=status,
        scan_metadata=metadata or {},
        finished_at=finished.replace(tzinfo=None),
        started_at=None,
        created_at=finished.replace(tzinfo=None),
    )


def test_freshness_marks_missing_timestamp_unknown() -> None:
    result = freshness(None, max_age_hours=24, now=NOW)

    assert result["status"] == "unknown"
    assert "不能证明" in result["detail"]


def test_freshness_marks_old_intelligence_stale() -> None:
    result = freshness(NOW - timedelta(hours=25), max_age_hours=24, now=NOW)

    assert result["status"] == "stale"
    assert result["age_hours"] == 25


def test_completed_sca_with_partial_assurance_is_not_success() -> None:
    result = scan_task_diagnostic(
        scan("sca", metadata={
            "assurance": {"status": "partial", "reasons": ["组件版本未验证"]},
            "osv_lookup": {"status": "offline_degraded", "error_count": 1},
        }),
        now=NOW,
    )

    assert result["persisted_status"] == "completed"
    assert result["status"] == "partial"
    assert result["result_complete"] is False
    assert any("OSV" in reason for reason in result["reasons"])


def test_completed_sast_with_incomplete_engine_is_partial() -> None:
    result = scan_task_diagnostic(
        scan("sast", metadata={"engine_status": {"assurance": {"execution_status": "partial", "statement": "Semgrep 未完成"}}}),
        now=NOW,
    )

    assert result["status"] == "partial"
    assert result["reasons"] == ["Semgrep 未完成"]


def test_completed_static_scan_without_metadata_is_partial() -> None:
    result = scan_task_diagnostic(scan("agent"), now=NOW)

    assert result["status"] == "partial"
    assert "缺少执行元数据" in result["reasons"][0]


def test_old_completed_scan_is_stale_even_when_execution_was_complete() -> None:
    result = scan_task_diagnostic(
        scan("sast", metadata={"engine_status": {"assurance": {"execution_status": "complete"}}}, age_hours=169),
        now=NOW,
        max_age_hours=168,
    )

    assert result["status"] == "stale"
    assert result["stale"] is True


def test_failed_task_preserves_failure_and_error() -> None:
    result = scan_task_diagnostic(scan("sca", status="failed", metadata={"error": "scanner crashed"}), now=NOW)

    assert result["status"] == "failed"
    assert result["reasons"] == ["scanner crashed"]


def test_dynamic_execution_uses_same_stale_contract() -> None:
    result = execution_diagnostic("completed", NOW - timedelta(hours=200), now=NOW, max_age_hours=168)

    assert result["status"] == "stale"


def test_configured_model_without_call_evidence_is_unverified() -> None:
    result = _model_check(
        "model", "模型", {"configured": True, "status": "configured", "provider": "deepseek", "model": "demo"},
        None, required=True,
    )

    assert result["status"] == "configured_unverified"
    assert "没有保存" in result["detail"]


def test_required_invalid_model_configuration_is_unavailable() -> None:
    result = _model_check(
        "model", "模型", {"configured": False, "status": "invalid_configuration", "detail": "bad URL"},
        None, required=True,
    )

    assert result["status"] == "unavailable"
    assert result["detail"] == "bad URL"


def test_successful_model_result_without_timestamp_is_not_health_proof() -> None:
    result = _model_check(
        "model", "模型", {"configured": True, "status": "configured"},
        None, required=False, stored_result={"status": "completed"},
    )

    assert result["status"] == "configured_unverified"


def test_stopped_target_is_not_reported_reachable_from_old_probe() -> None:
    target = SimpleNamespace(
        status="stopped", mode="docker", runtime_url="http://127.0.0.1:12345", updated_at=NOW,
        health_detail={"reachable": True, "status_code": 200, "checked_at": NOW.isoformat()},
    )

    result = _target_check(target, required=True)

    assert result["status"] == "stopped"
    assert result["metadata"]["runtime_url"] == "http://127.0.0.1:12345"


def test_available_source_without_timestamp_is_unknown_not_current() -> None:
    assert _source_state({"status": "available", "freshness": {"status": "unknown"}}) == "unknown"
