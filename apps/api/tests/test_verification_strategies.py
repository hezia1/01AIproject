import pytest
from datetime import datetime
from types import SimpleNamespace
from uuid import uuid4

from fastapi import HTTPException

from app.routers.dast import build_dast_report, confirm_probe_target, ensure_manual_validation_record, redact_evidence_summary
from app.models import DastVerdict
from app.services.dast_probe import build_probe_result
from app.services.verification_strategies import recommended_dast_strategies, resolve_dast_strategy


def test_sca_risk_prefers_component_exposure_strategy() -> None:
    strategies = recommended_dast_strategies(SimpleNamespace(source="SCA"))

    assert strategies[0].id == "component-exposure"
    assert "组件漏洞" in " ".join(strategies[0].limitations)


def test_unknown_strategy_is_rejected() -> None:
    try:
        resolve_dast_strategy("payload-scan")
    except ValueError as exc:
        assert "Unknown DAST" in str(exc)
    else:
        raise AssertionError("unknown strategy should be rejected")


def test_header_risk_is_reported_as_baseline_attention_not_exploitability() -> None:
    result = build_probe_result(
        "http://example.test/login",
        "http",
        200,
        25,
        {"Server": "example"},
        None,
    )

    assert result.verdict == DastVerdict.baseline_attention
    assert "不构成漏洞可利用性" in result.reproduction_steps


def test_clean_headers_are_reported_as_baseline_clear_not_non_exploitable() -> None:
    result = build_probe_result(
        "https://example.test/health",
        "https",
        200,
        25,
        {
            "Content-Security-Policy": "default-src 'self'",
            "X-Frame-Options": "DENY",
            "X-Content-Type-Options": "nosniff",
            "Strict-Transport-Security": "max-age=31536000",
            "Referrer-Policy": "same-origin",
        },
        None,
    )

    assert result.verdict == DastVerdict.baseline_clear
    assert result.verdict != DastVerdict.not_exploitable


def test_probe_target_requires_configured_origin_and_exact_confirmation() -> None:
    project = SimpleNamespace(runtime_url="https://example.test/app", api_base_url=None)
    target = "https://example.test/login"

    confirm_probe_target(project, target, "DAST_WEB_BASELINE:https://example.test/login")

    with pytest.raises(HTTPException, match="exact confirmation phrase"):
        confirm_probe_target(project, target, "confirm")
    with pytest.raises(HTTPException, match="same origin"):
        confirm_probe_target(project, "https://unapproved.example/login", "DAST_WEB_BASELINE:https://unapproved.example/login")


def test_automated_baseline_observation_is_read_only() -> None:
    automated_record = SimpleNamespace(validation_mode="automated_web_baseline")

    with pytest.raises(HTTPException, match="read-only"):
        ensure_manual_validation_record(automated_record)


def test_dast_report_summarizes_stored_records_without_new_probe() -> None:
    project_id = uuid4()
    now = datetime.utcnow()

    def record(*, verdict: str, mode: str, finding_id: str | None) -> SimpleNamespace:
        return SimpleNamespace(
            id=uuid4(),
            project_id=project_id,
            finding_id=finding_id,
            component_id=None,
            link_source="explicit-selection" if finding_id else "unlinked",
            link_confidence=100 if finding_id else 0,
            target_url="https://example.test/login",
            verdict=verdict,
            validator="reviewer",
            strategy_id="web-baseline",
            strategy_name="Web baseline",
            scope_summary="stored record only",
            limitations="limited scope",
            evidence_summary="stored evidence",
            request_summary="no new request",
            response_summary="stored response",
            reproduction_steps="stored reproduction steps",
            remediation_hint="stored remediation",
            validation_mode=mode,
            connection_confirmed=mode == "automated_web_baseline",
            created_at=now,
            updated_at=now,
        )

    report = build_dast_report(
        project_id,
        [
            record(verdict="baseline_clear", mode="automated_web_baseline", finding_id=None),
            record(verdict="uncertain", mode="manual_validation", finding_id=str(uuid4())),
        ],
    )

    assert report["schema"] == "ai-security-platform.dast-report/v1"
    assert report["summary"]["record_count"] == 2
    assert report["summary"]["automated_baseline_count"] == 1
    assert report["summary"]["manual_validation_count"] == 1
    assert report["summary"]["linked_record_count"] == 1
    assert report["summary"]["by_verdict"] == {
        "exploitable": 0,
        "uncertain": 1,
        "not_exploitable": 0,
        "baseline_attention": 0,
        "baseline_clear": 1,
    }
    assert report["summary"]["verification_plan_count"] == 0
    assert report["summary"]["evidence_item_count"] == 0
    assert len(report["records"]) == 2
    assert any("does not connect to targets" in item for item in report["capability_boundaries"])


def test_dast_evidence_summary_redacts_common_secret_values() -> None:
    result = redact_evidence_summary("Authorization: Bearer abc123 token=def456 password=secret")

    assert "abc123" not in result
    assert "def456" not in result
    assert "secret" not in result
    assert result.count("[REDACTED]") == 3
