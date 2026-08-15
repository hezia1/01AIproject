import pytest
from types import SimpleNamespace

from fastapi import HTTPException

from app.routers.dast import confirm_probe_target
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
