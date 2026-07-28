from types import SimpleNamespace

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


def test_header_risk_is_not_reported_as_exploitable() -> None:
    result = build_probe_result(
        "http://example.test/login",
        "http",
        200,
        25,
        {"Server": "example"},
        None,
    )

    assert result.verdict == DastVerdict.uncertain
