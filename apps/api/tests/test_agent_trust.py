from __future__ import annotations

from app.services.agent_governance import build_agent_html_report, effective_agent_profile, evaluate_agent_quality_gate
from app.services.agent_trust import calculate_agent_trust_score


def clean_inputs() -> dict[str, object]:
    return {
        "assets": [{
            "path": "mcp.json",
            "asset_type": "mcp-config",
            "integrity_status": "recorded",
            "file_sha256": "a" * 64,
            "provenance": [{
                "source_type": "registry",
                "version_status": "locked",
                "publisher_status": "claim-only",
                "issues": [],
            }],
        }],
        "permissions": [],
        "findings": [],
        "coverage": {
            "discovered_asset_count": 1,
            "parsed_asset_count": 1,
            "failed_asset_count": 0,
            "skipped_file_count": 0,
        },
        "intelligence": {"summary": {"coordinate_count": 1, "covered_count": 1}},
        "dataflow": {"schema": "flow/v1", "summary": {"path_count": 0}},
        "runtime_validation": {
            "schema": "runtime/v1",
            "mode": "preflight-only",
            "execution_enabled": False,
            "isolation_policy": {"network": "none"},
        },
    }


def score(**overrides: object) -> dict[str, object]:
    values = clean_inputs()
    values.update(overrides)
    return calculate_agent_trust_score(**values)  # type: ignore[arg-type]


def test_static_clean_evidence_is_capped_and_explained() -> None:
    result = score()

    assert result["score"] == 90
    assert result["uncapped_score"] == 93
    assert result["score_cap"] == 90
    assert result["grade"] == "provisional-high"
    assert result["confidence"] == "medium"
    assert result["evidence_summary"]["target_runtime_observed"] is False
    assert any(item["id"] == "static-evidence-only" for item in result["score_caps"])
    assert any(item["id"] == "target-runtime-not-observed" for item in result["top_deductions"])


def test_limited_target_observation_scores_seven_and_caps_at_95() -> None:
    result = score(runtime_validation={
        "schema": "runtime/v1",
        "isolation_policy": {"network": "none"},
        "evidence": {
            "status": "completed",
            "execution_id": "target-1",
            "policy_verified": True,
            "behavioral_telemetry_complete": False,
        },
    })
    runtime = next(item for item in result["dimensions"] if item["id"] == "runtime_assurance")

    assert runtime["score"] == 7
    assert runtime["status"] == "limited_observation"
    assert result["score"] == 95
    assert result["score_cap"] == 95
    assert result["confidence"] == "medium"
    assert any(item["id"] == "limited-runtime-telemetry" for item in result["score_caps"])


def test_empty_inventory_never_produces_a_trust_claim() -> None:
    result = score(
        assets=[],
        coverage={"discovered_asset_count": 0, "parsed_asset_count": 0},
        intelligence={"summary": {"coordinate_count": 0}},
    )

    assert result["score"] == 0
    assert result["grade"] == "insufficient-evidence"
    assert result["dimensions"][0]["status"] == "insufficient_evidence"


def test_risk_evidence_reduces_the_relevant_dimensions() -> None:
    result = score(
        permissions=[{
            "capability": "all-capabilities", "scope": "*", "risk_level": "critical", "approval": "none",
        }],
        intelligence={"summary": {
            "coordinate_count": 1, "covered_count": 1, "malicious_match_count": 1,
        }},
        dataflow={"schema": "flow/v1", "summary": {
            "path_count": 1, "critical_path_count": 1, "unguarded_path_count": 1,
            "prompt_injection_path_count": 1,
        }},
    )
    dimensions = {item["id"]: item for item in result["dimensions"]}

    assert dimensions["local_intelligence"]["score"] == 0
    assert dimensions["permission_approval"]["score"] == 7
    assert dimensions["instruction_dataflow"]["score"] == 8
    assert result["score"] < 75
    assert any(item["id"] == "malicious-package-match" for item in result["top_deductions"])


def test_checked_no_match_is_limited_and_not_presented_as_proof_of_safety() -> None:
    result = score(intelligence={
        "summary": {"coordinate_count": 1, "covered_count": 1},
        "packages": [{"lookup_status": "checked_no_match"}],
    })
    intelligence = next(item for item in result["dimensions"] if item["id"] == "local_intelligence")

    assert intelligence["score"] == 20
    assert any("不是安全结论" in item for item in intelligence["limitations"])
    assert any("does not prove safety" in item for item in result["limitations"])


def test_governance_exception_does_not_erase_technical_score_impact() -> None:
    result = score(findings=[{
        "rule_id": "AGENT.SECRET.INLINE_TOKEN",
        "status": "accepted_risk",
        "severity": "high",
    }])
    provenance = next(item for item in result["dimensions"] if item["id"] == "provenance_integrity")

    assert provenance["score"] == 16
    assert any(item["id"] == "inline-secret-material" for item in provenance["deductions"])


def test_trust_hash_is_deterministic() -> None:
    first = score()
    second = score()

    assert first == second
    assert len(first["trust_sha256"]) == 64


def test_html_report_includes_escaped_trust_evidence() -> None:
    trust = score()
    trust["improvements"] = [{"id": "escape", "title": "Review <script>", "action": "Use <control>"}]
    html = build_agent_html_report({
        "summary": {}, "assets": [], "findings": [], "quality_gate": {}, "trust_score": trust,
    })

    assert "可解释的 AGENT 信任评分" in html
    assert "90 / 100" in html
    assert "Review &lt;script&gt;" in html
    assert "Use &lt;control&gt;" in html
    assert "<script>" not in html


def test_html_report_summarizes_target_evidence_without_output() -> None:
    trust = score()
    html = build_agent_html_report({
        "summary": {}, "assets": [], "findings": [], "quality_gate": {}, "trust_score": trust,
        "runtime_validation": {"evidence": {
            "status": "completed", "execution_id": "target-1", "policy_verified": True,
            "behavioral_telemetry_complete": False, "evidence_sha256": "f" * 64,
            "telemetry_coverage": {"main_process": "observed", "tool_calls": "not-instrumented"},
            "output": {"stdout": "SECRET-MUST-NOT-RENDER"},
        }},
    })

    assert "指定 Agent 受控运行证据" in html
    assert "target-1" in html
    assert "not-instrumented" in html
    assert "SECRET-MUST-NOT-RENDER" not in html
    assert "行为插桩不完整时总分最高 95" in html


def test_quality_gate_can_optionally_block_low_trust_without_changing_default() -> None:
    low_trust = score(
        assets=[],
        coverage={"discovered_asset_count": 0, "parsed_asset_count": 0},
    )
    default_result = evaluate_agent_quality_gate(
        findings=[], permissions=[], coverage={}, profile=effective_agent_profile({}), trust_score=low_trust,
    )
    blocking_profile = effective_agent_profile({"agent_profile": {"quality_gate": {
        "enabled": True,
        "threshold": "none",
        "block_low_trust_score": True,
        "minimum_trust_score": 70,
    }}})
    blocking_result = evaluate_agent_quality_gate(
        findings=[], permissions=[], coverage={}, profile=blocking_profile, trust_score=low_trust,
    )

    assert default_result["decision"] == "pass"
    assert blocking_result["decision"] == "block"
    assert blocking_result["trust_score"]["score"] == 0
    assert any("below the required 70" in reason for reason in blocking_result["reasons"])
