from app.services.agent_audit import build_agent_offline_audit, compare_agent_offline_audits
from app.services.agent_governance import build_agent_html_report


def test_offline_agent_audit_builds_bounded_evidence_linked_review_drafts() -> None:
    report = build_agent_offline_audit(
        assets=[{
            "path": "agent.json",
            "provenance": [{
                "source_type": "registry",
                "source_visibility": "private-declared",
                "onboarding_status": "credentials-not-declared",
                "connection_status": "not-attempted",
            }],
        }],
        findings=[{
            "rule_id": "AGENT.TOOL.SHELL_EXEC",
            "title": "Agent exposes shell execution",
            "severity": "high",
            "file_path": "AGENTS.md",
            "line_start": 12,
            "status": "open",
        }, {
            "rule_id": "AGENT.OLD",
            "title": "Accepted finding",
            "severity": "critical",
            "file_path": "old.json",
            "line_start": 1,
            "status": "accepted_risk",
        }],
        coverage={"generic_parser_asset_count": 2, "schema_references_not_validated": 1},
        intelligence={"summary": {"not_covered_count": 1, "version_unresolved_count": 2}},
        dataflow={"summary": {"critical_path_count": 0, "high_path_count": 1}, "paths": [{
            "id": "df-1", "severity": "high", "title": "Prompt reaches network",
            "asset_path": "agent.json", "confidence": "medium",
        }]},
        trust_score={"score": 72, "grade": "guarded"},
    )

    assert report["mode"] == "local-rule-based-draft"
    assert report["model_status"] == "not-run"
    assert report["external_model_invoked"] is False
    assert report["summary"]["active_finding_count"] == 1
    assert report["summary"]["coverage_gap_count"] == 2
    assert report["summary"]["private_source_preflight_gap_count"] == 1
    assert {item["kind"] for item in report["items"]} == {
        "finding", "coverage-gap", "private-source-preflight", "static-dataflow",
    }
    assert all(item["review_status"] == "pending-human-review" for item in report["items"])
    assert len(report["audit_sha256"]) == 64


def test_offline_agent_audit_does_not_treat_private_source_as_connected() -> None:
    report = build_agent_offline_audit(
        assets=[{
            "path": "mcp.json",
            "provenance": [{
                "source_type": "remote-url",
                "source_visibility": "private-declared",
                "onboarding_status": "preflight-ready",
                "connection_status": "not-attempted",
            }],
        }],
        findings=[], coverage={}, intelligence={}, dataflow={}, trust_score={},
    )

    assert report["summary"]["private_source_preflight_gap_count"] == 0
    assert not any(item["kind"] == "private-source-preflight" for item in report["items"])
    assert "connectivity proof" in " ".join(report["limitations"])


def test_offline_agent_audit_does_not_repeat_a_dataflow_path_already_represented_by_a_finding() -> None:
    report = build_agent_offline_audit(
        assets=[],
        findings=[{
            "rule_id": "AGENT.FLOW.PROMPT_TO_SENSITIVE_RESOURCE",
            "title": "Prompt context can reach server-process: command python",
            "severity": "high",
            "file_path": ".mcp.json",
            "line_start": 1,
            "status": "open",
            "evidence": "path_id=df-1; capability=server-process; resource=command:python",
        }],
        coverage={"generic_parser_asset_count": 1},
        intelligence={},
        dataflow={"summary": {"high_path_count": 1}, "paths": [{
            "id": "df-1", "severity": "high", "title": "Prompt can reach server-process",
            "asset_path": ".mcp.json", "confidence": "medium",
        }]},
        trust_score={"score": 70, "grade": "guarded"},
    )

    assert report["summary"]["active_finding_count"] == 1
    assert report["summary"]["finding_review_count"] == 1
    assert report["summary"]["advisory_review_count"] == 1
    assert report["summary"]["review_item_count"] == 2
    assert [item["kind"] for item in report["items"]] == ["finding", "coverage-gap"]
    assert "path:df-1" in report["items"][0]["evidence_refs"]


def test_offline_agent_audit_is_included_in_html_report_without_a_model_claim() -> None:
    audit = build_agent_offline_audit(
        assets=[],
        findings=[{
            "rule_id": "AGENT.TOOL.SHELL_EXEC",
            "title": "Agent exposes shell execution",
            "severity": "high",
            "file_path": "AGENTS.md",
            "line_start": 12,
            "status": "open",
        }],
        coverage={},
        intelligence={},
        dataflow={},
        trust_score={"score": 52, "grade": "guarded"},
    )

    comparison = compare_agent_offline_audits(audit, audit)
    html = build_agent_html_report({"summary": {}, "audit": audit, "audit_comparison": comparison})

    assert "AGENT offline review draft" in html
    assert "local-rule-based-draft" in html
    assert "external model invoked: False" in html
    assert "Agent exposes shell execution" in html
    assert "AGENT offline audit history comparison" in html
    assert "still-pending" in html


def test_offline_agent_audit_comparison_labels_candidate_changes_without_remediation_claims() -> None:
    base = {
        "schema": "ai-security-platform.agent-offline-audit/v1",
        "items": [
            {"id": "audit-still", "kind": "finding", "priority": "high", "title": "Still pending", "evidence_refs": ["rule:A"]},
            {"id": "audit-prior", "kind": "coverage-gap", "priority": "medium", "title": "Prior only", "evidence_refs": ["coverage:A"]},
        ],
    }
    target = {
        "schema": "ai-security-platform.agent-offline-audit/v1",
        "items": [
            {"id": "audit-still", "kind": "finding", "priority": "high", "title": "Still pending", "evidence_refs": ["rule:A"]},
            {"id": "audit-new", "kind": "static-dataflow", "priority": "critical", "title": "New candidate", "evidence_refs": ["path:A"]},
        ],
    }

    result = compare_agent_offline_audits(base, target)

    assert result["has_comparison"] is True
    assert result["comparison_status"] == "ready"
    assert result["summary"] == {"new_count": 1, "still_pending_count": 1, "not_current_candidate_count": 1}
    assert {item["result"] for item in result["items"]} == {"new", "still-pending", "not-current-candidate"}
    assert "not proof of remediation" in " ".join(result["limitations"])


def test_offline_agent_audit_comparison_does_not_label_candidates_new_without_a_compatible_baseline() -> None:
    target = {"schema": "ai-security-platform.agent-offline-audit/v1", "items": []}

    result = compare_agent_offline_audits(None, target)

    assert result["has_comparison"] is False
    assert result["comparison_status"] == "base-audit-not-available"
    assert result["items"] == []
