from app.services.agent_audit import build_agent_offline_audit


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
