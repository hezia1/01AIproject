from datetime import datetime, timedelta, timezone

from app.models import Severity
from app.services.agent_governance import (
    add_agent_exception,
    build_agent_html_report,
    build_agent_sarif,
    decide_agent_exception,
    effective_agent_profile,
    evaluate_agent_quality_gate,
    filter_agent_findings,
    finding_governance_status,
    permission_is_exempt,
    persist_agent_profile_config,
    update_agent_profile,
)
from app.services.agent_scanner import AgentFinding, AgentPermission


def finding(rule_id: str = "AGENT.TOOL.SHELL_EXEC", severity: Severity = Severity.high) -> AgentFinding:
    return AgentFinding(
        rule_id=rule_id,
        title="Unsafe <agent>",
        severity=severity,
        file_path="agents/demo/AGENTS.md",
        line_start=7,
        line_end=7,
        evidence="Run ***REDACTED***",
        category="tool-abuse",
        description="Unsafe declaration",
        remediation="Require approval",
        trust_impact="Expanded execution boundary",
    )


def permission(approval: str = "unknown") -> AgentPermission:
    return AgentPermission(
        asset_path="mcp.json",
        subject="mcpservers:ops",
        capability="shell-execution",
        access="execute",
        resource_type="command",
        scope="powershell",
        approval=approval,
        risk_level="critical",
        source="mcpServers.ops.command",
    )


def coverage(**overrides) -> dict[str, object]:
    result = {"failed_asset_count": 0, "skipped_file_count": 0}
    result.update(overrides)
    return result


def test_profile_update_validates_and_versions_policy() -> None:
    profile = update_agent_profile({}, {
        "disabled_rule_ids": ["AGENT.NET.EXTERNAL_REQUEST"],
        "excluded_paths": ["fixtures/**"],
        "quality_gate": {"threshold": "medium", "block_new_only": True},
    }, actor="security-owner")

    assert profile["profile_version"] == 2
    assert profile["disabled_rule_ids"] == ["AGENT.NET.EXTERNAL_REQUEST"]
    assert profile["quality_gate"]["threshold"] == "medium"
    assert profile["audit_log"][0]["actor"] == "security-owner"
    assert filter_agent_findings([finding("AGENT.NET.EXTERNAL_REQUEST")], profile) == []


def test_exception_requires_approval_and_changes_future_finding_status() -> None:
    profile, item = add_agent_exception({}, {
        "kind": "finding",
        "disposition": "suppress",
        "rule_id": "AGENT.TOOL.SHELL_EXEC",
        "path_pattern": "agents/**",
        "reason": "Reviewed test fixture",
    }, actor="requester")
    assert finding_governance_status(finding(), profile)[0] == "open"

    config = persist_agent_profile_config({}, profile)
    profile, approved = decide_agent_exception(config, str(item["id"]), {
        "status": "approved",
        "approval_note": "Fixture is isolated",
    }, actor="approver")

    assert approved["approver"] == "approver"
    assert finding_governance_status(finding(), profile) == ("false_positive", item["id"], "suppress")


def test_expired_exception_is_not_active() -> None:
    profile = effective_agent_profile({"agent_profile": {
        "exceptions": [{
            "id": "expired",
            "kind": "finding",
            "disposition": "accept_risk",
            "rule_id": "*",
            "path_pattern": "**",
            "reason": "Expired",
            "status": "approved",
            "expires_at": (datetime.now(timezone.utc) - timedelta(days=1)).isoformat(),
        }],
    }})

    assert finding_governance_status(finding(), profile)[0] == "open"


def test_allowlisted_permission_does_not_block_expansion_or_approval_gate() -> None:
    profile = update_agent_profile({}, {"permission_allowlist": [{
        "asset_path": "mcp.json",
        "subject": "mcpservers:ops",
        "capability": "shell-execution",
        "scope": "powershell",
        "reason": "Controlled maintenance capability",
    }]}, actor="owner")

    assert permission_is_exempt(permission(), profile)[0] is True
    result = evaluate_agent_quality_gate(
        findings=[], permissions=[permission()], coverage=coverage(), profile=profile,
        expanded_permission_identities={"mcp.json::mcpservers:ops::shell-execution::execute::command::powershell"},
    )
    assert result["decision"] == "pass"


def test_gate_blocks_findings_parse_failures_and_unapproved_permissions() -> None:
    profile = effective_agent_profile({})
    result = evaluate_agent_quality_gate(
        findings=[{
            "rule_id": "AGENT.TOOL.SHELL_EXEC", "title": "Shell", "severity": "critical",
            "file_path": "AGENTS.md", "line_start": 1, "status": "open",
        }],
        permissions=[permission()],
        coverage=coverage(failed_asset_count=1),
        profile=profile,
        expanded_permission_identities={"mcp.json::mcpservers:ops::shell-execution::execute::command::powershell"},
    )

    assert result["decision"] == "block"
    assert result["blocking_finding_count"] == 1
    assert result["blocking_permission_count"] == 1
    assert len(result["reasons"]) >= 3


def test_none_threshold_and_new_only_do_not_block_old_findings() -> None:
    profile = update_agent_profile({}, {"quality_gate": {
        "threshold": "none", "block_new_only": True, "block_permission_expansion": False,
        "block_wildcard_permissions": False, "block_parse_failures": False,
        "require_approval_for_high_risk": False,
    }}, actor="owner")
    result = evaluate_agent_quality_gate(
        findings=[{"rule_id": "AGENT.X", "severity": "critical", "file_path": "x", "line_start": 1, "status": "open"}],
        permissions=[], coverage=coverage(), profile=profile, new_finding_identities=set(),
    )

    assert result["decision"] == "pass"
    assert result["blocking_finding_count"] == 0


def test_sarif_location_is_standard_and_html_escapes_content() -> None:
    payload = [{
        "rule_id": "AGENT.X", "title": "Unsafe <agent>", "severity": "high",
        "file_path": "AGENTS.md", "line_start": 7, "status": "open",
        "description": "Review <script>", "remediation": "Fix it",
    }]
    sarif = build_agent_sarif(payload, "scan-1")
    physical = sarif["runs"][0]["results"][0]["locations"][0]["physicalLocation"]
    assert physical["artifactLocation"] == {"uri": "AGENTS.md"}
    assert physical["region"] == {"startLine": 7}
    assert "evidence" not in str(sarif).lower()

    html = build_agent_html_report({
        "summary": {"asset_count": 0, "permission_count": 0, "finding_count": 1},
        "quality_gate": {"decision": "block", "reasons": ["unsafe <reason>"]},
        "assets": [{
            "path": "plugin.json", "asset_type": "plugin-manifest", "integrity_status": "recorded",
            "file_sha256": "a" * 64, "permission_count": 0, "finding_count": 1,
            "provenance": [{
                "subject": "plugin:<unsafe>", "package_name": "demo", "package_version": "latest",
                "version_status": "floating", "source_type": "git", "source_ref": "https://example.invalid/<repo>",
                "installation_method": "git", "publisher_claim": "<publisher>", "publisher_status": "claim-only",
                "issues": ["version-unpinned"],
            }],
        }], "findings": payload,
    })
    assert "&lt;agent&gt;" in html
    assert "&lt;reason&gt;" in html
    assert "&lt;publisher&gt;" in html
    assert "<script>" not in html


def test_gate_blocks_unpinned_source_and_integrity_change() -> None:
    profile = effective_agent_profile({})
    asset = {
        "path": "mcp.json",
        "asset_type": "mcp-config",
        "integrity_status": "recorded",
        "provenance": [{"issues": ["version-unpinned"], "version_status": "floating"}],
    }

    result = evaluate_agent_quality_gate(
        findings=[{
            "rule_id": "AGENT.SUPPLY.UNPINNED_VERSION", "severity": "medium", "file_path": "mcp.json",
            "line_start": 1, "status": "open", "title": "Unpinned",
        }], permissions=[], coverage=coverage(), profile=profile,
        assets=[asset], changed_integrity_identities={"mcp-config::mcp.json"},
    )

    assert result["decision"] == "block"
    assert result["blocking_asset_count"] == 1
    assert any("floating dependency versions" in reason for reason in result["reasons"])
    assert any("integrity digests changed" in reason for reason in result["reasons"])

    accepted = evaluate_agent_quality_gate(
        findings=[{
            "rule_id": "AGENT.SUPPLY.UNPINNED_VERSION", "severity": "medium", "file_path": "mcp.json",
            "line_start": 1, "status": "accepted_risk", "title": "Unpinned",
        }], permissions=[], coverage=coverage(), profile=profile, assets=[asset],
    )
    assert accepted["decision"] == "pass"
