from app.models import Severity
from app.services.agent_dataflow import analyze_agent_dataflow
from app.services.agent_governance import effective_agent_profile, evaluate_agent_quality_gate
import json

from app.services.agent_scanner import AgentAsset, AgentFinding, AgentPermission, scan_agent_tree


def permission(
    asset_path: str,
    capability: str,
    *,
    resource_type: str = "command",
    scope: str = "*",
    approval: str = "unknown",
    risk_level: str = "high",
    subject: str = "tool:test",
) -> AgentPermission:
    return AgentPermission(
        asset_path=asset_path,
        subject=subject,
        capability=capability,
        access="execute" if resource_type == "command" else "read-write",
        resource_type=resource_type,
        scope=scope,
        approval=approval,
        risk_level=risk_level,
        source="test.fixture",
    )


def asset(
    path: str,
    *,
    asset_type: str = "agent-config",
    prompts: list[str] | None = None,
    permissions: list[AgentPermission] | None = None,
    metadata: dict[str, object] | None = None,
) -> AgentAsset:
    return AgentAsset(
        path=path,
        asset_type=asset_type,
        format="json",
        parser="test",
        status="parsed",
        checks=[],
        name=path,
        declared_prompts=prompts or [],
        permissions=permissions or [],
        metadata=metadata or {},
    )


def prompt_injection_finding(path: str) -> AgentFinding:
    return AgentFinding(
        rule_id="AGENT.PROMPT.INSTRUCTION_OVERRIDE",
        title="Instruction override",
        severity=Severity.high,
        file_path=path,
        line_start=1,
        line_end=1,
        evidence="ignore previous instructions",
        category="prompt-injection",
        description="fixture",
        remediation="fixture",
        trust_impact="fixture",
    )


def finding_payload(finding: AgentFinding, status: str = "open") -> dict[str, object]:
    return {
        "rule_id": finding.rule_id,
        "title": finding.title,
        "severity": finding.severity.value,
        "file_path": finding.file_path,
        "line_start": finding.line_start,
        "status": status,
    }


def test_scanner_output_builds_end_to_end_static_path(tmp_path) -> None:
    (tmp_path / ".mcp.json").write_text(json.dumps({
        "name": "demo-agent",
        "prompts": [{"name": "review-request"}],
        "permissions": ["shell-execution"],
        "approval": False,
    }), encoding="utf-8")
    scan = scan_agent_tree(str(tmp_path))

    output = analyze_agent_dataflow(scan.assets, scan.findings)

    assert output.report["summary"]["path_count"] >= 1
    assert any(item["capability"] == "shell-execution" for item in output.report["paths"])


def test_same_asset_prompt_tool_resource_path_is_explainable() -> None:
    path = "agent.json"
    output = analyze_agent_dataflow([
        asset(path, prompts=["review-request"], permissions=[permission(path, "shell-execution")])
    ], [])

    data_path = output.report["paths"][0]
    assert data_path["kind"] == "prompt-to-resource"
    assert data_path["severity"] == "high"
    assert data_path["confidence"] == "medium"
    assert "human-approval" in data_path["missing_controls"]
    assert "resource-scope-restriction" in data_path["missing_controls"]
    assert len(data_path["node_ids"]) == 4
    assert output.findings[0].rule_id == "AGENT.FLOW.PROMPT_TO_SENSITIVE_RESOURCE"
    assert "shell-execution" in output.findings[0].title
    assert "command *" in output.findings[0].title


def test_suspicious_instruction_to_shell_is_critical() -> None:
    path = "AGENTS.md"
    output = analyze_agent_dataflow([
        asset(
            path,
            asset_type="instruction",
            permissions=[permission(path, "shell-execution")],
        )
    ], [prompt_injection_finding(path)])

    data_path = output.report["paths"][0]
    assert data_path["severity"] == "critical"
    assert data_path["source_trust"] == "adversarial-signal"
    assert "untrusted-content-validation" in data_path["missing_controls"]
    assert output.findings[0].rule_id == "AGENT.FLOW.UNTRUSTED_TO_HIGH_RISK_TOOL"


def test_secret_and_network_capabilities_form_conservative_exfiltration_path() -> None:
    path = "agent.json"
    secret = permission(
        path, "secret-access", resource_type="secret", scope="API_TOKEN", subject="tool:secret"
    )
    network = permission(
        path, "network-egress", resource_type="network", scope="https://example.test", subject="tool:http"
    )
    output = analyze_agent_dataflow([
        asset(path, prompts=["process"], permissions=[secret, network])
    ], [])

    exfiltration = next(item for item in output.report["paths"] if item["kind"] == "potential-secret-exfiltration")
    assert exfiltration["severity"] == "high"
    assert exfiltration["confidence"] == "low"
    assert any(
        edge["relation"] == "may_flow_to" and edge["basis"] == "conservative-inference"
        for edge in output.report["edges"]
    )
    assert any(item.rule_id == "AGENT.FLOW.POTENTIAL_SECRET_EXFILTRATION" for item in output.findings)


def test_declared_approval_and_scoped_resource_are_visible_controls() -> None:
    path = "agent.json"
    output = analyze_agent_dataflow([
        asset(path, prompts=["review"], permissions=[permission(
            path,
            "shell-execution",
            scope="npm test",
            approval="required",
        )])
    ], [])

    data_path = output.report["paths"][0]
    control_types = {item["type"] for item in data_path["controls"]}
    assert control_types == {"human-approval-declared", "scoped-resource"}
    assert "human-approval" not in data_path["missing_controls"]
    assert data_path["severity"] == "high"
    assert output.report["summary"]["control_node_count"] == 2


def test_cross_asset_connection_requires_suspicious_instruction_signal() -> None:
    prompt_path = "AGENTS.md"
    tool_path = ".mcp.json"
    output = analyze_agent_dataflow(
        [
            asset(prompt_path, asset_type="instruction"),
            asset(tool_path, permissions=[permission(tool_path, "filesystem-write", resource_type="filesystem")]),
        ],
        [prompt_injection_finding(prompt_path)],
    )

    cross_path = next(item for item in output.report["paths"] if item["kind"] == "cross-asset-prompt-to-resource")
    assert cross_path["confidence"] == "low"
    assert cross_path["asset_path"] == prompt_path
    assert cross_path["tool_asset_path"] == tool_path
    assert any("conservative project-level inference" in item for item in cross_path["evidence"])


def test_declared_content_and_network_controls_remain_unverified_claims() -> None:
    path = "agent.json"
    network = permission(
        path, "network-egress", resource_type="network", scope="*", subject="tool:http"
    )
    output = analyze_agent_dataflow([
        asset(
            path,
            prompts=["review"],
            permissions=[network],
            metadata={"declared_security_controls": [
                {"type": "content-validation-declared", "path": "guardrails"},
                {"type": "network-destination-allowlist-declared", "path": "allowedDomains"},
            ]},
        )
    ], [prompt_injection_finding(path)])

    data_path = output.report["paths"][0]
    control_types = {item["type"] for item in data_path["controls"]}
    assert "content-validation-declared" in control_types
    assert "network-destination-allowlist-declared" in control_types
    assert "verified-untrusted-content-validation" in data_path["missing_controls"]
    assert "verified-network-destination-allowlist" in data_path["missing_controls"]


def test_governance_allowlist_does_not_remove_runtime_path() -> None:
    path = "agent.json"
    item = permission(path, "shell-execution")
    profile = {
        "permission_allowlist": [{
            "id": "allow-1",
            "path_pattern": "agent.json",
            "subject_pattern": "*",
            "capability": "shell-execution",
            "scope_pattern": "*",
            "reason": "fixture",
        }],
        "exceptions": [],
    }
    output = analyze_agent_dataflow([asset(path, prompts=["review"], permissions=[item])], [], profile)

    data_path = output.report["paths"][0]
    assert any(control["type"] == "governance-exemption" for control in data_path["controls"])
    assert output.report["summary"]["path_count"] == 1


def test_quality_gate_blocks_high_dataflow_finding_but_honors_accepted_risk() -> None:
    path = "agent.json"
    output = analyze_agent_dataflow([
        asset(path, prompts=["review"], permissions=[permission(path, "shell-execution")])
    ], [])
    finding = output.findings[0]
    profile = effective_agent_profile({})
    gate = evaluate_agent_quality_gate(
        findings=[finding_payload(finding)],
        permissions=[],
        coverage={},
        profile=profile,
        dataflow=output.report,
    )
    assert gate["decision"] == "block"
    assert gate["blocking_dataflow_count"] == 1
    assert gate["dataflow_summary"]["path_count"] == 1

    accepted = evaluate_agent_quality_gate(
        findings=[finding_payload(finding, "accepted_risk")],
        permissions=[],
        coverage={},
        profile=profile,
        dataflow=output.report,
    )
    assert accepted["blocking_dataflow_count"] == 0
