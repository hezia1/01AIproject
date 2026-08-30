from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
from typing import Callable

from app.models import Severity
from app.services.agent_governance import permission_is_exempt
from app.services.agent_scanner import AgentAsset, AgentFinding, AgentPermission, build_finding


DATAFLOW_VERSION = "agent-dataflow/v1"
MAX_NODES = 1_000
MAX_EDGES = 2_000
MAX_PATHS = 300

HIGH_RISK_CAPABILITIES = {
    "all-capabilities",
    "shell-execution",
    "server-process",
    "filesystem-write",
    "secret-access",
}
BROAD_SCOPES = {"", "*", "*:*", "all", "any", "/", "\\"}
CONFIDENCE_RANK = {"low": 1, "medium": 2, "high": 3}


@dataclass(frozen=True)
class AgentDataflowOutput:
    findings: list[AgentFinding]
    report: dict[str, object]


class GraphBuilder:
    def __init__(self) -> None:
        self.nodes: dict[str, dict[str, object]] = {}
        self.edges: dict[str, dict[str, object]] = {}

    def node(
        self,
        kind: str,
        label: str,
        asset_path: str,
        *,
        trust: str = "unknown",
        attributes: dict[str, object] | None = None,
    ) -> str:
        node_id = stable_id("node", kind, asset_path, label)
        if node_id not in self.nodes and len(self.nodes) < MAX_NODES:
            self.nodes[node_id] = {
                "id": node_id,
                "kind": kind,
                "label": label[:300],
                "asset_path": asset_path,
                "trust": trust,
                "attributes": attributes or {},
            }
        return node_id

    def edge(
        self,
        source: str,
        target: str,
        relation: str,
        *,
        confidence: str,
        evidence: str,
        basis: str,
    ) -> str:
        edge_id = stable_id("edge", source, target, relation)
        if source in self.nodes and target in self.nodes and edge_id not in self.edges and len(self.edges) < MAX_EDGES:
            self.edges[edge_id] = {
                "id": edge_id,
                "source": source,
                "target": target,
                "relation": relation,
                "confidence": confidence,
                "evidence": evidence[:500],
                "basis": basis,
            }
        return edge_id


def analyze_agent_dataflow(
    assets: list[AgentAsset],
    findings: list[AgentFinding],
    profile: dict[str, object] | None = None,
) -> AgentDataflowOutput:
    graph = GraphBuilder()
    risk_paths: list[dict[str, object]] = []
    output_findings: list[AgentFinding] = []
    prompt_signal_paths = {
        finding.file_path
        for finding in findings
        if finding.rule_id == "AGENT.PROMPT.INSTRUCTION_OVERRIDE"
    }
    prompt_boundaries: list[dict[str, object]] = []
    permission_boundaries: list[dict[str, object]] = []

    for asset in assets:
        asset_node = graph.node(
            "agent_asset",
            asset.name or asset.path,
            asset.path,
            trust="local-declaration",
            attributes={"asset_type": asset.asset_type, "parser": asset.parser},
        )
        prompt_node, prompt_edge, prompt_confidence = add_prompt_boundary(
            graph, asset, asset_node, asset.path in prompt_signal_paths
        )
        if prompt_node:
            prompt_boundaries.append({
                "asset": asset,
                "asset_node": asset_node,
                "prompt_node": prompt_node,
                "prompt_edge": prompt_edge,
                "confidence": prompt_confidence,
                "injection_signal": asset.path in prompt_signal_paths,
            })
        permission_graph: list[dict[str, object]] = []
        for permission in asset.permissions:
            boundary = add_permission_boundary(graph, asset, asset_node, permission, profile or {})
            permission_graph.append(boundary)
            permission_boundaries.append({"asset": asset, **boundary})

        if prompt_node:
            for item in permission_graph:
                path = permission_path(
                    asset,
                    prompt_node,
                    prompt_edge,
                    prompt_confidence,
                    item,
                    injection_signal=asset.path in prompt_signal_paths,
                )
                if path is None or len(risk_paths) >= MAX_PATHS:
                    continue
                risk_paths.append(path)
                if path["severity"] in {"critical", "high", "medium"}:
                    output_findings.append(dataflow_finding(path))

            exfiltration = secret_exfiltration_path(
                graph,
                asset,
                prompt_node,
                prompt_edge,
                prompt_confidence,
                permission_graph,
                injection_signal=asset.path in prompt_signal_paths,
            )
            if exfiltration is not None and len(risk_paths) < MAX_PATHS:
                risk_paths.append(exfiltration)
                output_findings.append(dataflow_finding(exfiltration))

    cross_paths = cross_asset_injection_paths(graph, prompt_boundaries, permission_boundaries)
    for path in cross_paths:
        if len(risk_paths) >= MAX_PATHS:
            break
        risk_paths.append(path)
        output_findings.append(dataflow_finding(path))

    paths = dedupe_paths(risk_paths)
    findings_result = dedupe_findings(output_findings)
    report = {
        "schema": DATAFLOW_VERSION,
        "mode": "static-only",
        "summary": {
            "node_count": len(graph.nodes),
            "edge_count": len(graph.edges),
            "path_count": len(paths),
            "critical_path_count": sum(item["severity"] == "critical" for item in paths),
            "high_path_count": sum(item["severity"] == "high" for item in paths),
            "medium_path_count": sum(item["severity"] == "medium" for item in paths),
            "unguarded_path_count": sum(bool(item.get("missing_controls")) for item in paths),
            "prompt_injection_path_count": sum(item.get("source_trust") == "adversarial-signal" for item in paths),
            "inferred_edge_count": sum(item["basis"] == "conservative-inference" for item in graph.edges.values()),
            "control_node_count": sum(item["kind"] in {"control_claim", "governance_decision"} for item in graph.nodes.values()),
        },
        "nodes": list(graph.nodes.values()),
        "edges": list(graph.edges.values()),
        "paths": paths,
        "limitations": [
            "This graph is built from static declarations and local findings; it does not execute an Agent or prove that runtime data actually traversed a path.",
            "Prompt-to-asset and permission edges are explicit or co-declared relationships; every edge carries a confidence and basis instead of being presented as runtime fact.",
            "A project allowlist or approved exception is a governance decision, not a runtime security control, and therefore does not remove a path.",
            "Declared approval is recorded as a control claim; enforcement is not verified until a future sandbox validation stage.",
            "External resources are not assumed to enter model context unless a supported configuration provides a directional declaration.",
        ],
    }
    return AgentDataflowOutput(findings=findings_result, report=report)


def add_prompt_boundary(
    graph: GraphBuilder,
    asset: AgentAsset,
    asset_node: str,
    injection_signal: bool,
) -> tuple[str | None, str | None, str]:
    prompts = list(dict.fromkeys(asset.declared_prompts))
    explicit_instruction_asset = asset.asset_type in {"instruction", "prompt", "skill"}
    if not prompts and explicit_instruction_asset:
        prompts = [asset.name or asset.path]
    if not prompts:
        return None, None, "low"
    label = prompts[0] if len(prompts) == 1 else f"{prompts[0]} (+{len(prompts) - 1})"
    confidence = "high" if explicit_instruction_asset else "medium"
    trust = "adversarial-signal" if injection_signal else "unknown-input"
    prompt_node = graph.node(
        "prompt_input",
        label,
        asset.path,
        trust=trust,
        attributes={"declared_prompt_count": len(prompts), "instruction_override_signal": injection_signal},
    )
    edge = graph.edge(
        prompt_node,
        asset_node,
        "can_influence_agent_context",
        confidence=confidence,
        evidence=(
            "instruction/prompt/skill asset is treated as model context input"
            if explicit_instruction_asset
            else "prompt and Agent/tool declarations occur in the same structured asset"
        ),
        basis="explicit-asset-type" if explicit_instruction_asset else "co-declared",
    )
    return prompt_node, edge, confidence


def add_permission_boundary(
    graph: GraphBuilder,
    asset: AgentAsset,
    asset_node: str,
    permission: AgentPermission,
    profile: dict[str, object],
) -> dict[str, object]:
    tool_node = graph.node(
        "tool",
        f"{permission.subject} · {permission.capability}",
        permission.asset_path,
        trust="declared-capability",
        attributes={
            "subject": permission.subject,
            "capability": permission.capability,
            "approval": permission.approval,
            "risk_level": permission.risk_level,
        },
    )
    resource_node = graph.node(
        "resource",
        f"{permission.resource_type}: {permission.scope}",
        permission.asset_path,
        trust=resource_trust(permission),
        attributes={
            "resource_type": permission.resource_type,
            "scope": permission.scope,
            "access": permission.access,
        },
    )
    invoke_edge = graph.edge(
        asset_node,
        tool_node,
        "can_invoke",
        confidence="high",
        evidence=f"capability={permission.capability}; subject={permission.subject}; source={permission.source}",
        basis="explicit-permission",
    )
    resource_edge = graph.edge(
        tool_node,
        resource_node,
        "can_access",
        confidence="high",
        evidence=f"access={permission.access}; resource_type={permission.resource_type}; scope={permission.scope}",
        basis="explicit-permission",
    )
    exempt, exemption = permission_is_exempt(permission, profile)
    controls: list[dict[str, object]] = []
    if permission.approval == "required":
        controls.append({"type": "human-approval-declared", "runtime_verified": False})
    if not broad_scope(permission.scope):
        controls.append({"type": "scoped-resource", "runtime_verified": False})
    if exempt:
        controls.append({"type": "governance-exemption", "reference": exemption, "runtime_verified": False})
    controls.extend(applicable_control_claims(asset, permission))
    control_nodes: list[str] = []
    for control in controls:
        control_type = str(control["type"])
        governance_only = control_type == "governance-exemption"
        control_node = graph.node(
            "governance_decision" if governance_only else "control_claim",
            control_type,
            permission.asset_path,
            trust="governance-only" if governance_only else "declared-not-verified",
            attributes=control,
        )
        graph.edge(
            control_node,
            tool_node if control_type != "scoped-resource" else resource_node,
            "governs" if governance_only else "claims_guard_for",
            confidence="high" if governance_only else "medium",
            evidence=(
                f"project governance reference={control.get('reference')}"
                if governance_only
                else f"configuration declares {control_type}; runtime enforcement is unverified"
            ),
            basis="governance-policy" if governance_only else "explicit-permission",
        )
        control_nodes.append(control_node)
    return {
        "permission": permission,
        "asset_node": asset_node,
        "tool_node": tool_node,
        "resource_node": resource_node,
        "invoke_edge": invoke_edge,
        "resource_edge": resource_edge,
        "controls": controls,
        "control_nodes": control_nodes,
    }


def permission_path(
    asset: AgentAsset,
    prompt_node: str,
    prompt_edge: str | None,
    prompt_confidence: str,
    permission_graph: dict[str, object],
    *,
    injection_signal: bool,
) -> dict[str, object] | None:
    permission = permission_graph["permission"]
    if not isinstance(permission, AgentPermission) or permission.capability == "tool-invocation":
        return None
    severity = path_severity(permission, injection_signal)
    if severity == "info":
        return None
    controls = permission_graph["controls"] if isinstance(permission_graph["controls"], list) else []
    missing_controls = missing_controls_for_permission(permission, injection_signal, controls)
    confidence = minimum_confidence(prompt_confidence, "high")
    path_id = stable_id("path", asset.path, permission.subject, permission.capability, permission.scope)
    return {
        "id": path_id,
        "kind": "prompt-to-resource",
        "title": f"Prompt can reach {permission.capability}",
        "severity": severity,
        "confidence": confidence,
        "asset_path": asset.path,
        "source_trust": "adversarial-signal" if injection_signal else "unknown-input",
        "capability": permission.capability,
        "resource_type": permission.resource_type,
        "resource_scope": permission.scope,
        "approval": permission.approval,
        "node_ids": [prompt_node, permission_graph["asset_node"], permission_graph["tool_node"], permission_graph["resource_node"]],
        "edge_ids": [item for item in (prompt_edge, permission_graph["invoke_edge"], permission_graph["resource_edge"]) if item],
        "controls": controls,
        "missing_controls": missing_controls,
        "evidence": [
            "Prompt or instruction is declared for the asset.",
            f"The asset declares {permission.capability} for {permission.subject}.",
            f"The permission reaches {permission.resource_type} scope {permission.scope}.",
        ],
    }


def secret_exfiltration_path(
    graph: GraphBuilder,
    asset: AgentAsset,
    prompt_node: str,
    prompt_edge: str | None,
    prompt_confidence: str,
    permissions: list[dict[str, object]],
    *,
    injection_signal: bool,
) -> dict[str, object] | None:
    secret = first_permission(permissions, lambda item: item.capability == "secret-access")
    network = first_permission(permissions, lambda item: item.capability == "network-egress")
    if secret is None or network is None:
        return None
    secret_permission = secret["permission"]
    network_permission = network["permission"]
    if not isinstance(secret_permission, AgentPermission) or not isinstance(network_permission, AgentPermission):
        return None
    transfer_edge = graph.edge(
        str(secret["resource_node"]),
        str(network["tool_node"]),
        "may_flow_to",
        confidence="low",
        evidence="secret-access and network-egress are declared on the same Agent asset",
        basis="conservative-inference",
    )
    controls = [
        *list(secret.get("controls") or []),
        *list(network.get("controls") or []),
    ]
    missing = list(dict.fromkeys([
        *missing_controls_for_permission(secret_permission, injection_signal, list(secret.get("controls") or [])),
        *missing_controls_for_permission(network_permission, injection_signal, list(network.get("controls") or [])),
        "verified-data-egress-policy",
    ]))
    return {
        "id": stable_id("path", asset.path, "secret-exfiltration"),
        "kind": "potential-secret-exfiltration",
        "title": "Potential secret-to-network data path",
        "severity": "critical" if injection_signal else "high",
        "confidence": minimum_confidence(prompt_confidence, "low"),
        "asset_path": asset.path,
        "source_trust": "adversarial-signal" if injection_signal else "unknown-input",
        "capability": "secret-access + network-egress",
        "resource_type": "secret-to-network",
        "resource_scope": f"{secret_permission.scope} -> {network_permission.scope}",
        "approval": f"secret:{secret_permission.approval}; network:{network_permission.approval}",
        "node_ids": [
            prompt_node,
            secret["asset_node"],
            secret["tool_node"],
            secret["resource_node"],
            network["tool_node"],
            network["resource_node"],
        ],
        "edge_ids": [item for item in (
            prompt_edge,
            secret["invoke_edge"],
            secret["resource_edge"],
            transfer_edge,
            network["resource_edge"],
        ) if item],
        "controls": controls,
        "missing_controls": missing,
        "evidence": [
            "The same Agent asset declares access to secrets and an outbound network capability.",
            "The secret-to-network transfer edge is a conservative inference, not observed runtime behavior.",
        ],
    }


def cross_asset_injection_paths(
    graph: GraphBuilder,
    prompts: list[dict[str, object]],
    permissions: list[dict[str, object]],
) -> list[dict[str, object]]:
    if not any(bool(item.get("injection_signal")) for item in prompts) or not permissions:
        return []
    project_node = graph.node(
        "agent_boundary",
        "Project Agent execution boundary",
        "agent-project",
        trust="inferred-boundary",
        attributes={"basis": "project-level co-location"},
    )
    result: list[dict[str, object]] = []
    for prompt in prompts:
        prompt_asset = prompt.get("asset")
        if not isinstance(prompt_asset, AgentAsset) or not prompt.get("injection_signal"):
            continue
        context_edge = graph.edge(
            str(prompt["prompt_node"]),
            project_node,
            "may_influence_project_agent",
            confidence="low",
            evidence="a suspicious instruction asset and tool configuration exist in the same scanned project",
            basis="conservative-inference",
        )
        for boundary in permissions:
            tool_asset = boundary.get("asset")
            permission = boundary.get("permission")
            if (
                not isinstance(tool_asset, AgentAsset)
                or not isinstance(permission, AgentPermission)
                or tool_asset.path == prompt_asset.path
                or permission.capability == "tool-invocation"
            ):
                continue
            severity = path_severity(permission, True)
            if severity not in {"critical", "high"}:
                continue
            invoke_edge = graph.edge(
                project_node,
                str(boundary["tool_node"]),
                "may_invoke_project_tool",
                confidence="low",
                evidence=f"tool capability is configured elsewhere in the same project: {tool_asset.path}",
                basis="conservative-inference",
            )
            path_id = stable_id(
                "path", "cross-asset", prompt_asset.path, tool_asset.path,
                permission.subject, permission.capability, permission.scope,
            )
            result.append({
                "id": path_id,
                "kind": "cross-asset-prompt-to-resource",
                "title": f"Suspicious project instructions may reach {permission.capability}",
                "severity": severity,
                "confidence": "low",
                "asset_path": prompt_asset.path,
                "tool_asset_path": tool_asset.path,
                "source_trust": "adversarial-signal",
                "capability": permission.capability,
                "resource_type": permission.resource_type,
                "resource_scope": permission.scope,
                "approval": permission.approval,
                "node_ids": [
                    prompt["prompt_node"], project_node,
                    boundary["tool_node"], boundary["resource_node"],
                ],
                "edge_ids": [context_edge, invoke_edge, boundary["resource_edge"]],
                "controls": boundary.get("controls") or [],
                "missing_controls": missing_controls_for_permission(
                    permission, True, list(boundary.get("controls") or [])
                ),
                "evidence": [
                    f"Suspicious instruction evidence is located in {prompt_asset.path}.",
                    f"A high-risk capability is configured in {tool_asset.path}.",
                    "The cross-asset connection is a conservative project-level inference and must be confirmed against the actual Agent runtime configuration.",
                ],
            })
            if len(result) >= MAX_PATHS:
                return result
    return result


def dataflow_finding(path: dict[str, object]) -> AgentFinding:
    kind = str(path.get("kind") or "prompt-to-resource")
    source_trust = str(path.get("source_trust") or "unknown-input")
    capability = str(path.get("capability") or "sensitive-capability")
    resource_type = str(path.get("resource_type") or "resource")
    resource_scope = str(path.get("resource_scope") or "unspecified")
    scope_label = f"{resource_type} {resource_scope}"
    if kind == "potential-secret-exfiltration":
        rule_id = "AGENT.FLOW.POTENTIAL_SECRET_EXFILTRATION"
        title = f"Agent declarations form a potential secret-to-network path: {scope_label}"
    elif source_trust == "adversarial-signal":
        rule_id = "AGENT.FLOW.UNTRUSTED_TO_HIGH_RISK_TOOL"
        title = f"Suspicious instructions can reach {capability}: {scope_label}"
    else:
        rule_id = "AGENT.FLOW.PROMPT_TO_SENSITIVE_RESOURCE"
        title = f"Prompt context can reach {capability}: {scope_label}"
    missing = ",".join(str(item) for item in path.get("missing_controls") or []) or "none-recorded"
    return build_finding(
        rule_id,
        title,
        severity_value(path.get("severity")),
        "agent-dataflow",
        str(path.get("asset_path") or "agent-project"),
        1,
        f"path_id={path['id']}; capability={path.get('capability')}; resource={path.get('resource_type')}:{path.get('resource_scope')}; confidence={path.get('confidence')}; missing_controls={missing}",
        "Static declarations connect Prompt or instruction context to a tool capability and resource boundary. The path is potential, not observed runtime execution.",
        "Narrow the tool and resource scope, require enforceable human approval for high-risk actions, validate untrusted content, and verify the path in a controlled sandbox before deployment.",
        "Trust is reduced because model-influenced context may reach a sensitive capability without fully verified runtime controls.",
    )


def path_severity(permission: AgentPermission, injection_signal: bool) -> str:
    capability = permission.capability
    if injection_signal and capability in {"all-capabilities", "shell-execution", "server-process"}:
        return "critical"
    if injection_signal and capability in HIGH_RISK_CAPABILITIES | {"network-egress"}:
        return "high"
    if capability in {"all-capabilities", "shell-execution", "server-process"}:
        return "high"
    if capability in {"filesystem-write", "secret-access"}:
        return "high"
    if capability in {"network-egress", "filesystem-read"}:
        return "medium"
    return "info"


def missing_controls_for_permission(
    permission: AgentPermission,
    injection_signal: bool,
    controls: list[dict[str, object]] | None = None,
) -> list[str]:
    control_types = {str(item.get("type") or "") for item in controls or []}
    missing: list[str] = []
    if permission.capability in HIGH_RISK_CAPABILITIES and permission.approval != "required":
        missing.append("human-approval")
    if broad_scope(permission.scope):
        missing.append("resource-scope-restriction")
    if permission.capability == "network-egress" and broad_scope(permission.scope):
        missing.append(
            "verified-network-destination-allowlist"
            if "network-destination-allowlist-declared" in control_types
            else "network-destination-allowlist"
        )
    if injection_signal:
        missing.append(
            "verified-untrusted-content-validation"
            if "content-validation-declared" in control_types
            else "untrusted-content-validation"
        )
    return missing


def applicable_control_claims(asset: AgentAsset, permission: AgentPermission) -> list[dict[str, object]]:
    raw = asset.metadata.get("declared_security_controls")
    if not isinstance(raw, list):
        return []
    result: list[dict[str, object]] = []
    for item in raw:
        if not isinstance(item, dict):
            continue
        control_type = str(item.get("type") or "")
        if control_type == "network-destination-allowlist-declared" and permission.capability != "network-egress":
            continue
        if control_type not in {
            "content-validation-declared",
            "network-destination-allowlist-declared",
            "sandbox-isolation-declared",
        }:
            continue
        result.append({
            "type": control_type,
            "source_path": str(item.get("path") or "")[:300],
            "runtime_verified": False,
        })
    return result


def first_permission(
    permissions: list[dict[str, object]],
    predicate: Callable[[AgentPermission], bool],
) -> dict[str, object] | None:
    for item in permissions:
        permission = item.get("permission")
        if isinstance(permission, AgentPermission) and predicate(permission):
            return item
    return None


def resource_trust(permission: AgentPermission) -> str:
    if permission.resource_type in {"secret", "environment", "header"}:
        return "sensitive"
    if permission.resource_type == "filesystem" and sensitive_scope(permission.scope):
        return "sensitive"
    if broad_scope(permission.scope):
        return "broad-boundary"
    return "declared-resource"


def sensitive_scope(scope: str) -> bool:
    normalized = scope.lower().replace("\\", "/")
    return any(item in normalized for item in (".env", "/etc/", ".ssh", "credential", "secret", "token", "key"))


def broad_scope(scope: str) -> bool:
    return scope.strip().lower() in BROAD_SCOPES


def minimum_confidence(*values: str) -> str:
    return min(values, key=lambda value: CONFIDENCE_RANK.get(value, 0))


def stable_id(*parts: str) -> str:
    digest = sha256("\x1f".join(parts).encode("utf-8", errors="replace")).hexdigest()[:16]
    return f"df-{digest}"


def severity_value(value: object) -> Severity:
    try:
        return Severity(str(value or "medium"))
    except ValueError:
        return Severity.medium


def dedupe_paths(paths: list[dict[str, object]]) -> list[dict[str, object]]:
    result: dict[str, dict[str, object]] = {}
    for item in paths:
        result.setdefault(str(item["id"]), item)
    return list(result.values())[:MAX_PATHS]


def dedupe_findings(findings: list[AgentFinding]) -> list[AgentFinding]:
    result: dict[tuple[str, str, str], AgentFinding] = {}
    for item in findings:
        result.setdefault((item.rule_id, item.file_path, item.evidence), item)
    return list(result.values())
