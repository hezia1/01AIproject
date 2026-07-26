from __future__ import annotations

from collections.abc import Iterable
from uuid import UUID

from app.db_models import ComponentRecord, DastValidationRecord, FindingRecord, SandboxEvidenceRecord
from app.models import (
    AttackChain,
    AttackChainStep,
    EvidenceGraph,
    EvidenceGraphEdge,
    EvidenceGraphNode,
    Severity,
)


def build_evidence_graph(
    project_id: UUID,
    project_name: str,
    findings: list[FindingRecord],
    components: list[ComponentRecord],
    validations: list[DastValidationRecord],
    evidence_records: list[SandboxEvidenceRecord],
) -> EvidenceGraph:
    nodes = [
        EvidenceGraphNode(
            id=project_node_id(project_id),
            kind="project",
            module="ASPM",
            label=project_name,
            status="active",
        )
    ]
    edges: list[EvidenceGraphEdge] = []
    edge_ids: set[str] = set()

    for component in components:
        nodes.append(component_node(component))
        add_edge(
            edges,
            edge_ids,
            project_node_id(project_id),
            component_node_id(component.id),
            "contains",
            "project_id",
            100,
            component.created_at,
        )

    for finding in findings:
        nodes.append(finding_node(finding))
        add_edge(
            edges,
            edge_ids,
            project_node_id(project_id),
            finding_node_id(finding.id),
            "contains",
            "project_id",
            100,
            finding.created_at,
        )
        if finding.component_id:
            add_edge(
                edges,
                edge_ids,
                component_node_id(finding.component_id),
                finding_node_id(finding.id),
                "reported_by",
                "finding.component_id",
                100,
                finding.created_at,
            )

    linked_validation_count = 0
    for validation in validations:
        nodes.append(validation_node(validation))
        add_edge(
            edges,
            edge_ids,
            project_node_id(project_id),
            validation_node_id(validation.id),
            "contains",
            "project_id",
            100,
            validation.created_at,
        )
        confidence = explicit_confidence(validation.link_confidence)
        if validation.finding_id:
            linked_validation_count += 1
            add_edge(
                edges,
                edge_ids,
                finding_node_id(validation.finding_id),
                validation_node_id(validation.id),
                "validated_by",
                validation.link_source or "finding_id",
                confidence,
                validation.created_at,
            )
        if validation.component_id:
            linked_validation_count += int(validation.finding_id is None)
            add_edge(
                edges,
                edge_ids,
                component_node_id(validation.component_id),
                validation_node_id(validation.id),
                "validated_by",
                validation.link_source or "component_id",
                confidence,
                validation.created_at,
            )

    linked_evidence_count = 0
    for evidence in evidence_records:
        nodes.append(evidence_node(evidence))
        add_edge(
            edges,
            edge_ids,
            project_node_id(project_id),
            evidence_node_id(evidence.id),
            "contains",
            "project_id",
            100,
            evidence.created_at,
        )
        confidence = explicit_confidence(evidence.link_confidence)
        links = [
            (evidence.finding_id, finding_node_id, "finding_id"),
            (evidence.component_id, component_node_id, "component_id"),
            (evidence.validation_id, validation_node_id, "validation_id"),
        ]
        linked = False
        for record_id, node_id_factory, fallback_basis in links:
            if not record_id:
                continue
            linked = True
            add_edge(
                edges,
                edge_ids,
                node_id_factory(record_id),
                evidence_node_id(evidence.id),
                "observed_by",
                evidence.link_source or fallback_basis,
                confidence,
                evidence.created_at,
            )
        linked_evidence_count += int(linked)

    relation_edges = [edge for edge in edges if edge.relation_type != "contains"]
    return EvidenceGraph(
        project_id=project_id,
        nodes=nodes,
        edges=edges,
        summary={
            "node_count": len(nodes),
            "edge_count": len(edges),
            "relation_edge_count": len(relation_edges),
            "linked_validation_count": linked_validation_count,
            "unlinked_validation_count": len(validations) - linked_validation_count,
            "linked_evidence_count": linked_evidence_count,
            "unlinked_evidence_count": len(evidence_records) - linked_evidence_count,
        },
    )


def build_attack_chains_v2(
    findings: list[FindingRecord],
    components: list[ComponentRecord],
    validations: list[DastValidationRecord],
    evidence_records: list[SandboxEvidenceRecord],
) -> list[AttackChain]:
    finding_map = {str(item.id): item for item in findings}
    component_map = {str(item.id): item for item in components}
    validation_map = {str(item.id): item for item in validations}
    chains: list[AttackChain] = []
    consumed_evidence: set[str] = set()

    for validation in validations:
        origin_steps = origin_steps_for(
            validation.finding_id,
            validation.component_id,
            finding_map,
            component_map,
        )
        if not origin_steps:
            continue
        related_evidence = [
            item
            for item in evidence_records
            if evidence_matches_validation(item, validation)
        ]
        consumed_evidence.update(str(item.id) for item in related_evidence)
        steps = [
            *origin_steps,
            validation_step(validation),
            *(evidence_step(item) for item in related_evidence[:3]),
        ]
        confidence_values = [explicit_confidence(validation.link_confidence)]
        confidence_values.extend(explicit_confidence(item.link_confidence) for item in related_evidence[:3])
        confidence = min(confidence_values)
        severity = chain_severity(
            finding_map.get(str(validation.finding_id)) if validation.finding_id else None,
            component_map.get(str(validation.component_id)) if validation.component_id else None,
            validation,
        )
        basis = unique_values(
            [
                validation.link_source or "explicit-validation-link",
                *(item.link_source or "explicit-evidence-link" for item in related_evidence[:3]),
            ]
        )
        chains.append(
            AttackChain(
                id=f"validation-chain:{validation.id}",
                name=chain_name(validation.finding_id, validation.component_id, has_validation=True),
                severity=severity,
                modules=unique_modules(steps),
                evidence_count=len(steps),
                confidence=confidence,
                correlation_basis=basis,
                summary=f"风险对象已通过显式关联进入 DAST 验证；关联依据：{'、'.join(basis)}；可信度 {confidence}%。",
                recommended_action=recommended_action(validation),
                steps=steps,
            )
        )

    for evidence in evidence_records:
        if str(evidence.id) in consumed_evidence or evidence.validation_id:
            continue
        origin_steps = origin_steps_for(
            evidence.finding_id,
            evidence.component_id,
            finding_map,
            component_map,
        )
        if not origin_steps:
            continue
        steps = [*origin_steps, evidence_step(evidence)]
        finding = finding_map.get(str(evidence.finding_id)) if evidence.finding_id else None
        component = component_map.get(str(evidence.component_id)) if evidence.component_id else None
        chains.append(
            AttackChain(
                id=f"runtime-chain:{evidence.id}",
                name=chain_name(evidence.finding_id, evidence.component_id, has_validation=False),
                severity=record_severity(finding, component),
                modules=unique_modules(steps),
                evidence_count=len(steps),
                confidence=explicit_confidence(evidence.link_confidence),
                correlation_basis=[evidence.link_source or "explicit-evidence-link"],
                summary="风险对象已与 SANDBOX 运行时证据显式关联，可直接追溯原始发现和执行记录。",
                recommended_action="复核运行时证据，确认影响范围；修复后使用同一关联对象执行复测。",
                steps=steps,
            )
        )

    return sorted(chains, key=chain_rank, reverse=True)


def evidence_matches_validation(evidence: SandboxEvidenceRecord, validation: DastValidationRecord) -> bool:
    return bool(evidence.validation_id and str(evidence.validation_id) == str(validation.id))


def origin_steps_for(
    finding_id: str | None,
    component_id: str | None,
    finding_map: dict[str, FindingRecord],
    component_map: dict[str, ComponentRecord],
) -> list[AttackChainStep]:
    steps: list[AttackChainStep] = []
    finding = finding_map.get(str(finding_id)) if finding_id else None
    component = component_map.get(str(component_id)) if component_id else None
    if component is None and finding is not None and finding.component_id:
        component = component_map.get(str(finding.component_id))
    if component is not None:
        steps.append(component_step(component))
    if finding is not None:
        steps.append(finding_step(finding))
    return steps


def component_node(component: ComponentRecord) -> EvidenceGraphNode:
    version = f" {component.version}" if component.version else ""
    return EvidenceGraphNode(
        id=component_node_id(component.id),
        kind="component",
        module="SCA",
        label=f"{component.name}{version}",
        severity=severity_or_none(component.severity),
        status=component.risk_status,
        detail=f"{component.ecosystem} · {component.source_file}",
        created_at=component.created_at,
    )


def finding_node(finding: FindingRecord) -> EvidenceGraphNode:
    return EvidenceGraphNode(
        id=finding_node_id(finding.id),
        kind="finding",
        module=finding.source,
        label=finding.title,
        severity=severity_or_none(finding.severity),
        status=finding.status,
        detail=finding.evidence or finding.rule_id,
        created_at=finding.created_at,
    )


def validation_node(validation: DastValidationRecord) -> EvidenceGraphNode:
    return EvidenceGraphNode(
        id=validation_node_id(validation.id),
        kind="validation",
        module="DAST",
        label=validation.target_url,
        status=validation.verdict,
        detail=validation.evidence_summary,
        created_at=validation.created_at,
    )


def evidence_node(evidence: SandboxEvidenceRecord) -> EvidenceGraphNode:
    return EvidenceGraphNode(
        id=evidence_node_id(evidence.id),
        kind="evidence",
        module="SANDBOX",
        label=evidence.run_command,
        status="observed",
        detail=evidence.evidence_summary,
        created_at=evidence.created_at,
    )


def component_step(component: ComponentRecord) -> AttackChainStep:
    return AttackChainStep(
        module="SCA",
        title=f"{component.name} {component.version or ''}".strip(),
        evidence=component.risk_summary or component.remediation,
        node_id=component_node_id(component.id),
        relation_type="reported_by",
        confidence=100,
        created_at=component.created_at,
    )


def finding_step(finding: FindingRecord) -> AttackChainStep:
    location = f"{finding.file_path or '-'}:{finding.line_start or '-'}"
    return AttackChainStep(
        module=finding.source,
        title=finding.title,
        evidence=f"{location} · {finding.evidence or finding.rule_id}",
        node_id=finding_node_id(finding.id),
        relation_type="validated_by",
        confidence=100,
        created_at=finding.created_at,
    )


def validation_step(validation: DastValidationRecord) -> AttackChainStep:
    return AttackChainStep(
        module="DAST",
        title=f"动态验证：{validation.target_url}",
        evidence=validation.evidence_summary,
        node_id=validation_node_id(validation.id),
        relation_type="validated_by",
        confidence=explicit_confidence(validation.link_confidence),
        created_at=validation.created_at,
    )


def evidence_step(evidence: SandboxEvidenceRecord) -> AttackChainStep:
    return AttackChainStep(
        module="SANDBOX",
        title=f"运行时证据：{evidence.run_command}",
        evidence=evidence.evidence_summary,
        node_id=evidence_node_id(evidence.id),
        relation_type="observed_by",
        confidence=explicit_confidence(evidence.link_confidence),
        created_at=evidence.created_at,
    )


def add_edge(
    edges: list[EvidenceGraphEdge],
    edge_ids: set[str],
    source: str,
    target: str,
    relation_type: str,
    basis: str,
    confidence: int,
    created_at,
) -> None:
    edge_id = f"{relation_type}:{source}:{target}"
    if edge_id in edge_ids:
        return
    edge_ids.add(edge_id)
    edges.append(
        EvidenceGraphEdge(
            id=edge_id,
            source=source,
            target=target,
            relation_type=relation_type,
            basis=basis,
            confidence=confidence,
            created_at=created_at,
        )
    )


def chain_severity(
    finding: FindingRecord | None,
    component: ComponentRecord | None,
    validation: DastValidationRecord,
) -> Severity:
    base = record_severity(finding, component)
    if validation.verdict == "exploitable":
        return Severity.critical if base in {Severity.critical, Severity.high} else Severity.high
    return base


def record_severity(
    finding: FindingRecord | None,
    component: ComponentRecord | None,
) -> Severity:
    value = finding.severity if finding is not None else component.severity if component is not None else None
    return severity_or_none(value) or Severity.medium


def severity_or_none(value: str | None) -> Severity | None:
    try:
        return Severity(value) if value else None
    except ValueError:
        return None


def recommended_action(validation: DastValidationRecord) -> str:
    if validation.verdict == "exploitable":
        return "按最高优先级处置原始风险，修复后沿同一关联链执行 DAST 与 SANDBOX 复测。"
    if validation.verdict == "not_exploitable":
        return "保留不可利用证据，复核环境与入口覆盖范围后决定关闭或接受风险。"
    return "补充验证条件和运行时证据，确认入口可达性后再进行处置裁决。"


def chain_name(finding_id: str | None, component_id: str | None, has_validation: bool) -> str:
    origin = "Finding" if finding_id else "供应链组件" if component_id else "风险对象"
    outcome = "动态验证证据链" if has_validation else "沙箱运行时证据链"
    return f"{origin}{outcome}"


def chain_rank(chain: AttackChain) -> tuple[int, int, int]:
    severity_rank = {
        Severity.critical: 5,
        Severity.high: 4,
        Severity.medium: 3,
        Severity.low: 2,
        Severity.info: 1,
    }[chain.severity]
    return severity_rank, chain.confidence, chain.evidence_count


def unique_modules(steps: Iterable[AttackChainStep]) -> list[str]:
    return unique_values(step.module for step in steps)


def unique_values(values: Iterable[str]) -> list[str]:
    result: list[str] = []
    for value in values:
        if value and value not in result:
            result.append(value)
    return result


def explicit_confidence(value: int | None) -> int:
    return value if value and value > 0 else 100


def project_node_id(value) -> str:
    return f"project:{value}"


def component_node_id(value) -> str:
    return f"component:{value}"


def finding_node_id(value) -> str:
    return f"finding:{value}"


def validation_node_id(value) -> str:
    return f"validation:{value}"


def evidence_node_id(value) -> str:
    return f"evidence:{value}"
