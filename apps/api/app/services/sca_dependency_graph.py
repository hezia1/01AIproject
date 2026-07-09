from __future__ import annotations

from collections import defaultdict

from app.db_models import ComponentRecord, ProjectRecord
from app.services.sca_sbom import build_dependency_edge_records, component_ref, project_ref
from app.services.sca_native_tree import build_native_dependency_edge_records


SEVERITY_WEIGHT = {
    "critical": 5,
    "high": 4,
    "medium": 3,
    "low": 2,
    "info": 1,
    None: 0,
}


def build_dependency_graph(project: ProjectRecord, components: list[ComponentRecord]) -> dict[str, object]:
    nodes = [project_node(project)]
    nodes.extend(component_node(component) for component in components)
    dependency_edges = graph_dependency_edges(project, components)
    edges = [
        {
            "source": edge["source"],
            "target": edge["target"],
            "quality": edge["quality"],
        }
        for edge in dependency_edges
    ]
    upgrade_levers = build_upgrade_levers(project, components, dependency_edges)
    return {
        "project_id": str(project.id),
        "nodes": nodes,
        "edges": edges,
        "upgrade_levers": upgrade_levers,
        "summary": graph_summary(nodes, edges, components),
    }


def project_node(project: ProjectRecord) -> dict[str, object]:
    return {
        "id": project_ref(project),
        "label": project.name,
        "kind": "project",
        "risk_status": "project",
        "severity": None,
        "dependency_type": "project",
        "ecosystem": "project",
        "package_manager": None,
        "version": project.default_branch or "main",
    }


def component_node(component: ComponentRecord) -> dict[str, object]:
    return {
        "id": component_ref(component),
        "label": component.name,
        "kind": "component",
        "risk_status": component.risk_status,
        "severity": component.severity,
        "dependency_type": component.dependency_type,
        "ecosystem": component.ecosystem,
        "package_manager": component.package_manager,
        "version": component.version,
        "license_risk": component.license_risk,
        "risk_source": component.risk_source,
        "vulnerability_ids": component.vulnerability_ids or [],
        "source_file": component.source_file,
    }


def graph_dependency_edges(project: ProjectRecord, components: list[ComponentRecord]) -> list[dict[str, str]]:
    inferred_edges = build_dependency_edge_records(project, components)
    native_edges = build_native_dependency_edge_records(project, components)
    if not native_edges:
        return inferred_edges

    manifest_edges = [edge for edge in inferred_edges if edge["quality"] == "manifest_direct"]
    return dedupe_edges([*manifest_edges, *native_edges])


def build_upgrade_levers(
    project: ProjectRecord,
    components: list[ComponentRecord],
    dependency_edges: list[dict[str, str]] | None = None,
) -> list[dict[str, object]]:
    by_ref = {component_ref(component): component for component in components}
    risky_transitives_by_parent: dict[str, list[ComponentRecord]] = defaultdict(list)
    edges = dependency_edges or graph_dependency_edges(project, components)
    preferred_quality = "native_tree" if any(edge["quality"] == "native_tree" for edge in edges) else "lockfile_inferred"
    for edge in edges:
        if edge["quality"] != preferred_quality:
            continue
        child = by_ref.get(edge["target"])
        if child and is_risky_component(child):
            risky_transitives_by_parent[edge["source"]].append(child)

    levers: list[dict[str, object]] = []
    for parent_ref, risky_children in risky_transitives_by_parent.items():
        parent = by_ref.get(parent_ref)
        if parent is None:
            continue
        highest = highest_severity([child.severity for child in risky_children])
        levers.append(
            {
                "component_id": parent_ref,
                "component": parent.name,
                "ecosystem": parent.ecosystem,
                "version": parent.version,
                "risk_transitive_count": len(risky_children),
                "highest_severity": highest,
                "affected_components": [child.name for child in risky_children],
                "recommendation": lever_recommendation(parent, risky_children),
            }
        )
    return sorted(
        levers,
        key=lambda item: (int(item["risk_transitive_count"]), SEVERITY_WEIGHT.get(item["highest_severity"], 0)),
        reverse=True,
    )


def graph_summary(nodes: list[dict[str, object]], edges: list[dict[str, object]], components: list[ComponentRecord]) -> dict[str, int]:
    return {
        "node_count": len(nodes),
        "edge_count": len(edges),
        "risk_node_count": sum(1 for component in components if is_risky_component(component)),
        "direct_risk_count": sum(1 for component in components if component.dependency_type != "transitive" and is_risky_component(component)),
        "transitive_risk_count": sum(1 for component in components if component.dependency_type == "transitive" and is_risky_component(component)),
        "manifest_direct_edge_count": sum(1 for edge in edges if edge["quality"] == "manifest_direct"),
        "lockfile_inferred_edge_count": sum(1 for edge in edges if edge["quality"] == "lockfile_inferred"),
        "native_tree_edge_count": sum(1 for edge in edges if edge["quality"] == "native_tree"),
    }


def dedupe_edges(edges: list[dict[str, str]]) -> list[dict[str, str]]:
    priority = {"manifest_direct": 0, "native_tree": 2, "lockfile_inferred": 1}
    deduped: dict[tuple[str, str], dict[str, str]] = {}
    for edge in edges:
        key = (edge["source"], edge["target"])
        current = deduped.get(key)
        if current is None or priority.get(edge["quality"], 0) > priority.get(current["quality"], 0):
            deduped[key] = edge
    return sorted(deduped.values(), key=lambda edge: (edge["source"], edge["target"]))


def is_risky_component(component: ComponentRecord) -> bool:
    return component.risk_status in {"vulnerable", "license-risk"} or component.severity in {"critical", "high"}


def highest_severity(severities: list[str | None]) -> str | None:
    filtered = [severity for severity in severities if severity]
    if not filtered:
        return None
    return max(filtered, key=lambda severity: SEVERITY_WEIGHT.get(severity, 0))


def lever_recommendation(parent: ComponentRecord, risky_children: list[ComponentRecord]) -> str:
    highest = highest_severity([child.severity for child in risky_children])
    if highest in {"critical", "high"}:
        return f"优先升级或替换 {parent.name}，并验证其锁文件是否移除高风险传递依赖。"
    return f"评估升级 {parent.name}，减少其带入的风险传递依赖。"
