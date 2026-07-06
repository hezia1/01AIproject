from __future__ import annotations

from datetime import datetime
from uuid import uuid4

from app.db_models import ComponentRecord, ProjectRecord


def build_cyclonedx_sbom(project: ProjectRecord, components: list[ComponentRecord]) -> dict[str, object]:
    bom_components = [component_to_cyclonedx(component) for component in components]
    vulnerabilities = build_vulnerabilities(components)
    dependencies = build_dependencies(project, components)
    bom: dict[str, object] = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": datetime.utcnow().replace(microsecond=0).isoformat() + "Z",
            "component": {
                "type": "application",
                "name": project.name,
                "version": project.default_branch or "main",
                "bom-ref": f"project:{project.id}",
                "properties": [
                    property_item("project:id", str(project.id)),
                    property_item("project:repository_url", project.repository_url),
                    property_item("project:source_path", project.source_path),
                ],
            },
            "tools": [
                {
                    "vendor": "AI Security Platform",
                    "name": "SCA Module",
                    "version": "0.1.0",
                }
            ],
        },
        "components": bom_components,
        "dependencies": dependencies,
    }
    if vulnerabilities:
        bom["vulnerabilities"] = vulnerabilities
    return bom


def build_dependencies(project: ProjectRecord, components: list[ComponentRecord]) -> list[dict[str, object]]:
    project_ref = f"project:{project.id}"
    direct_components = [component for component in components if component.dependency_type != "transitive"]
    transitive_components = [component for component in components if component.dependency_type == "transitive"]
    direct_refs = sorted(component_ref(component) for component in direct_components)
    dependencies: list[dict[str, object]] = [{"ref": project_ref, "dependsOn": direct_refs}]

    for direct in direct_components:
        related_transitives = [
            component_ref(component)
            for component in transitive_components
            if components_share_dependency_context(direct, component)
        ]
        dependencies.append({"ref": component_ref(direct), "dependsOn": sorted(set(related_transitives))})

    direct_ref_set = set(direct_refs)
    for component in components:
        ref = component_ref(component)
        if ref in direct_ref_set:
            continue
        dependencies.append({"ref": ref, "dependsOn": []})
    return dependencies


def components_share_dependency_context(parent: ComponentRecord, child: ComponentRecord) -> bool:
    if parent.ecosystem != child.ecosystem:
        return False
    parent_sources = set(split_sources(parent.source_file))
    child_sources = set(split_sources(child.source_file))
    if parent_sources & child_sources:
        return True
    if parent.package_manager and child.package_manager and parent.package_manager == child.package_manager:
        return True
    return False


def split_sources(source_file: str | None) -> list[str]:
    if not source_file:
        return []
    return [item.strip() for item in source_file.split(",") if item.strip()]


def component_to_cyclonedx(component: ComponentRecord) -> dict[str, object]:
    bom_ref = component_ref(component)
    item: dict[str, object] = {
        "type": "library",
        "name": component.name,
        "bom-ref": bom_ref,
        "scope": dependency_scope(component.dependency_type),
        "properties": [
            property_item("sca:ecosystem", component.ecosystem),
            property_item("sca:dependency_type", component.dependency_type),
            property_item("sca:source_file", component.source_file),
            property_item("sca:package_manager", component.package_manager),
            property_item("sca:risk_status", component.risk_status),
            property_item("sca:risk_source", component.risk_source),
        ],
    }
    if component.version:
        item["version"] = component.version
    purl = package_url(component)
    if purl:
        item["purl"] = purl
    if component.license:
        item["licenses"] = [{"license": {"name": component.license}}]
    return item


def build_vulnerabilities(components: list[ComponentRecord]) -> list[dict[str, object]]:
    vulnerabilities: list[dict[str, object]] = []
    seen: set[tuple[str, str]] = set()
    for component in components:
        for vulnerability_id in component.vulnerability_ids or []:
            key = (component_ref(component), str(vulnerability_id))
            if key in seen:
                continue
            seen.add(key)
            vulnerability: dict[str, object] = {
                "id": str(vulnerability_id),
                "source": {"name": component.risk_source or "sca"},
                "ratings": [{"severity": cyclonedx_severity(component.severity)}],
                "affects": [{"ref": component_ref(component)}],
            }
            if component.risk_summary:
                vulnerability["description"] = component.risk_summary
            if component.remediation:
                vulnerability["recommendation"] = component.remediation
            vulnerabilities.append(vulnerability)
    return vulnerabilities


def component_ref(component: ComponentRecord) -> str:
    version = component.version or "unknown"
    return f"{component.ecosystem}:{component.name}@{version}"


def dependency_scope(dependency_type: str) -> str:
    if dependency_type in {"development", "test"}:
        return "excluded"
    if dependency_type == "optional":
        return "optional"
    return "required"


def package_url(component: ComponentRecord) -> str | None:
    version = component.version
    if not version:
        return None
    normalized_version = version.lstrip("=<>~^ ")
    if component.ecosystem == "npm":
        return f"pkg:npm/{component.name}@{normalized_version}"
    if component.ecosystem == "pypi":
        return f"pkg:pypi/{component.name}@{normalized_version}"
    if component.ecosystem == "maven" and ":" in component.name:
        group_id, artifact_id = component.name.split(":", 1)
        return f"pkg:maven/{group_id}/{artifact_id}@{normalized_version}"
    if component.ecosystem == "go":
        return f"pkg:golang/{component.name}@{normalized_version}"
    return None


def cyclonedx_severity(severity: str | None) -> str:
    if severity in {"critical", "high", "medium", "low", "info"}:
        return severity
    return "unknown"


def property_item(name: str, value: object | None) -> dict[str, str]:
    return {"name": name, "value": "" if value is None else str(value)}
