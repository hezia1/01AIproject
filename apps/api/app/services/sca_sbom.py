from __future__ import annotations

from datetime import datetime
import re
from uuid import uuid4

from app.db_models import ComponentRecord, ProjectRecord


SCA_TOOL_VENDOR = "AI Security Platform"
SCA_TOOL_NAME = "SCA Module"
SCA_TOOL_VERSION = "0.1.0"
HASH_STATUS_NOT_COLLECTED = "NOASSERTION: package artifact hash not collected"


def build_cyclonedx_sbom(project: ProjectRecord, components: list[ComponentRecord]) -> dict[str, object]:
    timestamp = utc_timestamp()
    bom_components = [component_to_cyclonedx(component) for component in components]
    vulnerabilities = build_vulnerabilities(components)
    dependencies = build_dependencies(project, components)
    edge_summary = dependency_edge_summary(project, components)
    project_component = {
        "type": "application",
        "name": project.name,
        "version": project.default_branch or "main",
        "bom-ref": project_ref(project),
        "properties": project_properties(project, components),
    }
    if project.repository_url:
        project_component["externalReferences"] = [{"type": "vcs", "url": project.repository_url}]
    bom: dict[str, object] = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": timestamp,
            "component": project_component,
            "tools": [
                {
                    "vendor": SCA_TOOL_VENDOR,
                    "name": SCA_TOOL_NAME,
                    "version": SCA_TOOL_VERSION,
                }
            ],
            "properties": [
                property_item("sca:sbom_profile", "local-platform-sca"),
                property_item("sca:hash_status", HASH_STATUS_NOT_COLLECTED),
                property_item("sca:dependency_edge_quality", dependency_edge_quality_label(edge_summary)),
                property_item("sca:manifest_direct_edge_count", edge_summary["manifest_direct"]),
                property_item("sca:lockfile_inferred_edge_count", edge_summary["lockfile_inferred"]),
                property_item("sca:dependency_edge_count", edge_summary["total"]),
            ],
        },
        "components": bom_components,
        "dependencies": dependencies,
    }
    if vulnerabilities:
        bom["vulnerabilities"] = vulnerabilities
    return bom


def build_spdx_sbom(project: ProjectRecord, components: list[ComponentRecord]) -> dict[str, object]:
    created_at = utc_timestamp()
    project_spdx_id = spdx_id(f"project-{project.id}")
    packages = [project_to_spdx_package(project, project_spdx_id)]
    packages.extend(component_to_spdx_package(component) for component in components)

    relationships: list[dict[str, str]] = [
        {
            "spdxElementId": "SPDXRef-DOCUMENT",
            "relationshipType": "DESCRIBES",
            "relatedSpdxElement": project_spdx_id,
        }
    ]
    for edge in build_dependency_edge_records(
        project,
        components,
        project_spdx_id,
        ref_builder=component_spdx_ref,
    ):
        relationship = {
            "spdxElementId": edge["source"],
            "relationshipType": "DEPENDS_ON",
            "relatedSpdxElement": edge["target"],
        }
        if edge["quality"]:
            relationship["comment"] = f"sca:edge_quality={edge['quality']}"
        relationships.append(
            relationship
        )

    return {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": f"{project.name} SCA SBOM",
        "documentNamespace": f"https://ai-security-platform.local/spdx/{project.id}/{uuid4()}",
        "documentDescribes": [project_spdx_id],
        "creationInfo": {
            "created": created_at,
            "creators": [f"Tool: {SCA_TOOL_VENDOR} {SCA_TOOL_NAME}-{SCA_TOOL_VERSION}"],
        },
        "packages": packages,
        "relationships": relationships,
    }


def build_dependencies(project: ProjectRecord, components: list[ComponentRecord]) -> list[dict[str, object]]:
    root_ref = project_ref(project)
    direct_components = [component for component in components if component.dependency_type != "transitive"]
    transitive_components = [component for component in components if component.dependency_type == "transitive"]
    direct_refs = sorted(component_ref(component) for component in direct_components)
    dependencies: list[dict[str, object]] = [
        {
            "ref": root_ref,
            "dependsOn": direct_refs,
            "properties": [property_item("sca:edge_quality", "manifest_direct")],
        }
    ]

    for direct in direct_components:
        related_transitives = [
            component_ref(component)
            for component in transitive_components
            if components_share_dependency_context(direct, component)
        ]
        dependency: dict[str, object] = {
            "ref": component_ref(direct),
            "dependsOn": sorted(set(related_transitives)),
        }
        if related_transitives:
            dependency["properties"] = [property_item("sca:edge_quality", "lockfile_inferred")]
        dependencies.append(dependency)

    direct_ref_set = set(direct_refs)
    for component in components:
        ref = component_ref(component)
        if ref in direct_ref_set:
            continue
        dependencies.append({"ref": ref, "dependsOn": []})
    return dependencies


def build_dependency_edges(
    project: ProjectRecord,
    components: list[ComponentRecord],
    project_ref: str | None = None,
    ref_builder=None,
) -> list[tuple[str, str]]:
    return [
        (edge["source"], edge["target"])
        for edge in build_dependency_edge_records(project, components, project_ref, ref_builder)
    ]


def build_dependency_edge_records(
    project: ProjectRecord,
    components: list[ComponentRecord],
    project_ref: str | None = None,
    ref_builder=None,
) -> list[dict[str, str]]:
    build_ref = ref_builder or component_ref
    source_project_ref = project_ref or f"project:{project.id}"
    direct_components = [component for component in components if component.dependency_type != "transitive"]
    transitive_components = [component for component in components if component.dependency_type == "transitive"]
    edges: list[dict[str, str]] = [
        {"source": source_project_ref, "target": build_ref(component), "quality": "manifest_direct"}
        for component in direct_components
    ]

    for direct in direct_components:
        for component in transitive_components:
            if components_share_dependency_context(direct, component):
                edges.append(
                    {
                        "source": build_ref(direct),
                        "target": build_ref(component),
                        "quality": "lockfile_inferred",
                    }
                )

    deduped: dict[tuple[str, str], dict[str, str]] = {}
    for edge in edges:
        deduped[(edge["source"], edge["target"])] = edge
    return sorted(deduped.values(), key=lambda edge: (edge["source"], edge["target"]))


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


def dependency_edge_summary(project: ProjectRecord, components: list[ComponentRecord]) -> dict[str, int]:
    counts = {"manifest_direct": 0, "lockfile_inferred": 0, "total": 0}
    for edge in build_dependency_edge_records(project, components):
        quality = edge["quality"]
        if quality in counts:
            counts[quality] += 1
        counts["total"] += 1
    return counts


def dependency_edge_quality_label(summary: dict[str, int]) -> str:
    labels: list[str] = []
    if summary.get("manifest_direct", 0):
        labels.append("manifest_direct")
    if summary.get("lockfile_inferred", 0):
        labels.append("lockfile_inferred")
    return ",".join(labels) if labels else "none"


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
            property_item("sca:component_id", str(component.id)),
            property_item("sca:project_id", str(component.project_id)),
            property_item("sca:scan_task_id", component.scan_task_id),
            property_item("sca:ecosystem", component.ecosystem),
            property_item("sca:dependency_type", component.dependency_type),
            property_item("sca:source_file", component.source_file),
            property_item("sca:source_count", len(split_sources(component.source_file))),
            property_item("sca:package_manager", component.package_manager),
            property_item("sca:risk_status", component.risk_status),
            property_item("sca:risk_source", component.risk_source),
            property_item("sca:severity", component.severity),
            property_item("sca:license_policy", component.license_risk),
            property_item("sca:vulnerability_ids", ",".join(str(item) for item in component.vulnerability_ids or [])),
            property_item("sca:osv_checked", component.osv_checked),
            property_item("sca:osv_error", component.osv_error),
            property_item("sca:hash_status", HASH_STATUS_NOT_COLLECTED),
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


def project_to_spdx_package(project: ProjectRecord, package_spdx_id: str) -> dict[str, object]:
    return {
        "name": project.name,
        "SPDXID": package_spdx_id,
        "versionInfo": project.default_branch or "main",
        "downloadLocation": project.repository_url or "NOASSERTION",
        "filesAnalyzed": False,
        "licenseConcluded": "NOASSERTION",
        "licenseDeclared": "NOASSERTION",
        "copyrightText": "NOASSERTION",
        "annotations": [
            spdx_annotation("project:id", str(project.id)),
            spdx_annotation("project:repository_url", project.repository_url),
            spdx_annotation("project:source_path", project.source_path),
            spdx_annotation("project:business_owner", project.business_owner),
            spdx_annotation("project:security_owner", project.security_owner),
            spdx_annotation("project:runtime_url", project.runtime_url),
            spdx_annotation("project:api_base_url", project.api_base_url),
            spdx_annotation("sca:hash_status", HASH_STATUS_NOT_COLLECTED),
        ],
    }


def component_to_spdx_package(component: ComponentRecord) -> dict[str, object]:
    package: dict[str, object] = {
        "name": component.name,
        "SPDXID": component_spdx_ref(component),
        "downloadLocation": "NOASSERTION",
        "filesAnalyzed": False,
        "licenseConcluded": normalize_spdx_license(component.license),
        "licenseDeclared": normalize_spdx_license(component.license),
        "copyrightText": "NOASSERTION",
        "supplier": "NOASSERTION",
        "primaryPackagePurpose": "LIBRARY",
        "annotations": [
            spdx_annotation("sca:component_id", str(component.id)),
            spdx_annotation("sca:project_id", str(component.project_id)),
            spdx_annotation("sca:scan_task_id", component.scan_task_id),
            spdx_annotation("sca:ecosystem", component.ecosystem),
            spdx_annotation("sca:dependency_type", component.dependency_type),
            spdx_annotation("sca:source_file", component.source_file),
            spdx_annotation("sca:source_count", len(split_sources(component.source_file))),
            spdx_annotation("sca:package_manager", component.package_manager),
            spdx_annotation("sca:risk_status", component.risk_status),
            spdx_annotation("sca:risk_source", component.risk_source),
            spdx_annotation("sca:severity", component.severity),
            spdx_annotation("sca:license_policy", component.license_risk),
            spdx_annotation("sca:vulnerability_ids", ",".join(str(item) for item in component.vulnerability_ids or [])),
            spdx_annotation("sca:osv_checked", component.osv_checked),
            spdx_annotation("sca:osv_error", component.osv_error),
            spdx_annotation("sca:hash_status", HASH_STATUS_NOT_COLLECTED),
        ],
    }
    if component.version:
        package["versionInfo"] = component.version
    purl = package_url(component)
    if purl:
        package["externalRefs"] = [
            {
                "referenceCategory": "PACKAGE-MANAGER",
                "referenceType": "purl",
                "referenceLocator": purl,
            }
        ]
    return package


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


def project_properties(project: ProjectRecord, components: list[ComponentRecord]) -> list[dict[str, str]]:
    edge_summary = dependency_edge_summary(project, components)
    direct_count = sum(1 for component in components if component.dependency_type != "transitive")
    transitive_count = sum(1 for component in components if component.dependency_type == "transitive")
    risky_count = sum(1 for component in components if component.risk_status not in {None, "clean", "not_checked"})
    ecosystems = ",".join(sorted({component.ecosystem for component in components if component.ecosystem}))
    return [
        property_item("project:id", str(project.id)),
        property_item("project:repository_url", project.repository_url),
        property_item("project:source_path", project.source_path),
        property_item("project:business_owner", project.business_owner),
        property_item("project:security_owner", project.security_owner),
        property_item("project:runtime_url", project.runtime_url),
        property_item("project:api_base_url", project.api_base_url),
        property_item("project:default_branch", project.default_branch),
        property_item("project:created_at", project.created_at.isoformat() if project.created_at else None),
        property_item("sca:component_count", len(components)),
        property_item("sca:direct_dependency_count", direct_count),
        property_item("sca:transitive_dependency_count", transitive_count),
        property_item("sca:risky_component_count", risky_count),
        property_item("sca:ecosystems", ecosystems),
        property_item("sca:hash_status", HASH_STATUS_NOT_COLLECTED),
        property_item("sca:dependency_edge_quality", dependency_edge_quality_label(edge_summary)),
        property_item("sca:manifest_direct_edge_count", edge_summary["manifest_direct"]),
        property_item("sca:lockfile_inferred_edge_count", edge_summary["lockfile_inferred"]),
        property_item("sca:dependency_edge_count", edge_summary["total"]),
    ]


def project_ref(project: ProjectRecord) -> str:
    return f"project:{project.id}"


def component_ref(component: ComponentRecord) -> str:
    version = component.version or "unknown"
    return f"{component.ecosystem}:{component.name}@{version}"


def spdx_id(value: str) -> str:
    return "SPDXRef-" + re.sub(r"[^A-Za-z0-9.-]", "-", value).strip("-")


def component_spdx_ref(component: ComponentRecord) -> str:
    return spdx_id(component_ref(component))


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


def normalize_spdx_license(license_value: str | None) -> str:
    if not license_value:
        return "NOASSERTION"
    normalized = license_value.strip()
    if not normalized or normalized.lower() in {"unknown", "none"}:
        return "NOASSERTION"
    if any(char.isspace() for char in normalized) and not any(token in normalized for token in ("AND", "OR", "WITH")):
        return f"LicenseRef-{spdx_id(normalized).removeprefix('SPDXRef-')}"
    return normalized


def spdx_annotation(key: str, value: object | None) -> dict[str, str]:
    return {
        "annotationType": "OTHER",
        "annotator": f"Tool: {SCA_TOOL_VENDOR} {SCA_TOOL_NAME}-{SCA_TOOL_VERSION}",
        "annotationDate": utc_timestamp(),
        "comment": f"{key}={'' if value is None else value}",
    }


def cyclonedx_severity(severity: str | None) -> str:
    if severity in {"critical", "high", "medium", "low", "info"}:
        return severity
    return "unknown"


def property_item(name: str, value: object | None) -> dict[str, str]:
    return {"name": name, "value": "" if value is None else str(value)}


def utc_timestamp() -> str:
    return datetime.utcnow().replace(microsecond=0).isoformat() + "Z"
