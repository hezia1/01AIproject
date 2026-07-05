from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from xml.etree import ElementTree


@dataclass(frozen=True)
class ParsedComponent:
    ecosystem: str
    name: str
    version: str | None
    dependency_type: str
    source_file: str
    package_manager: str | None
    license: str | None = None
    risk_status: str = "not_checked"
    vulnerability_ids: list[str] | None = None
    severity: str | None = None
    risk_summary: str | None = None
    remediation: str | None = None
    license_risk: str | None = None
    risk_source: str | None = None
    osv_checked: bool = False
    osv_error: str | None = None


@dataclass(frozen=True)
class ScaParseOutput:
    components: list[ParsedComponent]
    scanned_files: list[str]


DEPENDENCY_FILE_NAMES = {
    "package.json",
    "requirements.txt",
    "pom.xml",
    "go.mod",
}


def parse_dependency_tree(source_path: str) -> ScaParseOutput:
    root = Path(source_path).expanduser().resolve()
    if not root.exists() or not root.is_dir():
        raise ValueError("source_path must be an existing directory")

    components: list[ParsedComponent] = []
    scanned_files: list[str] = []

    for file_path in iter_dependency_files(root):
        relative_path = file_path.relative_to(root).as_posix()
        parsed = parse_dependency_file(file_path, relative_path)
        if parsed:
            scanned_files.append(relative_path)
            components.extend(parsed)

    return ScaParseOutput(components=dedupe_components(components), scanned_files=scanned_files)


def iter_dependency_files(root: Path):
    ignored_dirs = {".git", "node_modules", ".venv", "venv", "dist", "build", "target"}
    for path in root.rglob("*"):
        if not path.is_file() or path.name not in DEPENDENCY_FILE_NAMES:
            continue
        if any(part in ignored_dirs for part in path.parts):
            continue
        yield path


def parse_dependency_file(file_path: Path, relative_path: str) -> list[ParsedComponent]:
    if file_path.name == "package.json":
        return parse_package_json(file_path, relative_path)
    if file_path.name == "requirements.txt":
        return parse_requirements_txt(file_path, relative_path)
    if file_path.name == "pom.xml":
        return parse_pom_xml(file_path, relative_path)
    if file_path.name == "go.mod":
        return parse_go_mod(file_path, relative_path)
    return []


def parse_package_json(file_path: Path, relative_path: str) -> list[ParsedComponent]:
    data = json.loads(file_path.read_text(encoding="utf-8-sig"))
    components: list[ParsedComponent] = []
    sections = {
        "dependencies": "runtime",
        "devDependencies": "development",
        "peerDependencies": "peer",
        "optionalDependencies": "optional",
    }
    for section, dependency_type in sections.items():
        dependencies = data.get(section, {})
        if not isinstance(dependencies, dict):
            continue
        for name, version in dependencies.items():
            components.append(
                ParsedComponent(
                    ecosystem="npm",
                    name=str(name),
                    version=normalize_version(str(version)),
                    dependency_type=dependency_type,
                    source_file=relative_path,
                    package_manager="npm",
                    license=data.get("license") if isinstance(data.get("license"), str) else None,
                )
            )
    return components


def parse_requirements_txt(file_path: Path, relative_path: str) -> list[ParsedComponent]:
    components: list[ParsedComponent] = []
    for raw_line in file_path.read_text(encoding="utf-8-sig").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        line = line.split("#", 1)[0].strip()
        match = re.match(r"^([A-Za-z0-9_.-]+)\s*([=<>!~]{1,2})?\s*([^;\s]+)?", line)
        if not match:
            continue
        name, operator, version = match.groups()
        components.append(
            ParsedComponent(
                ecosystem="pypi",
                name=name,
                version=f"{operator or ''}{version or ''}" or None,
                dependency_type="runtime",
                source_file=relative_path,
                package_manager="pip",
            )
        )
    return components


def parse_pom_xml(file_path: Path, relative_path: str) -> list[ParsedComponent]:
    tree = ElementTree.parse(file_path)
    root = tree.getroot()
    namespace = ""
    if root.tag.startswith("{"):
        namespace = root.tag.split("}", 1)[0] + "}"

    properties = extract_maven_properties(root, namespace)
    components: list[ParsedComponent] = []
    for dependency in root.findall(f".//{namespace}dependency"):
        group_id = get_child_text(dependency, namespace, "groupId")
        artifact_id = get_child_text(dependency, namespace, "artifactId")
        version = get_child_text(dependency, namespace, "version")
        scope = get_child_text(dependency, namespace, "scope") or "runtime"
        if not group_id or not artifact_id:
            continue
        components.append(
            ParsedComponent(
                ecosystem="maven",
                name=f"{group_id}:{artifact_id}",
                version=resolve_maven_property(version, properties),
                dependency_type=scope,
                source_file=relative_path,
                package_manager="maven",
            )
        )
    return components


def extract_maven_properties(root: ElementTree.Element, namespace: str) -> dict[str, str]:
    properties: dict[str, str] = {}
    properties_node = root.find(f"{namespace}properties")
    if properties_node is None:
        return properties
    for child in list(properties_node):
        key = child.tag.split("}", 1)[-1]
        if child.text:
            properties[key] = child.text.strip()
    return properties


def get_child_text(node: ElementTree.Element, namespace: str, name: str) -> str | None:
    child = node.find(f"{namespace}{name}")
    if child is None or child.text is None:
        return None
    return child.text.strip()


def resolve_maven_property(version: str | None, properties: dict[str, str]) -> str | None:
    if not version:
        return None
    match = re.fullmatch(r"\$\{(.+)}", version)
    if not match:
        return version
    return properties.get(match.group(1), version)


def parse_go_mod(file_path: Path, relative_path: str) -> list[ParsedComponent]:
    components: list[ParsedComponent] = []
    in_require_block = False
    for raw_line in file_path.read_text(encoding="utf-8-sig").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("//"):
            continue
        if line == "require (":
            in_require_block = True
            continue
        if in_require_block and line == ")":
            in_require_block = False
            continue
        if line.startswith("require "):
            line = line.removeprefix("require ").strip()
        elif not in_require_block:
            continue
        line = line.split("//", 1)[0].strip()
        parts = line.split()
        if len(parts) < 2:
            continue
        components.append(
            ParsedComponent(
                ecosystem="go",
                name=parts[0],
                version=parts[1],
                dependency_type="runtime",
                source_file=relative_path,
                package_manager="go modules",
            )
        )
    return components


def normalize_version(version: str) -> str | None:
    cleaned = version.strip()
    return cleaned or None


def dedupe_components(components: list[ParsedComponent]) -> list[ParsedComponent]:
    seen: set[tuple[str, str, str | None, str, str]] = set()
    deduped: list[ParsedComponent] = []
    for component in components:
        key = (
            component.ecosystem,
            component.name.lower(),
            component.version,
            component.dependency_type,
            component.source_file,
        )
        if key in seen:
            continue
        seen.add(key)
        deduped.append(component)
    return deduped



