from __future__ import annotations

import json
import re
from dataclasses import dataclass, replace
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
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "requirements.txt",
    "poetry.lock",
    "Pipfile.lock",
    "pom.xml",
    "go.mod",
}

DEPENDENCY_TYPE_PRIORITY = {
    "runtime": 0,
    "development": 1,
    "optional": 2,
    "peer": 3,
    "test": 4,
    "transitive": 5,
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
    if file_path.name == "package-lock.json":
        return parse_package_lock(file_path, relative_path)
    if file_path.name == "yarn.lock":
        return parse_yarn_lock(file_path, relative_path)
    if file_path.name == "pnpm-lock.yaml":
        return parse_pnpm_lock(file_path, relative_path)
    if file_path.name == "requirements.txt":
        return parse_requirements_txt(file_path, relative_path)
    if file_path.name == "poetry.lock":
        return parse_poetry_lock(file_path, relative_path)
    if file_path.name == "Pipfile.lock":
        return parse_pipfile_lock(file_path, relative_path)
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


def parse_package_lock(file_path: Path, relative_path: str) -> list[ParsedComponent]:
    data = json.loads(file_path.read_text(encoding="utf-8-sig"))
    components: list[ParsedComponent] = []
    packages = data.get("packages")
    root_dependencies = package_lock_root_dependencies(data)

    if isinstance(packages, dict):
        for package_path, package_data in packages.items():
            if not package_path or not isinstance(package_data, dict):
                continue
            name = package_lock_package_name(str(package_path), package_data)
            if not name:
                continue
            dependency_type = root_dependencies.get(name, "transitive")
            components.append(
                ParsedComponent(
                    ecosystem="npm",
                    name=name,
                    version=normalize_version(str(package_data.get("version") or "")),
                    dependency_type=dependency_type,
                    source_file=relative_path,
                    package_manager="npm",
                    license=package_data.get("license") if isinstance(package_data.get("license"), str) else None,
                )
            )
        return components

    dependencies = data.get("dependencies")
    if isinstance(dependencies, dict):
        for name, dependency_data in dependencies.items():
            if not isinstance(dependency_data, dict):
                continue
            components.append(
                ParsedComponent(
                    ecosystem="npm",
                    name=str(name),
                    version=normalize_version(str(dependency_data.get("version") or "")),
                    dependency_type=root_dependencies.get(str(name), "transitive"),
                    source_file=relative_path,
                    package_manager="npm",
                    license=dependency_data.get("license") if isinstance(dependency_data.get("license"), str) else None,
                )
            )
    return components


def package_lock_root_dependencies(data: dict) -> dict[str, str]:
    root_dependencies: dict[str, str] = {}
    root_package = data.get("packages", {}).get("") if isinstance(data.get("packages"), dict) else None
    if not isinstance(root_package, dict):
        root_package = data
    for section, dependency_type in [
        ("dependencies", "runtime"),
        ("devDependencies", "development"),
        ("optionalDependencies", "optional"),
        ("peerDependencies", "peer"),
    ]:
        dependencies = root_package.get(section, {})
        if not isinstance(dependencies, dict):
            continue
        for name in dependencies:
            root_dependencies[str(name)] = dependency_type
    return root_dependencies


def package_lock_package_name(package_path: str, package_data: dict) -> str | None:
    explicit_name = package_data.get("name")
    if isinstance(explicit_name, str) and explicit_name.strip():
        return explicit_name.strip()
    marker = "node_modules/"
    if marker not in package_path:
        return None
    return package_path.rsplit(marker, 1)[-1].strip() or None


def parse_yarn_lock(file_path: Path, relative_path: str) -> list[ParsedComponent]:
    components: list[ParsedComponent] = []
    current_names: list[str] = []
    current_version: str | None = None
    for raw_line in file_path.read_text(encoding="utf-8-sig").splitlines():
        line = raw_line.rstrip()
        if not line.strip():
            continue
        if not line.startswith((" ", "\t")) and line.endswith(":"):
            if current_names and current_version:
                components.extend(yarn_components(current_names, current_version, relative_path))
            current_names = [yarn_package_name(item) for item in split_yarn_selectors(line[:-1])]
            current_names = [name for name in current_names if name]
            current_version = None
            continue
        version_match = re.match(r"\s+version\s+\"?([^\"\s]+)\"?", line)
        if version_match:
            current_version = version_match.group(1)
    if current_names and current_version:
        components.extend(yarn_components(current_names, current_version, relative_path))
    return components


def split_yarn_selectors(value: str) -> list[str]:
    selectors: list[str] = []
    current = ""
    quote: str | None = None
    for char in value:
        if char in {"'", '"'}:
            quote = None if quote == char else char
            current += char
            continue
        if char == "," and quote is None:
            selectors.append(current.strip().strip("'\""))
            current = ""
            continue
        current += char
    if current.strip():
        selectors.append(current.strip().strip("'\""))
    return selectors


def yarn_package_name(selector: str) -> str | None:
    cleaned = selector.strip().strip("'\"")
    if not cleaned:
        return None
    if cleaned.startswith("@"):
        parts = cleaned.split("@")
        return "@".join(parts[:2]) if len(parts) >= 2 else cleaned
    return cleaned.split("@", 1)[0]


def yarn_components(names: list[str], version: str, relative_path: str) -> list[ParsedComponent]:
    return [
        ParsedComponent(
            ecosystem="npm",
            name=name,
            version=normalize_version(version),
            dependency_type="transitive",
            source_file=relative_path,
            package_manager="yarn",
        )
        for name in sorted(set(names))
    ]


def parse_pnpm_lock(file_path: Path, relative_path: str) -> list[ParsedComponent]:
    lines = file_path.read_text(encoding="utf-8-sig").splitlines()
    direct_dependencies = pnpm_importer_dependencies(lines)
    package_entries = pnpm_package_entries(lines)
    components: list[ParsedComponent] = [
        ParsedComponent(
            ecosystem="npm",
            name=name,
            version=normalize_version(version),
            dependency_type=dependency_type,
            source_file=relative_path,
            package_manager="pnpm",
        )
        for name, (version, dependency_type) in direct_dependencies.items()
    ]
    for name, version in package_entries:
        components.append(
            ParsedComponent(
                ecosystem="npm",
                name=name,
                version=normalize_version(version),
                dependency_type=direct_dependencies.get(name, (None, "transitive"))[1],
                source_file=relative_path,
                package_manager="pnpm",
            )
        )
    return components


def pnpm_importer_dependencies(lines: list[str]) -> dict[str, tuple[str | None, str]]:
    direct: dict[str, tuple[str | None, str]] = {}
    section_type: str | None = None
    in_importers = False
    for raw_line in lines:
        line = raw_line.rstrip()
        stripped = line.strip()
        if stripped == "importers:":
            in_importers = True
            continue
        if in_importers and line and not line.startswith(" ") and stripped != "importers:":
            break
        if not in_importers:
            continue
        if re.match(r"\s{4}(dependencies|optionalDependencies|devDependencies):\s*$", line):
            section = stripped.removesuffix(":")
            section_type = {
                "dependencies": "runtime",
                "optionalDependencies": "optional",
                "devDependencies": "development",
            }.get(section)
            continue
        if section_type and re.match(r"\s{6}[^:\s][^:]*:\s*", line):
            name = stripped.split(":", 1)[0].strip("'\"")
            version = None
            inline_version = re.search(r"version:\s*([^,\s}]+)", stripped)
            if inline_version:
                version = inline_version.group(1).strip("'\"")
            direct[name] = (version, section_type)
    return direct


def pnpm_package_entries(lines: list[str]) -> list[tuple[str, str | None]]:
    entries: list[tuple[str, str | None]] = []
    in_packages = False
    for raw_line in lines:
        line = raw_line.rstrip()
        stripped = line.strip()
        if stripped == "packages:":
            in_packages = True
            continue
        if in_packages and line and not line.startswith(" "):
            break
        if not in_packages:
            continue
        match = re.match(r"\s{2}['\"]?([^'\"]+)['\"]?:\s*$", line)
        if not match:
            continue
        parsed = parse_pnpm_package_key(match.group(1))
        if parsed:
            entries.append(parsed)
    return entries


def parse_pnpm_package_key(key: str) -> tuple[str, str | None] | None:
    cleaned = key.strip().strip("/")
    if not cleaned:
        return None
    cleaned = cleaned.split("(", 1)[0]
    if cleaned.startswith("@"):
        match = re.match(r"(@[^/]+/[^@]+)@(.+)", cleaned)
    else:
        match = re.match(r"([^@/]+)@(.+)", cleaned)
    if match:
        return match.group(1), match.group(2)
    return cleaned, None


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


def parse_poetry_lock(file_path: Path, relative_path: str) -> list[ParsedComponent]:
    components: list[ParsedComponent] = []
    current: dict[str, str] = {}

    for raw_line in file_path.read_text(encoding="utf-8-sig").splitlines():
        line = raw_line.strip()
        if line == "[[package]]":
            append_poetry_package(components, current, relative_path)
            current = {}
            continue
        match = re.match(r"([A-Za-z_][A-Za-z0-9_-]*)\s*=\s*\"(.*)\"", line)
        if match:
            current[match.group(1)] = match.group(2)
    append_poetry_package(components, current, relative_path)
    return components


def append_poetry_package(components: list[ParsedComponent], package: dict[str, str], relative_path: str) -> None:
    name = package.get("name")
    if not name:
        return
    category = package.get("category") or ""
    dependency_type = "development" if category == "dev" else "transitive"
    components.append(
        ParsedComponent(
            ecosystem="pypi",
            name=name,
            version=normalize_version(package.get("version") or ""),
            dependency_type=dependency_type,
            source_file=relative_path,
            package_manager="poetry",
        )
    )


def parse_pipfile_lock(file_path: Path, relative_path: str) -> list[ParsedComponent]:
    data = json.loads(file_path.read_text(encoding="utf-8-sig"))
    components: list[ParsedComponent] = []
    for section, dependency_type in [("default", "transitive"), ("develop", "development")]:
        dependencies = data.get(section, {})
        if not isinstance(dependencies, dict):
            continue
        for name, package_data in dependencies.items():
            if not isinstance(package_data, dict):
                continue
            components.append(
                ParsedComponent(
                    ecosystem="pypi",
                    name=str(name),
                    version=normalize_version(str(package_data.get("version") or "")),
                    dependency_type=dependency_type,
                    source_file=relative_path,
                    package_manager="pipenv",
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


def normalize_version(version: str | None) -> str | None:
    if version is None:
        return None
    cleaned = version.strip()
    return cleaned or None


def dedupe_components(components: list[ParsedComponent]) -> list[ParsedComponent]:
    deduped_by_name: dict[tuple[str, str], ParsedComponent] = {}
    order: list[tuple[str, str]] = []
    for component in components:
        key = (component.ecosystem, component.name.lower())
        existing = deduped_by_name.get(key)
        if existing is None:
            deduped_by_name[key] = component
            order.append(key)
            continue
        deduped_by_name[key] = merge_component(existing, component)
    return [deduped_by_name[key] for key in order]


def merge_component(existing: ParsedComponent, candidate: ParsedComponent) -> ParsedComponent:
    dependency_type = best_dependency_type(existing.dependency_type, candidate.dependency_type)
    version = best_version(existing, candidate, dependency_type)
    source_file = existing.source_file
    if existing.version is None and candidate.version is not None:
        source_file = candidate.source_file
    package_manager = existing.package_manager or candidate.package_manager
    if existing.package_manager and candidate.package_manager and existing.package_manager != candidate.package_manager:
        package_manager = f"{existing.package_manager},{candidate.package_manager}"
    return replace(
        existing,
        version=version,
        dependency_type=dependency_type,
        source_file=source_file,
        package_manager=package_manager,
        license=existing.license or candidate.license,
    )


def best_dependency_type(left: str, right: str) -> str:
    left_priority = DEPENDENCY_TYPE_PRIORITY.get(left, 10)
    right_priority = DEPENDENCY_TYPE_PRIORITY.get(right, 10)
    return left if left_priority <= right_priority else right


def best_version(existing: ParsedComponent, candidate: ParsedComponent, dependency_type: str) -> str | None:
    if candidate.version is None:
        return existing.version
    if existing.version is None:
        return candidate.version
    if dependency_type != "transitive" and looks_like_range(existing.version) and not looks_like_range(candidate.version):
        return candidate.version
    return existing.version


def looks_like_range(version: str) -> bool:
    return bool(re.search(r"[\^~<>=*xX|]", version))



