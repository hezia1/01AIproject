from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

from app.db_models import ComponentRecord, ProjectRecord
from app.services.sca_sbom import component_ref, project_ref


NPM_TREE_TIMEOUT_SECONDS = 45
NATIVE_TREE_TIMEOUT_SECONDS = 60


def build_native_dependency_edge_records(project: ProjectRecord, components: list[ComponentRecord]) -> list[dict[str, str]]:
    if not project.source_path:
        return []
    root = Path(project.source_path).expanduser().resolve()
    if not root.exists() or not root.is_dir():
        return []

    edges: list[dict[str, str]] = []
    edges.extend(build_npm_dependency_edges(project, root, components))
    edges.extend(build_maven_dependency_edges(project, root, components))
    edges.extend(build_go_dependency_edges(project, root, components))
    return dedupe_edges(edges)


def build_npm_dependency_edges(project: ProjectRecord, root: Path, components: list[ComponentRecord]) -> list[dict[str, str]]:
    if shutil.which("npm") is None or not (root / "package.json").exists():
        return []

    payload = run_npm_ls(root)
    if not isinstance(payload, dict):
        return []

    refs = component_refs_by_name_version(components, "npm")
    edges: list[dict[str, str]] = []
    project_node = project_ref(project)
    for child_name, child_data in dependency_items(payload):
        child_ref = resolve_component_ref(refs, child_name, child_data)
        if child_ref is None:
            continue
        edges.append({"source": project_node, "target": child_ref, "quality": "native_tree"})
        collect_npm_child_edges(child_ref, child_data, refs, edges)
    return edges


def run_npm_ls(root: Path) -> dict | None:
    try:
        completed = subprocess.run(
            ["npm", "ls", "--json", "--all"],
            cwd=str(root),
            shell=False,
            capture_output=True,
            text=True,
            timeout=NPM_TREE_TIMEOUT_SECONDS,
            encoding="utf-8",
            errors="replace",
        )
    except (OSError, subprocess.TimeoutExpired):
        return None

    payload_text = completed.stdout.strip() or completed.stderr.strip()
    if not payload_text:
        return None
    try:
        payload = json.loads(payload_text)
    except json.JSONDecodeError:
        return None
    return payload if isinstance(payload, dict) else None


def build_maven_dependency_edges(project: ProjectRecord, root: Path, components: list[ComponentRecord]) -> list[dict[str, str]]:
    if shutil.which("mvn") is None or not (root / "pom.xml").exists():
        return []
    completed = run_native_command(["mvn", "-q", "dependency:tree", "-Dverbose"], root)
    if completed is None:
        return []
    refs = component_refs_by_name_version(components, "maven")
    edges: list[dict[str, str]] = []
    stack: list[tuple[int, str]] = []
    for raw_line in completed.stdout.splitlines():
        line = raw_line.strip()
        if not line or ":" not in line:
            continue
        marker = raw_line.find("+-")
        if marker < 0:
            marker = raw_line.find("\\-")
        if marker < 0:
            continue
        coordinate = raw_line[marker + 2:].strip().split(" ", 1)[0]
        parts = coordinate.split(":")
        if len(parts) < 4:
            continue
        name, version = f"{parts[0]}:{parts[1]}", parts[-2]
        ref = refs.get((name.lower(), version)) or refs.get((name.lower(), None))
        if ref is None:
            continue
        level = max(0, marker // 3)
        while stack and stack[-1][0] >= level:
            stack.pop()
        parent = stack[-1][1] if stack else project_ref(project)
        edges.append({"source": parent, "target": ref, "quality": "maven_native_tree"})
        stack.append((level, ref))
    return edges


def build_go_dependency_edges(project: ProjectRecord, root: Path, components: list[ComponentRecord]) -> list[dict[str, str]]:
    if shutil.which("go") is None or not (root / "go.mod").exists():
        return []
    completed = run_native_command(["go", "mod", "graph"], root)
    if completed is None:
        return []
    refs = component_refs_by_name_version(components, "go")
    edges: list[dict[str, str]] = []
    for line in completed.stdout.splitlines():
        parts = line.strip().split()
        if len(parts) != 2:
            continue
        parent_name, parent_version = split_go_coordinate(parts[0])
        child_name, child_version = split_go_coordinate(parts[1])
        child = refs.get((child_name.lower(), child_version)) or refs.get((child_name.lower(), None))
        if child is None:
            continue
        parent = refs.get((parent_name.lower(), parent_version)) or refs.get((parent_name.lower(), None)) or project_ref(project)
        if parent != child:
            edges.append({"source": parent, "target": child, "quality": "go_native_tree"})
    return edges


def split_go_coordinate(value: str) -> tuple[str, str | None]:
    name, separator, version = value.rpartition("@")
    return (name, version) if separator else (value, None)


def run_native_command(command: list[str], root: Path) -> subprocess.CompletedProcess[str] | None:
    try:
        completed = subprocess.run(command, cwd=str(root), shell=False, capture_output=True, text=True, timeout=NATIVE_TREE_TIMEOUT_SECONDS, encoding="utf-8", errors="replace")
    except (OSError, subprocess.TimeoutExpired):
        return None
    return completed if completed.returncode == 0 else None


def collect_npm_child_edges(
    parent_ref: str,
    node: dict,
    refs: dict[tuple[str, str | None], str | None],
    edges: list[dict[str, str]],
) -> None:
    for child_name, child_data in dependency_items(node):
        child_ref = resolve_component_ref(refs, child_name, child_data)
        if child_ref is None or child_ref == parent_ref:
            continue
        edges.append({"source": parent_ref, "target": child_ref, "quality": "native_tree"})
        collect_npm_child_edges(child_ref, child_data, refs, edges)


def dependency_items(node: dict):
    dependencies = node.get("dependencies")
    if not isinstance(dependencies, dict):
        return []
    return [(str(name), data) for name, data in dependencies.items() if isinstance(data, dict)]


def component_refs_by_name_version(components: list[ComponentRecord], ecosystem: str) -> dict[tuple[str, str | None], str | None]:
    refs: dict[tuple[str, str | None], str | None] = {}
    name_counts: dict[str, int] = {}
    for component in components:
        if component.ecosystem != ecosystem:
            continue
        normalized_name = component.name.lower()
        refs[(normalized_name, component.version)] = component_ref(component)
        name_counts[normalized_name] = name_counts.get(normalized_name, 0) + 1

    for component in components:
        if component.ecosystem != ecosystem:
            continue
        normalized_name = component.name.lower()
        refs[(normalized_name, None)] = component_ref(component) if name_counts[normalized_name] == 1 else None
    return refs


def resolve_component_ref(refs: dict[tuple[str, str | None], str | None], name: str, node: dict) -> str | None:
    normalized_name = name.lower()
    version = node.get("version")
    if isinstance(version, str) and version:
        exact = refs.get((normalized_name, version))
        if exact:
            return exact
    return refs.get((normalized_name, None))


def dedupe_edges(edges: list[dict[str, str]]) -> list[dict[str, str]]:
    deduped: dict[tuple[str, str], dict[str, str]] = {}
    for edge in edges:
        deduped[(edge["source"], edge["target"])] = edge
    return sorted(deduped.values(), key=lambda edge: (edge["source"], edge["target"]))
