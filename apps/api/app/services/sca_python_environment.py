from __future__ import annotations

import json
import os
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path

from app.db_models import ComponentRecord, ProjectRecord
from app.services.sca_parser import ParsedComponent
from app.services.sca_sbom import component_ref, project_ref


PIP_INSPECT_TIMEOUT_SECONDS = 20
PACKAGE_NAME_PATTERN = re.compile(r"\s*([A-Za-z0-9][A-Za-z0-9_.-]*)")
PIP_METADATA_FALLBACK_SCRIPT = (
    "import json,sys;"
    "from pip._internal.metadata import get_environment;"
    "from pip._internal.utils.compat import stdlib_pkgs;"
    "dists=get_environment(None).iter_installed_distributions(local_only=True,skip=set(stdlib_pkgs));"
    "out={'installed':[{'metadata':dist.metadata_dict,'requested':bool(dist.requested) if dist.installed_with_dist_info else False} for dist in dists]};"
    "json.dump(out,sys.stdout,ensure_ascii=False)"
)


@dataclass(frozen=True)
class PythonEnvironmentInspection:
    components: list[ParsedComponent]
    requirements_by_package: dict[str, list[str]]
    requested_packages: set[str]
    interpreter: str | None = None
    error: str | None = None

    @property
    def available(self) -> bool:
        return self.interpreter is not None and self.error is None


def inspect_python_environment(source_path: str) -> PythonEnvironmentInspection:
    root = Path(source_path).expanduser().resolve()
    interpreter = find_project_python(root)
    if interpreter is None:
        return PythonEnvironmentInspection([], {}, set(), error="未找到项目内 Python 虚拟环境")

    payload = run_pip_inspect(interpreter, root)
    if payload is None:
        return PythonEnvironmentInspection([], {}, set(), interpreter=str(interpreter), error="pip inspect 未返回可用的 JSON 元数据")
    return parse_pip_inspect_payload(payload, root, interpreter)


def find_project_python(root: Path) -> Path | None:
    candidates = [
        root / ".venv" / "Scripts" / "python.exe",
        root / "venv" / "Scripts" / "python.exe",
        root / ".venv" / "bin" / "python",
        root / "venv" / "bin" / "python",
    ]
    return next((candidate for candidate in candidates if candidate.is_file()), None)


def run_pip_inspect(interpreter: Path, root: Path) -> dict[str, object] | None:
    environment = {**os.environ, "PYTHONIOENCODING": "utf-8", "PYTHONUTF8": "1", "NO_COLOR": "1"}
    try:
        completed = subprocess.run(
            [str(interpreter), "-I", "-X", "utf8", "-m", "pip", "inspect", "--local"],
            cwd=str(root),
            shell=False,
            capture_output=True,
            text=True,
            timeout=PIP_INSPECT_TIMEOUT_SECONDS,
            encoding="utf-8",
            errors="replace",
            env=environment,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if payload := json_payload(completed.stdout):
        return payload
    return run_pip_metadata_fallback(interpreter, root, environment)


def run_pip_metadata_fallback(interpreter: Path, root: Path, environment: dict[str, str]) -> dict[str, object] | None:
    """Avoid Windows console rendering failures in some pip releases while reading pip's own metadata."""
    try:
        completed = subprocess.run(
            [str(interpreter), "-I", "-X", "utf8", "-c", PIP_METADATA_FALLBACK_SCRIPT],
            cwd=str(root),
            shell=False,
            capture_output=True,
            text=True,
            timeout=PIP_INSPECT_TIMEOUT_SECONDS,
            encoding="utf-8",
            errors="replace",
            env=environment,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    return json_payload(completed.stdout)


def json_payload(value: str) -> dict[str, object] | None:
    if not value.strip():
        return None
    try:
        payload = json.loads(value)
    except json.JSONDecodeError:
        return None
    return payload if isinstance(payload, dict) else None


def parse_pip_inspect_payload(
    payload: dict[str, object],
    root: Path,
    interpreter: Path,
) -> PythonEnvironmentInspection:
    installed = payload.get("installed")
    if not isinstance(installed, list):
        return PythonEnvironmentInspection([], {}, set(), interpreter=str(interpreter), error="pip inspect 缺少 installed 列表")

    source_file = environment_source_file(root, interpreter)
    components: list[ParsedComponent] = []
    requirements_by_package: dict[str, list[str]] = {}
    requested_packages: set[str] = set()
    for item in installed:
        if not isinstance(item, dict):
            continue
        metadata = item.get("metadata")
        if not isinstance(metadata, dict):
            continue
        name = metadata.get("name")
        version = metadata.get("version")
        if not isinstance(name, str) or not name.strip():
            continue
        normalized_name = normalize_package_name(name)
        requested = item.get("requested") is True
        if requested:
            requested_packages.add(normalized_name)
        requirements_by_package[normalized_name] = dependency_names(metadata.get("requires_dist"))
        components.append(
            ParsedComponent(
                ecosystem="PyPI",
                name=name,
                version=version.strip() if isinstance(version, str) and version.strip() else None,
                dependency_type="runtime" if requested else "transitive",
                source_file=source_file,
                package_manager="pip",
            )
        )
    return PythonEnvironmentInspection(
        components=components,
        requirements_by_package=requirements_by_package,
        requested_packages=requested_packages,
        interpreter=str(interpreter),
    )


def build_python_environment_dependency_edges(
    project: ProjectRecord,
    components: list[ComponentRecord],
) -> list[dict[str, str]]:
    if not project.source_path:
        return []
    inspection = inspect_python_environment(project.source_path)
    return build_python_environment_edges_from_inspection(project, components, inspection)


def build_python_environment_edges_from_inspection(
    project: ProjectRecord,
    components: list[ComponentRecord],
    inspection: PythonEnvironmentInspection,
) -> list[dict[str, str]]:
    if not inspection.available:
        return []

    refs = component_refs_by_normalized_name(components)
    edges: list[dict[str, str]] = []
    project_node = project_ref(project)
    for package_name in inspection.requested_packages:
        target = refs.get(package_name)
        if target:
            edges.append({"source": project_node, "target": target, "quality": "python_environment"})
    for parent_name, dependency_names in inspection.requirements_by_package.items():
        parent = refs.get(parent_name)
        if parent is None:
            continue
        for dependency_name in dependency_names:
            child = refs.get(dependency_name)
            if child and child != parent:
                edges.append({"source": parent, "target": child, "quality": "python_environment"})
    return dedupe_edges(edges)


def environment_metadata(inspection: PythonEnvironmentInspection) -> dict[str, object]:
    return {
        "status": "available" if inspection.available else "unavailable",
        "interpreter": inspection.interpreter,
        "component_count": len(inspection.components),
        "requested_component_count": len(inspection.requested_packages),
        "error": inspection.error,
    }


def dependency_names(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    names: list[str] = []
    for item in value:
        if not isinstance(item, str) or "extra ==" in item:
            continue
        match = PACKAGE_NAME_PATTERN.match(item)
        if match:
            names.append(normalize_package_name(match.group(1)))
    return list(dict.fromkeys(names))


def component_refs_by_normalized_name(components: list[ComponentRecord]) -> dict[str, str | None]:
    refs: dict[str, str | None] = {}
    ambiguous: set[str] = set()
    for component in components:
        if component.ecosystem != "PyPI":
            continue
        name = normalize_package_name(component.name)
        if name in ambiguous:
            continue
        existing = refs.get(name)
        ref = component_ref(component)
        if existing is None:
            refs[name] = ref
        elif existing != ref:
            refs[name] = None
            ambiguous.add(name)
    return refs


def environment_source_file(root: Path, interpreter: Path) -> str:
    try:
        return f"{interpreter.parent.parent.relative_to(root).as_posix()}/pip inspect"
    except ValueError:
        return "Python environment / pip inspect"


def normalize_package_name(value: str) -> str:
    return re.sub(r"[-_.]+", "-", value).lower()


def dedupe_edges(edges: list[dict[str, str]]) -> list[dict[str, str]]:
    deduped = {(edge["source"], edge["target"]): edge for edge in edges}
    return sorted(deduped.values(), key=lambda edge: (edge["source"], edge["target"]))
