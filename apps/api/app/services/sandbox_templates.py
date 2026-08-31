from __future__ import annotations

import json
import re
from pathlib import Path

from app.models import SandboxCommandTemplate


def discover_sandbox_templates(source_path: str | None) -> list[SandboxCommandTemplate]:
    if not source_path:
        return []
    root = Path(source_path).expanduser().resolve()
    if not root.exists() or not root.is_dir():
        return []

    templates: list[SandboxCommandTemplate] = []
    templates.extend(discover_node_templates(root))
    templates.extend(discover_python_templates(root))
    templates.extend(discover_go_templates(root))
    templates.extend(discover_maven_templates(root))
    templates.extend(discover_docker_templates(root))
    runtime_port = discover_runtime_port(root)
    return [
        template.model_copy(update={"container_port": runtime_port})
        if template.command_type == "start" else template
        for template in dedupe_templates(templates)
    ]


def discover_runtime_port(root: Path) -> int | None:
    """Infer a declared application port from common source configuration files."""
    candidates = [
        root / "Dockerfile", root / "docker-compose.yml", root / "docker-compose.yaml",
        root / ".env", root / ".env.example", root / "package.json",
        *_discover_node_entrypoints(root),
        root / "app.py", root / "main.py",
    ]
    patterns = [
        r"(?im)^\s*EXPOSE\s+(\d{2,5})\b",
        r"(?i)(?:process\.env\.)?PORT\s*\|\|\s*['\"]?(\d{2,5})",
        r"(?im)^\s*(?:APP_PORT|SERVER_PORT|PORT)\s*[:=]\s*['\"]?(\d{2,5})",
        r"(?i)listen\s*\(\s*(\d{2,5})",
        r"(?i)--port(?:=|\s+)(\d{2,5})",
    ]
    for path in dict.fromkeys(candidates):
        if not path.is_file():
            continue
        try:
            content = path.read_text(encoding="utf-8-sig", errors="ignore")[:200_000]
        except OSError:
            continue
        for pattern in patterns:
            match = re.search(pattern, content)
            if match and 1 <= int(match.group(1)) <= 65535:
                return int(match.group(1))
    return None


def _discover_node_entrypoints(root: Path) -> list[Path]:
    """Return safe Node.js entrypoints declared by the package or common layouts."""
    relative_paths: list[str] = []
    package_json = root / "package.json"
    if package_json.is_file():
        try:
            package = json.loads(package_json.read_text(encoding="utf-8-sig"))
        except (OSError, json.JSONDecodeError):
            package = {}
        for key in ("main", "module"):
            value = package.get(key)
            if isinstance(value, str):
                relative_paths.append(value)
        scripts = package.get("scripts") if isinstance(package.get("scripts"), dict) else {}
        entry_pattern = re.compile(
            r"(?i)(?:node|nodemon|tsx|ts-node(?:-dev)?)"
            r"(?:\s+--[^\s]+)*\s+['\"]?([^'\"\s;&|]+\.(?:[cm]?js|tsx?))"
        )
        for script in scripts.values():
            if not isinstance(script, str):
                continue
            match = entry_pattern.search(script)
            if match:
                relative_paths.append(match.group(1))

    relative_paths.extend([
        "server.js", "app.js", "index.js", "main.js",
        "server.mjs", "app.mjs", "index.mjs", "main.mjs",
        "server.cjs", "app.cjs", "index.cjs", "main.cjs",
        "src/server.js", "src/app.js", "src/index.js", "src/main.js",
        "src/server.ts", "src/app.ts", "src/index.ts", "src/main.ts",
        "server/index.js", "config/server.js",
    ])
    resolved_root = root.resolve()
    result: list[Path] = []
    for value in relative_paths:
        candidate = (resolved_root / value).resolve()
        if candidate != resolved_root and resolved_root in candidate.parents:
            result.append(candidate)
    return result


def discover_node_templates(root: Path) -> list[SandboxCommandTemplate]:
    package_json = root / "package.json"
    if not package_json.exists():
        return []
    try:
        data = json.loads(package_json.read_text(encoding="utf-8-sig"))
    except (OSError, json.JSONDecodeError):
        return []
    scripts = data.get("scripts") if isinstance(data.get("scripts"), dict) else {}
    templates: list[SandboxCommandTemplate] = []
    for script, command_type, risk_level in [
        ("test", "test", "low"),
        ("start", "start", "medium"),
        ("dev", "start", "medium"),
        ("build", "build", "low"),
    ]:
        if script in scripts:
            templates.append(
                SandboxCommandTemplate(
                    name=f"npm {script}",
                    command=f"npm run {script}" if script not in {"start", "test"} else f"npm {script}",
                    command_type=command_type,
                    image="node:20-alpine",
                    risk_level=risk_level,
                    description=f"Run package.json script '{script}' inside a read-only Node container.",
                )
            )
    return templates


def discover_python_templates(root: Path) -> list[SandboxCommandTemplate]:
    has_python = any((root / name).exists() for name in ["requirements.txt", "pyproject.toml", "setup.py"])
    py_files = {path.name for path in root.glob("*.py")}
    if not has_python and not py_files:
        return []
    templates: list[SandboxCommandTemplate] = []
    fastapi_entry = root / "app" / "main.py"
    if fastapi_entry.is_file():
        try:
            content = fastapi_entry.read_text(encoding="utf-8-sig", errors="replace")[:50_000]
        except OSError:
            content = ""
        if "FastAPI(" in content:
            templates.append(python_template("uvicorn app.main:app --host 0.0.0.0 --port 8000", "start", "medium", "Run the detected FastAPI application on the sandbox interface."))
    if "app.py" in py_files:
        templates.append(python_template("python app.py", "start", "medium", "Run app.py inside an isolated Python container."))
    if "main.py" in py_files:
        templates.append(python_template("python main.py", "start", "medium", "Run main.py inside an isolated Python container."))
    if (root / "tests").exists() or (root / "pytest.ini").exists() or (root / "pyproject.toml").exists():
        templates.append(python_template("python -m pytest", "test", "low", "Run pytest inside an isolated Python container."))
    templates.append(python_template("python --version", "inspect", "low", "Inspect Python runtime inside the sandbox."))
    return templates


def python_template(command: str, command_type: str, risk_level: str, description: str) -> SandboxCommandTemplate:
    return SandboxCommandTemplate(
        name=command,
        command=command,
        command_type=command_type,
        image="python:3.12-slim",
        risk_level=risk_level,
        description=description,
    )


def discover_go_templates(root: Path) -> list[SandboxCommandTemplate]:
    if not (root / "go.mod").exists():
        return []
    return [
        SandboxCommandTemplate(
            name="go test",
            command="go test ./...",
            command_type="test",
            image="golang:1.22-alpine",
            risk_level="low",
            description="Run Go tests inside an isolated Go container.",
        ),
        SandboxCommandTemplate(
            name="go run",
            command="go run .",
            command_type="start",
            image="golang:1.22-alpine",
            risk_level="medium",
            description="Run the Go application entrypoint inside an isolated Go container.",
        ),
    ]


def discover_maven_templates(root: Path) -> list[SandboxCommandTemplate]:
    if not (root / "pom.xml").exists():
        return []
    return [
        SandboxCommandTemplate(
            name="mvn test",
            command="mvn test",
            command_type="test",
            image="maven:3.9-eclipse-temurin-21",
            risk_level="low",
            description="Run Maven tests inside an isolated Maven container.",
        )
    ]


def discover_docker_templates(root: Path) -> list[SandboxCommandTemplate]:
    if not (root / "Dockerfile").exists():
        return []
    return [
        SandboxCommandTemplate(
            name="dockerfile inspect",
            command="ls -la /workspace && sed -n '1,120p' Dockerfile",
            command_type="inspect",
            image="alpine:3.20",
            risk_level="low",
            description="Inspect Dockerfile content inside a read-only Alpine container.",
        )
    ]


def dedupe_templates(templates: list[SandboxCommandTemplate]) -> list[SandboxCommandTemplate]:
    seen: set[tuple[str, str, str]] = set()
    deduped: list[SandboxCommandTemplate] = []
    for template in templates:
        key = (template.command, template.image, template.command_type)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(template)
    return deduped
