from __future__ import annotations

import json
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
    return dedupe_templates(templates)


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
