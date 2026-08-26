"""Deterministic-first, DeepSeek-assisted project launch planning.

The model sees a bounded, redacted source summary and returns structured
suggestions only.  Every executable candidate is independently allowlisted;
the model never runs a command or authorizes an image pull.
"""
from __future__ import annotations

import json
from pathlib import Path
import re
from typing import Any

import yaml

from app.services.dast_deepseek import dast_deepseek_settings
from app.services.deepseek_client import DeepSeekClient, DeepSeekUnavailable
from app.services.sandbox_templates import discover_sandbox_templates


APPROVED_IMAGE = re.compile(r"^(?:node|python|golang|maven|gradle|eclipse-temurin|php|ruby|rust|alpine|postgres|redis)(?::[A-Za-z0-9_.-]+|@sha256:[a-f0-9]{64})$")
SAFE_COMMAND = re.compile(r"^(?:npm (?:start|run [A-Za-z0-9_.:-]+)|node [A-Za-z0-9_./-]+|python(?: -m)? [A-Za-z0-9_./:-]+(?: --[A-Za-z0-9_-]+(?: [A-Za-z0-9_./:-]+)?)*|uvicorn [A-Za-z0-9_.:-]+(?: --[A-Za-z0-9_-]+(?: [A-Za-z0-9_./:-]+)?)*|gunicorn [A-Za-z0-9_.:-]+(?: --[A-Za-z0-9_-]+(?: [A-Za-z0-9_./:-]+)?)*|go run [A-Za-z0-9_./-]+|mvn spring-boot:run|java -jar [A-Za-z0-9_./*-]+)$")
CONTEXT_FILES = (
    "package.json", "package-lock.json", "requirements.txt", "pyproject.toml", "Pipfile",
    "pom.xml", "build.gradle", "build.gradle.kts", "go.mod", "Dockerfile",
    "docker-compose.yml", "docker-compose.yaml", "Procfile", ".env.example", "README.md", "README.rst",
)
SECRET = re.compile(r"(?i)((?:password|passwd|secret|token|api[_-]?key|authorization)\s*[:=]\s*)[^\s,'\"]+")


def approved_runtime_image(image: str) -> bool:
    return bool(APPROVED_IMAGE.fullmatch(image.strip()))


def safe_start_command(command: str) -> bool:
    value = " ".join(command.strip().split())
    return bool(value and SAFE_COMMAND.fullmatch(value))


def build_launch_plan(project: Any, *, use_ai: bool = True) -> dict[str, object]:
    root = Path(str(getattr(project, "source_path", "") or "")).expanduser()
    if not root.is_dir():
        return _empty("项目源码目录不存在，无法生成启动方案。")
    support_services = _discover_support_services(root)
    deterministic: list[dict[str, object]] = []
    candidate_roots = [root]
    apps_dir = root / "apps"
    if apps_dir.is_dir():
        candidate_roots.extend(path for path in apps_dir.iterdir() if path.is_dir())
    for service_root in candidate_roots[:12]:
        relative = "." if service_root == root else service_root.relative_to(root).as_posix()
        for item in discover_sandbox_templates(str(service_root)):
            if item.command_type != "start":
                continue
            deterministic.append({
                "name": item.name if relative == "." else f"{relative}: {item.name}",
                "image": item.image, "command": item.command,
                "container_port": item.container_port or 8000, "health_path": "/",
                "source": "deterministic", "source_subdir": relative,
                "confidence": 90 if item.container_port else 72, "rationale": item.description,
                "approved": approved_runtime_image(item.image) and safe_start_command(item.command),
                "services": support_services,
            })
    configured = None
    if getattr(project, "sandbox_image", None) and getattr(project, "sandbox_command", None):
        configured = {
            "name": "项目已保存运行方案", "image": str(project.sandbox_image), "command": str(project.sandbox_command),
            "container_port": deterministic[0]["container_port"] if deterministic else 8000, "health_path": "/",
            "source": "project_config", "confidence": 100, "rationale": "该方案已保存在当前项目资产中。", "approved": True,
            "services": support_services,
            "source_subdir": ".",
        }
    candidates = ([configured] if configured else []) + deterministic
    ai = {"status": "not_requested", "configured": False, "model": None, "rationale": None, "missing_services": [], "environment_variables": []}
    if use_ai:
        try:
            settings = dast_deepseek_settings()
            ai["configured"] = settings.configured
            if not settings.configured:
                raise DeepSeekUnavailable("未配置 DAST_DEEPSEEK_API_KEY")
            result = _ask_deepseek(root, candidates, settings)
            ai.update({"status": "completed", "model": result["model"], "rationale": result["rationale"], "missing_services": result["missing_services"], "environment_variables": result["environment_variables"]})
            proposed = result.get("proposed_candidate")
            if isinstance(proposed, dict):
                validated = _validated_ai_candidate(proposed)
                if validated:
                    validated["services"] = support_services
                if validated and not any(item["image"] == validated["image"] and item["command"] == validated["command"] for item in candidates):
                    candidates.append(validated)
            preferred = int(result.get("recommended_index") or 0)
            if 0 <= preferred < len(candidates):
                candidates.insert(0, candidates.pop(preferred))
        except (DeepSeekUnavailable, TypeError, ValueError) as exc:
            ai.update({"status": "unavailable", "rationale": str(exc)[:500]})
    approved = [item for item in candidates if item.get("approved")]
    return {
        "schema": "ai-security-platform.sandbox-launch-plan/v1",
        "project_id": str(project.id),
        "status": "ready" if approved else "needs_adapter",
        "recommended": approved[0] if approved else None,
        "candidates": candidates,
        "ai": ai,
        "source_summary": {"root": str(root.resolve()), "evidence_files": [name for name in CONTEXT_FILES if (root / name).is_file()]},
        "orchestration": {"mode": "multi_service" if support_services else "single_service", "support_services": support_services},
        "message": "已生成可执行启动方案。" if approved else "没有通过安全校验的启动候选；需要专用运行适配器。",
    }


def _ask_deepseek(root: Path, candidates: list[dict[str, object]], settings: Any) -> dict[str, object]:
    system = (
        "You are a launch-plan analyst for an isolated application-security sandbox. Return strict JSON only. "
        "Rank supplied candidates. If none exist, you may propose exactly one conventional web start candidate. "
        "Never include secrets, shell metacharacters, package installation, curl/wget, privilege changes, filesystem deletion, or network targets. "
        "Images must be official node/python/golang/maven/gradle/eclipse-temurin/php/ruby/rust/alpine tags. Do not claim execution succeeded."
    )
    payload = {
        "source_evidence": _source_context(root),
        "deterministic_candidates": candidates,
        "required_output": {
            "recommended_index": "integer, zero-based",
            "confidence": "0-100",
            "rationale": "string",
            "missing_services": ["service names only"],
            "environment_variables": ["names only, never values"],
            "proposed_candidate": {"name": "string", "image": "string", "command": "string", "container_port": 8000, "health_path": "/"},
        },
    }
    call = DeepSeekClient(settings=settings, user_agent="ai-security-platform/sandbox-launch-planner").complete_json(
        role="sandbox_launch_planner", system_prompt=system, user_prompt=json.dumps(payload, ensure_ascii=False),
        max_tokens=1800, required_keys=("recommended_index", "confidence", "rationale", "missing_services", "environment_variables"),
    )
    content = call.content
    return {
        **content, "model": call.model,
        "rationale": str(content.get("rationale") or "")[:1000],
        "missing_services": _safe_names(content.get("missing_services")),
        "environment_variables": _safe_names(content.get("environment_variables")),
    }


def _source_context(root: Path) -> dict[str, str]:
    context: dict[str, str] = {}
    budget = 30_000
    for name in CONTEXT_FILES:
        path = root / name
        if not path.is_file() or budget <= 0:
            continue
        try:
            raw = path.read_text(encoding="utf-8-sig", errors="replace")[: min(8000, budget)]
        except OSError:
            continue
        redacted = SECRET.sub(r"\1[REDACTED]", raw)
        context[name] = redacted
        budget -= len(redacted)
    return context


def _validated_ai_candidate(value: dict[str, object]) -> dict[str, object] | None:
    image, command = str(value.get("image") or "").strip(), " ".join(str(value.get("command") or "").split())
    try:
        port = int(value.get("container_port") or 8000)
    except (TypeError, ValueError):
        return None
    health_path = str(value.get("health_path") or "/")
    safe_health_path = bool(re.fullmatch(r"/[A-Za-z0-9_./{}-]*", health_path)) and ".." not in health_path
    if not approved_runtime_image(image) or not safe_start_command(command) or not 1 <= port <= 65535 or not safe_health_path:
        return None
    return {"name": str(value.get("name") or "DeepSeek 启动候选")[:120], "image": image, "command": command, "container_port": port, "health_path": health_path[:300], "source": "deepseek_validated", "confidence": 60, "rationale": "DeepSeek 候选已通过本地镜像、命令、端口和路径白名单校验。", "approved": True}


def _discover_support_services(root: Path) -> list[dict[str, object]]:
    """Extract only fixed, non-published PostgreSQL/Redis dependencies.

    Compose files are treated as hints.  User commands, mounts, ports, secrets
    and arbitrary environment values are intentionally ignored.
    """
    paths = [root / "compose.yml", root / "compose.yaml", root / "docker-compose.yml", root / "docker-compose.yaml", root / "infra" / "docker-compose.yml", root / "infra" / "docker-compose.yaml"]
    result: list[dict[str, object]] = []
    for path in paths:
        if not path.is_file():
            continue
        try:
            document = yaml.safe_load(path.read_text(encoding="utf-8-sig", errors="replace"))
        except (OSError, yaml.YAMLError):
            continue
        services = document.get("services") if isinstance(document, dict) else None
        if not isinstance(services, dict):
            continue
        for name, raw in services.items():
            if not isinstance(raw, dict):
                continue
            image = str(raw.get("image") or "")
            kind = "postgres" if image.startswith("postgres:") else "redis" if image.startswith("redis:") else ""
            if not kind or not approved_runtime_image(image):
                continue
            result.append({"name": re.sub(r"[^a-z0-9-]", "-", str(name).lower())[:40] or kind, "kind": kind, "image": image, "source": path.relative_to(root).as_posix(), "healthcheck": "pg_isready" if kind == "postgres" else "redis-cli ping"})
        if result:
            break
    deduped: dict[str, dict[str, object]] = {str(item["kind"]): item for item in result}
    return list(deduped.values())


def _safe_names(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    return [text for item in value if (text := re.sub(r"[^A-Za-z0-9_.:-]", "", str(item)))][:30]


def _empty(message: str) -> dict[str, object]:
    return {"schema": "ai-security-platform.sandbox-launch-plan/v1", "status": "blocked", "recommended": None, "candidates": [], "ai": {"status": "not_run", "configured": False}, "source_summary": {}, "message": message}
