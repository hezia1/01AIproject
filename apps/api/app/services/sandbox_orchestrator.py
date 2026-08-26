"""Target lifecycle and fixed DAST execution orchestration for SANDBOX."""
from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timedelta
import json
import os
from pathlib import Path
import re
import secrets as secret_factory
import shutil
import socket
import subprocess
import time
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse, urlunparse
from urllib.request import Request, urlopen
from uuid import uuid4

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db_models import ProjectRecord, SandboxEvidenceRecord, SandboxTargetInstanceRecord, SandboxTaskEventRecord, SandboxTaskRecord
from app.services.sandbox_identity import AUTO_REF_PREFIX, forget_target, resolve_credential
from app.services.sandbox_launch_planner import approved_runtime_image
from app.services.dast_sandbox_contract import step_adapter


EXECUTOR_IMAGE = os.getenv("SANDBOX_EXECUTOR_IMAGE", "python:3.12-slim")
BROWSER_IMAGE = os.getenv("SANDBOX_BROWSER_IMAGE", "ai-security-platform/playwright-python:1.54.0")
RUNNER_PATH = Path(__file__).with_name("sandbox_http_executor.py").resolve()
BROWSER_RUNNER_PATH = Path(__file__).with_name("sandbox_browser_executor.py").resolve()
AGENT_RUNNER_PATH = Path(__file__).with_name("sandbox_agent_executor.py").resolve()
BROWSER_DOCKERFILE_PATH = Path(__file__).with_name("sandbox_browser_executor.Dockerfile").resolve()
TARGET_GATEWAY_PATH = Path(__file__).with_name("sandbox_target_gateway.py").resolve()
ARTIFACT_ROOT = Path(__file__).resolve().parents[4] / "artifacts" / "sandbox-browser"
MANAGED_LABEL = "ai-security-platform.sandbox"
SECRET_VALUE = re.compile(r"(?i)(bearer\s+)[A-Za-z0-9._~+/-]+|((?:password|passwd|token|secret|api[_-]?key|cookie)\s*[:=]\s*)\S+")
SENSITIVE_HEADER_LINE = re.compile(r"(?im)^(\s*(?:authorization|proxy-authorization|cookie|set-cookie|x-api-key)\s*:\s*).+$")
SENSITIVE_KEYS = {"authorization", "proxy-authorization", "cookie", "set-cookie", "x-api-key", "password", "passwd", "token", "secret", "api_key"}


class SandboxOrchestrationError(RuntimeError):
    def __init__(self, message: str, *, stage: str = "orchestration", diagnostic: dict[str, object] | None = None) -> None:
        super().__init__(message)
        self.stage = stage
        self.diagnostic = diagnostic or diagnose_startup_failure(message, stage=stage)

    def to_detail(self) -> dict[str, object]:
        return {"message": str(self), "diagnostic": self.diagnostic}


def diagnose_startup_failure(message: str, *, stage: str = "startup") -> dict[str, object]:
    detail = _safe_container_diagnostic(message)
    lowered = detail.lower()
    code, title, remediation = "unknown_startup_failure", "启动失败，尚无法自动归类", "查看脱敏容器日志，核对启动命令、运行镜像、依赖和健康路径。"
    rules = [
        (("no module named", "module not found", "cannot find module", "command not found", "can't open file", "cannot open file"), "dependency_or_entrypoint", "依赖或应用入口缺失", "核对锁文件、入口模块和工作目录；依赖准备成功后再试。"),
        (("address already in use", "port is already allocated"), "port_conflict", "端口冲突", "调整容器内服务端口，或停止占用目标端口的项目进程。"),
        (("connection refused", "could not connect to server", "redis connection", "econnrefused"), "dependency_unreachable", "依赖服务不可达", "确认 PostgreSQL/Redis 依赖已就绪，且应用使用编排网络内的服务名连接。"),
        (("failed to map segment", "operation not permitted"), "runtime_tmpfs_exec_policy", "运行时临时目录禁止加载 native addon", "对需要复制到临时目录运行的 Node/Python native 扩展目标，使用受管 tmpfs 运行副本并允许目标容器加载本地动态库；执行器容器仍保持 noexec。"),
        (("read-only file system", "permission denied", "eacces"), "filesystem_policy", "应用与只读文件系统策略冲突", "将临时文件写入 /tmp，持久化路径需通过专用受管卷显式声明。"),
        (("exit=137", "oomkilled", "out of memory"), "resource_limit", "资源上限触发", "减少启动期资源占用，或在审批后提高该项目的内存上限。"),
        (("health", "timed out", "urlopen error"), "healthcheck_failed", "HTTP 健康检查未通过", "确认应用监听 0.0.0.0，容器端口与 health_path 匹配，并留足启动时间。"),
        (("image", "pull access denied", "manifest unknown"), "image_unavailable", "运行镜像不可用", "确认使用白名单中的官方镜像标签，并检查 Docker Registry 连接。"),
    ]
    for needles, next_code, next_title, next_remediation in rules:
        if any(needle in lowered for needle in needles):
            code, title, remediation = next_code, next_title, next_remediation
            break
    return {"stage": stage, "code": code, "title": title, "detail": detail, "remediation": remediation, "redacted": True}


def _run_docker(args: list[str], *, timeout: int = 20, input_text: str | None = None, environment: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            ["docker", *args], input=input_text, capture_output=True, text=True,
            timeout=timeout, check=False, shell=False, encoding="utf-8", errors="replace",
            env=environment,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise SandboxOrchestrationError(f"Docker 调用失败：{exc}") from exc


def _image_exists(image: str) -> bool:
    result = _run_docker(["image", "inspect", image], timeout=10)
    return result.returncode == 0


def _ensure_runtime_image(image: str) -> None:
    if _image_exists(image):
        return
    if not approved_runtime_image(image):
        raise SandboxOrchestrationError(f"本地没有目标镜像 {image}，且它不在可自动拉取的官方运行时白名单中")
    pulled = _run_docker(["pull", image], timeout=300)
    if pulled.returncode != 0 or not _image_exists(image):
        raise SandboxOrchestrationError(f"自动拉取官方运行镜像 {image} 失败：{_safe_container_diagnostic(pulled.stderr)}")


def _allocate_loopback_port() -> int:
    """Reserve a candidate loopback port for Docker Desktop.

    Docker Desktop on Windows accepts ``127.0.0.1::PORT`` but may leave the
    host port empty. Supplying an explicit free port makes the mapping
    deterministic and lets the workbench report the real runtime URL.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])


def _safe_container_diagnostic(value: str) -> str:
    cleaned = SENSITIVE_HEADER_LINE.sub(r"\1[REDACTED]", value)
    cleaned = SECRET_VALUE.sub("[REDACTED]", cleaned)
    cleaned = re.sub(r"(?i)([a-z][a-z0-9+.-]*://[^\s:/@]+:)[^\s@]+(@)", r"\1[REDACTED]\2", cleaned)
    return " ".join(cleaned.strip().split())[:700]


def _redact_public(value: Any) -> Any:
    if isinstance(value, str):
        cleaned = SENSITIVE_HEADER_LINE.sub(r"\1[REDACTED]", value)
        return SECRET_VALUE.sub("[REDACTED]", cleaned)
    if isinstance(value, list):
        return [_redact_public(item) for item in value]
    if isinstance(value, dict):
        return {
            key: "[REDACTED]" if str(key).lower() in SENSITIVE_KEYS else _redact_public(item)
            for key, item in value.items()
        }
    return value


def _source_prepare_command(source: Path, command: str) -> tuple[str | None, list[str]]:
    """Return a fixed dependency recipe and target environment.

    Recipes are selected from manifests, never generated by the model.  They run
    in a short-lived build container with network access, while the application
    itself still starts on the internal target-only network.
    """
    if "/app" in command or not source.is_dir():
        return None, []
    copy = "cp -R /source/. /workspace && cd /workspace"
    if (source / "package.json").is_file():
        install = "npm ci" if (source / "package-lock.json").is_file() else "npm install"
        return f"{copy} && {install}", []
    if (source / "requirements.txt").is_file():
        return f"{copy} && pip install --no-cache-dir --target /workspace/.sandbox_deps -r requirements.txt", ["-e", "PYTHONPATH=/workspace/.sandbox_deps"]
    if (source / "pyproject.toml").is_file() or (source / "setup.py").is_file():
        return f"{copy} && pip install --no-cache-dir --target /workspace/.sandbox_deps .", ["-e", "PYTHONPATH=/workspace/.sandbox_deps"]
    if (source / "go.mod").is_file():
        environment = ["-e", "GOMODCACHE=/workspace/.sandbox_go/pkg/mod", "-e", "GOCACHE=/workspace/.sandbox_go/cache"]
        return f"{copy} && export GOMODCACHE=/workspace/.sandbox_go/pkg/mod GOCACHE=/workspace/.sandbox_go/cache && go mod download", environment
    if (source / "pom.xml").is_file():
        return f"{copy} && mvn -q -DskipTests -Dmaven.repo.local=/workspace/.sandbox_m2 dependency:go-offline", ["-e", "MAVEN_OPTS=-Dmaven.repo.local=/workspace/.sandbox_m2"]
    return None, []


def _target_runtime_command(image: str, command: str) -> tuple[str, dict[str, object]]:
    normalized_image = image.lower()
    normalized_command = " ".join(command.split())
    if normalized_image.startswith("appsecco/dvna") and normalized_command == "cd /app && npm start":
        runtime_dir = "/tmp/dvna-runtime"
        return (
            f"rm -rf {runtime_dir} && cp -R /app {runtime_dir} && cd {runtime_dir} && npm start",
            {"writable_runtime_copy": True, "runtime_copy_source": "/app", "runtime_copy_destination": runtime_dir},
        )
    return command, {"writable_runtime_copy": False}


def capability_health() -> dict[str, object]:
    docker_available = shutil.which("docker") is not None
    docker_detail = "未找到 Docker CLI"
    engine_ready = False
    if docker_available:
        result = _run_docker(["info", "--format", "{{.ServerVersion}}"], timeout=10)
        engine_ready = result.returncode == 0
        docker_detail = f"Docker Engine {result.stdout.strip()}" if engine_ready else (result.stderr.strip() or "Docker Engine 不可用")
    executor_ready = engine_ready and _image_exists(EXECUTOR_IMAGE)
    browser_image_ready = engine_ready and _image_exists(BROWSER_IMAGE)
    browser_runtime_ready = False
    if browser_image_ready:
        probe = _run_docker(["run", "--rm", "--network", "none", BROWSER_IMAGE, "python", "-c", "import playwright"], timeout=20)
        browser_runtime_ready = probe.returncode == 0
    capabilities = {
        "isolated_http": {"status": "ready" if executor_ready else "blocked", "detail": f"固定 HTTP 探针镜像：{EXECUTOR_IMAGE}" if executor_ready else f"本地缺少执行镜像 {EXECUTOR_IMAGE}"},
        "timing_probe": {"status": "ready" if executor_ready else "blocked", "detail": "固定多轮基线/延迟差分探针可用。" if executor_ready else "依赖固定 HTTP 探针镜像。"},
        "oast": {"status": "ready" if executor_ready else "blocked", "detail": "隔离网络内一次性 HTTP 回调探针可用；仅支持 Docker 目标实例。" if executor_ready else "依赖固定 HTTP 探针镜像。"},
        "browser": {"status": "ready" if browser_runtime_ready and BROWSER_RUNNER_PATH.is_file() else "blocked", "detail": f"固定 Playwright 同源取证执行器已就绪：{BROWSER_IMAGE}" if browser_runtime_ready and BROWSER_RUNNER_PATH.is_file() else f"本地缺少已锁定 Python 包的浏览器执行镜像 {BROWSER_IMAGE}；请使用 {BROWSER_DOCKERFILE_PATH.name} 构建"},
        "agent_runtime": {
            "status": "ready" if executor_ready and AGENT_RUNNER_PATH.is_file() else "blocked",
            "detail": "通用 Agent Runtime 证据协议执行器已就绪。"
            if executor_ready and AGENT_RUNNER_PATH.is_file()
            else "依赖固定 HTTP 探针镜像和 sandbox_agent_executor.py。",
        },
    }
    return {
        "status": "ready" if executor_ready else "blocked",
        "docker": {"available": docker_available, "ready": engine_ready, "detail": docker_detail},
        "executor_image": EXECUTOR_IMAGE,
        "browser_image": BROWSER_IMAGE,
        "capabilities": capabilities,
        "checked_at": datetime.utcnow().isoformat(),
    }


def enqueue_dast_handoff(db: Session, handoff: dict[str, object]) -> SandboxTaskRecord:
    source_task_id = str(handoff.get("task_id") or "")
    existing = db.scalar(select(SandboxTaskRecord).where(
        SandboxTaskRecord.source_module == "DAST", SandboxTaskRecord.source_task_id == source_task_id,
    ))
    if existing is not None:
        return existing
    callback = handoff.get("callback") if isinstance(handoff.get("callback"), dict) else {}
    token = str(callback.get("token") or "")
    if not source_task_id or len(token) < 32:
        raise SandboxOrchestrationError("DAST handoff is missing task ID or callback token")
    sanitized = deepcopy(handoff)
    sanitized["callback"] = {"path": str(callback.get("path") or "")}
    task = SandboxTaskRecord(
        project_id=str(handoff.get("project_id")), source_module="DAST", source_task_id=source_task_id,
        strategy_id=str(handoff.get("strategy_id")), finding_id=str(handoff.get("finding_id")) if handoff.get("finding_id") else None,
        status="queued", required_capabilities=list(handoff.get("required_capabilities") or []),
        contract=sanitized, callback_token=token,
    )
    db.add(task)
    db.flush()
    record_event(db, task, "PENDING", "queued", {"message": "DAST 合同已自动进入 SANDBOX 队列。"})
    return task


def record_event(db: Session, task: SandboxTaskRecord, state: str, status: str, detail: dict[str, object]) -> SandboxTaskEventRecord:
    event = SandboxTaskEventRecord(task_id=str(task.id), state=state, status=status, detail=detail)
    db.add(event)
    db.flush()
    return event


def target_to_dict(record: SandboxTargetInstanceRecord) -> dict[str, object]:
    return {
        "id": record.id, "project_id": record.project_id, "mode": record.mode, "status": record.status,
        "runtime_url": record.runtime_url, "internal_url": record.internal_url, "image": record.image,
        "command": record.command, "container_port": record.container_port, "health_path": record.health_path,
        "health_detail": record.health_detail or {}, "policy": record.policy or {}, "operator": record.operator,
        "expires_at": record.expires_at, "stopped_at": record.stopped_at,
        "created_at": record.created_at, "updated_at": record.updated_at,
    }


def task_to_dict(record: SandboxTaskRecord) -> dict[str, object]:
    contract = deepcopy(record.contract or {})
    if isinstance(contract.get("callback"), dict):
        contract["callback"].pop("token", None)
    return {
        "id": record.id, "project_id": record.project_id, "target_instance_id": record.target_instance_id,
        "source_module": record.source_module, "source_task_id": record.source_task_id,
        "strategy_id": record.strategy_id, "finding_id": record.finding_id, "status": record.status,
        "required_capabilities": list(record.required_capabilities or []), "contract": _redact_public(contract),
        "execution_id": record.execution_id, "evidence": _redact_public(list(record.evidence or [])),
        "result_summary": _redact_public(record.result_summary), "error": _redact_public(record.error), "operator": record.operator,
        "started_at": record.started_at, "completed_at": record.completed_at,
        "created_at": record.created_at, "updated_at": record.updated_at,
    }


def event_to_dict(record: SandboxTaskEventRecord) -> dict[str, object]:
    return {"id": record.id, "task_id": record.task_id, "state": record.state, "status": record.status, "detail": _redact_public(record.detail or {}), "created_at": record.created_at}


def persist_task_evidence_record(db: Session, task: SandboxTaskRecord, target: SandboxTargetInstanceRecord) -> SandboxEvidenceRecord:
    """Project a completed task into the existing ASPM evidence graph model."""
    evidence_items = list(task.evidence or [])
    record = SandboxEvidenceRecord(
        project_id=str(task.project_id), finding_id=str(task.finding_id) if task.finding_id else None,
        validation_id=None, component_id=None, link_source="dast-sandbox-contract",
        link_confidence=100 if task.finding_id else 0,
        run_command=f"fixed-policy:{task.strategy_id}", runtime_profile=task.execution_id,
        network_policy="docker-internal-target-only" if target.mode == "docker" else "application-same-origin-target-only",
        filesystem_policy="readonly-rootfs-no-source-mount",
        observed_files=[{
            "event_type": "artifact_index", "evidence_id": item.get("evidence_id"),
            "artifact_reference": item.get("artifact_reference"), "artifact_sha256": item.get("artifact_sha256"),
            "mime_type": item.get("mime_type"), "size_bytes": item.get("size_bytes", 0),
        } for item in evidence_items],
        observed_network=[{
            "event_type": str(item.get("type") or "runtime_trace"), "request_id": item.get("request_id"),
            "confirmed": bool(item.get("confirmed")), "facts": item.get("facts"),
            "exchange": item.get("exchange"), "timing": item.get("timing"),
        } for item in evidence_items],
        observed_processes=[{
            "event_type": "fixed_executor", "execution_id": task.execution_id,
            "status": task.status, "started_at": task.started_at.isoformat() if task.started_at else None,
            "completed_at": task.completed_at.isoformat() if task.completed_at else None,
        }],
        observed_tool_calls=[{
            "tool": "sandbox-fixed-probe", "strategy_id": task.strategy_id,
            "capabilities": list(task.required_capabilities or []), "arbitrary_command": False,
        }],
        evidence_summary=task.result_summary or task.error,
        operator=task.operator, strategy_name=f"DAST strategy {task.strategy_id}",
        purpose="在项目授权范围内执行 DAST 固定验证策略，并把事实证据回传给 DAST 进行独立三色裁决。",
        limitations="证据只适用于合同记录的目标、路径、时间与环境；未安装的浏览器或 Agent 运行时能力会阻塞，不会按未触发处理。",
    )
    db.add(record)
    db.flush()
    return record


def _same_origin(left: str, right: str) -> bool:
    def normalized(value: str) -> tuple[str, str, int] | None:
        parsed = urlparse(value)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            return None
        return parsed.scheme.lower(), parsed.hostname.lower(), parsed.port or (443 if parsed.scheme == "https" else 80)
    return normalized(left) is not None and normalized(left) == normalized(right)


def register_external_target(db: Session, project: ProjectRecord, runtime_url: str, health_path: str, operator: str, confirmed: bool) -> SandboxTargetInstanceRecord:
    if not confirmed:
        raise SandboxOrchestrationError("必须确认该地址属于当前项目且已获动态测试授权")
    configured = [value for value in (project.runtime_url, project.api_base_url) if value]
    if not any(_same_origin(runtime_url, value) for value in configured):
        raise SandboxOrchestrationError("外部目标必须与项目配置的 runtime_url/api_base_url 同源")
    record = SandboxTargetInstanceRecord(
        project_id=str(project.id), mode="external", status="pending", runtime_url=runtime_url.rstrip("/"),
        internal_url=runtime_url.rstrip("/"), health_path=health_path, operator=operator,
        policy={"network": "application-target-only", "same_origin_only": True, "source": "project-runtime-config"},
        expires_at=datetime.utcnow() + timedelta(hours=8),
    )
    db.add(record)
    db.flush()
    check_target_health(record)
    return record


def _start_support_services(instance_id: str, suffix: str, network_name: str, services: list[dict[str, object]]) -> tuple[list[str], list[str], list[dict[str, object]]]:
    names: list[str] = []
    target_environment: list[str] = []
    summary: list[dict[str, object]] = []
    for service in services[:4]:
        kind = str(service.get("kind") or "")
        image = str(service.get("image") or "")
        if kind not in {"postgres", "redis"} or not approved_runtime_image(image):
            raise SandboxOrchestrationError(f"依赖服务 {kind or 'unknown'} 未通过固定编排白名单")
        _ensure_runtime_image(image)
        alias = kind
        name = f"aisec-sbx-{kind}-{suffix}"
        service_args = [
            "run", "-d", "--name", name, "--network", network_name, "--network-alias", alias,
            "--label", f"{MANAGED_LABEL}=true", "--label", f"ai-security-platform.instance-id={instance_id}",
            "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
            "--memory", "384m", "--cpus", ".5", "--pids-limit", "128", "--tmpfs", "/tmp:rw,noexec,nosuid,size=64m",
        ]
        if kind == "postgres":
            password = secret_factory.token_urlsafe(24)
            service_args.extend(["--user", "999:999", "--tmpfs", "/var/lib/postgresql/data:rw,nosuid,size=256m,uid=999,gid=999,mode=0700", "--tmpfs", "/var/run/postgresql:rw,nosuid,size=16m,uid=999,gid=999,mode=0770", "-e", "POSTGRES_DB=sandbox", "-e", "POSTGRES_USER=sandbox", "-e", f"POSTGRES_PASSWORD={password}", image])
            target_environment.extend(["-e", f"DATABASE_URL=postgresql://sandbox:{password}@postgres:5432/sandbox", "-e", "POSTGRES_HOST=postgres", "-e", "POSTGRES_DB=sandbox", "-e", "POSTGRES_USER=sandbox", "-e", f"POSTGRES_PASSWORD={password}"])
            check = ["exec", name, "pg_isready", "-U", "sandbox", "-d", "sandbox"]
        else:
            service_args.extend(["--user", "999:999", "--tmpfs", "/data:rw,nosuid,size=64m,uid=999,gid=999", image, "redis-server", "--save", "", "--appendonly", "no"])
            target_environment.extend(["-e", "REDIS_URL=redis://redis:6379/0", "-e", "REDIS_HOST=redis"])
            check = ["exec", name, "redis-cli", "ping"]
        started = _run_docker(service_args, timeout=45)
        if started.returncode != 0:
            for created in reversed(names):
                _stop_managed_container(created, instance_id)
            raise SandboxOrchestrationError(f"启动 {kind} 依赖服务失败：{_safe_container_diagnostic(started.stderr)}")
        names.append(name)
        ready = False
        for _ in range(20):
            probe = _run_docker(check, timeout=5)
            if probe.returncode == 0:
                ready = True
                break
            time.sleep(0.25)
        if not ready:
            logs = _run_docker(["logs", "--tail", "30", name], timeout=10)
            for created in reversed(names):
                _stop_managed_container(created, instance_id)
            raise SandboxOrchestrationError(f"{kind} 依赖服务未就绪：{_safe_container_diagnostic(logs.stdout + ' ' + logs.stderr)}")
        summary.append({"kind": kind, "image": image, "container_name": name, "status": "ready", "published_ports": []})
    return names, target_environment, summary


def _stop_support_services(names: list[str], instance_id: str) -> None:
    for name in reversed(names):
        _stop_managed_container(name, instance_id)


def start_docker_target(db: Session, project: ProjectRecord, *, image: str, command: str, container_port: int, health_path: str, operator: str, confirmed: bool, services: list[dict[str, object]] | None = None, source_subdir: str = ".") -> SandboxTargetInstanceRecord:
    if not confirmed:
        raise SandboxOrchestrationError("必须确认容器仅承载当前项目的测试实例")
    source_root = Path(str(project.source_path or "")).resolve()
    source = (source_root / source_subdir).resolve()
    if source_root not in source.parents and source != source_root:
        raise SandboxOrchestrationError("启动服务子目录越出项目源码根目录")
    if not source.is_dir():
        raise SandboxOrchestrationError("项目源码目录不存在，无法创建只读目标实例")
    if not image or not command:
        raise SandboxOrchestrationError("项目缺少 sandbox_image 或 sandbox_command")
    _ensure_runtime_image(image)
    effective_command, runtime_command_policy = _target_runtime_command(image, command)
    instance_id = str(uuid4())
    suffix = instance_id.split("-")[0]
    network_name, edge_network_name = f"aisec-sbx-net-{suffix}", f"aisec-sbx-edge-{suffix}"
    workspace_volume_name = f"aisec-sbx-work-{suffix}"
    container_name, gateway_name = f"aisec-sbx-target-{suffix}", f"aisec-sbx-gateway-{suffix}"
    record = SandboxTargetInstanceRecord(
        id=instance_id, project_id=str(project.id), mode="docker", status="starting", runtime_url="pending://docker",
        internal_url=f"http://target:{container_port}", image=image, command=effective_command,
        container_name=container_name, network_name=network_name, container_port=container_port,
        health_path=health_path, operator=operator, expires_at=datetime.utcnow() + timedelta(hours=8),
        policy={"network": "docker-internal-with-fixed-loopback-gateway", "filesystem": "readonly-source-with-managed-build-volume", "capabilities": "drop-all", "gateway_container_name": gateway_name, "edge_network_name": edge_network_name, "workspace_volume_name": None, "source_subdir": source_subdir, "support_container_names": [], "support_services": [], "runtime_command": runtime_command_policy, "resources": {"cpus": "1", "memory": "768m", "pids": 192}},
    )
    db.add(record)
    db.flush()
    network = _run_docker(["network", "create", "--internal", "--label", f"{MANAGED_LABEL}=true", "--label", f"ai-security-platform.instance-id={instance_id}", network_name])
    if network.returncode != 0:
        raise SandboxOrchestrationError(network.stderr.strip() or "创建隔离网络失败")
    edge_network = _run_docker(["network", "create", "--label", f"{MANAGED_LABEL}=true", "--label", f"ai-security-platform.instance-id={instance_id}", edge_network_name])
    if edge_network.returncode != 0:
        _remove_managed_network(network_name, instance_id)
        raise SandboxOrchestrationError(edge_network.stderr.strip() or "创建本机入口网络失败")
    support_names, support_environment, support_summary = _start_support_services(instance_id, suffix, network_name, list(services or []))
    record.policy = {**record.policy, "support_container_names": support_names, "support_services": support_summary}
    prepare_command, target_environment = _source_prepare_command(source, effective_command)
    if prepare_command:
        volume = _run_docker(["volume", "create", "--label", f"{MANAGED_LABEL}=true", "--label", f"ai-security-platform.instance-id={instance_id}", workspace_volume_name])
        if volume.returncode != 0:
            _stop_support_services(support_names, instance_id)
            _remove_managed_network(edge_network_name, instance_id)
            _remove_managed_network(network_name, instance_id)
            raise SandboxOrchestrationError(volume.stderr.strip() or "创建项目依赖卷失败")
        record.policy = {**record.policy, "workspace_volume_name": workspace_volume_name, "dependency_prepared": False}
        prepared = _run_docker([
            "run", "--rm", "--network", edge_network_name,
            "--label", f"{MANAGED_LABEL}=true", "--label", f"ai-security-platform.instance-id={instance_id}",
            "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--memory", "1g", "--cpus", "2", "--pids-limit", "256",
            "-v", f"{source}:/source:ro", "-v", f"{workspace_volume_name}:/workspace", "-w", "/workspace",
            image, "sh", "-lc", prepare_command,
        ], timeout=300)
        if prepared.returncode != 0:
            detail = _safe_container_diagnostic(" ".join([prepared.stdout, prepared.stderr]))
            _remove_managed_volume(workspace_volume_name, instance_id)
            _stop_support_services(support_names, instance_id)
            _remove_managed_network(edge_network_name, instance_id)
            _remove_managed_network(network_name, instance_id)
            raise SandboxOrchestrationError(f"项目依赖准备失败。{detail or '请检查锁文件、依赖源或专用构建环境。'}")
        record.policy = {**record.policy, "dependency_prepared": True}
        mounts = ["-v", f"{workspace_volume_name}:/workspace"]
    else:
        mounts = ["-v", f"{source}:/workspace:ro"]
    host_port = _allocate_loopback_port()
    run = _run_docker([
        "run", "-d", "--name", container_name, "--network", network_name, "--network-alias", "target",
        "--label", f"{MANAGED_LABEL}=true", "--label", f"ai-security-platform.instance-id={instance_id}",
        "--label", f"ai-security-platform.project-id={project.id}", "--read-only", "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges", "--memory", "768m", "--cpus", "1", "--pids-limit", "192",
        "--tmpfs", "/tmp:rw,exec,nosuid,size=256m", *support_environment, *target_environment,
        *mounts, "-w", "/workspace", image, "sh", "-lc", effective_command,
    ], timeout=45)
    if run.returncode != 0:
        if prepare_command:
            _remove_managed_volume(workspace_volume_name, instance_id)
        _stop_support_services(support_names, instance_id)
        _remove_managed_network(edge_network_name, instance_id)
        _remove_managed_network(network_name, instance_id)
        raise SandboxOrchestrationError(run.stderr.strip() or "启动目标容器失败", stage="target_container")
    record.container_id = run.stdout.strip()
    gateway = _run_docker([
        "run", "-d", "--name", gateway_name, "--network", edge_network_name,
        "--label", f"{MANAGED_LABEL}=true", "--label", f"ai-security-platform.instance-id={instance_id}",
        "--label", f"ai-security-platform.project-id={project.id}", "--read-only", "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges", "--memory", "128m", "--cpus", ".25", "--pids-limit", "64",
        "--tmpfs", "/tmp:rw,noexec,nosuid,size=32m", "-p", f"127.0.0.1:{host_port}:8080",
        "-e", "SANDBOX_TARGET_HOST=target", "-e", f"SANDBOX_TARGET_PORT={container_port}",
        "-v", f"{TARGET_GATEWAY_PATH}:/runner/target_gateway.py:ro", EXECUTOR_IMAGE, "python", "/runner/target_gateway.py",
    ], timeout=45)
    if gateway.returncode != 0:
        _stop_managed_container(container_name, instance_id)
        _stop_support_services(support_names, instance_id)
        if prepare_command:
            _remove_managed_volume(workspace_volume_name, instance_id)
        _remove_managed_network(edge_network_name, instance_id)
        _remove_managed_network(network_name, instance_id)
        raise SandboxOrchestrationError(gateway.stderr.strip() or "启动固定本机入口网关失败")
    connected = _run_docker(["network", "connect", network_name, gateway_name], timeout=15)
    if connected.returncode != 0:
        _stop_managed_container(gateway_name, instance_id)
        _stop_managed_container(container_name, instance_id)
        _stop_support_services(support_names, instance_id)
        if prepare_command:
            _remove_managed_volume(workspace_volume_name, instance_id)
        _remove_managed_network(edge_network_name, instance_id)
        _remove_managed_network(network_name, instance_id)
        raise SandboxOrchestrationError(connected.stderr.strip() or "入口网关无法连接项目隔离网络")
    port = _run_docker(["port", gateway_name, "8080/tcp"], timeout=10)
    if port.returncode != 0 or not port.stdout.strip():
        state = _run_docker(["inspect", gateway_name, "--format", "{{.State.Status}} exit={{.State.ExitCode}} {{.State.Error}}"], timeout=10)
        logs = _run_docker(["logs", "--tail", "30", gateway_name], timeout=10)
        detail = _safe_container_diagnostic(" ".join([state.stdout, state.stderr, logs.stdout, logs.stderr]))
        _stop_managed_container(gateway_name, instance_id)
        _stop_managed_container(container_name, instance_id)
        _stop_support_services(support_names, instance_id)
        if prepare_command:
            _remove_managed_volume(workspace_volume_name, instance_id)
        _remove_managed_network(edge_network_name, instance_id)
        _remove_managed_network(network_name, instance_id)
        raise SandboxOrchestrationError(f"本机入口网关没有建立端口映射。{detail or '请检查 Docker Desktop 端口发布能力。'}")
    mapped_port = port.stdout.strip().splitlines()[0].rsplit(":", 1)[-1]
    if mapped_port != str(host_port):
        _stop_managed_container(gateway_name, instance_id)
        _stop_managed_container(container_name, instance_id)
        _stop_support_services(support_names, instance_id)
        if prepare_command:
            _remove_managed_volume(workspace_volume_name, instance_id)
        _remove_managed_network(edge_network_name, instance_id)
        _remove_managed_network(network_name, instance_id)
        raise SandboxOrchestrationError("Docker 返回的端口映射与已分配的本机端口不一致，已停止实例")
    record.runtime_url = f"http://127.0.0.1:{host_port}"
    record.updated_at = datetime.utcnow()
    for _ in range(40):
        check_target_health(record)
        if record.status == "running":
            break
        time.sleep(0.5)
    state = _run_docker(["inspect", container_name, "--format", "{{.State.Status}}|{{.State.ExitCode}}|{{.State.Error}}"], timeout=10)
    state_parts = state.stdout.strip().split("|", 2) if state.returncode == 0 else []
    if state_parts and state_parts[0] not in {"running", "created", "restarting"}:
        logs = _run_docker(["logs", "--tail", "30", container_name], timeout=10)
        detail = _safe_container_diagnostic(" ".join([logs.stdout, logs.stderr, state_parts[2] if len(state_parts) > 2 else ""]))
        _stop_managed_container(gateway_name, instance_id)
        _stop_managed_container(container_name, instance_id)
        _stop_support_services(support_names, instance_id)
        if prepare_command:
            _remove_managed_volume(workspace_volume_name, instance_id)
        _remove_managed_network(edge_network_name, instance_id)
        _remove_managed_network(network_name, instance_id)
        raise SandboxOrchestrationError(f"目标容器启动后退出（exit={state_parts[1] or 'unknown'}）。{detail or '请检查项目依赖、启动命令和运行镜像。'}", stage="target_container")
    if record.status != "running":
        record.health_detail = {**(record.health_detail or {}), "container_status": state_parts[0] if state_parts else "unknown", "remediation": "容器仍在运行但 HTTP 健康检查未通过；请确认应用监听 0.0.0.0、容器端口和健康路径。"}
    return record


def check_target_health(record: SandboxTargetInstanceRecord) -> SandboxTargetInstanceRecord:
    if record.status == "stopped":
        return record
    url = record.runtime_url.rstrip("/") + (record.health_path if record.health_path.startswith("/") else "/" + record.health_path)
    started = time.perf_counter()
    try:
        response = urlopen(Request(url, method="GET"), timeout=3)
        status = response.status
        response.read(1024)
        reachable = 100 <= status < 500
        error = None
    except HTTPError as exc:
        status, reachable, error = exc.code, 100 <= exc.code < 500, None
    except (URLError, TimeoutError, OSError, ValueError) as exc:
        status, reachable, error = 0, False, str(exc)[:500]
    record.status = "running" if reachable else "unhealthy"
    identity = (record.health_detail or {}).get("identity")
    record.health_detail = {"url": url, "reachable": reachable, "status_code": status, "latency_ms": round((time.perf_counter() - started) * 1000, 2), "error": error, "checked_at": datetime.utcnow().isoformat()}
    if not reachable:
        diagnostic = diagnose_startup_failure(error or "HTTP healthcheck failed", stage="healthcheck")
        record.health_detail.update({"diagnostic_code": diagnostic["code"], "diagnostic_title": diagnostic["title"], "remediation": diagnostic["remediation"]})
    if identity:
        record.health_detail["identity"] = identity
    record.updated_at = datetime.utcnow()
    return record


def _managed_labels(kind: str, name: str) -> dict[str, str]:
    result = _run_docker([kind, "inspect", name, "--format", "{{json .Config.Labels}}" if kind == "container" else "{{json .Labels}}"], timeout=10)
    if result.returncode != 0:
        raise SandboxOrchestrationError(f"无法检查 Docker {kind} {name}；停止清理以避免误操作")
    try:
        return json.loads(result.stdout.strip() or "{}")
    except json.JSONDecodeError as exc:
        raise SandboxOrchestrationError(f"Docker {kind} 标签无法解析；停止清理以避免误操作") from exc


def _stop_managed_container(name: str, instance_id: str) -> None:
    labels = _managed_labels("container", name)
    if labels.get(MANAGED_LABEL) != "true" or labels.get("ai-security-platform.instance-id") != instance_id:
        raise SandboxOrchestrationError("目标容器标签不匹配；拒绝停止非本任务资源")
    stopped = _run_docker(["stop", "--time", "5", name], timeout=15)
    if stopped.returncode != 0:
        raise SandboxOrchestrationError(stopped.stderr.strip() or "停止目标容器失败")
    removed = _run_docker(["rm", name], timeout=15)
    if removed.returncode != 0:
        raise SandboxOrchestrationError(removed.stderr.strip() or "移除已停止目标容器失败")


def _remove_managed_network(name: str, instance_id: str) -> None:
    labels = _managed_labels("network", name)
    if labels.get(MANAGED_LABEL) != "true" or labels.get("ai-security-platform.instance-id") != instance_id:
        raise SandboxOrchestrationError("隔离网络标签不匹配；拒绝移除非本任务资源")
    removed = _run_docker(["network", "rm", name], timeout=15)
    if removed.returncode != 0:
        raise SandboxOrchestrationError(removed.stderr.strip() or "移除隔离网络失败")


def _remove_managed_volume(name: str, instance_id: str) -> None:
    labels = _managed_labels("volume", name)
    if labels.get(MANAGED_LABEL) != "true" or labels.get("ai-security-platform.instance-id") != instance_id:
        raise SandboxOrchestrationError("项目依赖卷标签不匹配；拒绝移除非本任务资源")
    removed = _run_docker(["volume", "rm", name], timeout=30)
    if removed.returncode != 0:
        raise SandboxOrchestrationError(removed.stderr.strip() or "移除项目依赖卷失败")


def stop_target(record: SandboxTargetInstanceRecord) -> SandboxTargetInstanceRecord:
    if record.mode != "docker":
        forget_target(record.id)
        record.status, record.stopped_at, record.updated_at = "stopped", datetime.utcnow(), datetime.utcnow()
        return record
    if record.status == "stopped":
        return record
    if not record.container_name or not record.network_name:
        raise SandboxOrchestrationError("目标实例缺少可验证的 Docker 资源标识")
    policy = record.policy if isinstance(record.policy, dict) else {}
    gateway_name = str(policy.get("gateway_container_name") or "")
    edge_network_name = str(policy.get("edge_network_name") or "")
    workspace_volume_name = str(policy.get("workspace_volume_name") or "")
    if gateway_name:
        _stop_managed_container(gateway_name, str(record.id))
    _stop_managed_container(record.container_name, str(record.id))
    _stop_support_services([str(item) for item in (record.policy or {}).get("support_container_names", [])], str(record.id))
    if workspace_volume_name:
        _remove_managed_volume(workspace_volume_name, str(record.id))
    if edge_network_name:
        _remove_managed_network(edge_network_name, str(record.id))
    _remove_managed_network(record.network_name, str(record.id))
    forget_target(record.id)
    record.status, record.stopped_at, record.updated_at = "stopped", datetime.utcnow(), datetime.utcnow()
    return record


def _runtime_contract(contract: dict[str, object], target: SandboxTargetInstanceRecord) -> dict[str, object]:
    runtime = deepcopy(contract)
    target_spec = runtime.get("target") if isinstance(runtime.get("target"), dict) else {}
    original = str(target_spec.get("url") or "")
    replacement = str(target.internal_url if target.mode == "docker" else target.runtime_url)
    original_parts, replacement_parts = urlparse(original), urlparse(replacement)
    target_spec["url"] = urlunparse(replacement_parts._replace(path=original_parts.path or "/", query=original_parts.query, fragment=""))
    runtime["target"] = target_spec
    runtime["isolation"] = {"mode": target.mode, "disposable": target.mode == "docker"}
    for step in runtime.get("steps", []):
        if not isinstance(step, dict):
            continue
        for key in ("url", "setup_url", "observer_url"):
            if not step.get(key):
                continue
            parsed = urlparse(str(step[key]))
            if parsed.scheme and parsed.netloc:
                step[key] = urlunparse(replacement_parts._replace(path=parsed.path or "/", query=parsed.query, fragment=""))
    return runtime


def _executor_output(result: subprocess.CompletedProcess[str], label: str) -> dict[str, Any]:
    output: dict[str, Any] = {}
    for line in reversed(result.stdout.splitlines()):
        try:
            candidate = json.loads(line)
            if isinstance(candidate, dict):
                output = candidate
                break
        except json.JSONDecodeError:
            continue
    if result.returncode != 0 or not output:
        return {"status": "failed", "error": (output.get("error") if output else None) or _safe_container_diagnostic(result.stderr) or f"{label}没有返回结构化结果", "evidence": list(output.get("evidence") or [])}
    return output


def _run_policy_executor(
    *, adapter: str, execution_id: str, contract: dict[str, object], network_args: list[str],
    secrets: list[str], environment: dict[str, str], timeout: int, artifact_dir: Path | None = None,
) -> dict[str, Any]:
    if adapter == "browser":
        if artifact_dir is None:
            raise SandboxOrchestrationError("浏览器取证缺少任务级证据目录")
        artifact_dir.mkdir(parents=True, exist_ok=True)
        args = [
            "run", "--rm", "-i", "--name", f"{execution_id}-browser", *network_args,
            "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
            "--memory", "1g", "--cpus", "1", "--pids-limit", "256",
            "--tmpfs", "/tmp:rw,noexec,nosuid,size=256m", *secrets,
            "--env", "SANDBOX_ARTIFACT_DIR=/artifacts",
            "-v", f"{BROWSER_RUNNER_PATH}:/runner/sandbox_browser_executor.py:ro",
            "-v", f"{artifact_dir.resolve()}:/artifacts",
            BROWSER_IMAGE, "python", "/runner/sandbox_browser_executor.py",
        ]
        result = _run_docker(args, timeout=timeout + 20, input_text=json.dumps(contract, ensure_ascii=False), environment=environment)
        return _executor_output(result, "浏览器证据执行器")
    if adapter == "agent":
        args = [
            "run", "--rm", "-i", "--name", f"{execution_id}-agent", *network_args,
            "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
            "--memory", "512m", "--cpus", "1", "--pids-limit", "128",
            "--tmpfs", "/tmp:rw,noexec,nosuid,size=128m", *secrets,
            "-v", f"{AGENT_RUNNER_PATH}:/runner/sandbox_agent_executor.py:ro",
            EXECUTOR_IMAGE, "python", "/runner/sandbox_agent_executor.py",
        ]
        result = _run_docker(args, timeout=timeout + 20, input_text=json.dumps(contract, ensure_ascii=False), environment=environment)
        return _executor_output(result, "Agent Runtime 证据执行器")
    args = [
        "run", "--rm", "-i", "--name", f"{execution_id}-http", *network_args,
        "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
        "--memory", "512m", "--cpus", "1", "--pids-limit", "128",
        "--tmpfs", "/tmp:rw,noexec,nosuid,size=128m", "--env", f"SANDBOX_CALLBACK_HOST={execution_id}",
        *secrets, "-v", f"{RUNNER_PATH}:/runner/sandbox_http_executor.py:ro",
        EXECUTOR_IMAGE, "python", "/runner/sandbox_http_executor.py",
    ]
    result = _run_docker(args, timeout=timeout + 20, input_text=json.dumps(contract, ensure_ascii=False), environment=environment)
    return _executor_output(result, "固定 HTTP 执行器")


def execute_task(db: Session, task: SandboxTaskRecord, target: SandboxTargetInstanceRecord, operator: str) -> dict[str, object]:
    if task.status not in {"queued", "blocked", "failed"}:
        raise SandboxOrchestrationError(f"任务状态 {task.status} 不允许执行")
    if str(target.project_id) != str(task.project_id) or target.status != "running":
        raise SandboxOrchestrationError("目标实例不属于当前项目或当前不可用")
    health = capability_health()
    statuses = health["capabilities"]
    missing = [cap for cap in task.required_capabilities if statuses.get(cap, {}).get("status") != "ready"]
    if "oast" in task.required_capabilities and target.mode != "docker":
        missing.append("oast(需要 Docker 隔离目标)")
    if missing:
        task.status, task.error, task.operator = "blocked", "缺少 SANDBOX 执行能力：" + "、".join(sorted(set(missing))), operator
        task.completed_at = task.updated_at = datetime.utcnow()
        record_event(db, task, "BLOCKED", "blocked", {"message": task.error, "capability_health": statuses})
        return {"status": "blocked", "execution_id": f"blocked-{uuid4().hex}", "capabilities": [], "evidence": [], "verdict_signal": None, "verdict_reason": task.error}
    execution_id = f"sbx-{str(task.id).split('-')[0]}-{uuid4().hex[:8]}"
    task.target_instance_id, task.execution_id, task.operator = str(target.id), execution_id, operator
    task.status, task.started_at, task.updated_at = "running", datetime.utcnow(), datetime.utcnow()
    record_event(db, task, "RUNNING", "running", {"execution_id": execution_id, "target_instance_id": str(target.id), "message": "固定探针执行器已启动。"})
    db.flush()
    contract = _runtime_contract(task.contract or {}, target)
    network_args = ["--network", target.network_name] if target.mode == "docker" and target.network_name else []
    secrets: list[str] = []
    execution_environment = dict(os.environ)
    for role in contract.get("roles", []):
        ref = str(role.get("credential_ref") or "") if isinstance(role, dict) else ""
        if ref.startswith("env:") and os.getenv(ref[4:]):
            secrets.extend(["--env", ref[4:]])
        elif ref.startswith(AUTO_REF_PREFIX) and isinstance(role, dict):
            credential = resolve_credential(task.project_id, ref)
            if not credential:
                raise SandboxOrchestrationError(f"项目测试身份尚未就绪：{role.get('alias') or 'unknown'}")
            env_name = f"DAST_SANDBOX_{str(task.id).replace('-', '')[:8]}_{str(role.get('alias') or 'ROLE').upper()}"
            execution_environment[env_name] = json.dumps(credential, ensure_ascii=False)
            role["credential_ref"] = f"env:{env_name}"
            secrets.extend(["--env", env_name])
    steps = [step for step in contract.get("steps", []) if isinstance(step, dict)]
    disposable_only_steps = [
        step for step in steps
        if str(step.get("kind") or "") == "sandbox_probe"
        and str(step.get("probe") or "") in {"csrf", "access_control_mutation", "file_upload", "agent_capability", "prompt_injection"}
    ]
    if disposable_only_steps and target.mode != "docker":
        task.status, task.error, task.operator = "blocked", "文件上传、状态变更和 Agent Runtime 验证只允许在可回滚的一次性 Docker 隔离目标中执行。", operator
        task.completed_at = task.updated_at = datetime.utcnow()
        record_event(db, task, "BLOCKED", "blocked", {"message": task.error})
        return {"status": "blocked", "execution_id": f"blocked-{uuid4().hex}", "capabilities": [], "evidence": [], "verdict_signal": None, "verdict_reason": task.error}
    browser_steps = [step for step in steps if step_adapter(step) == "browser"]
    http_steps = [step for step in steps if step_adapter(step) == "http"]
    agent_steps = [step for step in steps if step_adapter(step) == "agent"]
    unsupported_steps = [step for step in steps if step_adapter(step) is None]
    if unsupported_steps:
        names = sorted({str(step.get("id") or step.get("probe") or "unknown") for step in unsupported_steps})
        task.status, task.error = "failed", "执行合同包含未映射的步骤：" + "、".join(names)
        task.completed_at = task.updated_at = datetime.utcnow()
        record_event(db, task, "FAILED", "failed", {"message": task.error})
        return {"status": "failed", "execution_id": execution_id, "capabilities": [], "evidence": [], "verdict_signal": None, "verdict_reason": task.error}
    timeout = int((contract.get("limits") if isinstance(contract.get("limits"), dict) else {}).get("timeout_seconds", 120))
    outputs: list[dict[str, Any]] = []
    if http_steps:
        http_contract = {**contract, "steps": http_steps}
        outputs.append(_run_policy_executor(adapter="http", execution_id=execution_id, contract=http_contract, network_args=network_args, secrets=secrets, environment=execution_environment, timeout=timeout))
    if browser_steps:
        browser_contract = {**contract, "steps": browser_steps}
        outputs.append(_run_policy_executor(adapter="browser", execution_id=execution_id, contract=browser_contract, network_args=network_args, secrets=secrets, environment=execution_environment, timeout=timeout, artifact_dir=ARTIFACT_ROOT / str(task.project_id) / execution_id))
    if agent_steps:
        agent_contract = {**contract, "steps": agent_steps}
        outputs.append(_run_policy_executor(adapter="agent", execution_id=execution_id, contract=agent_contract, network_args=network_args, secrets=secrets, environment=execution_environment, timeout=timeout))
    if not outputs:
        outputs.append({"status": "failed", "error": "执行合同没有可运行步骤", "evidence": []})
    status = "completed" if all(str(item.get("status")) == "completed" for item in outputs) else "failed"
    signals = [str(item.get("verdict_signal") or "uncertain") for item in outputs]
    verdict_signal = "exploitable" if "exploitable" in signals else "not_exploitable" if signals and all(item == "not_exploitable" for item in signals) else "uncertain"
    evidence = [_redact_public(item) for output in outputs for item in list(output.get("evidence") or [])]
    reasons = [str(output.get("verdict_reason") or output.get("error") or "").strip() for output in outputs]
    errors = [str(output.get("error") or "").strip() for output in outputs if output.get("error")]
    task.status = status
    task.evidence = evidence
    task.result_summary = _redact_public(" ".join(item for item in reasons if item)[:4000]) or None
    task.error = _redact_public(" ".join(errors)[:4000]) or None
    task.completed_at = task.updated_at = datetime.utcnow()
    terminal_state = "ANALYZING" if status == "completed" else status.upper()
    record_event(db, task, terminal_state, status, {"execution_id": execution_id, "message": task.result_summary or task.error or status, "evidence_count": len(task.evidence)})
    return {
        "status": status, "execution_id": execution_id,
        "capabilities": list(task.required_capabilities or []), "evidence": task.evidence,
        "verdict_signal": verdict_signal, "verdict_reason": task.result_summary or task.error,
    }
