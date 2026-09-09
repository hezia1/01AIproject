from __future__ import annotations

from datetime import datetime, timezone
import shutil
import socket
import ssl
import subprocess
from typing import Callable
from urllib.parse import unquote, urlparse

from sqlalchemy import text
from sqlalchemy.engine import Engine

from app.db import REDIS_URL, engine
from app.services.sca_tool_scanner import GRYPE_IMAGE, SYFT_IMAGE, TRIVY_IMAGE
from app.services.semgrep_scanner import DEFAULT_SEMGREP_IMAGE


HealthCheck = dict[str, object]


def platform_health(
    *,
    database_probe: Callable[[], HealthCheck] | None = None,
    redis_probe: Callable[[], HealthCheck] | None = None,
    runtime_probe: Callable[[], list[HealthCheck]] | None = None,
    include_optional_tools: bool = True,
) -> dict[str, object]:
    checks: list[HealthCheck] = [
        check("api", "API", "ok", True, "HTTP 健康检查路由可以响应。"),
        (database_probe or probe_database)(),
        (redis_probe or probe_redis)(),
    ]
    if include_optional_tools:
        checks.extend((runtime_probe or probe_runtime_dependencies)())
    required_unavailable = any(
        bool(item.get("required")) and item.get("status") != "ok" for item in checks
    )
    optional_degraded = any(item.get("status") != "ok" for item in checks)
    status = "unavailable" if required_unavailable else "degraded" if optional_degraded else "ok"
    return {
        "status": status,
        "checked_at": datetime.now(timezone.utc).isoformat(),
        "checks": checks,
        "limitations": [
            "工具状态只表示本机命令或固定 Docker 镜像已准备，不代表目标扫描成功。",
            "外部网络、漏洞情报时效、模型服务和被测目标应在对应模块内单独核实。",
        ],
    }


def probe_database(database_engine: Engine = engine) -> HealthCheck:
    try:
        with database_engine.connect() as connection:
            connection.execute(text("SELECT 1"))
        return check("database", "PostgreSQL", "ok", True, "数据库连接和只读查询成功。")
    except Exception:
        return check(
            "database", "PostgreSQL", "unavailable", True,
            "数据库连接或只读查询失败；认证和业务数据当前不可用。",
        )


def probe_redis(redis_url: str = REDIS_URL) -> HealthCheck:
    try:
        parsed = urlparse(redis_url)
        if parsed.scheme not in {"redis", "rediss"} or not parsed.hostname:
            raise ValueError("unsupported Redis URL")
        with socket.create_connection((parsed.hostname, parsed.port or 6379), timeout=1.5) as raw_socket:
            connection = (
                ssl.create_default_context().wrap_socket(raw_socket, server_hostname=parsed.hostname)
                if parsed.scheme == "rediss"
                else raw_socket
            )
            with connection:
                if parsed.password:
                    credentials = [unquote(parsed.password)]
                    if parsed.username:
                        credentials.insert(0, unquote(parsed.username))
                    _redis_command(connection, "AUTH", *credentials)
                database = (parsed.path or "/0").lstrip("/") or "0"
                if database != "0":
                    _redis_command(connection, "SELECT", database)
                response = _redis_command(connection, "PING")
                if not response.startswith(b"+PONG"):
                    raise ConnectionError("Redis did not return PONG")
        return check("redis", "Redis", "ok", False, "Redis PING 成功。")
    except Exception:
        return check(
            "redis", "Redis", "unavailable", False,
            "Redis 连接或 PING 失败；当前核心数据库路径仍可独立运行。",
        )


def probe_runtime_dependencies() -> list[HealthCheck]:
    docker_path = shutil.which("docker")
    semgrep_cli = shutil.which("semgrep")
    if not docker_path:
        return _runtime_unavailable("未找到 Docker 命令。", semgrep_cli)

    try:
        docker_ready = bool(
            _run_command([docker_path, "version", "--format", "{{.Server.Version}}"])
            .strip()
        )
    except (OSError, subprocess.SubprocessError):
        docker_ready = False
    if not docker_ready:
        return _runtime_unavailable("Docker 命令存在，但 Engine 不可达。", semgrep_cli)

    images: set[str] = set()
    try:
        listing = _run_command([docker_path, "image", "ls", "--format", "{{.Repository}}:{{.Tag}}"])
        images = {line.strip() for line in listing.splitlines() if line.strip()}
    except (OSError, subprocess.SubprocessError):
        pass

    sca_images = {SYFT_IMAGE, GRYPE_IMAGE, TRIVY_IMAGE}
    prepared_sca = sorted(sca_images & images)
    semgrep_ready = bool(semgrep_cli) or DEFAULT_SEMGREP_IMAGE in images
    return [
        check("docker", "Docker Engine", "ok", False, "Docker Engine 可以响应。"),
        check(
            "sca_tools", "SCA Docker 工具",
            "ok" if len(prepared_sca) == len(sca_images) else "degraded", False,
            f"已准备 {len(prepared_sca)}/{len(sca_images)} 个固定 SCA 工具镜像；未执行扫描。",
        ),
        check(
            "semgrep", "Semgrep", "ok" if semgrep_ready else "unavailable", False,
            "已准备本机命令或固定 Docker 镜像；未执行扫描。"
            if semgrep_ready else "未找到本机命令或固定 Docker 镜像。",
        ),
    ]


def _runtime_unavailable(reason: str, semgrep_cli: str | None) -> list[HealthCheck]:
    return [
        check("docker", "Docker Engine", "unavailable", False, reason),
        check(
            "sca_tools", "SCA Docker 工具", "unavailable", False,
            "Docker 不可用，无法核实 Syft、Grype 和 Trivy 镜像。",
        ),
        check(
            "semgrep", "Semgrep", "ok" if semgrep_cli else "unavailable", False,
            "已找到本机 Semgrep 命令。" if semgrep_cli else "未找到本机 Semgrep 命令，且 Docker 不可用。",
        ),
    ]


def check(key: str, name: str, status: str, required: bool, detail: str) -> HealthCheck:
    return {"key": key, "name": name, "status": status, "required": required, "detail": detail}


def _run_command(command: list[str]) -> str:
    result = subprocess.run(command, capture_output=True, text=True, timeout=3, check=True)
    return result.stdout


def _redis_command(connection: socket.socket, *parts: str) -> bytes:
    encoded = [part.encode("utf-8") for part in parts]
    payload = f"*{len(encoded)}\r\n".encode("ascii") + b"".join(
        f"${len(part)}\r\n".encode("ascii") + part + b"\r\n" for part in encoded
    )
    connection.sendall(payload)
    response = connection.recv(512)
    if response.startswith(b"-"):
        raise ConnectionError("Redis command failed")
    return response
