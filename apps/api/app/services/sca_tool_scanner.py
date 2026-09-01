from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import threading
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import quote, unquote
from uuid import uuid4

from app.services.sca_parser import ParsedComponent


SYFT_IMAGE = "anchore/syft:latest"
GRYPE_IMAGE = "anchore/grype:latest"
TRIVY_IMAGE = "aquasec/trivy:latest"
NODE_RESOLVER_IMAGE = "node:20-alpine"
TOOL_TIMEOUT_SECONDS = 120
HEALTH_TIMEOUT_SECONDS = 20
DATABASE_IMPORT_TIMEOUT_SECONDS = 600
DATABASE_UPDATE_TIMEOUT_SECONDS = 600
GRYPE_OFFLINE_MAX_DATABASE_AGE = "720h"
GRYPE_DATABASE_MAX_AGE_HOURS = 720
_grype_database_update_lock = threading.Lock()


@dataclass(frozen=True)
class ToolVulnerability:
    ecosystem: str
    name: str
    version: str | None
    vulnerability_id: str
    severity: str | None
    summary: str | None
    remediation: str | None
    tool: str = "grype"


@dataclass(frozen=True)
class TrivySecurityFinding:
    kind: str
    rule_id: str
    severity: str
    title: str
    target: str
    line: int | None = None
    description: str | None = None
    remediation: str | None = None


@dataclass(frozen=True)
class ToolScanResult:
    components: list[ParsedComponent]
    vulnerabilities: list[ToolVulnerability]
    errors: list[str]
    grype_input: str | None = None
    trivy_vulnerabilities: int = 0
    trivy_vulnerability_fallback: bool = False
    trivy_misconfiguration_count: int = 0
    trivy_secret_count: int = 0
    trivy_security_findings: tuple[TrivySecurityFinding, ...] = ()
    syft_status: str = "not_run"
    syft_detail: str | None = None
    grype_status: str = "not_run"
    grype_detail: str | None = None
    trivy_status: str = "not_run"
    trivy_detail: str | None = None
    dependency_resolution_status: str = "not_needed"
    dependency_resolution_detail: str | None = None


@dataclass(frozen=True)
class ToolHealthCheck:
    name: str
    status: str
    detail: str | None = None
    remediation: str | None = None


@dataclass(frozen=True)
class ToolHealthResult:
    status: str
    recommended_grype_input: str
    checks: list[ToolHealthCheck]


@dataclass(frozen=True)
class GrypeDatabaseStatus:
    status: str
    valid: bool
    schema_version: str | None = None
    built_at: str | None = None
    expires_at: str | None = None
    database_path: str | None = None
    detail: str | None = None
    can_update: bool = False


def offline_assets_dir() -> Path:
    configured = os.getenv("SCA_OFFLINE_DIR")
    # services/ -> app/ -> api/ -> apps/ -> repository root
    return Path(configured).expanduser().resolve() if configured else Path(__file__).resolve().parents[4] / "artifacts" / "sca-offline"


def grype_cache_dir() -> Path:
    return offline_assets_dir() / "grype-cache"


def trivy_cache_dir() -> Path:
    return offline_assets_dir() / "trivy-cache"


def database_detail(database: Path) -> str:
    if not database.is_file():
        return "offline database not found"
    metadata = database.with_name("metadata.json")
    details = [f"{database.name} · {database.stat().st_size // (1024 * 1024)} MB"]
    if metadata.is_file():
        try:
            payload = json.loads(metadata.read_text(encoding="utf-8"))
            for key in ("UpdatedAt", "DownloadedAt", "NextUpdate", "Version"):
                if payload.get(key): details.append(f"{key}: {payload[key]}")
        except (OSError, json.JSONDecodeError):
            pass
    return " · ".join(details)


def check_syft_grype_health() -> ToolHealthResult:
    checks: list[ToolHealthCheck] = []
    docker_path = shutil.which("docker")
    if docker_path is None:
        return ToolHealthResult(
            status="failed",
            recommended_grype_input="unavailable",
            checks=[
                ToolHealthCheck(
                    name="docker_cli",
                    status="failed",
                    detail="Docker CLI was not found",
                    remediation="安装 Docker Desktop，并确认 docker 命令在 PATH 中可用。",
                )
            ],
        )

    checks.append(ToolHealthCheck(name="docker_cli", status="success", detail=docker_path))
    docker_info = run_health_command(["docker", "info", "--format", "{{.ServerVersion}}"])
    if docker_info[0] != 0:
        checks.append(
            ToolHealthCheck(
                name="docker_engine",
                status="failed",
                detail=docker_info[1],
                remediation="启动 Docker Desktop，等待 Docker Engine 进入 Running 状态后重试。",
            )
        )
        return ToolHealthResult(status="failed", recommended_grype_input="unavailable", checks=checks)

    checks.append(ToolHealthCheck(name="docker_engine", status="success", detail=f"server {docker_info[1]}"))
    checks.append(check_image("syft_image", SYFT_IMAGE, "docker pull anchore/syft:latest"))
    checks.append(check_image("grype_image", GRYPE_IMAGE, "docker pull anchore/grype:latest"))
    checks.append(check_image("trivy_image", TRIVY_IMAGE, "docker pull aquasec/trivy:latest"))

    grype_db = run_health_command(["docker", "run", "--rm", "-e", "XDG_CACHE_HOME=/cache", "-e", f"GRYPE_DB_MAX_ALLOWED_BUILT_AGE={GRYPE_OFFLINE_MAX_DATABASE_AGE}", "-v", f"{grype_cache_dir()}:/cache", GRYPE_IMAGE, "db", "status"])
    if grype_db[0] == 0:
        checks.append(ToolHealthCheck(name="grype_db", status="success", detail=grype_db[1]))
    else:
        checks.append(
            ToolHealthCheck(
                name="grype_db",
                status="warning",
                detail=grype_db[1],
                remediation=grype_database_remediation(),
            )
        )

    trivy_db = trivy_cache_dir() / "db" / "trivy.db"
    trivy_java_db = trivy_cache_dir() / "java-db" / "trivy-java.db"
    checks.append(ToolHealthCheck(
        name="trivy_db",
        status="success" if trivy_db.is_file() else "warning",
        detail=database_detail(trivy_db),
        remediation="在联网机器执行 Trivy 数据库下载，并将 artifacts/sca-offline/trivy-cache 带入沙箱。",
    ))
    checks.append(ToolHealthCheck(
        name="trivy_java_db",
        status="success" if trivy_java_db.is_file() else "warning",
        detail=database_detail(trivy_java_db),
        remediation="如需扫描 Maven/JAR，预下载 Trivy Java 数据库。",
    ))

    failed = any(check.status == "failed" for check in checks)
    warning = any(check.status == "warning" for check in checks)
    status = "failed" if failed else "warning" if warning else "success"
    recommended_input = "syft-sbom" if not failed else "directory"
    return ToolHealthResult(status=status, recommended_grype_input=recommended_input, checks=checks)


def check_image(name: str, image: str, pull_command: str) -> ToolHealthCheck:
    result = run_health_command(["docker", "image", "inspect", image])
    if result[0] == 0:
        return ToolHealthCheck(name=name, status="success", detail=image)
    return ToolHealthCheck(
        name=name,
        status="failed",
        detail=result[1],
        remediation=f"拉取镜像：{pull_command}",
    )


def run_health_command(command: list[str], timeout: int = HEALTH_TIMEOUT_SECONDS) -> tuple[int, str]:
    try:
        completed = subprocess.run(
            command,
            shell=False,
            capture_output=True,
            text=True,
            timeout=timeout,
            encoding="utf-8",
            errors="replace",
        )
    except subprocess.TimeoutExpired:
        return 124, f"timed out after {timeout}s"
    except OSError as exc:
        return 1, str(exc)

    output = output_excerpt(completed.stdout) or output_excerpt(completed.stderr)
    return completed.returncode, output or f"exit code {completed.returncode}"


def grype_database_status() -> GrypeDatabaseStatus:
    docker_path = shutil.which("docker")
    if docker_path is None:
        return GrypeDatabaseStatus(status="unavailable", valid=False, detail="Docker CLI was not found", can_update=False)
    docker_info = run_health_command(["docker", "info", "--format", "{{.ServerVersion}}"])
    if docker_info[0] != 0:
        return GrypeDatabaseStatus(status="unavailable", valid=False, detail=f"Docker Engine 不可用：{docker_info[1]}", can_update=False)
    image = run_health_command(["docker", "image", "inspect", GRYPE_IMAGE])
    if image[0] != 0:
        return GrypeDatabaseStatus(status="unavailable", valid=False, detail=f"未找到本地镜像 {GRYPE_IMAGE}", can_update=False)

    return _read_grype_database_status()


def _read_grype_database_status() -> GrypeDatabaseStatus:
    command = [
        "docker", "run", "--rm", "--pull=never",
        "-e", "XDG_CACHE_HOME=/cache",
        "-e", f"GRYPE_DB_MAX_ALLOWED_BUILT_AGE={GRYPE_OFFLINE_MAX_DATABASE_AGE}",
        "-v", f"{grype_cache_dir()}:/cache",
        GRYPE_IMAGE, "db", "status", "-o", "json",
    ]
    returncode, stdout, stderr = run_database_command(command, HEALTH_TIMEOUT_SECONDS)
    payload: dict[str, object] | None = None
    try:
        parsed = json.loads(stdout)
        payload = parsed if isinstance(parsed, dict) else None
    except json.JSONDecodeError:
        payload = None

    if payload is not None:
        built_at = string_value(payload.get("built"))
        expires_at = database_expiry(built_at)
        valid = payload.get("valid") is True and returncode == 0
        return GrypeDatabaseStatus(
            status="current" if valid else "stale",
            valid=valid,
            schema_version=string_value(payload.get("schemaVersion")),
            built_at=built_at,
            expires_at=expires_at,
            database_path=string_value(payload.get("path")),
            detail=None if valid else output_excerpt(stderr or stdout),
            can_update=True,
        )

    detail = output_excerpt(stderr or stdout) or f"exit code {returncode}"
    normalized = detail.lower()
    missing = any(marker in normalized for marker in ("not found", "no database", "does not exist", "unable to find"))
    return GrypeDatabaseStatus(status="missing" if missing else "error", valid=False, detail=detail, can_update=True)


def update_grype_database() -> tuple[bool, str, GrypeDatabaseStatus]:
    initial = grype_database_status()
    if not initial.can_update:
        return False, initial.detail or "Grype 数据库当前无法更新", initial
    if not _grype_database_update_lock.acquire(blocking=False):
        return False, "Grype 数据库正在更新，请稍后重新检测。", initial
    try:
        grype_cache_dir().mkdir(parents=True, exist_ok=True)
        command = [
            "docker", "run", "--rm", "--pull=never",
            "-e", "XDG_CACHE_HOME=/cache",
            "-v", f"{grype_cache_dir()}:/cache",
            GRYPE_IMAGE, "db", "update",
        ]
        returncode, stdout, stderr = run_database_command(command, DATABASE_UPDATE_TIMEOUT_SECONDS)
        if returncode != 0:
            detail = output_excerpt(stderr or stdout) or f"exit code {returncode}"
            return False, f"Grype 数据库更新失败：{detail}", _read_grype_database_status()
        current = _read_grype_database_status()
        if not current.valid:
            return False, "Grype 数据库下载完成，但有效性检查未通过。", current
        return True, "Grype 数据库已更新并通过有效性检查。", current
    finally:
        _grype_database_update_lock.release()


def run_database_command(command: list[str], timeout: int) -> tuple[int, str, str]:
    try:
        completed = subprocess.run(
            command,
            shell=False,
            capture_output=True,
            text=True,
            timeout=timeout,
            encoding="utf-8",
            errors="replace",
        )
    except subprocess.TimeoutExpired:
        return 124, "", f"timed out after {timeout}s"
    except OSError as exc:
        return 1, "", str(exc)
    return completed.returncode, completed.stdout.strip()[:8000], completed.stderr.strip()[:4000]


def database_expiry(built_at: str | None) -> str | None:
    if not built_at:
        return None
    try:
        built = datetime.fromisoformat(built_at.replace("Z", "+00:00"))
    except ValueError:
        return None
    if built.tzinfo is None:
        built = built.replace(tzinfo=timezone.utc)
    return (built + timedelta(hours=GRYPE_DATABASE_MAX_AGE_HOURS)).isoformat().replace("+00:00", "Z")


def string_value(value: object) -> str | None:
    return value if isinstance(value, str) and value else None


def grype_database_archive() -> Path | None:
    archives = sorted(grype_cache_dir().glob("grype-db-*.tar.zst"), key=lambda item: item.stat().st_mtime, reverse=True)
    return archives[0] if archives else None


def grype_database_remediation() -> str:
    archive = grype_database_archive()
    if archive:
        return f"已找到离线数据库 {archive.name}，执行增强扫描时会自动导入；首次导入可能需要数分钟。"
    return "未找到 Grype 离线数据库；请将数据库归档放入 artifacts/sca-offline/grype-cache。"


def ensure_grype_database() -> str | None:
    status_command = ["docker", "run", "--rm", "-e", "XDG_CACHE_HOME=/cache", "-e", f"GRYPE_DB_MAX_ALLOWED_BUILT_AGE={GRYPE_OFFLINE_MAX_DATABASE_AGE}", "-v", f"{grype_cache_dir()}:/cache", GRYPE_IMAGE, "db", "status"]
    status = run_health_command(status_command)
    if status[0] == 0:
        return None
    # Re-importing the same stale database on every scan is expensive and can
    # never make it fresh. Only import an archive when no database exists yet.
    existing_database = next(grype_cache_dir().glob("grype/db/*/vulnerability.db"), None)
    if existing_database is not None:
        return f"Grype 离线数据库不可用：{status[1]}"
    archive = grype_database_archive()
    if archive is None:
        return f"Grype 离线数据库不可用：{status[1]}；未找到可导入的数据库归档"
    import_result = run_health_command(
        ["docker", "run", "--rm", "-e", "XDG_CACHE_HOME=/cache", "-v", f"{grype_cache_dir()}:/cache", GRYPE_IMAGE, "db", "import", f"/cache/{archive.name}"],
        timeout=DATABASE_IMPORT_TIMEOUT_SECONDS,
    )
    if import_result[0] != 0:
        return f"Grype 离线数据库导入失败：{import_result[1]}"
    verified = run_health_command(status_command)
    if verified[0] != 0:
        return f"Grype 离线数据库导入后仍不可用：{verified[1]}"
    return None


def build_platform_cyclonedx(components: list[ParsedComponent]) -> dict:
    payload_components: list[dict[str, object]] = []
    for component in components:
        item: dict[str, object] = {
            "type": "library",
            "name": component.name,
            "bom-ref": parsed_component_ref(component),
            "properties": [
                {"name": "sca:source", "value": "platform-parser"},
                {"name": "sca:dependency_type", "value": component.dependency_type},
            ],
        }
        if component.version:
            item["version"] = component.version
        purl = parsed_component_purl(component)
        if purl:
            item["purl"] = purl
        payload_components.append(item)
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {"component": {"type": "application", "name": "local-project", "version": "scan"}},
        "components": payload_components,
    }


def parsed_component_ref(component: ParsedComponent) -> str:
    return f"pkg:{component.ecosystem}:{component.name}:{component.version or 'unknown'}"


def parsed_component_purl(component: ParsedComponent) -> str | None:
    if not component.version:
        return None
    package_type = {
        "python": "pypi",
        "pip": "pypi",
        "node": "npm",
        "javascript": "npm",
        "golang": "golang",
        "go": "golang",
    }.get(component.ecosystem.lower(), component.ecosystem.lower())
    name = component.name
    if package_type == "maven" and ":" in name:
        namespace, package_name = name.split(":", 1)
        encoded_name = f"{quote(namespace, safe='')}/{quote(package_name, safe='')}"
    else:
        encoded_name = quote(name, safe="/")
    return f"pkg:{package_type}/{encoded_name}@{quote(component.version, safe='.-_+')}"


def scan_with_syft_grype(source_path: str, fallback_components: list[ParsedComponent] | None = None) -> ToolScanResult:
    root = Path(source_path).expanduser().resolve()
    if not root.exists() or not root.is_dir():
        return ToolScanResult(components=[], vulnerabilities=[], errors=["source_path must be an existing directory"])
    if shutil.which("docker") is None:
        return ToolScanResult(components=[], vulnerabilities=[], errors=["Docker CLI was not found"])

    errors: list[str] = []
    syft_components: list[ParsedComponent] = []
    grype_vulnerabilities: list[ToolVulnerability] = []
    trivy_vulnerabilities: list[ToolVulnerability] = []
    trivy_security_findings: list[TrivySecurityFinding] = []
    trivy_vulnerability_fallback = False
    grype_input: str | None = None
    syft_status = "not_run"
    syft_detail: str | None = None
    grype_status = "not_run"
    grype_detail: str | None = None
    trivy_status = "not_run"
    trivy_detail: str | None = None
    dependency_resolution_status = "not_needed"
    dependency_resolution_detail: str | None = None

    with isolated_dependency_scan_root(root) as (scan_root, dependency_resolution_status, dependency_resolution_detail):
        if dependency_resolution_status == "failed" and dependency_resolution_detail:
            errors.append(f"Dependency resolution failed: {dependency_resolution_detail}")
        syft_payload, syft_error = run_tool_json(scan_root, SYFT_IMAGE, ["dir:/workspace", "-o", "cyclonedx-json"])
        if syft_error:
            errors.append(f"Syft failed: {syft_error}")
            syft_status = "failed"
            syft_detail = syft_error
        elif syft_payload:
            syft_components = parse_syft_cyclonedx(syft_payload)
            if syft_components:
                syft_status = "success"
                syft_detail = f"Syft 识别到 {len(syft_components)} 个组件"
            else:
                syft_status = "fallback"
                syft_detail = "Syft 未从锁文件或已安装目录识别到组件，已使用平台基础组件生成 SBOM"

        grype_sbom = syft_payload if syft_components else build_platform_cyclonedx(fallback_components or [])
        database_error = ensure_grype_database()
        input_name = "platform-sbom" if not syft_components else "syft-sbom"
        grype_input = input_name
        if database_error:
            grype_payload, grype_error = None, database_error
            trivy_payload, trivy_error, trivy_vulnerability_fallback, trivy_warning = run_trivy(scan_root, include_vulnerabilities=True)
        else:
            # Grype only matches the already-generated SBOM. Trivy walks the
            # source once for configuration and secret checks in parallel.
            with ThreadPoolExecutor(max_workers=2) as executor:
                grype_future = executor.submit(run_grype, scan_root, grype_sbom, input_name)
                trivy_future = executor.submit(run_trivy, scan_root, False)
                grype_payload, grype_error, grype_input = grype_future.result()
                trivy_payload, trivy_error, _, trivy_warning = trivy_future.result()
            if grype_error:
                # Rare execution failures after a successful health check still
                # receive a vulnerability fallback. This second Trivy pass is
                # avoided during the normal healthy and known-unhealthy paths.
                fallback_payload, fallback_error, fallback_enabled, fallback_warning = run_trivy(scan_root, include_vulnerabilities=True)
                if fallback_payload is not None:
                    trivy_payload = fallback_payload
                    trivy_error = fallback_error
                    trivy_vulnerability_fallback = fallback_enabled
                    trivy_warning = fallback_warning or trivy_warning
                else:
                    # Keep a successful configuration/secret result even when
                    # the additional vulnerability fallback cannot start.
                    fallback_detail = f"漏洞回退失败：{fallback_error}" if fallback_error else fallback_warning
                    trivy_warning = "；".join(item for item in (trivy_warning, fallback_detail) if item)
        if grype_error:
            errors.append(f"Grype failed: {grype_error}")
            grype_status = "failed"
            grype_detail = grype_error
        elif grype_payload:
            grype_vulnerabilities = parse_grype_json(grype_payload)
            grype_status = "success"
            grype_detail = f"Grype 扫描完成，发现 {len(grype_vulnerabilities)} 条漏洞匹配"

        if trivy_warning:
            errors.append(f"Trivy warning: {trivy_warning}")
        if trivy_error:
            errors.append(f"Trivy failed: {trivy_error}")
            trivy_status = "failed"
            trivy_detail = trivy_error
        elif trivy_payload is not None:
            trivy_vulnerabilities = parse_trivy_json(trivy_payload)
            trivy_security_findings = parse_trivy_security_findings(trivy_payload)
            trivy_status = "success"
            misconfigurations = sum(item.kind == "misconfiguration" for item in trivy_security_findings)
            secrets = sum(item.kind == "secret" for item in trivy_security_findings)
            vulnerability_detail = f"，漏洞回退匹配 {len(trivy_vulnerabilities)} 条" if trivy_vulnerability_fallback else "，未重复执行漏洞扫描"
            trivy_detail = f"Trivy 配置检查 {misconfigurations} 条、密钥检查 {secrets} 条{vulnerability_detail}"

    return ToolScanResult(
        components=syft_components,
        vulnerabilities=[*grype_vulnerabilities, *trivy_vulnerabilities],
        errors=errors,
        grype_input=grype_input,
        trivy_vulnerabilities=len(trivy_vulnerabilities),
        trivy_vulnerability_fallback=trivy_vulnerability_fallback,
        trivy_misconfiguration_count=sum(item.kind == "misconfiguration" for item in trivy_security_findings),
        trivy_secret_count=sum(item.kind == "secret" for item in trivy_security_findings),
        trivy_security_findings=tuple(trivy_security_findings),
        syft_status=syft_status,
        syft_detail=syft_detail,
        grype_status=grype_status,
        grype_detail=grype_detail,
        trivy_status=trivy_status,
        trivy_detail=trivy_detail,
        dependency_resolution_status=dependency_resolution_status,
        dependency_resolution_detail=dependency_resolution_detail,
    )


@contextmanager
def isolated_dependency_scan_root(root: Path):
    """Create an npm lock snapshot without mutating or executing the target.

    A manifest-only project otherwise exposes only direct dependencies to Syft.
    The resolver works on a temporary copy, disables lifecycle scripts, and
    yields the original tree with an explicit failure when the pinned resolver
    image or registry is unavailable.
    """
    package_json = root / "package.json"
    lock_files = [root / "package-lock.json", root / "npm-shrinkwrap.json"]
    if not package_json.is_file():
        yield root, "not_needed", "未发现 npm package.json"
        return
    if any(path.is_file() for path in lock_files) or (root / "node_modules").is_dir():
        yield root, "not_needed", "已存在 npm 锁文件或已安装依赖目录"
        return

    with tempfile.TemporaryDirectory(prefix="sca-npm-resolve-") as directory:
        prepared = Path(directory)
        try:
            shutil.copytree(
                root,
                prepared,
                dirs_exist_ok=True,
                ignore=shutil.ignore_patterns(
                    ".git",
                    "node_modules",
                    "dist",
                    "build",
                    "coverage",
                    "vendor",
                    ".venv",
                    "venv",
                    "__pycache__",
                ),
            )
        except OSError as exc:
            yield root, "failed", f"无法复制待扫描源码到隔离目录：{exc}"
            return
        command = [
            "docker", "run", "--rm", "--pull=never",
            "--cap-drop=ALL", "--security-opt=no-new-privileges", "--pids-limit", "256", "--memory", "1g",
            "-v", f"{prepared}:/workspace", "-w", "/workspace",
            NODE_RESOLVER_IMAGE,
            "npm", "install", "--package-lock-only", "--ignore-scripts", "--no-audit", "--no-fund",
        ]
        try:
            completed = subprocess.run(
                command,
                cwd=str(prepared),
                shell=False,
                capture_output=True,
                text=True,
                timeout=TOOL_TIMEOUT_SECONDS,
                encoding="utf-8",
                errors="replace",
            )
        except subprocess.TimeoutExpired:
            yield root, "failed", f"npm 临时解析超过 {TOOL_TIMEOUT_SECONDS} 秒"
            return
        except OSError as exc:
            yield root, "failed", str(exc)
            return
        lock_file = prepared / "package-lock.json"
        if completed.returncode != 0 or not lock_file.is_file():
            detail = command_error_summary(completed.returncode, completed.stderr, completed.stdout)
            yield root, "failed", detail or "npm 未生成 package-lock.json"
            return
        yield prepared, "success", "已在隔离 Docker 容器中生成临时 package-lock.json；未执行依赖脚本，原项目未被修改"


def run_grype(root: Path, sbom_payload: dict | None, input_name: str = "syft-sbom") -> tuple[dict | None, str | None, str]:
    if sbom_payload:
        with temporary_sbom_file() as sbom_path:
            sbom_path.write_text(json.dumps(sbom_payload), encoding="utf-8")
            container_sbom_path = "/cache/" + sbom_path.relative_to(grype_cache_dir()).as_posix()
            payload, error = run_tool_json(
                root,
                GRYPE_IMAGE,
                [f"sbom:{container_sbom_path}", "-o", "json"],
                container_env={"XDG_CACHE_HOME": "/cache", "GRYPE_DB_AUTO_UPDATE": "false", "GRYPE_DB_MAX_ALLOWED_BUILT_AGE": GRYPE_OFFLINE_MAX_DATABASE_AGE},
                extra_mounts=[(grype_cache_dir(), "/cache")],
            )
            return payload, error, input_name

    payload, error = run_tool_json(root, GRYPE_IMAGE, ["dir:/workspace", "-o", "json"], extra_mounts=[(grype_cache_dir(), "/cache")], container_env={"XDG_CACHE_HOME": "/cache", "GRYPE_DB_AUTO_UPDATE": "false", "GRYPE_DB_MAX_ALLOWED_BUILT_AGE": GRYPE_OFFLINE_MAX_DATABASE_AGE})
    return payload, error, "directory"


def run_trivy(root: Path, include_vulnerabilities: bool = False) -> tuple[dict | None, str | None, bool, str | None]:
    cache_dir = trivy_cache_dir()
    vulnerability_enabled = include_vulnerabilities and (cache_dir / "db" / "trivy.db").is_file()
    warning = None
    if include_vulnerabilities and not vulnerability_enabled:
        warning = "离线漏洞数据库不存在，Trivy 仅执行配置与密钥检查，无法完成漏洞回退"
    scanners = "vuln,misconfig,secret" if vulnerability_enabled else "misconfig,secret"
    args = [
        "fs", "--scanners", scanners, "--format", "json", "--skip-check-update", "--offline-scan",
        "--cache-dir", "/cache",
    ]
    if vulnerability_enabled:
        args.extend(["--skip-db-update", "--skip-java-db-update"])
    for pattern in ("**/.git", "**/node_modules", "**/dist", "**/build", "**/coverage", "**/vendor"):
        args.extend(["--skip-dirs", pattern])
    args.append("/workspace")
    payload, error = run_tool_json(
        root,
        TRIVY_IMAGE,
        args,
        extra_mounts=[(cache_dir, "/cache")],
    )
    return payload, error, vulnerability_enabled, warning


@contextmanager
def temporary_sbom_file():
    runtime_dir = grype_cache_dir() / "runtime"
    runtime_dir.mkdir(parents=True, exist_ok=True)
    path = runtime_dir / f"sca-sbom-{uuid4().hex}.cdx.json"
    try:
        yield path
    finally:
        path.unlink(missing_ok=True)


def run_tool_json(
    root: Path,
    image: str,
    args: list[str],
    extra_mounts: list[tuple[Path, str]] | None = None,
    container_env: dict[str, str] | None = None,
) -> tuple[dict | None, str | None]:
    command = [
        "docker",
        "run",
        "--rm",
        "-v",
        f"{root}:/workspace:ro",
        "-w",
        "/workspace",
    ]
    for host_path, container_path in extra_mounts or []:
        host_path.mkdir(parents=True, exist_ok=True)
        command.extend(["-v", f"{host_path}:{container_path}:ro"])
    for key, value in (container_env or {}).items():
        command.extend(["-e", f"{key}={value}"])
    command.extend([image, *args])
    try:
        completed = subprocess.run(
            command,
            cwd=str(root),
            shell=False,
            capture_output=True,
            text=True,
            timeout=TOOL_TIMEOUT_SECONDS,
            encoding="utf-8",
            errors="replace",
        )
    except subprocess.TimeoutExpired:
        return None, f"timed out after {TOOL_TIMEOUT_SECONDS}s"
    except OSError as exc:
        return None, str(exc)

    if completed.returncode != 0:
        details = command_error_summary(completed.returncode, completed.stderr, completed.stdout)
        return None, details or f"exit code {completed.returncode}"
    try:
        return json.loads(completed.stdout), None
    except json.JSONDecodeError as exc:
        return None, f"invalid JSON output: {exc}"


def parse_syft_cyclonedx(payload: dict) -> list[ParsedComponent]:
    components: list[ParsedComponent] = []
    for item in payload.get("components", []):
        if not isinstance(item, dict):
            continue
        name = item.get("name")
        if not isinstance(name, str) or not name.strip():
            continue
        purl = item.get("purl") if isinstance(item.get("purl"), str) else None
        ecosystem = ecosystem_from_purl(purl) or ecosystem_from_syft_type(item.get("type"))
        if ecosystem is None:
            continue
        components.append(
            ParsedComponent(
                ecosystem=ecosystem,
                name=name.strip(),
                version=str(item.get("version")) if item.get("version") else None,
                dependency_type="transitive",
                source_file="syft:docker",
                package_manager=ecosystem,
                license=component_license(item),
                risk_source="syft",
            )
        )
    return components


def parse_grype_json(payload: dict) -> list[ToolVulnerability]:
    vulnerabilities: list[ToolVulnerability] = []
    for match in payload.get("matches", []):
        if not isinstance(match, dict):
            continue
        artifact = match.get("artifact") if isinstance(match.get("artifact"), dict) else {}
        vulnerability = match.get("vulnerability") if isinstance(match.get("vulnerability"), dict) else {}
        name = artifact.get("name")
        vulnerability_id = vulnerability.get("id")
        if not isinstance(name, str) or not isinstance(vulnerability_id, str):
            continue
        purl = artifact.get("purl") if isinstance(artifact.get("purl"), str) else None
        ecosystem = ecosystem_from_purl(purl) or ecosystem_from_syft_type(artifact.get("type")) or "unknown"
        vulnerabilities.append(
            ToolVulnerability(
                ecosystem=ecosystem,
                name=name,
                version=str(artifact.get("version")) if artifact.get("version") else None,
                vulnerability_id=vulnerability_id,
                severity=normalize_severity(vulnerability.get("severity")),
                summary=vulnerability.get("description") if isinstance(vulnerability.get("description"), str) else None,
                remediation=grype_remediation(match),
            )
        )
    return vulnerabilities


def parse_trivy_json(payload: dict) -> list[ToolVulnerability]:
    vulnerabilities: list[ToolVulnerability] = []
    for result in payload.get("Results", []):
        if not isinstance(result, dict):
            continue
        ecosystem = trivy_ecosystem(str(result.get("Target") or ""))
        for item in result.get("Vulnerabilities", []) or []:
            if not isinstance(item, dict) or not isinstance(item.get("PkgName"), str) or not isinstance(item.get("VulnerabilityID"), str):
                continue
            fixed = item.get("FixedVersion")
            vulnerabilities.append(ToolVulnerability(
                ecosystem=ecosystem,
                name=item["PkgName"],
                version=str(item.get("InstalledVersion")) if item.get("InstalledVersion") else None,
                vulnerability_id=item["VulnerabilityID"],
                severity=normalize_severity(item.get("Severity")),
                summary=item.get("Title") if isinstance(item.get("Title"), str) else None,
                remediation=f"升级到修复版本：{fixed}" if fixed else None,
                tool="trivy",
            ))
    return vulnerabilities


def parse_trivy_security_findings(payload: dict) -> list[TrivySecurityFinding]:
    findings: list[TrivySecurityFinding] = []
    seen: set[tuple[str, str, str, int | None]] = set()
    for result in payload.get("Results", []):
        if not isinstance(result, dict):
            continue
        target = str(result.get("Target") or "unknown")[:500]
        for item in result.get("Misconfigurations", []) or []:
            if not isinstance(item, dict):
                continue
            cause = item.get("CauseMetadata") if isinstance(item.get("CauseMetadata"), dict) else {}
            finding = TrivySecurityFinding(
                kind="misconfiguration",
                rule_id=str(item.get("AVDID") or item.get("ID") or "TRIVY-MISCONFIG-UNKNOWN")[:160],
                severity=normalize_severity(item.get("Severity")) or "info",
                title=str(item.get("Title") or item.get("Message") or "配置安全检查")[:300],
                target=target,
                line=positive_int(cause.get("StartLine")),
                description=optional_text(item.get("Message") or item.get("Description"), 800),
                remediation=optional_text(item.get("Resolution"), 800),
            )
            key = (finding.kind, finding.rule_id, finding.target, finding.line)
            if key not in seen:
                seen.add(key)
                findings.append(finding)
        for item in result.get("Secrets", []) or []:
            if not isinstance(item, dict):
                continue
            # Never persist Trivy's Match or Code fields because they may
            # contain the credential value that the scanner is reporting.
            finding = TrivySecurityFinding(
                kind="secret",
                rule_id=str(item.get("RuleID") or "TRIVY-SECRET-UNKNOWN")[:160],
                severity=normalize_severity(item.get("Severity")) or "high",
                title=str(item.get("Title") or item.get("Category") or "疑似明文密钥")[:300],
                target=target,
                line=positive_int(item.get("StartLine")),
                description="Trivy 在明文文件中识别到疑似凭据；匹配值未被平台保存。",
                remediation="立即确认并轮换真实凭据，改用密钥管理服务或受控环境变量。",
            )
            key = (finding.kind, finding.rule_id, finding.target, finding.line)
            if key not in seen:
                seen.add(key)
                findings.append(finding)
    return findings


def positive_int(value: object) -> int | None:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return None
    return parsed if parsed > 0 else None


def optional_text(value: object, limit: int) -> str | None:
    if not isinstance(value, str) or not value.strip():
        return None
    return value.strip()[:limit]


def trivy_ecosystem(target: str) -> str:
    lower = target.lower()
    if "package" in lower or "npm" in lower or "yarn" in lower or "pnpm" in lower:
        return "npm"
    if "requirements" in lower or "poetry" in lower or "pipfile" in lower:
        return "pypi"
    if "pom.xml" in lower:
        return "maven"
    if "go.mod" in lower:
        return "go"
    return "unknown"


def ecosystem_from_purl(purl: str | None) -> str | None:
    if not purl or not purl.startswith("pkg:"):
        return None
    package_type = purl.removeprefix("pkg:").split("/", 1)[0].split("@", 1)[0].lower()
    return {
        "npm": "npm",
        "pypi": "pypi",
        "maven": "maven",
        "golang": "go",
        "go": "go",
        "deb": "deb",
        "rpm": "rpm",
        "apk": "apk",
    }.get(package_type, package_type or None)


def ecosystem_from_syft_type(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    normalized = value.lower()
    return {
        "library": None,
        "application": None,
        "framework": None,
    }.get(normalized, normalized)


def component_license(item: dict) -> str | None:
    licenses = item.get("licenses")
    if not isinstance(licenses, list) or not licenses:
        return None
    names: list[str] = []
    for entry in licenses:
        if not isinstance(entry, dict):
            continue
        license_value = entry.get("license")
        if isinstance(license_value, dict):
            value = license_value.get("id") or license_value.get("name")
            if isinstance(value, str) and value:
                names.append(value)
    return ", ".join(names) if names else None


def grype_remediation(match: dict) -> str | None:
    vulnerability = match.get("vulnerability") if isinstance(match.get("vulnerability"), dict) else {}
    fix = vulnerability.get("fix") if isinstance(vulnerability.get("fix"), dict) else {}
    versions = fix.get("versions")
    if isinstance(versions, list) and versions:
        return "升级到修复版本：" + ", ".join(str(version) for version in versions[:5])
    state = fix.get("state")
    if isinstance(state, str) and state:
        return f"Grype 修复状态：{state}"
    return None


def normalize_severity(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    normalized = value.lower()
    if normalized in {"critical", "high", "medium", "low", "info"}:
        return normalized
    if normalized == "negligible":
        return "info"
    return None


def command_error_summary(returncode: int, stderr: str, stdout: str) -> str:
    parts = [f"exit code {returncode}"]
    stderr_excerpt = output_excerpt(stderr)
    stdout_excerpt = output_excerpt(stdout)
    if stderr_excerpt:
        parts.append(f"stderr: {stderr_excerpt}")
    if stdout_excerpt:
        parts.append(f"stdout: {stdout_excerpt}")
    return "; ".join(parts)[:900]


def output_excerpt(value: str, limit: int = 6) -> str:
    lines = [line.strip() for line in value.splitlines() if line.strip()]
    if not lines:
        return ""
    if len(lines) <= limit:
        selected = lines
    else:
        head_count = max(1, limit // 2)
        tail_count = max(1, limit - head_count)
        selected = [*lines[:head_count], "...", *lines[-tail_count:]]
    return " | ".join(selected)[:760]


def purl_name(purl: str | None) -> str | None:
    if not purl or "@" not in purl:
        return None
    path = purl.removeprefix("pkg:").split("/", 1)[-1].split("@", 1)[0]
    return unquote(path) or None
