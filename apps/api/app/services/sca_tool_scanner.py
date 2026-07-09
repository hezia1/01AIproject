from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import unquote

from app.services.sca_parser import ParsedComponent


SYFT_IMAGE = "anchore/syft:latest"
GRYPE_IMAGE = "anchore/grype:latest"
TOOL_TIMEOUT_SECONDS = 120
HEALTH_TIMEOUT_SECONDS = 20


@dataclass(frozen=True)
class ToolVulnerability:
    ecosystem: str
    name: str
    version: str | None
    vulnerability_id: str
    severity: str | None
    summary: str | None
    remediation: str | None


@dataclass(frozen=True)
class ToolScanResult:
    components: list[ParsedComponent]
    vulnerabilities: list[ToolVulnerability]
    errors: list[str]
    grype_input: str | None = None


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

    grype_db = run_health_command(["docker", "run", "--rm", GRYPE_IMAGE, "db", "status"])
    if grype_db[0] == 0:
        checks.append(ToolHealthCheck(name="grype_db", status="success", detail=grype_db[1]))
    else:
        checks.append(
            ToolHealthCheck(
                name="grype_db",
                status="warning",
                detail=grype_db[1],
                remediation="首次运行可能需要联网下载 Grype 漏洞库；如处于离线环境，需要提前准备 Grype DB。",
            )
        )

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


def run_health_command(command: list[str]) -> tuple[int, str]:
    try:
        completed = subprocess.run(
            command,
            shell=False,
            capture_output=True,
            text=True,
            timeout=HEALTH_TIMEOUT_SECONDS,
            encoding="utf-8",
            errors="replace",
        )
    except subprocess.TimeoutExpired:
        return 124, f"timed out after {HEALTH_TIMEOUT_SECONDS}s"
    except OSError as exc:
        return 1, str(exc)

    output = output_excerpt(completed.stdout) or output_excerpt(completed.stderr)
    return completed.returncode, output or f"exit code {completed.returncode}"


def scan_with_syft_grype(source_path: str) -> ToolScanResult:
    root = Path(source_path).expanduser().resolve()
    if not root.exists() or not root.is_dir():
        return ToolScanResult(components=[], vulnerabilities=[], errors=["source_path must be an existing directory"])
    if shutil.which("docker") is None:
        return ToolScanResult(components=[], vulnerabilities=[], errors=["Docker CLI was not found"])

    errors: list[str] = []
    syft_components: list[ParsedComponent] = []
    grype_vulnerabilities: list[ToolVulnerability] = []
    grype_input: str | None = None

    syft_payload, syft_error = run_tool_json(root, SYFT_IMAGE, ["dir:/workspace", "-o", "cyclonedx-json"])
    if syft_error:
        errors.append(f"Syft failed: {syft_error}")
    elif syft_payload:
        syft_components = parse_syft_cyclonedx(syft_payload)

    grype_payload, grype_error, grype_input = run_grype(root, syft_payload)
    if grype_error:
        errors.append(f"Grype failed: {grype_error}")
    elif grype_payload:
        grype_vulnerabilities = parse_grype_json(grype_payload)

    return ToolScanResult(
        components=syft_components,
        vulnerabilities=grype_vulnerabilities,
        errors=errors,
        grype_input=grype_input,
    )


def run_grype(root: Path, syft_payload: dict | None) -> tuple[dict | None, str | None, str]:
    if syft_payload:
        with temporary_sbom_dir(root) as temp_dir:
            sbom_path = Path(temp_dir) / "syft.cdx.json"
            sbom_path.write_text(json.dumps(syft_payload), encoding="utf-8")
            payload, error = run_tool_json(
                root,
                GRYPE_IMAGE,
                ["sbom:/tmp/sca/syft.cdx.json", "-o", "json"],
                extra_mounts=[(Path(temp_dir), "/tmp/sca")],
            )
            return payload, error, "syft-sbom"

    payload, error = run_tool_json(root, GRYPE_IMAGE, ["dir:/workspace", "-o", "json"])
    return payload, error, "directory"


def temporary_sbom_dir(root: Path) -> tempfile.TemporaryDirectory:
    try:
        return tempfile.TemporaryDirectory(prefix="sca-sbom-", dir=str(root.parent))
    except OSError:
        return tempfile.TemporaryDirectory(prefix="sca-sbom-")


def run_tool_json(
    root: Path,
    image: str,
    args: list[str],
    extra_mounts: list[tuple[Path, str]] | None = None,
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
        command.extend(["-v", f"{host_path}:{container_path}:ro"])
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
