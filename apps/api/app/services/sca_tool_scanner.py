from __future__ import annotations

import json
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import unquote

from app.services.sca_parser import ParsedComponent


SYFT_IMAGE = "anchore/syft:latest"
GRYPE_IMAGE = "anchore/grype:latest"
TOOL_TIMEOUT_SECONDS = 120


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


def scan_with_syft_grype(source_path: str) -> ToolScanResult:
    root = Path(source_path).expanduser().resolve()
    if not root.exists() or not root.is_dir():
        return ToolScanResult(components=[], vulnerabilities=[], errors=["source_path must be an existing directory"])
    if shutil.which("docker") is None:
        return ToolScanResult(components=[], vulnerabilities=[], errors=["Docker CLI was not found"])

    errors: list[str] = []
    syft_components: list[ParsedComponent] = []
    grype_vulnerabilities: list[ToolVulnerability] = []

    syft_payload, syft_error = run_tool_json(root, SYFT_IMAGE, ["dir:/workspace", "-o", "cyclonedx-json"])
    if syft_error:
        errors.append(f"Syft failed: {syft_error}")
    elif syft_payload:
        syft_components = parse_syft_cyclonedx(syft_payload)

    grype_payload, grype_error = run_tool_json(root, GRYPE_IMAGE, ["dir:/workspace", "-o", "json"])
    if grype_error:
        errors.append(f"Grype failed: {grype_error}")
    elif grype_payload:
        grype_vulnerabilities = parse_grype_json(grype_payload)

    return ToolScanResult(
        components=syft_components,
        vulnerabilities=grype_vulnerabilities,
        errors=errors,
    )


def run_tool_json(root: Path, image: str, args: list[str]) -> tuple[dict | None, str | None]:
    command = [
        "docker",
        "run",
        "--rm",
        "-v",
        f"{root}:/workspace:ro",
        "-w",
        "/workspace",
        image,
        *args,
    ]
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
        return None, first_line(completed.stderr) or first_line(completed.stdout) or f"exit code {completed.returncode}"
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


def first_line(value: str) -> str:
    for line in value.splitlines():
        stripped = line.strip()
        if stripped:
            return stripped[:260]
    return ""


def purl_name(purl: str | None) -> str | None:
    if not purl or "@" not in purl:
        return None
    path = purl.removeprefix("pkg:").split("/", 1)[-1].split("@", 1)[0]
    return unquote(path) or None
