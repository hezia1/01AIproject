from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from typing import Any

from app.models import Severity
from app.services.sast_noise import is_noise_path
from app.services.sast_scanner import ParsedFinding, SastScanOutput, detect_language, redact_evidence


class SemgrepUnavailable(RuntimeError):
    pass


def scan_with_semgrep(source_path: str, config: str = "p/default", timeout_seconds: int = 240) -> SastScanOutput:
    root = Path(source_path).expanduser().resolve()
    if not root.exists() or not root.is_dir():
        raise ValueError("source_path must be an existing directory")

    command = build_semgrep_command(root, config)
    if command is None:
        raise SemgrepUnavailable("Semgrep CLI or Docker is not available")

    try:
        completed = subprocess.run(
            command,
            cwd=str(root),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout_seconds,
        )
    except subprocess.TimeoutExpired as exc:
        raise SemgrepUnavailable(f"Semgrep scan timed out after {timeout_seconds}s") from exc
    if completed.returncode not in {0, 1} and not completed.stdout.strip():
        raise SemgrepUnavailable((completed.stderr or completed.stdout or "Semgrep scan failed").strip()[:500])

    try:
        payload = json.loads(completed.stdout or "{}")
    except json.JSONDecodeError as exc:
        raise SemgrepUnavailable(f"Semgrep returned invalid JSON: {exc}") from exc

    findings = [
        parse_semgrep_result(item, root)
        for item in payload.get("results", [])
        if isinstance(item, dict) and not is_noise_path(normalize_path(str(item.get("path") or ""), root))
    ]
    scanned_files = sorted({finding.file_path for finding in findings})
    return SastScanOutput(findings=findings, scanned_files=scanned_files)


def build_semgrep_command(root: Path, config: str) -> list[str] | None:
    semgrep_path = shutil.which("semgrep")
    if semgrep_path:
        return [semgrep_path, "scan", "--json", "--config", config, "--no-git-ignore", *semgrep_excludes(), "."]

    docker_path = shutil.which("docker")
    if docker_path:
        return [
            docker_path,
            "run",
            "--rm",
            "-v",
            f"{root}:/src",
            "-w",
            "/src",
            "semgrep/semgrep:latest",
            "semgrep",
            "scan",
            "--json",
            "--config",
            config,
            "--no-git-ignore",
            *semgrep_excludes(),
            ".",
        ]
    return None


def semgrep_excludes() -> list[str]:
    patterns = [
        "node_modules",
        "dist",
        "build",
        "coverage",
        "target",
        "vendor",
        "vendors",
        "third_party",
        "bower_components",
        "public/assets",
        "public/vendor",
        "static/assets",
        "static/vendor",
        "*.min.js",
        "*.min.css",
        "*.bundle.js",
        "*.bundle.css",
        "*.map",
    ]
    return [item for pattern in patterns for item in ("--exclude", pattern)]


def parse_semgrep_result(item: dict[str, Any], root: Path) -> ParsedFinding:
    extra = item.get("extra") if isinstance(item.get("extra"), dict) else {}
    metadata = extra.get("metadata") if isinstance(extra.get("metadata"), dict) else {}
    file_path = normalize_path(str(item.get("path") or ""), root)
    line_start = int(item.get("start", {}).get("line") or 1)
    line_end = int(item.get("end", {}).get("line") or line_start)
    check_id = str(item.get("check_id") or "semgrep.unknown")
    title = str(extra.get("message") or check_id)
    rule_id = check_id if check_id.startswith("SEMGREP.") else f"SEMGREP.{check_id}"

    return ParsedFinding(
        rule_id=rule_id[:300],
        title=title[:300],
        severity=map_semgrep_severity(str(extra.get("severity") or metadata.get("severity") or "")),
        file_path=file_path,
        line_start=line_start,
        line_end=line_end,
        evidence=redact_evidence(str(extra.get("lines") or ""))[:500],
        category=metadata_value(metadata, "category") or metadata_value(metadata, "vulnerability_class") or "semgrep",
        cwe=metadata_value(metadata, "cwe") or "-",
        owasp=metadata_value(metadata, "owasp") or "-",
        description=title,
        remediation=metadata_value(metadata, "fix") or metadata_value(metadata, "technology") or "根据 Semgrep 规则说明修复代码，并执行复测。",
        language=detect_language(Path(file_path)),
    )


def normalize_path(path: str, root: Path) -> str:
    candidate = Path(path)
    if candidate.is_absolute():
        try:
            return candidate.relative_to(root).as_posix()
        except ValueError:
            return candidate.name
    return path.replace("\\", "/")


def map_semgrep_severity(value: str) -> Severity:
    normalized = value.lower()
    if normalized in {"critical", "error"}:
        return Severity.high
    if normalized in {"high", "warning"}:
        return Severity.medium
    if normalized in {"low", "info", "inventory"}:
        return Severity.low
    return Severity.medium


def metadata_value(metadata: dict[str, Any], key: str) -> str | None:
    value = metadata.get(key)
    if value is None:
        return None
    if isinstance(value, list):
        return ", ".join(str(item) for item in value if item)
    if isinstance(value, dict):
        return ", ".join(f"{item_key}: {item_value}" for item_key, item_value in value.items())
    return str(value)
