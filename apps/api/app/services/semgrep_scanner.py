from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any, Iterable

from app.models import Severity
from app.services.sast_noise import is_noise_path
from app.services.sast_scanner import ParsedFinding, SastScanOutput, detect_language, redact_evidence
from app.services.sast_semgrep_rules import BUILTIN_CONFIG, builtin_rule_pack_path


DEFAULT_SEMGREP_IMAGE = os.getenv("SAST_SEMGREP_IMAGE", "semgrep/semgrep:1.167.0")


class SemgrepUnavailable(RuntimeError):
    pass


def scan_with_semgrep(source_path: str, config: str = BUILTIN_CONFIG, timeout_seconds: int = 240, extra_configs: Iterable[Path] | None = None, include_paths: Iterable[str] | None = None) -> SastScanOutput:
    root = Path(source_path).expanduser().resolve()
    if not root.exists() or not root.is_dir():
        raise ValueError("source_path must be an existing directory")
    if config.startswith("p/"):
        raise SemgrepUnavailable("Remote Semgrep registry packs are disabled; use the built-in offline rules or an imported local rule pack")

    configs: list[str | Path] = [builtin_rule_pack_path() if config == BUILTIN_CONFIG else config]
    configs.extend(extra_configs or [])
    command = build_semgrep_command(root, configs, include_paths=include_paths)
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
    if completed.returncode not in {0, 1}:
        detail = (completed.stderr or completed.stdout or "Semgrep scan failed").strip()[:1000]
        raise SemgrepUnavailable(f"Semgrep 执行失败（exit {completed.returncode}）：{detail}")

    try:
        payload = json.loads(completed.stdout or "{}")
    except json.JSONDecodeError as exc:
        raise SemgrepUnavailable(f"Semgrep returned invalid JSON: {exc}") from exc
    errors = payload.get("errors")
    if isinstance(errors, list) and errors:
        messages = [str(item.get("message") or item) for item in errors[:3] if isinstance(item, dict)]
        raise SemgrepUnavailable("Semgrep 配置或扫描错误：" + "；".join(messages))

    findings = [
        parse_semgrep_result(item, root)
        for item in payload.get("results", [])
        if isinstance(item, dict) and not is_noise_path(normalize_path(str(item.get("path") or ""), root))
    ]
    scanned_files = sorted({finding.file_path for finding in findings})
    return SastScanOutput(findings=findings, scanned_files=scanned_files)


def build_semgrep_command(root: Path, configs: Iterable[str | Path], include_paths: Iterable[str] | None = None) -> list[str] | None:
    values = list(configs)
    config_args = [item for config in values for item in ("--config", str(config))]
    include_args = [item for path in (include_paths or []) for item in ("--include", path)]
    semgrep_path = shutil.which("semgrep")
    if semgrep_path:
        return [semgrep_path, "scan", "--json", "--metrics=off", "--disable-version-check", *config_args, *include_args, "--no-git-ignore", *semgrep_excludes(), "."]

    docker_path = shutil.which("docker")
    if docker_path:
        if not docker_image_available(docker_path, DEFAULT_SEMGREP_IMAGE):
            raise SemgrepUnavailable(
                f"本地未找到 Semgrep 镜像 {DEFAULT_SEMGREP_IMAGE}；平台不会自动联网拉取，请先离线导入镜像或通过 SAST_SEMGREP_IMAGE 指定已存在的镜像"
            )
        docker_mount_args: list[str] = []
        docker_config_args: list[str] = []
        for index, config in enumerate(values):
            if isinstance(config, Path) or Path(str(config)).is_absolute():
                path = Path(config).resolve()
                if not path.exists() or not (path.is_file() or path.is_dir()):
                    raise SemgrepUnavailable(f"Semgrep config path does not exist: {path}")
                mount = f"/sast-config/{index}"
                if path.is_dir():
                    docker_mount_args.extend(["-v", f"{path}:{mount}:ro"])
                    docker_config_args.extend(["--config", mount])
                else:
                    docker_mount_args.extend(["-v", f"{path.parent}:{mount}:ro"])
                    docker_config_args.extend(["--config", f"{mount}/{path.name}"])
            else:
                docker_config_args.extend(["--config", str(config)])
        return [
            docker_path,
            "run",
            "--rm",
            "--pull=never",
            "-v",
            f"{root}:/src:ro",
            "-w",
            "/src",
            *docker_mount_args,
            DEFAULT_SEMGREP_IMAGE,
            "semgrep",
            "scan",
            "--json",
            "--metrics=off",
            "--disable-version-check",
            *docker_config_args,
            *include_args,
            "--no-git-ignore",
            *semgrep_excludes(),
            ".",
        ]
    return None


def docker_image_available(docker_path: str, image: str) -> bool:
    """Check the exact local image without giving Docker an opportunity to pull it."""
    try:
        return subprocess.run(
            [docker_path, "image", "inspect", image],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=12,
        ).returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


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
