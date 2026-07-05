from __future__ import annotations

import re
import shutil
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path


class SandboxCommandRejected(ValueError):
    pass


@dataclass(frozen=True)
class SandboxRunResult:
    command: str
    cwd: str
    runtime_profile: str
    image: str | None
    exit_code: int | None
    stdout: str
    stderr: str
    elapsed_ms: int
    timed_out: bool
    evidence_summary: str


BLOCKED_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"\brm\s+-[^\n\r;|&]*r[^\n\r;|&]*f\b", re.IGNORECASE),
    re.compile(r"\bdel\s+(/[a-z]*s|-[a-z]*s)\b", re.IGNORECASE),
    re.compile(r"\b(rd|rmdir)\s+(/[a-z]*s|-[a-z]*s)\b", re.IGNORECASE),
    re.compile(r"\bremove-item\b.*\b-recurse\b", re.IGNORECASE),
    re.compile(r"\bformat\b", re.IGNORECASE),
    re.compile(r"\bshutdown\b", re.IGNORECASE),
    re.compile(r"\breg\s+delete\b", re.IGNORECASE),
    re.compile(r"\bdiskpart\b", re.IGNORECASE),
    re.compile(r"\bmkfs(\.|$|\s)", re.IGNORECASE),
)

SECRET_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"(?i)(password|passwd|secret|token|api[_-]?key)\s*[:=]\s*([^\s,;]+)"),
)


def run_sandbox_command(command: str, workdir: str | None, timeout_seconds: int = 10, image: str | None = None) -> SandboxRunResult:
    normalized = command.strip()
    if not normalized:
        raise SandboxCommandRejected("run_command cannot be empty")
    _reject_unsafe_command(normalized)

    cwd = _resolve_workdir(workdir)
    selected_image = image or infer_image(cwd)
    if selected_image is None:
        raise SandboxCommandRejected("No Docker image could be inferred for this project. Select a sandbox command template first.")
    docker_command = build_docker_command(cwd, normalized, selected_image)
    started = time.perf_counter()
    timed_out = False
    exit_code: int | None
    stdout = ""
    stderr = ""

    try:
        completed = subprocess.run(
            docker_command,
            cwd=str(cwd),
            shell=False,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            encoding="utf-8",
            errors="replace",
        )
        exit_code = completed.returncode
        stdout = completed.stdout
        stderr = completed.stderr
    except subprocess.TimeoutExpired as exc:
        timed_out = True
        exit_code = None
        stdout = _to_text(exc.stdout)
        stderr = _to_text(exc.stderr) or f"Command timed out after {timeout_seconds}s"

    elapsed_ms = int((time.perf_counter() - started) * 1000)
    stdout = _sanitize_output(stdout)
    stderr = _sanitize_output(stderr)

    return SandboxRunResult(
        command=normalized,
        cwd=str(cwd),
        runtime_profile="docker-isolated-v1",
        image=selected_image,
        exit_code=exit_code,
        stdout=stdout,
        stderr=stderr,
        elapsed_ms=elapsed_ms,
        timed_out=timed_out,
        evidence_summary=_build_summary(exit_code, elapsed_ms, timed_out, stdout, stderr),
    )


def _reject_unsafe_command(command: str) -> None:
    for pattern in BLOCKED_PATTERNS:
        if pattern.search(command):
            raise SandboxCommandRejected("Command is blocked by the local sandbox safety policy")


def build_docker_command(workdir: Path, command: str, image: str) -> list[str]:
    docker_path = shutil.which("docker")
    if docker_path is None:
        raise SandboxCommandRejected("Docker is required for isolated SANDBOX execution but was not found")
    return [
        docker_path,
        "run",
        "--rm",
        "--network",
        "none",
        "--read-only",
        "--cpus",
        "1",
        "--memory",
        "512m",
        "--pids-limit",
        "128",
        "--security-opt",
        "no-new-privileges",
        "--tmpfs",
        "/tmp:rw,noexec,nosuid,size=128m",
        "-v",
        f"{workdir}:/workspace:ro",
        "-w",
        "/workspace",
        image,
        "sh",
        "-lc",
        command,
    ]


def infer_image(workdir: Path) -> str | None:
    if (workdir / "package.json").exists():
        return "node:20-alpine"
    if any((workdir / name).exists() for name in ["requirements.txt", "pyproject.toml", "setup.py"]) or list(workdir.glob("*.py")):
        return "python:3.12-slim"
    if (workdir / "go.mod").exists():
        return "golang:1.22-alpine"
    if (workdir / "pom.xml").exists():
        return "maven:3.9-eclipse-temurin-21"
    if (workdir / "Dockerfile").exists():
        return "alpine:3.20"
    return None


def _resolve_workdir(workdir: str | None) -> Path:
    if workdir:
        candidate = Path(workdir).expanduser()
        if candidate.exists() and candidate.is_dir():
            return candidate.resolve()
    return Path.cwd().resolve()


def _to_text(value: str | bytes | None) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return value


def _sanitize_output(value: str, limit: int = 4000) -> str:
    redacted = value
    for pattern in SECRET_PATTERNS:
        redacted = pattern.sub(lambda match: f"{match.group(1)}=[redacted]", redacted)
    return redacted[:limit]


def _build_summary(exit_code: int | None, elapsed_ms: int, timed_out: bool, stdout: str, stderr: str) -> str:
    status = "timeout" if timed_out else f"exit_code={exit_code}"
    output = _first_line(stdout) or _first_line(stderr) or "no output"
    return f"Command completed with {status}, elapsed={elapsed_ms}ms, output={output}"


def _first_line(value: str) -> str:
    for line in value.splitlines():
        stripped = line.strip()
        if stripped:
            return stripped[:220]
    return ""
