from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import time
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path
from typing import Callable
from uuid import uuid4

from app.services.agent_runtime_validation import image_is_digest_pinned, safe_identifier, staging_workspace_path
from app.services.agent_staging import build_filtered_staging


FIXTURE_RUNTIME_SCHEMA = "ai-security-platform.agent-fixture-runtime-evidence/v1"
FIXTURE_ROOT = Path(__file__).resolve().parents[2] / "tests" / "fixtures" / "agent_runtime_safe"
EVIDENCE_ROOT = Path(__file__).resolve().parents[4] / "artifacts" / "agent-sandbox" / "fixture-evidence"
FIXED_CONTAINER_COMMAND = ["python", "-I", "-B", "/workspace/policy_probe.py"]
MAX_OUTPUT_CHARACTERS = 16_000
RunCommand = Callable[..., subprocess.CompletedProcess[str]]


class FixtureRuntimeRejected(ValueError):
    pass


def list_local_fixture_images(run_command: RunCommand = subprocess.run) -> dict[str, object]:
    docker = docker_executable()
    docker_context = ensure_local_docker_context(docker, run_command)
    completed = run_command(
        [docker, "image", "ls", "python", "--digests", "--format", "{{json .}}"],
        shell=False,
        capture_output=True,
        text=True,
        timeout=10,
        encoding="utf-8",
        errors="replace",
    )
    images: list[dict[str, str]] = []
    if completed.returncode == 0:
        for line in completed.stdout.splitlines():
            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                continue
            repository = str(item.get("Repository") or "")
            digest = str(item.get("Digest") or "")
            if not repository or not re.fullmatch(r"sha256:[0-9a-f]{64}", digest):
                continue
            reference = f"{repository}@{digest}"
            if valid_fixture_image(reference):
                images.append({
                    "reference": reference,
                    "repository": repository,
                    "digest": digest,
                    "image_id": str(item.get("ID") or ""),
                    "size": str(item.get("Size") or "unknown"),
                })
    return {
        "available": bool(images),
        "images": images,
        "download_performed": False,
        "recommended_image": images[0]["reference"] if images else None,
        "docker_context": docker_context,
        "message": (
            "A local digest-pinned Python image is available; no download is required."
            if images else "No local digest-pinned Python image is available. This endpoint never downloads one."
        ),
    }


def run_harmless_fixture_validation(
    *,
    project_id: str,
    image: str,
    timeout_seconds: int = 5,
    run_command: RunCommand = subprocess.run,
) -> dict[str, object]:
    normalized_image = image.strip()
    if not valid_fixture_image(normalized_image):
        raise FixtureRuntimeRejected("Fixture validation requires a credential-free python@sha256:<digest> image reference.")
    timeout = max(1, min(15, int(timeout_seconds)))
    docker = docker_executable()
    docker_context = ensure_local_docker_context(docker, run_command)
    inspected_image = inspect_local_image(docker, normalized_image, run_command)
    staging = build_filtered_staging(
        source_path=str(FIXTURE_ROOT),
        project_id=f"fixture-{project_id}",
        destination_root=staging_workspace_path(f"fixture-{project_id}"),
    )
    staging_path = Path(str(staging["destination_path"])).resolve(strict=True)
    run_id = f"fixture-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}-{uuid4().hex[:10]}"
    container_name = f"ai-agent-fixture-{uuid4().hex[:12]}"
    create_command = build_fixture_container_command(
        docker=docker,
        container_name=container_name,
        staging_path=staging_path,
        image=normalized_image,
    )
    started_at = datetime.now(timezone.utc)
    started_clock = time.perf_counter()
    container_id: str | None = None
    inspect_payload: dict[str, object] = {}
    stdout = ""
    stderr = ""
    exit_code: int | None = None
    timed_out = False
    cleanup_succeeded = False
    docker_environment = os.environ.copy()
    docker_environment["AGENT_HOST_CANARY"] = "present-on-host-cli-only"
    try:
        created = run_command(
            create_command,
            shell=False,
            capture_output=True,
            text=True,
            timeout=15,
            encoding="utf-8",
            errors="replace",
            env=docker_environment,
        )
        if created.returncode != 0:
            raise FixtureRuntimeRejected(f"Docker refused the fixed fixture policy: {sanitize_output(created.stderr)}")
        container_id = created.stdout.strip()
        if not re.fullmatch(r"[0-9a-f]{12,64}", container_id):
            raise FixtureRuntimeRejected("Docker returned an invalid container identifier.")
        inspect_payload = inspect_container(docker, container_id, run_command)
        try:
            executed = run_command(
                [docker, "start", "--attach", container_id],
                shell=False,
                capture_output=True,
                text=True,
                timeout=timeout,
                encoding="utf-8",
                errors="replace",
                env=docker_environment,
            )
            stdout = executed.stdout
            stderr = executed.stderr
            exit_code = executed.returncode
        except subprocess.TimeoutExpired as exc:
            timed_out = True
            stdout = to_text(exc.stdout)
            stderr = to_text(exc.stderr) or f"Fixture timed out after {timeout} seconds."
            run_command(
                [docker, "kill", container_id], shell=False, capture_output=True, text=True,
                timeout=10, encoding="utf-8", errors="replace",
            )
        final_state = inspect_container(docker, container_id, run_command).get("State")
        if isinstance(final_state, dict) and not timed_out:
            state_exit_code = final_state.get("ExitCode")
            if isinstance(state_exit_code, int):
                exit_code = state_exit_code
    finally:
        if container_id and re.fullmatch(r"[0-9a-f]{12,64}", container_id):
            removed = run_command(
                [docker, "rm", "--force", container_id], shell=False, capture_output=True, text=True,
                timeout=10, encoding="utf-8", errors="replace",
            )
            cleanup_succeeded = removed.returncode == 0

    elapsed_ms = int((time.perf_counter() - started_clock) * 1000)
    stdout = sanitize_output(stdout)
    stderr = sanitize_output(stderr)
    probe = parse_probe_output(stdout)
    configured_policy = configured_policy_checks(inspect_payload, staging_path, normalized_image)
    probe_checks = probe.get("checks") if isinstance(probe.get("checks"), dict) else {}
    cgroup = probe.get("cgroup") if isinstance(probe.get("cgroup"), dict) else {}
    observed_limits = observed_limit_checks(cgroup)
    all_checks = {
        **configured_policy,
        **{f"probe_{key}": value is True for key, value in probe_checks.items()},
        **observed_limits,
        "container_exit_zero": exit_code == 0,
        "container_not_timed_out": not timed_out,
        "container_cleanup_succeeded": cleanup_succeeded,
    }
    decision = "pass" if all_checks and all(all_checks.values()) else "block"
    finished_at = datetime.now(timezone.utc)
    evidence: dict[str, object] = {
        "schema": FIXTURE_RUNTIME_SCHEMA,
        "scope": "repository-harmless-fixture-only",
        "decision": decision,
        "execution_enabled_for_real_agents": False,
        "run_id": run_id,
        "project_id": project_id,
        "started_at": started_at.isoformat(),
        "finished_at": finished_at.isoformat(),
        "elapsed_ms": elapsed_ms,
        "image": {
            "reference": normalized_image,
            "digest": normalized_image.rsplit("@", 1)[1],
            "local_image_id": inspected_image.get("Id"),
            "download_performed": False,
        },
        "docker_context": docker_context,
        "staging": {
            "path": str(staging_path),
            "staging_sha256": staging.get("staging_sha256"),
            "manifest_sha256": staging.get("manifest_sha256"),
            "verification": staging.get("verification"),
        },
        "container": {
            "name": container_name,
            "id_sha256": sha256(str(container_id or "").encode("utf-8")).hexdigest(),
            "command": FIXED_CONTAINER_COMMAND,
            "exit_code": exit_code,
            "timed_out": timed_out,
            "removed_after_run": cleanup_succeeded,
        },
        "policy_checks": all_checks,
        "configured_policy": configured_policy,
        "probe": probe,
        "output": {
            "stdout": stdout,
            "stderr": stderr,
            "truncated": len(stdout) >= MAX_OUTPUT_CHARACTERS or len(stderr) >= MAX_OUTPUT_CHARACTERS,
            "redacted": True,
        },
        "limitations": [
            "This validates only the bundled harmless fixture, not a project Agent, MCP server, plugin or tool.",
            "Docker configuration and in-container probes support the listed controls but are not kernel-level forensic telemetry.",
            "No host source directory, credential file, environment variable or Docker control socket was mounted into the container.",
        ],
    }
    evidence["evidence_sha256"] = sha256(
        json.dumps(evidence, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    evidence_path = write_fixture_evidence(project_id, run_id, evidence)
    evidence["evidence_path"] = str(evidence_path)
    return evidence


def build_fixture_container_command(
    *, docker: str, container_name: str, staging_path: Path, image: str,
) -> list[str]:
    return [
        docker, "create", "--pull=never", "--name", container_name,
        "--label", "ai-security-platform.scope=agent-harmless-fixture",
        "--network", "none", "--read-only", "--cpus", "0.5",
        "--memory", "128m", "--pids-limit", "32", "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges:true", "--user", "65534:65534",
        "--tmpfs", "/tmp:rw,noexec,nosuid,size=16m",
        "--mount", f"type=bind,src={staging_path},dst=/workspace,readonly",
        "--workdir", "/workspace", image, *FIXED_CONTAINER_COMMAND,
    ]


def configured_policy_checks(
    inspected: dict[str, object], staging_path: Path, image: str,
) -> dict[str, bool]:
    host = inspected.get("HostConfig") if isinstance(inspected.get("HostConfig"), dict) else {}
    config = inspected.get("Config") if isinstance(inspected.get("Config"), dict) else {}
    mounts = inspected.get("Mounts") if isinstance(inspected.get("Mounts"), list) else []
    security_options = {str(value) for value in host.get("SecurityOpt", [])} if isinstance(host.get("SecurityOpt"), list) else set()
    cap_drop = {str(value).upper() for value in host.get("CapDrop", [])} if isinstance(host.get("CapDrop"), list) else set()
    workspace_mount = next((item for item in mounts if isinstance(item, dict) and item.get("Destination") == "/workspace"), {})
    tmpfs = host.get("Tmpfs") if isinstance(host.get("Tmpfs"), dict) else {}
    command = config.get("Cmd") if isinstance(config.get("Cmd"), list) else []
    configured_image = str(config.get("Image") or "")
    return {
        "image_digest_exact": configured_image == image,
        "fixed_command_exact": command == FIXED_CONTAINER_COMMAND,
        "network_none": str(host.get("NetworkMode") or "") == "none",
        "root_filesystem_read_only": host.get("ReadonlyRootfs") is True,
        "workspace_read_only": bool(workspace_mount) and workspace_mount.get("RW") is False,
        "workspace_source_exact": Path(str(workspace_mount.get("Source") or "")).resolve(strict=False) == staging_path.resolve(strict=False),
        "capabilities_drop_all": "ALL" in cap_drop,
        "no_new_privileges": any(value.startswith("no-new-privileges") for value in security_options),
        "not_privileged": host.get("Privileged") is False,
        "non_root_user": str(config.get("User") or "") == "65534:65534",
        "cpu_limit": int(host.get("NanoCpus") or 0) == 500_000_000,
        "memory_limit": int(host.get("Memory") or 0) == 128 * 1024 * 1024,
        "pids_limit": int(host.get("PidsLimit") or 0) == 32,
        "tmpfs_limited": "/tmp" in tmpfs and "noexec" in str(tmpfs.get("/tmp")) and "size=16m" in str(tmpfs.get("/tmp")),
        "no_host_socket_mount": all(
            not any(token in str(item.get("Source") or "").lower() for token in ("docker.sock", "podman.sock", "containerd.sock"))
            for item in mounts if isinstance(item, dict)
        ),
        "only_workspace_mount": len([item for item in mounts if isinstance(item, dict) and item.get("Type") == "bind"]) == 1,
        "host_environment_not_injected": not any(
            str(value).startswith("AGENT_HOST_CANARY=") for value in config.get("Env", [])
        ) if isinstance(config.get("Env"), list) else True,
    }


def observed_limit_checks(cgroup: dict[str, object]) -> dict[str, bool]:
    cpu = str(cgroup.get("cpu_max") or "")
    cpu_parts = cpu.split()
    cpu_ok = False
    if len(cpu_parts) == 2 and all(part.isdigit() for part in cpu_parts):
        quota, period = int(cpu_parts[0]), int(cpu_parts[1])
        cpu_ok = period > 0 and quota / period <= 0.5
    return {
        "probe_cpu_limit_observed": cpu_ok,
        "probe_memory_limit_observed": str(cgroup.get("memory_max") or "") == str(128 * 1024 * 1024),
        "probe_pids_limit_observed": str(cgroup.get("pids_max") or "") == "32",
    }


def inspect_local_image(docker: str, image: str, run_command: RunCommand) -> dict[str, object]:
    completed = run_command(
        [docker, "image", "inspect", image], shell=False, capture_output=True, text=True,
        timeout=10, encoding="utf-8", errors="replace",
    )
    if completed.returncode != 0:
        raise FixtureRuntimeRejected("The exact digest-pinned fixture image is not available locally; no image was downloaded.")
    try:
        payload = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise FixtureRuntimeRejected("Docker returned invalid local image metadata.") from exc
    if not isinstance(payload, list) or not payload or not isinstance(payload[0], dict):
        raise FixtureRuntimeRejected("Docker returned no local image metadata.")
    return payload[0]


def inspect_container(docker: str, container_id: str, run_command: RunCommand) -> dict[str, object]:
    completed = run_command(
        [docker, "container", "inspect", container_id], shell=False, capture_output=True, text=True,
        timeout=10, encoding="utf-8", errors="replace",
    )
    if completed.returncode != 0:
        raise FixtureRuntimeRejected("The temporary fixture container could not be inspected.")
    try:
        payload = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise FixtureRuntimeRejected("Docker returned invalid container policy metadata.") from exc
    if not isinstance(payload, list) or not payload or not isinstance(payload[0], dict):
        raise FixtureRuntimeRejected("Docker returned no container policy metadata.")
    return payload[0]


def parse_probe_output(stdout: str) -> dict[str, object]:
    lines = [line.strip() for line in stdout.splitlines() if line.strip()]
    if len(lines) != 1:
        return {"schema": None, "checks": {}, "cgroup": {}, "parse_error": "Expected exactly one JSON output line."}
    try:
        payload = json.loads(lines[0])
    except json.JSONDecodeError:
        return {"schema": None, "checks": {}, "cgroup": {}, "parse_error": "Fixture output was not valid JSON."}
    if not isinstance(payload, dict) or payload.get("schema") != "ai-security-platform.agent-fixture-probe/v1":
        return {"schema": None, "checks": {}, "cgroup": {}, "parse_error": "Fixture output schema was invalid."}
    return payload


def valid_fixture_image(image: str) -> bool:
    if not image_is_digest_pinned(image):
        return False
    prefix = image.rsplit("@sha256:", 1)[0]
    allowed_repositories = {"python", "docker.io/library/python", "registry-1.docker.io/library/python"}
    return prefix.lower() in allowed_repositories and not any(
        token in image.lower() for token in ("token=", "password=", "secret=")
    )


def ensure_local_docker_context(docker: str, run_command: RunCommand) -> dict[str, str]:
    configured_host = os.environ.get("DOCKER_HOST", "").strip()
    if configured_host and not configured_host.lower().startswith(("npipe://", "unix://")):
        raise FixtureRuntimeRejected("Remote Docker hosts are not allowed for fixture validation.")
    completed = run_command(
        [docker, "context", "inspect", "--format", "{{json .Endpoints.docker.Host}}"],
        shell=False, capture_output=True, text=True, timeout=10, encoding="utf-8", errors="replace",
    )
    if completed.returncode != 0:
        raise FixtureRuntimeRejected("The active Docker context could not be verified as local.")
    try:
        endpoint = json.loads(completed.stdout.strip())
    except json.JSONDecodeError as exc:
        raise FixtureRuntimeRejected("Docker returned invalid context metadata.") from exc
    if not isinstance(endpoint, str) or not endpoint.lower().startswith(("npipe://", "unix://")):
        raise FixtureRuntimeRejected("Remote Docker contexts are not allowed for fixture validation.")
    return {"endpoint_type": "npipe" if endpoint.lower().startswith("npipe://") else "unix", "remote": "false"}


def docker_executable() -> str:
    docker = shutil.which("docker")
    if docker is None:
        raise FixtureRuntimeRejected("Docker CLI is unavailable; no installation or download was attempted.")
    return docker


def sanitize_output(value: str) -> str:
    redacted = re.sub(
        r"(?i)(password|passwd|secret|token|api[_-]?key)\s*[:=]\s*([^\s,;]+)",
        lambda match: f"{match.group(1)}=[redacted]",
        value,
    )
    return redacted[:MAX_OUTPUT_CHARACTERS]


def to_text(value: str | bytes | None) -> str:
    if value is None:
        return ""
    return value.decode("utf-8", errors="replace") if isinstance(value, bytes) else value


def write_fixture_evidence(project_id: str, run_id: str, evidence: dict[str, object]) -> Path:
    project_root = EVIDENCE_ROOT / safe_identifier(project_id)
    project_root.mkdir(parents=True, exist_ok=True)
    path = project_root / f"{safe_identifier(run_id)}.json"
    with path.open("x", encoding="utf-8") as handle:
        json.dump(evidence, handle, ensure_ascii=False, indent=2)
    return path


def list_fixture_evidence(project_id: str, limit: int = 20) -> list[dict[str, object]]:
    project_root = EVIDENCE_ROOT / safe_identifier(project_id)
    if not project_root.exists():
        return []
    resolved_root = project_root.resolve(strict=True)
    if not resolved_root.is_dir() or resolved_root.is_symlink():
        raise FixtureRuntimeRejected("Fixture evidence directory is unsafe.")
    results: list[dict[str, object]] = []
    for path in sorted(resolved_root.glob("fixture-*.json"), reverse=True)[:max(1, min(100, limit))]:
        if path.is_symlink() or not path.is_file() or path.stat().st_size > 2 * 1024 * 1024:
            continue
        try:
            item = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if isinstance(item, dict) and item.get("schema") == FIXTURE_RUNTIME_SCHEMA:
            results.append({**item, "evidence_path": str(path)})
    return results
