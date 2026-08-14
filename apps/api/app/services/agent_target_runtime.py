from __future__ import annotations

import hmac
import json
import os
import re
import shlex
import shutil
import subprocess
import time
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path
from typing import Callable
from uuid import uuid4

from app.services.agent_runtime_validation import (
    command_check,
    image_is_digest_pinned,
    redact_command,
    safe_identifier,
    staging_workspace_path,
)
from app.services.agent_staging import (
    is_link_or_junction,
    load_filtered_staging_manifest,
    verify_filtered_staging,
)


TARGET_RUNTIME_SCHEMA = "ai-security-platform.agent-target-runtime-evidence/v1"
EVIDENCE_ROOT = Path(__file__).resolve().parents[4] / "artifacts" / "agent-sandbox" / "target-evidence"
AUTHORIZATION_PHRASE = "RUN ISOLATED AGENT"
MAX_OUTPUT_CHARACTERS = 16_000
MAX_COMMAND_TOKENS = 64
RunCommand = Callable[..., subprocess.CompletedProcess[str]]


class TargetRuntimeRejected(ValueError):
    pass


def list_target_runtime_status(project_id: str, execution_enabled: bool) -> dict[str, object]:
    builds: list[dict[str, object]] = []
    root = staging_workspace_path(project_id)
    if root.exists():
        resolved_root = root.resolve(strict=True)
        if not resolved_root.is_dir() or is_link_or_junction(resolved_root):
            raise TargetRuntimeRejected("The target staging root is unsafe.")
        for path in sorted(resolved_root.iterdir(), key=lambda item: item.name, reverse=True)[:100]:
            if not path.is_dir() or is_link_or_junction(path) or path.name.startswith("."):
                continue
            try:
                manifest = load_filtered_staging_manifest(path)
            except (OSError, ValueError, json.JSONDecodeError):
                continue
            binding = manifest.get("binding") if isinstance(manifest.get("binding"), dict) else {}
            if binding.get("schema") != "ai-security-platform.agent-staging-binding/v1":
                continue
            builds.append({
                "build_id": str(manifest.get("build_id") or path.name),
                "created_at": manifest.get("created_at"),
                "destination_path": str(path),
                "staging_sha256": manifest.get("staging_sha256"),
                "manifest_sha256": manifest.get("manifest_sha256"),
                "scan_task_id": binding.get("scan_task_id"),
                "plan_sha256": binding.get("plan_sha256"),
                "command_sha256": binding.get("command_sha256"),
                "image": binding.get("image"),
                "timeout_seconds": binding.get("timeout_seconds"),
                "file_count": int((manifest.get("summary") or {}).get("copied_file_count") or 0),
            })
            if len(builds) >= 20:
                break
    return {
        "schema": "ai-security-platform.agent-target-runtime-status/v1",
        "execution_enabled_by_project_policy": bool(execution_enabled),
        "authorization_phrase": AUTHORIZATION_PHRASE,
        "builds": builds,
        "download_performed": False,
        "message": (
            "Target execution is enabled by project policy; an exact verified build and separate confirmation are still required."
            if execution_enabled
            else "Target execution is disabled by default. Enable the project policy only after reviewing the exact target."
        ),
    }


def run_target_agent_validation(
    *,
    project_id: str,
    scan_task_id: str,
    command: str,
    image: str,
    timeout_seconds: int,
    plan_sha256: str,
    staging_build_id: str,
    staging_sha256: str,
    manifest_sha256: str,
    authorization_phrase: str,
    operator_confirmed: bool,
    dataflow: dict[str, object] | None,
    run_command: RunCommand = subprocess.run,
) -> dict[str, object]:
    if not operator_confirmed or not hmac.compare_digest(authorization_phrase, AUTHORIZATION_PHRASE):
        raise TargetRuntimeRejected("Exact target execution requires the separate authorization phrase and confirmation.")
    normalized_command = command.strip()
    normalized_image = image.strip()
    timeout = max(1, min(30, int(timeout_seconds)))
    validate_command_and_image(normalized_command, normalized_image)
    command_tokens = parse_command_tokens(normalized_command)
    staging_path = resolve_bound_staging(project_id, staging_build_id)
    manifest = load_filtered_staging_manifest(staging_path)
    verification = verify_filtered_staging(staging_path)
    verify_execution_binding(
        manifest=manifest,
        scan_task_id=scan_task_id,
        command=normalized_command,
        image=normalized_image,
        timeout_seconds=timeout,
        plan_sha256=plan_sha256,
        staging_sha256=staging_sha256,
        manifest_sha256=manifest_sha256,
    )

    docker = docker_executable()
    docker_context = ensure_local_docker_context(docker, run_command)
    inspected_image = inspect_local_image(docker, normalized_image, run_command)
    execution_id = f"target-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}-{uuid4().hex[:10]}"
    container_name = f"ai-agent-target-{uuid4().hex[:12]}"
    create_command = build_target_container_command(
        docker=docker,
        container_name=container_name,
        staging_path=staging_path,
        image=normalized_image,
        command_tokens=command_tokens,
    )
    started_at = datetime.now(timezone.utc)
    started_clock = time.perf_counter()
    container_id: str | None = None
    inspect_payload: dict[str, object] = {}
    exit_code: int | None = None
    timed_out = False
    cleanup_succeeded = False
    stdout = ""
    stderr = ""
    docker_environment = os.environ.copy()
    docker_environment["AGENT_HOST_CANARY"] = "present-on-host-cli-only"
    try:
        created = run_command(
            create_command, shell=False, capture_output=True, text=True, timeout=15,
            encoding="utf-8", errors="replace", env=docker_environment,
        )
        if created.returncode != 0:
            raise TargetRuntimeRejected(f"Docker refused the fixed target policy: {sanitize_output(created.stderr)}")
        container_id = created.stdout.strip()
        if not re.fullmatch(r"[0-9a-f]{12,64}", container_id):
            raise TargetRuntimeRejected("Docker returned an invalid target container identifier.")
        inspect_payload = inspect_container(docker, container_id, run_command)
        configured_checks = configured_policy_checks(
            inspect_payload, staging_path, normalized_image, command_tokens
        )
        if not configured_checks or not all(configured_checks.values()):
            failed = ", ".join(key for key, value in configured_checks.items() if not value)
            raise TargetRuntimeRejected(f"Created container failed closed policy verification: {failed}")
        started = run_command(
            [docker, "start", container_id], shell=False, capture_output=True, text=True,
            timeout=10, encoding="utf-8", errors="replace", env=docker_environment,
        )
        if started.returncode != 0:
            raise TargetRuntimeRejected(f"Docker could not start the isolated target: {sanitize_output(started.stderr)}")
        try:
            waited = run_command(
                [docker, "wait", container_id], shell=False, capture_output=True, text=True,
                timeout=timeout, encoding="utf-8", errors="replace", env=docker_environment,
            )
            if waited.returncode != 0:
                stderr = waited.stderr
        except subprocess.TimeoutExpired:
            timed_out = True
            run_command(
                [docker, "kill", container_id], shell=False, capture_output=True, text=True,
                timeout=10, encoding="utf-8", errors="replace",
            )
        final_inspect = inspect_container(docker, container_id, run_command)
        state = final_inspect.get("State") if isinstance(final_inspect.get("State"), dict) else {}
        state_exit_code = state.get("ExitCode")
        exit_code = state_exit_code if isinstance(state_exit_code, int) else None
        logs = run_command(
            [docker, "logs", "--tail", "200", container_id], shell=False,
            capture_output=True, text=True, timeout=10, encoding="utf-8", errors="replace",
        )
        stdout = logs.stdout
        stderr = "\n".join(value for value in (stderr, logs.stderr) if value)
    finally:
        if container_id and re.fullmatch(r"[0-9a-f]{12,64}", container_id):
            try:
                removed = run_command(
                    [docker, "rm", "--force", container_id], shell=False, capture_output=True,
                    text=True, timeout=10, encoding="utf-8", errors="replace",
                )
                cleanup_succeeded = removed.returncode == 0
            except subprocess.TimeoutExpired:
                cleanup_succeeded = False

    after_verification = verify_filtered_staging(staging_path)
    configured_checks = configured_policy_checks(
        inspect_payload, staging_path, normalized_image, command_tokens
    )
    policy_checks = {
        **configured_checks,
        "staging_verified_before_run": verification.get("status") == "verified",
        "staging_unchanged_after_run": hmac.compare_digest(
            str(verification.get("staging_sha256") or ""),
            str(after_verification.get("staging_sha256") or ""),
        ),
        "container_cleanup_succeeded": cleanup_succeeded,
    }
    observations = {
        "processes": [{
            "id": "container-main-process",
            "capability": "server-process",
            "outcome": "observed",
            "exit_code": exit_code,
            "timed_out": timed_out,
        }],
        "file_access": [],
        "network_attempts": [],
        "tool_calls": [],
    }
    dataflow_paths = (
        dataflow.get("paths") if isinstance(dataflow, dict) and isinstance(dataflow.get("paths"), list) else []
    )
    path_results = limited_path_results(
        [item for item in dataflow_paths if isinstance(item, dict)]
    )
    policy_verified = bool(policy_checks) and all(policy_checks.values())
    finished_at = datetime.now(timezone.utc)
    stdout = sanitize_output(stdout)
    stderr = sanitize_output(stderr)
    evidence: dict[str, object] = {
        "schema": TARGET_RUNTIME_SCHEMA,
        "scope": "project-agent-target",
        "status": "completed",
        "decision": "pass" if policy_verified and not timed_out else "attention",
        "execution_id": execution_id,
        "project_id": project_id,
        "scan_task_id": scan_task_id,
        "started_at": started_at.isoformat(),
        "finished_at": finished_at.isoformat(),
        "elapsed_ms": int((time.perf_counter() - started_clock) * 1000),
        "policy_verified": policy_verified,
        "behavioral_telemetry_complete": False,
        "plan_sha256": plan_sha256,
        "image": {
            "reference": normalized_image,
            "digest": normalized_image.rsplit("@", 1)[1],
            "local_image_id": inspected_image.get("Id"),
            "download_performed": False,
        },
        "staging": {
            "build_id": staging_build_id,
            "path": str(staging_path),
            "staging_sha256": verification.get("staging_sha256"),
            "manifest_sha256": verification.get("manifest_sha256"),
            "unchanged_after_run": policy_checks["staging_unchanged_after_run"],
        },
        "container": {
            "id_sha256": sha256(str(container_id or "").encode("utf-8")).hexdigest(),
            "command_sha256": sha256(normalized_command.encode("utf-8")).hexdigest(),
            "command_preview": redact_command(normalized_command),
            "exit_code": exit_code,
            "timed_out": timed_out,
            "removed_after_run": cleanup_succeeded,
        },
        "docker_context": docker_context,
        "policy_checks": policy_checks,
        "telemetry_coverage": {
            "main_process": "observed",
            "workspace_integrity": "observed",
            "network": "policy-enforced-not-instrumented",
            "file_access": "not-instrumented",
            "child_processes": "not-instrumented",
            "tool_calls": "not-instrumented",
        },
        "observations": observations,
        "path_results": path_results,
        "output": {
            "stdout_char_count": len(stdout),
            "stderr_char_count": len(stderr),
            "stdout_sha256": sha256(stdout.encode("utf-8")).hexdigest(),
            "stderr_sha256": sha256(stderr.encode("utf-8")).hexdigest(),
            "truncated": len(stdout) >= MAX_OUTPUT_CHARACTERS or len(stderr) >= MAX_OUTPUT_CHARACTERS,
            "redacted_before_hashing": True,
            "content_stored": False,
        },
        "limitations": [
            "This evidence covers one exact staging digest, image digest, command and timeout only.",
            "Network was disabled by container policy, but attempted destinations were not instrumented.",
            "Only the main container process and before/after workspace integrity were observed; child processes, file access and tool calls were not instrumented.",
            "Container output content is not stored or returned; only redacted lengths and hashes are retained.",
            "A not_observed path result does not prove that the behavior is impossible.",
        ],
    }
    evidence["evidence_sha256"] = sha256(
        json.dumps(evidence, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    evidence_path = write_target_evidence(project_id, execution_id, evidence)
    evidence["evidence_path"] = str(evidence_path)
    return evidence


def build_target_container_command(
    *, docker: str, container_name: str, staging_path: Path, image: str,
    command_tokens: list[str],
) -> list[str]:
    return [
        docker, "create", "--pull=never", "--name", container_name,
        "--label", "ai-security-platform.scope=agent-project-target",
        "--network", "none", "--read-only", "--cpus", "0.5",
        "--memory", "256m", "--pids-limit", "64", "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges:true", "--user", "65534:65534",
        "--tmpfs", "/tmp:rw,noexec,nosuid,size=32m", "--ipc", "none",
        "--no-healthcheck", "--log-driver", "local", "--log-opt", "max-size=1m",
        "--log-opt", "max-file=1", "--log-opt", "compress=false",
        "--mount", f"type=bind,src={staging_path},dst=/workspace,readonly",
        "--workdir", "/workspace", "--entrypoint", command_tokens[0],
        image, *command_tokens[1:],
    ]


def limited_path_results(paths: list[dict[str, object]]) -> list[dict[str, object]]:
    results: list[dict[str, object]] = []
    for path in paths[:1_000]:
        capability = str(path.get("capability") or "")
        main_process_only = capability == "server-process"
        results.append({
            "dataflow_path_id": str(path.get("id") or ""),
            "static_severity": path.get("severity"),
            "static_confidence": path.get("confidence"),
            "runtime_status": "observed" if main_process_only else "not_instrumented",
            "observation_ids": ["container-main-process"] if main_process_only else [],
            "reason": (
                "The main container process was observed for this server-process path."
                if main_process_only
                else "This execution did not instrument the child process, file, network destination or tool-call evidence required for this path."
            ),
        })
    return results


def configured_policy_checks(
    inspected: dict[str, object], staging_path: Path, image: str,
    command_tokens: list[str],
) -> dict[str, bool]:
    host = inspected.get("HostConfig") if isinstance(inspected.get("HostConfig"), dict) else {}
    config = inspected.get("Config") if isinstance(inspected.get("Config"), dict) else {}
    mounts = inspected.get("Mounts") if isinstance(inspected.get("Mounts"), list) else []
    security_options = {str(value) for value in host.get("SecurityOpt", [])} if isinstance(host.get("SecurityOpt"), list) else set()
    cap_drop = {str(value).upper() for value in host.get("CapDrop", [])} if isinstance(host.get("CapDrop"), list) else set()
    workspace = next((item for item in mounts if isinstance(item, dict) and item.get("Destination") == "/workspace"), {})
    tmpfs = host.get("Tmpfs") if isinstance(host.get("Tmpfs"), dict) else {}
    log_config = host.get("LogConfig") if isinstance(host.get("LogConfig"), dict) else {}
    healthcheck = config.get("Healthcheck") if isinstance(config.get("Healthcheck"), dict) else {}
    entrypoint = config.get("Entrypoint") if isinstance(config.get("Entrypoint"), list) else []
    command = config.get("Cmd") if isinstance(config.get("Cmd"), list) else []
    return {
        "image_digest_exact": str(config.get("Image") or "") == image,
        "command_exact": entrypoint == [command_tokens[0]] and command == command_tokens[1:],
        "network_none": str(host.get("NetworkMode") or "") == "none",
        "root_filesystem_read_only": host.get("ReadonlyRootfs") is True,
        "workspace_read_only": bool(workspace) and workspace.get("RW") is False,
        "workspace_source_exact": Path(str(workspace.get("Source") or "")).resolve(strict=False) == staging_path.resolve(strict=False),
        "only_workspace_mount": len(mounts) == 1 and bool(workspace),
        "capabilities_drop_all": "ALL" in cap_drop,
        "no_new_privileges": any(value.startswith("no-new-privileges") for value in security_options),
        "not_privileged": host.get("Privileged") is False,
        "non_root_user": str(config.get("User") or "") == "65534:65534",
        "cpu_limit": int(host.get("NanoCpus") or 0) == 500_000_000,
        "memory_limit": int(host.get("Memory") or 0) == 256 * 1024 * 1024,
        "pids_limit": int(host.get("PidsLimit") or 0) == 64,
        "tmpfs_limited": "/tmp" in tmpfs and "noexec" in str(tmpfs.get("/tmp")) and "size=32m" in str(tmpfs.get("/tmp")),
        "ipc_isolated": str(host.get("IpcMode") or "") == "none",
        "pid_namespace_isolated": str(host.get("PidMode") or "") in {"", "private"},
        "healthcheck_disabled": healthcheck.get("Test") == ["NONE"],
        "bounded_local_logs": (
            log_config.get("Type") == "local"
            and str((log_config.get("Config") or {}).get("max-size")) == "1m"
            and str((log_config.get("Config") or {}).get("max-file")) == "1"
            and str((log_config.get("Config") or {}).get("compress")).lower() == "false"
        ),
        "host_environment_not_injected": not any(
            str(value).startswith("AGENT_HOST_CANARY=") for value in config.get("Env", [])
        ) if isinstance(config.get("Env"), list) else True,
        "no_host_socket_mount": all(
            not any(token in str(item.get("Source") or "").lower() for token in ("docker.sock", "podman.sock", "containerd.sock"))
            for item in mounts if isinstance(item, dict)
        ),
    }


def verify_execution_binding(
    *, manifest: dict[str, object], scan_task_id: str, command: str, image: str,
    timeout_seconds: int, plan_sha256: str, staging_sha256: str, manifest_sha256: str,
) -> None:
    binding = manifest.get("binding") if isinstance(manifest.get("binding"), dict) else {}
    expected = {
        "scan_task_id": scan_task_id,
        "plan_sha256": plan_sha256,
        "command_sha256": sha256(command.encode("utf-8")).hexdigest(),
        "image": image,
        "timeout_seconds": timeout_seconds,
        "staging_sha256": staging_sha256,
        "manifest_sha256": manifest_sha256,
    }
    observed = {
        "scan_task_id": str(binding.get("scan_task_id") or ""),
        "plan_sha256": str(binding.get("plan_sha256") or ""),
        "command_sha256": str(binding.get("command_sha256") or ""),
        "image": str(binding.get("image") or ""),
        "timeout_seconds": int(binding.get("timeout_seconds") or 0),
        "staging_sha256": str(manifest.get("staging_sha256") or ""),
        "manifest_sha256": str(manifest.get("manifest_sha256") or ""),
    }
    mismatches = [
        key for key, value in expected.items()
        if not hmac.compare_digest(str(value), str(observed.get(key) or ""))
    ]
    if mismatches:
        raise TargetRuntimeRejected(f"Target execution binding changed: {', '.join(mismatches)}")


def validate_command_and_image(command: str, image: str) -> None:
    command_result = command_check(command)
    if command_result.get("status") != "pass":
        raise TargetRuntimeRejected(str(command_result.get("detail") or "Target command failed static policy."))
    if not image_is_digest_pinned(image):
        raise TargetRuntimeRejected("Target execution requires a digest-pinned image available locally.")
    prefix = image.rsplit("@sha256:", 1)[0]
    if re.search(r"\s", image) or "://" in image or "@" in prefix or re.search(r"(?i)(token|password|secret|api[-_]?key)=", image):
        raise TargetRuntimeRejected("Target image reference contains credentials, a URL scheme or whitespace.")


def parse_command_tokens(command: str) -> list[str]:
    try:
        tokens = shlex.split(command, posix=True)
    except ValueError as exc:
        raise TargetRuntimeRejected("Target command quoting is invalid.") from exc
    if not tokens or len(tokens) > MAX_COMMAND_TOKENS or any(len(token) > 500 for token in tokens):
        raise TargetRuntimeRejected("Target command token count or token length exceeds the review limit.")
    if tokens[0].startswith(("/", "\\")) or re.match(r"^[A-Za-z]:", tokens[0]):
        raise TargetRuntimeRejected("Target executable must resolve inside the selected image, not from a host path.")
    return tokens


def resolve_bound_staging(project_id: str, build_id: str) -> Path:
    if safe_identifier(build_id) != build_id or not re.fullmatch(r"[A-Za-z0-9_-]{1,80}", build_id):
        raise TargetRuntimeRejected("Target staging build identifier is invalid.")
    root = staging_workspace_path(project_id).resolve(strict=True)
    candidate = (root / build_id).resolve(strict=True)
    if candidate.parent != root or not candidate.is_dir() or is_link_or_junction(candidate):
        raise TargetRuntimeRejected("Target staging build is missing, outside the project root or unsafe.")
    return candidate


def docker_executable() -> str:
    docker = shutil.which("docker")
    if docker is None:
        raise TargetRuntimeRejected("Docker CLI is unavailable; no installation or download was attempted.")
    return docker


def ensure_local_docker_context(docker: str, run_command: RunCommand) -> dict[str, object]:
    configured_host = os.environ.get("DOCKER_HOST", "").strip()
    if configured_host and not configured_host.lower().startswith(("npipe://", "unix://")):
        raise TargetRuntimeRejected("Remote Docker hosts are not allowed for target validation.")
    completed = run_command(
        [docker, "context", "inspect", "--format", "{{json .Endpoints.docker.Host}}"],
        shell=False, capture_output=True, text=True, timeout=10, encoding="utf-8", errors="replace",
    )
    if completed.returncode != 0:
        raise TargetRuntimeRejected("The active Docker context could not be verified as local.")
    try:
        endpoint = json.loads(completed.stdout.strip())
    except json.JSONDecodeError as exc:
        raise TargetRuntimeRejected("Docker returned invalid context metadata.") from exc
    if not isinstance(endpoint, str) or not endpoint.lower().startswith(("npipe://", "unix://")):
        raise TargetRuntimeRejected("Remote Docker contexts are not allowed for target validation.")
    return {"endpoint_type": "npipe" if endpoint.lower().startswith("npipe://") else "unix", "remote": False}


def inspect_local_image(docker: str, image: str, run_command: RunCommand) -> dict[str, object]:
    completed = run_command(
        [docker, "image", "inspect", image], shell=False, capture_output=True, text=True,
        timeout=10, encoding="utf-8", errors="replace",
    )
    if completed.returncode != 0:
        raise TargetRuntimeRejected("The exact digest-pinned target image is not available locally; no image was downloaded.")
    try:
        payload = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise TargetRuntimeRejected("Docker returned invalid local image metadata.") from exc
    if not isinstance(payload, list) or not payload or not isinstance(payload[0], dict):
        raise TargetRuntimeRejected("Docker returned no local target image metadata.")
    return payload[0]


def inspect_container(docker: str, container_id: str, run_command: RunCommand) -> dict[str, object]:
    completed = run_command(
        [docker, "container", "inspect", container_id], shell=False, capture_output=True,
        text=True, timeout=10, encoding="utf-8", errors="replace",
    )
    if completed.returncode != 0:
        raise TargetRuntimeRejected("The temporary target container could not be inspected.")
    try:
        payload = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise TargetRuntimeRejected("Docker returned invalid target container metadata.") from exc
    if not isinstance(payload, list) or not payload or not isinstance(payload[0], dict):
        raise TargetRuntimeRejected("Docker returned no target container metadata.")
    return payload[0]


def sanitize_output(value: str) -> str:
    redacted = re.sub(
        r"(?i)(password|passwd|secret|token|api[_-]?key)\s*[:=]\s*([^\s,;]+)",
        lambda match: f"{match.group(1)}=[redacted]",
        value,
    )
    return redacted[:MAX_OUTPUT_CHARACTERS]


def write_target_evidence(project_id: str, execution_id: str, evidence: dict[str, object]) -> Path:
    project_root = EVIDENCE_ROOT / safe_identifier(project_id)
    project_root.mkdir(parents=True, exist_ok=True)
    path = project_root / f"{safe_identifier(execution_id)}.json"
    with path.open("x", encoding="utf-8") as handle:
        json.dump(evidence, handle, ensure_ascii=False, indent=2)
    return path


def list_target_evidence(project_id: str, limit: int = 20) -> list[dict[str, object]]:
    project_root = EVIDENCE_ROOT / safe_identifier(project_id)
    if not project_root.exists():
        return []
    resolved_root = project_root.resolve(strict=True)
    if not resolved_root.is_dir() or is_link_or_junction(resolved_root):
        raise TargetRuntimeRejected("Target evidence directory is unsafe.")
    results: list[dict[str, object]] = []
    for path in sorted(resolved_root.glob("target-*.json"), reverse=True)[:max(1, min(100, limit))]:
        if is_link_or_junction(path) or not path.is_file() or path.stat().st_size > 2 * 1024 * 1024:
            continue
        try:
            item = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if isinstance(item, dict) and item.get("schema") == TARGET_RUNTIME_SCHEMA:
            results.append({**item, "evidence_path": str(path)})
    return results
