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
MCP_LEDGER_SCHEMA = "ai-security-platform.agent-mcp-runtime-ledger/v1"
MCP_AUDIT_EVENT_SCHEMA = "ai-security-platform.agent-mcp-stdio-event/v1"
MCP_AUDIT_PREFIX = "@@AGENT_MCP_AUDIT@@"
EVIDENCE_ROOT = Path(__file__).resolve().parents[4] / "artifacts" / "agent-sandbox" / "target-evidence"
OBSERVER_ASSET_ROOT = Path(__file__).with_name("runtime_assets")
OBSERVER_SCRIPT_NAME = "mcp_stdio_observer.py"
AUTHORIZATION_PHRASE = "RUN ISOLATED AGENT"
MAX_OUTPUT_CHARACTERS = 16_000
MAX_COMMAND_TOKENS = 64
MAX_MCP_AUDIT_LINE_CHARACTERS = 8_192
MAX_MCP_AUDIT_EVENTS = 500
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
    observer_root, observer_sha256 = resolve_observer_asset()

    docker = docker_executable()
    docker_context = ensure_local_docker_context(docker, run_command)
    inspected_image = inspect_local_image(docker, normalized_image, run_command)
    execution_id = f"target-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}-{uuid4().hex[:10]}"
    container_name = f"ai-agent-target-{uuid4().hex[:12]}"
    create_command = build_target_container_command(
        docker=docker,
        container_name=container_name,
        staging_path=staging_path,
        observer_path=observer_root,
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
            inspect_payload, staging_path, observer_root, normalized_image, command_tokens
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
        inspect_payload, staging_path, observer_root, normalized_image, command_tokens
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
    mcp_ledger, stdout, stderr = extract_mcp_audit_ledger(stdout, stderr)
    child_processes = mcp_child_process_observations(mcp_ledger)
    tool_calls = mcp_tool_call_observations(mcp_ledger)
    observations = {
        "processes": [{
            "id": "container-main-process",
            "capability": "server-process",
            "outcome": "observed",
            "exit_code": exit_code,
            "timed_out": timed_out,
        }, *child_processes],
        "file_access": [],
        "network_attempts": [],
        "tool_calls": tool_calls,
    }
    dataflow_paths = (
        dataflow.get("paths") if isinstance(dataflow, dict) and isinstance(dataflow.get("paths"), list) else []
    )
    path_results = limited_path_results(
        [item for item in dataflow_paths if isinstance(item, dict)], observations
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
        "observer": {
            "transport": "stdio-jsonrpc",
            "mount_destination": "/opt/agent-observer",
            "script_sha256": observer_sha256,
            "content_stored": False,
            "integrity": "format-and-event-hash-validated-not-cryptographically-authenticated",
        },
        "mcp_ledger": mcp_ledger,
        "policy_checks": policy_checks,
        "telemetry_coverage": {
            "main_process": "observed",
            "workspace_integrity": "observed",
            "network": "policy-enforced-not-instrumented",
            "file_access": "not-instrumented",
            "child_processes": telemetry_status(mcp_ledger, "child_process_count"),
            "tool_calls": telemetry_status(mcp_ledger, "tool_call_count"),
            "mcp_stdio": telemetry_status(mcp_ledger, "request_count"),
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
            "The read-only stdio observer records bounded MCP method metadata and the MCP server child process; file access and system-level child processes remain uninstrumented.",
            "Observer records have validated schemas and recomputed hashes, but the target-visible log channel is not cryptographically authenticated and could be forged by a hostile target.",
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


def canonical_sha256(value: object) -> str:
    encoded = json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return sha256(encoded).hexdigest()


def resolve_observer_asset() -> tuple[Path, str]:
    try:
        root = OBSERVER_ASSET_ROOT.resolve(strict=True)
        script = (root / OBSERVER_SCRIPT_NAME).resolve(strict=True)
    except OSError as exc:
        raise TargetRuntimeRejected("The bundled MCP stdio observer is unavailable.") from exc
    if (
        not root.is_dir()
        or is_link_or_junction(root)
        or script.parent != root
        or not script.is_file()
        or is_link_or_junction(script)
        or script.stat().st_size > 256 * 1024
    ):
        raise TargetRuntimeRejected("The bundled MCP stdio observer asset is unsafe.")
    return root, sha256(script.read_bytes()).hexdigest()


def _bounded_label(value: object, *, allow_redacted: bool = True) -> str:
    text = str(value or "")[:120]
    if allow_redacted and text == "[redacted-label]":
        return text
    return text if re.fullmatch(r"[A-Za-z0-9_.:/@-]{1,120}", text) else "[invalid-label]"


def _bounded_hash(value: object) -> str:
    text = str(value or "")
    return text if re.fullmatch(r"[0-9a-f]{64}", text) else ""


def normalize_mcp_audit_event(item: dict[str, object]) -> dict[str, object] | None:
    if item.get("schema") != MCP_AUDIT_EVENT_SCHEMA:
        return None
    supplied_hash = _bounded_hash(item.get("event_sha256"))
    unhashed = {key: value for key, value in item.items() if key != "event_sha256"}
    if not supplied_hash or not hmac.compare_digest(supplied_hash, canonical_sha256(unhashed)):
        return None
    event_type = str(item.get("event_type") or "")
    if event_type not in {"mcp_request", "mcp_response", "child_process", "observer_error"}:
        return None
    sequence = item.get("sequence")
    if not isinstance(sequence, int) or isinstance(sequence, bool) or not 1 <= sequence <= 10_000:
        return None
    event_id = str(item.get("event_id") or "")
    if not re.fullmatch(r"mcp-[0-9]{4,8}", event_id):
        return None
    normalized: dict[str, object] = {
        "schema": MCP_AUDIT_EVENT_SCHEMA,
        "observer_version": _bounded_label(item.get("observer_version")),
        "event_id": event_id,
        "sequence": sequence,
        "occurred_at": str(item.get("occurred_at") or "")[:64],
        "event_type": event_type,
        "event_sha256": supplied_hash,
    }
    if event_type in {"mcp_request", "mcp_response"}:
        direction = str(item.get("direction") or "")
        expected_direction = "client-to-server" if event_type == "mcp_request" else "server-to-client"
        if direction != expected_direction:
            return None
        payload_bytes = item.get("payload_bytes")
        if not isinstance(payload_bytes, int) or isinstance(payload_bytes, bool) or not 0 <= payload_bytes <= 64 * 1024:
            return None
        subject_kind = str(item.get("subject_kind") or "")
        if subject_kind not in {"tool", "resource-scheme", "prompt", "method"}:
            return None
        normalized.update({
            "direction": direction,
            "method": _bounded_label(item.get("method")),
            "subject_kind": subject_kind,
            "subject": _bounded_label(item.get("subject")),
            "expects_response": item.get("expects_response", True) is True,
            "payload_bytes": payload_bytes,
            "redacted_metadata_sha256": _bounded_hash(item.get("redacted_metadata_sha256")),
        })
        if not normalized["redacted_metadata_sha256"]:
            return None
        if event_type == "mcp_response":
            duration_ms = item.get("duration_ms")
            outcome = str(item.get("outcome") or "")
            request_event_id = str(item.get("request_event_id") or "")
            if (
                outcome not in {"success", "error", "missing-or-oversized"}
                or not isinstance(duration_ms, int)
                or isinstance(duration_ms, bool)
                or not 0 <= duration_ms <= 300_000
                or not re.fullmatch(r"mcp-[0-9]{4,8}", request_event_id)
            ):
                return None
            normalized.update({
                "outcome": outcome,
                "duration_ms": duration_ms,
                "request_event_id": request_event_id,
            })
    elif event_type == "child_process":
        phase = str(item.get("phase") or "")
        if phase not in {"start", "exit"} or item.get("process_role") != "mcp-server":
            return None
        argument_count = item.get("argument_count")
        if not isinstance(argument_count, int) or isinstance(argument_count, bool) or not 0 <= argument_count <= 64:
            return None
        normalized.update({
            "phase": phase,
            "process_role": "mcp-server",
            "executable": _bounded_label(item.get("executable")),
            "argument_count": argument_count,
            "command_metadata_sha256": _bounded_hash(item.get("command_metadata_sha256")),
            "pid_sha256": _bounded_hash(item.get("pid_sha256")),
        })
        if not normalized["command_metadata_sha256"] or not normalized["pid_sha256"]:
            return None
        if phase == "exit":
            exit_code = item.get("exit_code")
            stderr_bytes = item.get("stderr_bytes")
            if (
                not isinstance(exit_code, int)
                or isinstance(exit_code, bool)
                or not -255 <= exit_code <= 255
                or not isinstance(stderr_bytes, int)
                or isinstance(stderr_bytes, bool)
                or not 0 <= stderr_bytes <= 64 * 1024 * 1024
                or not isinstance(item.get("timed_out"), bool)
            ):
                return None
            normalized.update({
                "exit_code": exit_code,
                "timed_out": item["timed_out"],
                "stderr_bytes": stderr_bytes,
            })
    else:
        normalized["code"] = _bounded_label(item.get("code"))
    return normalized


def extract_mcp_audit_ledger(
    stdout: str, stderr: str
) -> tuple[dict[str, object], str, str]:
    events: list[dict[str, object]] = []
    rejected = 0

    def process_stream(value: str) -> str:
        nonlocal rejected
        clean_lines: list[str] = []
        for line in value.splitlines(keepends=True):
            if not line.startswith(MCP_AUDIT_PREFIX):
                clean_lines.append(line)
                continue
            if len(events) >= MAX_MCP_AUDIT_EVENTS or len(line) > MAX_MCP_AUDIT_LINE_CHARACTERS:
                rejected += 1
                continue
            try:
                decoded = json.loads(line[len(MCP_AUDIT_PREFIX):].strip())
            except json.JSONDecodeError:
                rejected += 1
                continue
            normalized = normalize_mcp_audit_event(decoded) if isinstance(decoded, dict) else None
            if normalized is None:
                rejected += 1
            else:
                events.append(normalized)
        return "".join(clean_lines)

    clean_stdout = process_stream(stdout)
    clean_stderr = process_stream(stderr)
    method_counts: dict[str, int] = {}
    notification_count = 0
    response_count = success_count = error_count = 0
    for event in events:
        if event.get("event_type") == "mcp_request":
            method = str(event.get("method") or "[invalid-label]")
            method_counts[method] = method_counts.get(method, 0) + 1
            if event.get("expects_response") is False:
                notification_count += 1
        elif event.get("event_type") == "mcp_response":
            response_count += 1
            if event.get("outcome") == "success":
                success_count += 1
            else:
                error_count += 1
    child_ids = {
        str(event.get("pid_sha256"))
        for event in events
        if event.get("event_type") == "child_process" and event.get("phase") == "exit"
    }
    observer_versions = {
        str(event.get("observer_version")) for event in events if event.get("observer_version")
    }
    ledger: dict[str, object] = {
        "schema": MCP_LEDGER_SCHEMA,
        "transport": "stdio-jsonrpc",
        "source": "platform-readonly-observer",
        "observer_version": next(iter(observer_versions)) if len(observer_versions) == 1 else "mixed-or-unavailable",
        "integrity": "format-and-event-hash-validated-not-cryptographically-authenticated",
        "content_stored": False,
        "rejected_event_count": rejected,
        "summary": {
            "event_count": len(events),
            "request_count": sum(method_counts.values()),
            "response_count": response_count,
            "notification_count": notification_count,
            "successful_response_count": success_count,
            "error_response_count": error_count,
            "method_counts": dict(sorted(method_counts.items())),
            "tool_call_count": method_counts.get("tools/call", 0),
            "resource_read_count": method_counts.get("resources/read", 0),
            "prompt_get_count": method_counts.get("prompts/get", 0),
            "child_process_count": len(child_ids),
        },
        "events": sorted(events, key=lambda event: int(event.get("sequence") or 0)),
    }
    return ledger, clean_stdout, clean_stderr


def mcp_child_process_observations(ledger: dict[str, object]) -> list[dict[str, object]]:
    events = ledger.get("events") if isinstance(ledger.get("events"), list) else []
    return [{
        "id": f"mcp-child-{str(event.get('pid_sha256') or '')[:12]}",
        "capability": "server-process",
        "process_role": "mcp-server",
        "executable": event.get("executable"),
        "outcome": "observed",
        "exit_code": event.get("exit_code"),
        "timed_out": event.get("timed_out"),
        "pid_sha256": event.get("pid_sha256"),
        "source": "stdio-observer",
    } for event in events if isinstance(event, dict) and event.get("event_type") == "child_process" and event.get("phase") == "exit"]


def mcp_tool_call_observations(ledger: dict[str, object]) -> list[dict[str, object]]:
    events = ledger.get("events") if isinstance(ledger.get("events"), list) else []
    request_hashes = {
        str(event.get("event_id")): event.get("event_sha256")
        for event in events
        if isinstance(event, dict) and event.get("event_type") == "mcp_request"
    }
    return [{
        "id": str(event.get("event_id") or ""),
        "capability": "tool-invocation",
        "protocol": "mcp-stdio-jsonrpc",
        "method": "tools/call",
        "subject": event.get("subject"),
        "subject_kind": event.get("subject_kind"),
        "outcome": event.get("outcome"),
        "duration_ms": event.get("duration_ms"),
        "request_event_id": event.get("request_event_id"),
        "request_event_sha256": request_hashes.get(str(event.get("request_event_id") or "")),
        "response_event_sha256": event.get("event_sha256"),
        "content_stored": False,
        "source": "stdio-observer",
    } for event in events if isinstance(event, dict) and event.get("event_type") == "mcp_response" and event.get("method") == "tools/call"]


def telemetry_status(ledger: dict[str, object], count_key: str) -> str:
    summary = ledger.get("summary") if isinstance(ledger.get("summary"), dict) else {}
    if int(summary.get(count_key) or 0) > 0:
        return "observed-via-stdio-proxy"
    if int(summary.get("event_count") or 0) > 0:
        return "stdio-proxy-active-no-matching-event"
    return "not-instrumented"


def build_target_container_command(
    *, docker: str, container_name: str, staging_path: Path, observer_path: Path, image: str,
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
        "--mount", f"type=bind,src={observer_path},dst=/opt/agent-observer,readonly",
        "--workdir", "/workspace", "--entrypoint", command_tokens[0],
        image, *command_tokens[1:],
    ]


def limited_path_results(
    paths: list[dict[str, object]], observations: dict[str, object]
) -> list[dict[str, object]]:
    results: list[dict[str, object]] = []
    processes = observations.get("processes") if isinstance(observations.get("processes"), list) else []
    tool_calls = observations.get("tool_calls") if isinstance(observations.get("tool_calls"), list) else []
    for path in paths[:1_000]:
        capability = str(path.get("capability") or "")
        observation_ids: list[str] = []
        if capability == "server-process":
            observation_ids = [
                str(item.get("id") or "") for item in processes if isinstance(item, dict)
            ]
        elif capability == "tool-invocation":
            observation_ids = [
                str(item.get("id") or "") for item in tool_calls if isinstance(item, dict)
            ]
        observed = bool(observation_ids)
        results.append({
            "dataflow_path_id": str(path.get("id") or ""),
            "static_severity": path.get("severity"),
            "static_confidence": path.get("confidence"),
            "runtime_status": "observed" if observed else "not_instrumented",
            "observation_ids": observation_ids,
            "reason": (
                "Runtime observations were correlated with this static capability path."
                if observed
                else "This execution did not capture the file, network destination or matching MCP tool-call evidence required for this path."
            ),
        })
    return results


def configured_policy_checks(
    inspected: dict[str, object], staging_path: Path, observer_path: Path, image: str,
    command_tokens: list[str],
) -> dict[str, bool]:
    host = inspected.get("HostConfig") if isinstance(inspected.get("HostConfig"), dict) else {}
    config = inspected.get("Config") if isinstance(inspected.get("Config"), dict) else {}
    mounts = inspected.get("Mounts") if isinstance(inspected.get("Mounts"), list) else []
    security_options = {str(value) for value in host.get("SecurityOpt", [])} if isinstance(host.get("SecurityOpt"), list) else set()
    cap_drop = {str(value).upper() for value in host.get("CapDrop", [])} if isinstance(host.get("CapDrop"), list) else set()
    workspace = next((item for item in mounts if isinstance(item, dict) and item.get("Destination") == "/workspace"), {})
    observer = next((item for item in mounts if isinstance(item, dict) and item.get("Destination") == "/opt/agent-observer"), {})
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
        "observer_read_only": bool(observer) and observer.get("RW") is False,
        "observer_source_exact": Path(str(observer.get("Source") or "")).resolve(strict=False) == observer_path.resolve(strict=False),
        "only_expected_mounts": len(mounts) == 2 and bool(workspace) and bool(observer),
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
