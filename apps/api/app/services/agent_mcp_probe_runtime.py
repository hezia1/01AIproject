from __future__ import annotations

import hmac
import json
import os
import re
import shlex
import subprocess
import time
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path
from typing import Callable
from uuid import uuid4

from app.services.agent_runtime_validation import command_check, image_is_digest_pinned, redact_command, safe_identifier
from app.services.agent_scanner import extract_mcp_servers, is_dangerous_command, parse_structured_config
from app.services.agent_staging import is_link_or_junction, load_filtered_staging_manifest, safe_manifest_target, verify_filtered_staging
from app.services.agent_target_runtime import (
    MAX_OUTPUT_CHARACTERS,
    TargetRuntimeRejected,
    build_target_container_command,
    canonical_sha256,
    configured_policy_checks,
    docker_executable,
    ensure_local_docker_context,
    extract_mcp_audit_ledger,
    inspect_container,
    inspect_local_image,
    resolve_bound_staging,
    resolve_observer_asset,
    sanitize_output,
)


MCP_PROBE_STATUS_SCHEMA = "ai-security-platform.agent-mcp-probe-status/v1"
MCP_PROBE_EVIDENCE_SCHEMA = "ai-security-platform.agent-mcp-probe-evidence/v1"
MCP_PROBE_RESULT_SCHEMA = "ai-security-platform.agent-mcp-capability-probe-result/v1"
MCP_PROBE_PREFIX = "@@AGENT_MCP_PROBE@@"
MCP_PROBE_SCRIPT = "mcp_capability_probe.py"
MCP_PROBE_AUTHORIZATION_PHRASE = "PROBE STDIO MCP SERVER"
MCP_PROBE_EVIDENCE_ROOT = Path(__file__).resolve().parents[4] / "artifacts" / "agent-sandbox" / "mcp-probe-evidence"
MAX_CONFIG_BYTES = 512 * 1024
MAX_CONFIG_FILES = 500
MAX_CANDIDATES = 100
RunCommand = Callable[..., subprocess.CompletedProcess[str]]


def list_mcp_probe_status(
    project_id: str, current_scan_task_id: str | None, execution_enabled: bool
) -> dict[str, object]:
    builds: list[dict[str, object]] = []
    root = resolve_staging_root(project_id)
    if root is not None:
        for path in sorted(root.iterdir(), key=lambda item: item.name, reverse=True)[:100]:
            if not path.is_dir() or is_link_or_junction(path) or path.name.startswith("."):
                continue
            try:
                manifest = load_filtered_staging_manifest(path)
            except (OSError, ValueError, json.JSONDecodeError):
                continue
            binding = manifest.get("binding") if isinstance(manifest.get("binding"), dict) else {}
            if current_scan_task_id and str(binding.get("scan_task_id") or "") != current_scan_task_id:
                continue
            candidates = [public_candidate(item) for item in discover_stdio_candidates(path, manifest)]
            builds.append({
                "build_id": str(manifest.get("build_id") or path.name),
                "created_at": manifest.get("created_at"),
                "staging_sha256": manifest.get("staging_sha256"),
                "manifest_sha256": manifest.get("manifest_sha256"),
                "scan_task_id": binding.get("scan_task_id"),
                "plan_sha256": binding.get("plan_sha256"),
                "image": binding.get("image"),
                "timeout_seconds": binding.get("timeout_seconds"),
                "candidates": candidates,
            })
            if len(builds) >= 20:
                break
    return {
        "schema": MCP_PROBE_STATUS_SCHEMA,
        "execution_enabled_by_project_policy": bool(execution_enabled),
        "authorization_phrase": MCP_PROBE_AUTHORIZATION_PHRASE,
        "current_scan_task_id": current_scan_task_id,
        "builds": builds,
        "download_performed": False,
        "limitations": [
            "Only recognized JSON, YAML and TOML stdio MCP declarations in a verified staging build are listed.",
            "Candidates with configured environment variables, remote URLs, shell commands, inline code or unsafe arguments are rejected.",
            "The selected local digest image must already contain Python 3, the MCP server executable and all dependencies.",
            "The probe initializes the server and lists capabilities only; it never calls tools or reads resource or prompt content.",
        ],
    }


def resolve_staging_root(project_id: str) -> Path | None:
    from app.services.agent_runtime_validation import staging_workspace_path

    root = staging_workspace_path(project_id)
    if not root.exists():
        return None
    resolved = root.resolve(strict=True)
    if not resolved.is_dir() or is_link_or_junction(resolved):
        raise TargetRuntimeRejected("The MCP probe staging root is unsafe.")
    return resolved


def discover_stdio_candidates(staging_path: Path, manifest: dict[str, object]) -> list[dict[str, object]]:
    files = manifest.get("files") if isinstance(manifest.get("files"), list) else []
    candidates: list[dict[str, object]] = []
    for entry in files[:MAX_CONFIG_FILES]:
        if not isinstance(entry, dict):
            continue
        relative_path = str(entry.get("path") or "")
        suffix = Path(relative_path).suffix.lower().lstrip(".")
        if suffix not in {"json", "yaml", "yml", "toml"}:
            continue
        try:
            config_path = safe_manifest_target(staging_path, relative_path)
            if config_path.stat().st_size > MAX_CONFIG_BYTES:
                continue
            content = config_path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError, ValueError):
            continue
        data, error = parse_structured_config(content, suffix)
        if error or not isinstance(data, dict):
            continue
        for server_name, node in extract_mcp_servers(data):
            candidate = build_candidate(
                relative_path=relative_path,
                config_sha256=str(entry.get("sha256") or ""),
                server_name=server_name,
                node=node,
            )
            candidates.append(candidate)
            if len(candidates) >= MAX_CANDIDATES:
                return candidates
    return candidates


def build_candidate(
    *, relative_path: str, config_sha256: str, server_name: str, node: dict[str, object]
) -> dict[str, object]:
    command = node.get("command")
    args_value = node.get("args", [])
    args = [str(item) for item in args_value] if isinstance(args_value, list) and all(isinstance(item, str) for item in args_value) else []
    tokens = [str(command).strip(), *args] if isinstance(command, str) and command.strip() else []
    explicit_transport = str(node.get("transport") or node.get("type") or "").strip().lower()
    remote_url = node.get("url") or node.get("endpoint")
    env = node.get("env") or node.get("environment")
    headers = node.get("headers")
    checks: dict[str, bool] = {
        "enabled": node.get("disabled") is not True,
        "stdio_transport": bool(tokens) and not remote_url and explicit_transport in {"", "stdio"},
        "command_present": bool(tokens),
        "arguments_are_string_list": isinstance(args_value, list) and all(isinstance(item, str) for item in args_value),
        "no_configured_environment": not isinstance(env, dict) or not env,
        "no_configured_headers": not isinstance(headers, dict) or not headers,
        "no_custom_working_directory": not bool(node.get("cwd") or node.get("workingDirectory") or node.get("working_directory")),
        "bounded_command": bool(tokens) and len(tokens) <= 64 and all(len(token) <= 500 for token in tokens),
        "non_shell_command": bool(tokens) and not is_dangerous_command(tokens[0], tokens[1:]),
        "no_secret_like_arguments": bool(tokens) and not any(
            re.search(r"(?i)(token|password|secret|api[_-]?key)(?:=|:)", token) for token in tokens
        ),
        "relative_or_image_executable": bool(tokens) and not tokens[0].startswith(("/", "\\")) and not re.match(r"^[A-Za-z]:", tokens[0]),
        "static_command_policy": bool(tokens) and command_check(shlex.join(tokens)).get("status") == "pass",
    }
    identity = canonical_sha256({
        "config_path": relative_path,
        "config_sha256": config_sha256,
        "server_name": server_name,
        "command_tokens": tokens,
    })
    return {
        "candidate_id": identity[:24],
        "config_path": relative_path[:500],
        "config_sha256": config_sha256 if re.fullmatch(r"[0-9a-f]{64}", config_sha256) else "",
        "server_name": safe_display_label(server_name),
        "transport": "stdio" if checks["stdio_transport"] else explicit_transport or "unknown",
        "command_preview": redact_command(shlex.join(tokens)) if tokens else None,
        "command_sha256": sha256(shlex.join(tokens).encode("utf-8")).hexdigest() if tokens else None,
        "eligible": all(checks.values()),
        "checks": checks,
        "rejection_reasons": [key for key, passed in checks.items() if not passed],
        "_command_tokens": tokens,
    }


def safe_display_label(value: object) -> str:
    text = str(value or "").strip()[:120]
    return text if re.fullmatch(r"[A-Za-z0-9_.:@/-]{1,120}", text) else "[redacted-label]"


def public_candidate(candidate: dict[str, object]) -> dict[str, object]:
    return {key: value for key, value in candidate.items() if not key.startswith("_")}


def resolve_probe_asset(observer_root: Path) -> tuple[Path, str]:
    try:
        path = (observer_root / MCP_PROBE_SCRIPT).resolve(strict=True)
    except OSError as exc:
        raise TargetRuntimeRejected("The bundled MCP capability probe is unavailable.") from exc
    if path.parent != observer_root or not path.is_file() or is_link_or_junction(path) or path.stat().st_size > 256 * 1024:
        raise TargetRuntimeRejected("The bundled MCP capability probe asset is unsafe.")
    return path, sha256(path.read_bytes()).hexdigest()


def run_mcp_probe_validation(
    *, project_id: str, scan_task_id: str, image: str, timeout_seconds: int,
    plan_sha256: str, staging_build_id: str, staging_sha256: str,
    manifest_sha256: str, candidate_id: str, authorization_phrase: str,
    operator_confirmed: bool, run_command: RunCommand = subprocess.run,
) -> dict[str, object]:
    if not operator_confirmed or not hmac.compare_digest(authorization_phrase, MCP_PROBE_AUTHORIZATION_PHRASE):
        raise TargetRuntimeRejected("MCP capability probing requires its separate authorization phrase and confirmation.")
    normalized_image = image.strip()
    timeout = max(1, min(15, int(timeout_seconds)))
    if not image_is_digest_pinned(normalized_image):
        raise TargetRuntimeRejected("MCP probing requires a digest-pinned image available locally.")
    staging_path = resolve_bound_staging(project_id, staging_build_id)
    manifest = load_filtered_staging_manifest(staging_path)
    verification = verify_filtered_staging(staging_path)
    verify_probe_binding(
        manifest=manifest, scan_task_id=scan_task_id, image=normalized_image,
        timeout_seconds=timeout, plan_sha256=plan_sha256,
        staging_sha256=staging_sha256, manifest_sha256=manifest_sha256,
    )
    candidates = discover_stdio_candidates(staging_path, manifest)
    candidate = next((item for item in candidates if item.get("candidate_id") == candidate_id), None)
    if candidate is None:
        raise TargetRuntimeRejected("The selected MCP server candidate is not present in the verified staging build.")
    if candidate.get("eligible") is not True:
        reasons = ", ".join(str(item) for item in candidate.get("rejection_reasons", []))
        raise TargetRuntimeRejected(f"The selected MCP server is not eligible for safe capability probing: {reasons}")
    server_tokens = candidate.get("_command_tokens")
    if not isinstance(server_tokens, list) or not server_tokens or not all(isinstance(item, str) for item in server_tokens):
        raise TargetRuntimeRejected("The selected MCP server command is invalid.")

    observer_root, observer_sha256 = resolve_observer_asset()
    _, probe_sha256 = resolve_probe_asset(observer_root)
    probe_tokens = [
        "python", "-I", "-B", "/opt/agent-observer/mcp_capability_probe.py",
        "--observer", "/opt/agent-observer/mcp_stdio_observer.py",
        "--timeout-seconds", str(timeout), "--", *server_tokens,
    ]
    docker = docker_executable()
    docker_context = ensure_local_docker_context(docker, run_command)
    inspected_image = inspect_local_image(docker, normalized_image, run_command)
    execution_id = f"mcp-probe-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}-{uuid4().hex[:10]}"
    container_name = f"ai-agent-mcp-probe-{uuid4().hex[:12]}"
    create_command = build_target_container_command(
        docker=docker, container_name=container_name, staging_path=staging_path,
        observer_path=observer_root, image=normalized_image, command_tokens=probe_tokens,
    )
    started_at = datetime.now(timezone.utc)
    started_clock = time.perf_counter()
    container_id: str | None = None
    inspect_payload: dict[str, object] = {}
    exit_code: int | None = None
    timed_out = False
    cleanup_succeeded = False
    stdout = stderr = ""
    docker_environment = os.environ.copy()
    docker_environment["AGENT_HOST_CANARY"] = "present-on-host-cli-only"
    try:
        created = run_command(
            create_command, shell=False, capture_output=True, text=True, timeout=15,
            encoding="utf-8", errors="replace", env=docker_environment,
        )
        if created.returncode != 0:
            raise TargetRuntimeRejected(f"Docker refused the fixed MCP probe policy: {sanitize_output(created.stderr)}")
        container_id = created.stdout.strip()
        if not re.fullmatch(r"[0-9a-f]{12,64}", container_id):
            raise TargetRuntimeRejected("Docker returned an invalid MCP probe container identifier.")
        inspect_payload = inspect_container(docker, container_id, run_command)
        configured = configured_policy_checks(
            inspect_payload, staging_path, observer_root, normalized_image, probe_tokens
        )
        if not configured or not all(configured.values()):
            failed = ", ".join(key for key, value in configured.items() if not value)
            raise TargetRuntimeRejected(f"Created MCP probe container failed closed policy verification: {failed}")
        started = run_command(
            [docker, "start", container_id], shell=False, capture_output=True, text=True,
            timeout=10, encoding="utf-8", errors="replace", env=docker_environment,
        )
        if started.returncode != 0:
            raise TargetRuntimeRejected("Docker could not start the isolated MCP capability probe.")
        try:
            run_command(
                [docker, "wait", container_id], shell=False, capture_output=True, text=True,
                timeout=timeout + 5, encoding="utf-8", errors="replace",
            )
        except subprocess.TimeoutExpired:
            timed_out = True
            run_command(
                [docker, "kill", container_id], shell=False, capture_output=True, text=True,
                timeout=10, encoding="utf-8", errors="replace",
            )
        final_inspect = inspect_container(docker, container_id, run_command)
        state = final_inspect.get("State") if isinstance(final_inspect.get("State"), dict) else {}
        exit_code = state.get("ExitCode") if isinstance(state.get("ExitCode"), int) else None
        logs = run_command(
            [docker, "logs", "--tail", "200", container_id], shell=False,
            capture_output=True, text=True, timeout=10, encoding="utf-8", errors="replace",
        )
        stdout, stderr = logs.stdout, logs.stderr
    finally:
        if container_id and re.fullmatch(r"[0-9a-f]{12,64}", container_id):
            try:
                removed = run_command(
                    [docker, "rm", "--force", container_id], shell=False,
                    capture_output=True, text=True, timeout=10,
                    encoding="utf-8", errors="replace",
                )
                cleanup_succeeded = removed.returncode == 0
            except subprocess.TimeoutExpired:
                cleanup_succeeded = False

    after_verification = verify_filtered_staging(staging_path)
    configured = configured_policy_checks(
        inspect_payload, staging_path, observer_root, normalized_image, probe_tokens
    )
    policy_checks = {
        **configured,
        "staging_verified_before_run": verification.get("status") == "verified",
        "staging_unchanged_after_run": hmac.compare_digest(
            str(verification.get("staging_sha256") or ""),
            str(after_verification.get("staging_sha256") or ""),
        ),
        "container_cleanup_succeeded": cleanup_succeeded,
    }
    ledger, stdout, stderr = extract_mcp_audit_ledger(stdout, stderr)
    probe_result, stdout, stderr = extract_probe_result(stdout, stderr)
    policy_checks["content_actions_disabled"] = probe_result.get("content_actions_performed") is False
    policy_verified = bool(policy_checks) and all(policy_checks.values())
    decision = "pass" if policy_verified and not timed_out and probe_result.get("status") in {"success", "partial"} else "attention"
    stdout, stderr = sanitize_output(stdout), sanitize_output(stderr)
    evidence: dict[str, object] = {
        "schema": MCP_PROBE_EVIDENCE_SCHEMA,
        "scope": "project-mcp-server-capability-probe",
        "status": "completed",
        "decision": decision,
        "execution_id": execution_id,
        "project_id": project_id,
        "scan_task_id": scan_task_id,
        "started_at": started_at.isoformat(),
        "finished_at": datetime.now(timezone.utc).isoformat(),
        "elapsed_ms": int((time.perf_counter() - started_clock) * 1000),
        "policy_verified": policy_verified,
        "behavioral_telemetry_complete": False,
        "plan_sha256": plan_sha256,
        "candidate": public_candidate(candidate),
        "capability_probe": probe_result,
        "mcp_ledger": ledger,
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
            "probe_command_sha256": sha256(shlex.join(probe_tokens).encode("utf-8")).hexdigest(),
            "server_command_sha256": candidate.get("command_sha256"),
            "exit_code": exit_code,
            "timed_out": timed_out,
            "removed_after_run": cleanup_succeeded,
        },
        "observer": {
            "observer_sha256": observer_sha256,
            "probe_sha256": probe_sha256,
            "integrity": "format-and-event-hash-validated-not-cryptographically-authenticated",
        },
        "docker_context": docker_context,
        "policy_checks": policy_checks,
        "output": {
            "stdout_char_count": len(stdout), "stderr_char_count": len(stderr),
            "stdout_sha256": sha256(stdout.encode("utf-8")).hexdigest(),
            "stderr_sha256": sha256(stderr.encode("utf-8")).hexdigest(),
            "truncated": len(stdout) >= MAX_OUTPUT_CHARACTERS or len(stderr) >= MAX_OUTPUT_CHARACTERS,
            "content_stored": False,
        },
        "limitations": [
            "This evidence covers one selected stdio MCP server declaration, staging digest and local image digest only.",
            "The probe only initializes and lists tools, resources and prompts; it does not call tools or read content.",
            "Capability names are server-provided claims and the target-visible log channel is not cryptographically authenticated.",
            "File access, system-level child processes and network destinations remain uninstrumented.",
        ],
    }
    evidence["evidence_sha256"] = canonical_sha256(evidence)
    path = write_mcp_probe_evidence(project_id, execution_id, evidence)
    evidence["evidence_path"] = str(path)
    return evidence


def verify_probe_binding(
    *, manifest: dict[str, object], scan_task_id: str, image: str,
    timeout_seconds: int, plan_sha256: str, staging_sha256: str,
    manifest_sha256: str,
) -> None:
    binding = manifest.get("binding") if isinstance(manifest.get("binding"), dict) else {}
    expected = {
        "scan_task_id": scan_task_id, "image": image,
        "timeout_seconds": timeout_seconds, "plan_sha256": plan_sha256,
        "staging_sha256": staging_sha256, "manifest_sha256": manifest_sha256,
    }
    observed = {
        "scan_task_id": str(binding.get("scan_task_id") or ""),
        "image": str(binding.get("image") or ""),
        "timeout_seconds": int(binding.get("timeout_seconds") or 0),
        "plan_sha256": str(binding.get("plan_sha256") or ""),
        "staging_sha256": str(manifest.get("staging_sha256") or ""),
        "manifest_sha256": str(manifest.get("manifest_sha256") or ""),
    }
    mismatches = [
        key for key, value in expected.items()
        if not hmac.compare_digest(str(value), str(observed.get(key) or ""))
    ]
    if mismatches:
        raise TargetRuntimeRejected(f"MCP probe execution binding changed: {', '.join(mismatches)}")


def extract_probe_result(
    stdout: str, stderr: str
) -> tuple[dict[str, object], str, str]:
    accepted: dict[str, object] = {}

    def process(value: str) -> str:
        nonlocal accepted
        clean: list[str] = []
        for line in value.splitlines(keepends=True):
            if not line.startswith(MCP_PROBE_PREFIX):
                clean.append(line)
                continue
            if accepted or len(line) > 16_384:
                continue
            try:
                item = json.loads(line[len(MCP_PROBE_PREFIX):].strip())
            except json.JSONDecodeError:
                continue
            normalized = normalize_probe_result(item) if isinstance(item, dict) else None
            if normalized:
                accepted = normalized
        return "".join(clean)

    clean_stdout = process(stdout)
    clean_stderr = process(stderr)
    if not accepted:
        accepted = {
            "schema": MCP_PROBE_RESULT_SCHEMA, "status": "missing",
            "content_actions_performed": False, "content_stored": False,
        }
    return accepted, clean_stdout, clean_stderr


def normalize_probe_result(item: dict[str, object]) -> dict[str, object] | None:
    if item.get("schema") != MCP_PROBE_RESULT_SCHEMA:
        return None
    supplied_hash = str(item.get("result_sha256") or "")
    unhashed = {key: value for key, value in item.items() if key != "result_sha256"}
    if not re.fullmatch(r"[0-9a-f]{64}", supplied_hash) or not hmac.compare_digest(supplied_hash, canonical_sha256(unhashed)):
        return None
    status = str(item.get("status") or "")
    if status not in {"success", "partial", "error"}:
        return None
    method_outcomes = item.get("method_outcomes") if isinstance(item.get("method_outcomes"), dict) else {}
    return {
        "schema": MCP_PROBE_RESULT_SCHEMA,
        "probe_version": safe_display_label(item.get("probe_version")),
        "status": status,
        "protocol_version": safe_display_label(item.get("protocol_version")),
        "server_name": safe_display_label(item.get("server_name")),
        "server_version": safe_display_label(item.get("server_version")),
        "tool_names": normalized_names(item.get("tool_names")),
        "resource_schemes": normalized_names(item.get("resource_schemes")),
        "prompt_names": normalized_names(item.get("prompt_names")),
        "method_outcomes": {
            method: str(method_outcomes.get(method) or "missing")
            for method in ("initialize", "tools/list", "resources/list", "prompts/list")
            if str(method_outcomes.get(method) or "missing") in {"success", "error", "missing"}
        },
        "observer_exit_code": item.get("observer_exit_code") if isinstance(item.get("observer_exit_code"), int) else None,
        "error_code": safe_display_label(item.get("error_code")) if item.get("error_code") else None,
        "content_actions_performed": item.get("content_actions_performed") is True,
        "content_stored": False,
        "result_sha256": supplied_hash,
    }


def normalized_names(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    return sorted({safe_display_label(item) for item in value[:100]})[:100]


def write_mcp_probe_evidence(
    project_id: str, execution_id: str, evidence: dict[str, object]
) -> Path:
    root = MCP_PROBE_EVIDENCE_ROOT / safe_identifier(project_id)
    root.mkdir(parents=True, exist_ok=True)
    path = root / f"{safe_identifier(execution_id)}.json"
    with path.open("x", encoding="utf-8") as handle:
        json.dump(evidence, handle, ensure_ascii=False, indent=2)
    return path


def list_mcp_probe_evidence(project_id: str, limit: int = 20) -> list[dict[str, object]]:
    root = MCP_PROBE_EVIDENCE_ROOT / safe_identifier(project_id)
    if not root.exists():
        return []
    resolved = root.resolve(strict=True)
    if not resolved.is_dir() or is_link_or_junction(resolved):
        raise TargetRuntimeRejected("The MCP probe evidence directory is unsafe.")
    results: list[dict[str, object]] = []
    for path in sorted(resolved.glob("mcp-probe-*.json"), reverse=True)[:max(1, min(100, limit))]:
        if is_link_or_junction(path) or not path.is_file() or path.stat().st_size > 2 * 1024 * 1024:
            continue
        try:
            item = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if isinstance(item, dict) and item.get("schema") == MCP_PROBE_EVIDENCE_SCHEMA:
            results.append({**item, "evidence_path": str(path)})
    return results
