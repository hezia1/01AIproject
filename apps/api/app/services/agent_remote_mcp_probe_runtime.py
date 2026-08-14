from __future__ import annotations

import hmac
import ipaddress
import json
import os
import re
import socket
import subprocess
import time
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path
from typing import Callable
from urllib.parse import urlsplit, urlunsplit
from uuid import uuid4

from app.services.agent_mcp_probe_runtime import (
    MAX_CANDIDATES,
    MAX_CONFIG_BYTES,
    MAX_CONFIG_FILES,
    public_candidate,
    resolve_staging_root,
    safe_display_label,
    verify_probe_binding,
)
from app.services.agent_runtime_validation import image_is_digest_pinned, safe_identifier
from app.services.agent_scanner import extract_mcp_servers, parse_structured_config
from app.services.agent_staging import (
    is_link_or_junction,
    load_filtered_staging_manifest,
    safe_manifest_target,
    verify_filtered_staging,
)
from app.services.agent_target_runtime import (
    MAX_OUTPUT_CHARACTERS,
    TargetRuntimeRejected,
    canonical_sha256,
    configured_policy_checks,
    docker_executable,
    ensure_local_docker_context,
    inspect_container,
    inspect_local_image,
    resolve_bound_staging,
    resolve_observer_asset,
    sanitize_output,
)


REMOTE_MCP_STATUS_SCHEMA = "ai-security-platform.agent-remote-mcp-probe-status/v1"
REMOTE_MCP_EVIDENCE_SCHEMA = "ai-security-platform.agent-remote-mcp-probe-evidence/v1"
REMOTE_MCP_RESULT_SCHEMA = "ai-security-platform.agent-remote-mcp-capability-probe-result/v1"
REMOTE_MCP_PREFIX = "@@AGENT_REMOTE_MCP_PROBE@@"
REMOTE_MCP_SCRIPT = "mcp_remote_capability_probe.py"
REMOTE_MCP_AUTHORIZATION_PHRASE = "PROBE REMOTE MCP SERVER"
REMOTE_MCP_EVIDENCE_ROOT = Path(__file__).resolve().parents[4] / "artifacts" / "agent-sandbox" / "remote-mcp-probe-evidence"
SUPPORTED_TRANSPORTS = {
    "", "http", "https", "sse", "streamable-http", "streamable_http", "streamablehttp",
}
BLOCKED_HOST_SUFFIXES = (
    ".localhost", ".local", ".internal", ".home.arpa", ".lan", ".localdomain",
)
RunCommand = Callable[..., subprocess.CompletedProcess[str]]
ResolveAddress = Callable[[str, int], list[str]]


def list_remote_mcp_probe_status(
    project_id: str, current_scan_task_id: str | None, execution_enabled: bool,
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
            candidates = [public_candidate(item) for item in discover_remote_candidates(path, manifest)]
            builds.append({
                "build_id": str(manifest.get("build_id") or path.name),
                "created_at": manifest.get("created_at"),
                "staging_sha256": manifest.get("staging_sha256"),
                "manifest_sha256": manifest.get("manifest_sha256"),
                "scan_task_id": binding.get("scan_task_id"),
                "plan_sha256": binding.get("plan_sha256"),
                "image": binding.get("image"),
                "timeout_seconds": min(15, int(binding.get("timeout_seconds") or 10)),
                "candidates": candidates,
            })
            if len(builds) >= 20:
                break
    return {
        "schema": REMOTE_MCP_STATUS_SCHEMA,
        "execution_enabled_by_project_policy": bool(execution_enabled),
        "authorization_phrase": REMOTE_MCP_AUTHORIZATION_PHRASE,
        "current_scan_task_id": current_scan_task_id,
        "builds": builds,
        "download_performed": False,
        "limitations": [
            "Only recognized HTTPS remote MCP declarations in verified JSON, YAML and TOML staging files are eligible.",
            "Configured credentials, headers, environment variables, URL credentials, query strings and non-standard ports are rejected.",
            "DNS is resolved immediately before execution; every resolved address must be globally routable and the probe connects only to approved IPs.",
            "The fixed probe lists capabilities only and never calls tools or reads resource or prompt content.",
            "The local digest image must already contain Python 3 and a usable TLS trust store; no image is downloaded.",
        ],
    }


def discover_remote_candidates(
    staging_path: Path, manifest: dict[str, object],
) -> list[dict[str, object]]:
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
            candidate = build_remote_candidate(
                relative_path=relative_path,
                config_sha256=str(entry.get("sha256") or ""),
                server_name=server_name,
                node=node,
            )
            if candidate is not None:
                candidates.append(candidate)
            if len(candidates) >= MAX_CANDIDATES:
                return candidates
    return candidates


def build_remote_candidate(
    *, relative_path: str, config_sha256: str, server_name: str, node: dict[str, object],
) -> dict[str, object] | None:
    remote_url = node.get("url") or node.get("endpoint")
    if not isinstance(remote_url, str) or not remote_url.strip():
        return None
    endpoint = remote_url.strip()
    explicit_transport = str(node.get("transport") or node.get("type") or "").strip().lower()
    headers = node.get("headers")
    environment = node.get("env") or node.get("environment")
    configured_credentials = any(
        credential_key(str(key))
        and value not in (None, "", {}, [])
        for key, value in node.items()
    )
    parsed, url_checks, preview = static_endpoint_checks(endpoint)
    checks: dict[str, bool] = {
        "enabled": node.get("disabled") is not True,
        "recognized_remote_transport": explicit_transport in SUPPORTED_TRANSPORTS,
        "remote_url_present": True,
        "https_transport": url_checks["https_transport"],
        "hostname_eligible": url_checks["hostname_eligible"],
        "standard_https_port": url_checks["standard_https_port"],
        "no_url_credentials": url_checks["no_url_credentials"],
        "no_url_query_or_fragment": url_checks["no_url_query_or_fragment"],
        "bounded_url": len(endpoint) <= 1000,
        "no_local_command": not bool(node.get("command")),
        "no_configured_headers": not isinstance(headers, dict) or not headers,
        "no_configured_environment": not isinstance(environment, dict) or not environment,
        "no_configured_credentials": not configured_credentials,
    }
    identity = canonical_sha256({
        "config_path": relative_path,
        "config_sha256": config_sha256,
        "server_name": server_name,
        "endpoint": endpoint,
    })
    return {
        "candidate_id": identity[:24],
        "config_path": relative_path[:500],
        "config_sha256": config_sha256 if re.fullmatch(r"[0-9a-f]{64}", config_sha256) else "",
        "server_name": safe_display_label(server_name),
        "transport": normalized_transport(explicit_transport),
        "endpoint_preview": preview,
        "endpoint_sha256": sha256(endpoint.encode("utf-8")).hexdigest(),
        "hostname": parsed.hostname if parsed is not None else "[invalid-hostname]",
        "eligible": all(checks.values()),
        "checks": checks,
        "rejection_reasons": [key for key, passed in checks.items() if not passed],
        "_endpoint": endpoint,
    }


def normalized_transport(value: str) -> str:
    if value == "sse":
        return "legacy-sse"
    if value in {"streamable-http", "streamable_http", "streamablehttp", "http", "https"}:
        return "streamable-http"
    return "auto-http"


def credential_key(value: str) -> bool:
    normalized = re.sub(r"[^a-z0-9]", "", value.lower())
    return any(marker in normalized for marker in (
        "authorization", "credential", "password", "secret", "token",
        "apikey", "bearer", "oauth", "clientsecret",
    ))


def static_endpoint_checks(endpoint: str):
    try:
        parsed = urlsplit(endpoint)
        port = parsed.port
    except ValueError:
        parsed = None
        port = None
    host = (parsed.hostname or "").rstrip(".").lower() if parsed is not None else ""
    hostname_eligible = eligible_hostname(host)
    checks = {
        "https_transport": parsed is not None and parsed.scheme.lower() == "https",
        "hostname_eligible": hostname_eligible,
        "standard_https_port": parsed is not None and port in {None, 443},
        "no_url_credentials": parsed is not None and parsed.username is None and parsed.password is None,
        "no_url_query_or_fragment": parsed is not None and not parsed.query and not parsed.fragment,
    }
    preview = "[invalid-endpoint]"
    if parsed is not None and parsed.scheme and host:
        display_host = f"[{host}]" if ":" in host else host
        preview = urlunsplit((parsed.scheme.lower(), display_host, parsed.path or "/", "", ""))[:500]
    return parsed, checks, preview


def eligible_hostname(host: str) -> bool:
    if not host or host == "localhost" or host.endswith(BLOCKED_HOST_SUFFIXES):
        return False
    try:
        return ipaddress.ip_address(host).is_global
    except ValueError:
        return bool("." in host and re.fullmatch(r"[a-z0-9.-]{1,253}", host))


def default_resolve_address(host: str, port: int) -> list[str]:
    try:
        values = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise TargetRuntimeRejected("The remote MCP hostname could not be resolved.") from exc
    return [str(item[4][0]) for item in values if item and len(item) >= 5 and item[4]]


def resolve_public_addresses(
    endpoint: str, resolver: ResolveAddress = default_resolve_address,
) -> tuple[str, int, list[str]]:
    parsed, checks, _ = static_endpoint_checks(endpoint)
    if parsed is None or not all(checks.values()):
        raise TargetRuntimeRejected("The remote MCP endpoint failed the static HTTPS policy.")
    host = str(parsed.hostname or "").rstrip(".").lower()
    port = parsed.port or 443
    raw_addresses = resolver(host, port)
    addresses: set[str] = set()
    for value in raw_addresses[:32]:
        try:
            address = ipaddress.ip_address(value)
        except ValueError as exc:
            raise TargetRuntimeRejected("DNS returned an invalid address for the remote MCP endpoint.") from exc
        if not address.is_global:
            raise TargetRuntimeRejected("Remote MCP probing blocks loopback, private, link-local, reserved and metadata destinations.")
        addresses.add(address.compressed)
    if not addresses:
        raise TargetRuntimeRejected("The remote MCP hostname did not resolve to an approved public address.")
    if len(addresses) > 16:
        raise TargetRuntimeRejected("The remote MCP hostname resolved to too many addresses.")
    return host, port, sorted(addresses)


def resolve_remote_probe_asset(observer_root: Path) -> tuple[Path, str]:
    try:
        path = (observer_root / REMOTE_MCP_SCRIPT).resolve(strict=True)
    except OSError as exc:
        raise TargetRuntimeRejected("The bundled remote MCP probe is unavailable.") from exc
    if path.parent != observer_root or not path.is_file() or is_link_or_junction(path) or path.stat().st_size > 256 * 1024:
        raise TargetRuntimeRejected("The bundled remote MCP probe asset is unsafe.")
    return path, sha256(path.read_bytes()).hexdigest()


def build_remote_probe_container_command(
    *, docker: str, container_name: str, staging_path: Path, observer_path: Path,
    image: str, command_tokens: list[str],
) -> list[str]:
    return [
        docker, "create", "--pull=never", "--name", container_name,
        "--label", "ai-security-platform.scope=agent-remote-mcp-probe",
        "--network", "bridge", "--read-only", "--cpus", "0.5",
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


def configured_remote_policy_checks(
    inspected: dict[str, object], staging_path: Path, observer_path: Path,
    image: str, command_tokens: list[str],
) -> dict[str, bool]:
    checks = configured_policy_checks(
        inspected, staging_path, observer_path, image, command_tokens,
    )
    checks.pop("network_none", None)
    host = inspected.get("HostConfig") if isinstance(inspected.get("HostConfig"), dict) else {}
    checks.update({
        "network_bridge": str(host.get("NetworkMode") or "") == "bridge",
        "no_published_ports": not bool(host.get("PortBindings")),
        "no_extra_hosts": not bool(host.get("ExtraHosts")),
        "destination_enforced_by_fixed_probe": command_tokens[:4] == [
            "python", "-I", "-B", "/opt/agent-observer/mcp_remote_capability_probe.py",
        ],
    })
    return checks


def run_remote_mcp_probe_validation(
    *, project_id: str, scan_task_id: str, image: str, timeout_seconds: int,
    plan_sha256: str, staging_build_id: str, staging_sha256: str,
    manifest_sha256: str, candidate_id: str, authorization_phrase: str,
    operator_confirmed: bool, run_command: RunCommand = subprocess.run,
    resolver: ResolveAddress = default_resolve_address,
) -> dict[str, object]:
    if not operator_confirmed or not hmac.compare_digest(
        authorization_phrase, REMOTE_MCP_AUTHORIZATION_PHRASE,
    ):
        raise TargetRuntimeRejected("Remote MCP probing requires its separate authorization phrase and confirmation.")
    normalized_image = image.strip()
    timeout = max(1, min(15, int(timeout_seconds)))
    if not image_is_digest_pinned(normalized_image):
        raise TargetRuntimeRejected("Remote MCP probing requires a digest-pinned image available locally.")
    staging_path = resolve_bound_staging(project_id, staging_build_id)
    manifest = load_filtered_staging_manifest(staging_path)
    verification = verify_filtered_staging(staging_path)
    verify_probe_binding(
        manifest=manifest, scan_task_id=scan_task_id, image=normalized_image,
        timeout_seconds=timeout, plan_sha256=plan_sha256,
        staging_sha256=staging_sha256, manifest_sha256=manifest_sha256,
    )
    candidates = discover_remote_candidates(staging_path, manifest)
    candidate = next((item for item in candidates if item.get("candidate_id") == candidate_id), None)
    if candidate is None:
        raise TargetRuntimeRejected("The selected remote MCP candidate is not present in the verified staging build.")
    if candidate.get("eligible") is not True:
        reasons = ", ".join(str(item) for item in candidate.get("rejection_reasons", []))
        raise TargetRuntimeRejected(f"The selected remote MCP server is not eligible for probing: {reasons}")
    endpoint = candidate.get("_endpoint")
    if not isinstance(endpoint, str):
        raise TargetRuntimeRejected("The selected remote MCP endpoint is invalid.")
    hostname, port, approved_ips = resolve_public_addresses(endpoint, resolver)

    observer_root, _ = resolve_observer_asset()
    _, probe_sha256 = resolve_remote_probe_asset(observer_root)
    probe_tokens = [
        "python", "-I", "-B", "/opt/agent-observer/mcp_remote_capability_probe.py",
        "--endpoint", endpoint, "--timeout-seconds", str(timeout),
        "--transport-hint", str(candidate.get("transport") or "auto-http"),
    ]
    for address in approved_ips:
        probe_tokens.extend(["--approved-ip", address])
    docker = docker_executable()
    docker_context = ensure_local_docker_context(docker, run_command)
    inspected_image = inspect_local_image(docker, normalized_image, run_command)
    execution_id = f"remote-mcp-probe-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}-{uuid4().hex[:10]}"
    container_name = f"ai-agent-remote-mcp-{uuid4().hex[:12]}"
    create_command = build_remote_probe_container_command(
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
            raise TargetRuntimeRejected(f"Docker refused the fixed remote MCP probe policy: {sanitize_output(created.stderr)}")
        container_id = created.stdout.strip()
        if not re.fullmatch(r"[0-9a-f]{12,64}", container_id):
            raise TargetRuntimeRejected("Docker returned an invalid remote MCP probe container identifier.")
        inspect_payload = inspect_container(docker, container_id, run_command)
        configured = configured_remote_policy_checks(
            inspect_payload, staging_path, observer_root, normalized_image, probe_tokens,
        )
        if not configured or not all(configured.values()):
            failed = ", ".join(key for key, value in configured.items() if not value)
            raise TargetRuntimeRejected(f"Created remote MCP probe container failed closed policy verification: {failed}")
        started = run_command(
            [docker, "start", container_id], shell=False, capture_output=True, text=True,
            timeout=10, encoding="utf-8", errors="replace", env=docker_environment,
        )
        if started.returncode != 0:
            raise TargetRuntimeRejected("Docker could not start the isolated remote MCP probe.")
        try:
            run_command(
                [docker, "wait", container_id], shell=False, capture_output=True, text=True,
                timeout=timeout + 8, encoding="utf-8", errors="replace",
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
    configured = configured_remote_policy_checks(
        inspect_payload, staging_path, observer_root, normalized_image, probe_tokens,
    )
    probe_result, stdout, stderr = extract_remote_probe_result(stdout, stderr)
    policy_checks = {
        **configured,
        "staging_verified_before_run": verification.get("status") == "verified",
        "staging_unchanged_after_run": hmac.compare_digest(
            str(verification.get("staging_sha256") or ""),
            str(after_verification.get("staging_sha256") or ""),
        ),
        "container_cleanup_succeeded": cleanup_succeeded,
        "dns_addresses_public": bool(approved_ips),
        "endpoint_binding_exact": hmac.compare_digest(
            str(probe_result.get("endpoint") or ""), str(candidate.get("endpoint_preview") or ""),
        ),
        "approved_addresses_exact": probe_result.get("approved_ips") == approved_ips,
        "authentication_disabled": probe_result.get("authentication_sent") is False,
        "configured_headers_disabled": probe_result.get("configured_headers_used") is False,
        "content_actions_disabled": probe_result.get("content_actions_performed") is False,
    }
    policy_verified = bool(policy_checks) and all(policy_checks.values())
    decision = "pass" if policy_verified and not timed_out and probe_result.get("status") in {"success", "partial"} else "attention"
    stdout, stderr = sanitize_output(stdout), sanitize_output(stderr)
    evidence: dict[str, object] = {
        "schema": REMOTE_MCP_EVIDENCE_SCHEMA,
        "scope": "project-remote-mcp-server-capability-probe",
        "status": "completed", "decision": decision,
        "execution_id": execution_id, "project_id": project_id,
        "scan_task_id": scan_task_id, "started_at": started_at.isoformat(),
        "finished_at": datetime.now(timezone.utc).isoformat(),
        "elapsed_ms": int((time.perf_counter() - started_clock) * 1000),
        "policy_verified": policy_verified,
        "behavioral_telemetry_complete": False,
        "plan_sha256": plan_sha256,
        "candidate": public_candidate(candidate),
        "capability_probe": probe_result,
        "network_policy": {
            "hostname": hostname, "port": port,
            "approved_ips": approved_ips,
            "dns_resolved_immediately_before_run": True,
            "private_and_metadata_destinations_blocked": True,
            "cross_origin_redirects_blocked": True,
            "transport_enforcement": "fixed-probe-application-layer",
        },
        "image": {
            "reference": normalized_image,
            "digest": normalized_image.rsplit("@", 1)[1],
            "local_image_id": inspected_image.get("Id"),
            "download_performed": False,
        },
        "staging": {
            "build_id": staging_build_id, "path": str(staging_path),
            "staging_sha256": verification.get("staging_sha256"),
            "manifest_sha256": verification.get("manifest_sha256"),
            "unchanged_after_run": policy_checks["staging_unchanged_after_run"],
        },
        "container": {
            "id_sha256": sha256(str(container_id or "").encode("utf-8")).hexdigest(),
            "probe_command_sha256": sha256("\0".join(probe_tokens).encode("utf-8")).hexdigest(),
            "exit_code": exit_code, "timed_out": timed_out,
            "removed_after_run": cleanup_succeeded,
        },
        "probe_asset": {
            "script_sha256": probe_sha256,
            "content_stored": False,
            "integrity": "mounted-read-only-and-command-hash-bound",
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
            "This evidence covers one selected remote MCP declaration, staging digest, image digest and one bounded network probe only.",
            "The probe lists capability names only; it does not call tools, read resources, retrieve prompts or store response content.",
            "Configured authentication is intentionally not used, so private servers may return only public capabilities or reject the probe.",
            "Destination enforcement is implemented by the fixed probe and pinned IP connection, not a dedicated egress firewall.",
            "Server-provided names and identity are claims and do not prove the implementation or the whole Agent is safe.",
        ],
    }
    evidence["evidence_sha256"] = canonical_sha256(evidence)
    path = write_remote_mcp_probe_evidence(project_id, execution_id, evidence)
    evidence["evidence_path"] = str(path)
    return evidence


def extract_remote_probe_result(
    stdout: str, stderr: str,
) -> tuple[dict[str, object], str, str]:
    accepted: dict[str, object] = {}

    def process(value: str) -> str:
        nonlocal accepted
        clean: list[str] = []
        for line in value.splitlines(keepends=True):
            if not line.startswith(REMOTE_MCP_PREFIX):
                clean.append(line)
                continue
            if accepted or len(line) > 32_768:
                continue
            try:
                item = json.loads(line[len(REMOTE_MCP_PREFIX):].strip())
            except json.JSONDecodeError:
                continue
            normalized = normalize_remote_probe_result(item) if isinstance(item, dict) else None
            if normalized:
                accepted = normalized
        return "".join(clean)

    clean_stdout = process(stdout)
    clean_stderr = process(stderr)
    if not accepted:
        accepted = {
            "schema": REMOTE_MCP_RESULT_SCHEMA, "status": "missing",
            "endpoint": "", "approved_ips": [],
            "authentication_sent": False, "configured_headers_used": False,
            "content_actions_performed": False, "content_stored": False,
        }
    return accepted, clean_stdout, clean_stderr


def normalize_remote_probe_result(item: dict[str, object]) -> dict[str, object] | None:
    if item.get("schema") != REMOTE_MCP_RESULT_SCHEMA:
        return None
    supplied_hash = str(item.get("result_sha256") or "")
    unhashed = {key: value for key, value in item.items() if key != "result_sha256"}
    if not re.fullmatch(r"[0-9a-f]{64}", supplied_hash) or not hmac.compare_digest(
        supplied_hash, canonical_sha256(unhashed),
    ):
        return None
    status = str(item.get("status") or "")
    if status not in {"success", "partial", "error"}:
        return None
    outcomes = item.get("method_outcomes") if isinstance(item.get("method_outcomes"), dict) else {}
    network = item.get("network_requests") if isinstance(item.get("network_requests"), list) else []
    return {
        "schema": REMOTE_MCP_RESULT_SCHEMA,
        "probe_version": safe_display_label(item.get("probe_version")),
        "status": status,
        "transport_mode": safe_display_label(item.get("transport_mode")),
        "protocol_version": safe_display_label(item.get("protocol_version")),
        "server_name": safe_display_label(item.get("server_name")),
        "server_version": safe_display_label(item.get("server_version")),
        "endpoint": normalized_endpoint(item.get("endpoint")),
        "approved_ips": normalized_public_ips(item.get("approved_ips")),
        "redirects": [normalized_endpoint(value) for value in list_values(item.get("redirects"), 2)],
        "tool_names": normalized_names(item.get("tool_names")),
        "resource_schemes": normalized_names(item.get("resource_schemes")),
        "prompt_names": normalized_names(item.get("prompt_names")),
        "method_outcomes": {
            method: str(outcomes.get(method) or "missing")
            for method in ("server/discover", "initialize", "tools/list", "resources/list", "prompts/list")
            if str(outcomes.get(method) or "missing") in {"success", "error", "missing"}
        },
        "network_requests": [normalized_network_event(value) for value in network[:10] if isinstance(value, dict)],
        "session_established": item.get("session_established") is True,
        "error_code": safe_display_label(item.get("error_code")) if item.get("error_code") else None,
        "authentication_sent": item.get("authentication_sent") is True,
        "configured_headers_used": item.get("configured_headers_used") is True,
        "content_actions_performed": item.get("content_actions_performed") is True,
        "content_stored": False,
        "result_sha256": supplied_hash,
    }


def normalized_names(value: object) -> list[str]:
    return sorted({safe_display_label(item) for item in list_values(value, 100)})[:100]


def list_values(value: object, limit: int) -> list[str]:
    return [str(item) for item in value[:limit] if isinstance(item, str)] if isinstance(value, list) else []


def normalized_endpoint(value: object) -> str:
    text = str(value or "")[:500]
    try:
        parsed = urlsplit(text)
    except ValueError:
        return "[invalid-endpoint]"
    if parsed.scheme not in {"https", "http"} or not parsed.hostname:
        return "[invalid-endpoint]"
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path or "/", "", ""))[:500]


def normalized_public_ips(value: object) -> list[str]:
    results: list[str] = []
    for item in list_values(value, 16):
        try:
            address = ipaddress.ip_address(item)
        except ValueError:
            continue
        if address.is_global:
            results.append(address.compressed)
    return sorted(set(results))


def normalized_network_event(value: dict[str, object]) -> dict[str, object]:
    return {
        "method": safe_display_label(value.get("method")),
        "http_status": value.get("http_status") if isinstance(value.get("http_status"), int) else None,
        "content_type": safe_display_label(value.get("content_type")),
        "response_bytes": min(512 * 1024, max(0, int(value.get("response_bytes") or 0))),
        "remote_ip": normalized_public_ips([value.get("remote_ip")])[0] if normalized_public_ips([value.get("remote_ip")]) else "",
        "elapsed_ms": min(60_000, max(0, int(value.get("elapsed_ms") or 0))),
        "outcome": str(value.get("outcome") or "unknown") if str(value.get("outcome") or "") in {"success", "error", "accepted"} else "unknown",
    }


def write_remote_mcp_probe_evidence(
    project_id: str, execution_id: str, evidence: dict[str, object],
) -> Path:
    root = REMOTE_MCP_EVIDENCE_ROOT / safe_identifier(project_id)
    root.mkdir(parents=True, exist_ok=True)
    path = root / f"{safe_identifier(execution_id)}.json"
    with path.open("x", encoding="utf-8") as handle:
        json.dump(evidence, handle, ensure_ascii=False, indent=2)
    return path


def list_remote_mcp_probe_evidence(
    project_id: str, limit: int = 20,
) -> list[dict[str, object]]:
    root = REMOTE_MCP_EVIDENCE_ROOT / safe_identifier(project_id)
    if not root.exists():
        return []
    resolved = root.resolve(strict=True)
    if not resolved.is_dir() or is_link_or_junction(resolved):
        raise TargetRuntimeRejected("The remote MCP probe evidence directory is unsafe.")
    results: list[dict[str, object]] = []
    for path in sorted(resolved.glob("remote-mcp-probe-*.json"), reverse=True)[:max(1, min(100, limit))]:
        if is_link_or_junction(path) or not path.is_file() or path.stat().st_size > 2 * 1024 * 1024:
            continue
        try:
            item = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if isinstance(item, dict) and item.get("schema") == REMOTE_MCP_EVIDENCE_SCHEMA:
            results.append({**item, "evidence_path": str(path)})
    return results
