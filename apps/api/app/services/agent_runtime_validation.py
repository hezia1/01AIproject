from __future__ import annotations

import os
import json
import re
import shutil
from hashlib import sha256
from pathlib import Path
from typing import Iterable


RUNTIME_PLAN_SCHEMA = "ai-security-platform.agent-runtime-plan/v1"
EVIDENCE_SCHEMA = "ai-security-platform.agent-runtime-evidence/v1"
STAGING_RELATIVE_ROOT = Path("artifacts") / "agent-sandbox" / "staging"
MAX_DISCOVERED_FILES = 20_000

SENSITIVE_NAMES = {
    ".env", ".env.local", ".env.production", ".env.development",
    "id_rsa", "id_ed25519", "credentials", "credentials.json",
    "secrets.json", "secret.json", ".npmrc", ".pypirc", ".netrc",
}
SENSITIVE_SUFFIXES = {".pem", ".key", ".p12", ".pfx", ".kdbx"}
EXCLUDED_DIRECTORY_NAMES = {
    ".git", ".svn", ".hg", ".ssh", ".aws", ".azure", ".kube",
    "node_modules", ".venv", "venv", "__pycache__",
}
UNSAFE_COMMAND_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("shell-control-operator", re.compile(r"(?:[;&|`]|\$\(|(?:^|\s)[<>])")),
    ("destructive-command", re.compile(r"(?i)(?:\brm\s+-[^\r\n]*r[^\r\n]*f\b|\bremove-item\b[^\r\n]*-recurse|\bformat\b|\bmkfs\b|\bdiskpart\b)")),
    ("network-downloader", re.compile(r"(?i)\b(curl|wget|invoke-webrequest|irm|iwr)\b")),
    ("package-install", re.compile(r"(?i)\b(npm|pnpm|yarn|pip|pipx|uv|apt(?:-get)?|apk|dnf|yum)\s+(?:install|add|i)\b")),
    ("secret-enumeration", re.compile(r"(?i)(?:\bprintenv\b|\benv\s*$|get-childitem\s+env:|/proc/(?:self|\d+)/environ)")),
    ("nested-container", re.compile(r"(?i)\b(docker|podman|nerdctl)\s+(run|build|compose|exec)\b")),
    ("privilege-escalation", re.compile(r"(?i)\b(sudo|su\s+-|runas)\b")),
    ("sensitive-path-reference", re.compile(r"(?i)(?:^|[\s=])(?:[A-Z]:\\|/etc/|/proc/|~[/\\]|\.env(?:\.|\s|$)|\.ssh[/\\])")),
)


def build_agent_runtime_plan(
    *,
    project_id: str,
    source_path: str | None,
    command: str | None,
    image: str | None,
    dataflow: dict[str, object] | None,
    sandbox_enabled: bool,
    operator_confirmed: bool = False,
    timeout_seconds: int = 10,
) -> dict[str, object]:
    root = resolve_source_root(source_path)
    normalized_command = str(command or "").strip()
    normalized_image = str(image or "").strip()
    sensitive_inventory = inspect_sensitive_inventory(root)
    staging_path = staging_workspace_path(project_id)
    selected_paths = select_runtime_candidate_paths(dataflow)
    checks = [
        check("sandbox-module", sandbox_enabled, "SANDBOX module is enabled.", "Enable the project SANDBOX module before runtime validation."),
        check("source-directory", root is not None, "Project source directory exists.", "Configure an existing project source directory."),
        check("source-link-boundary", root is not None and not is_link_or_junction(root), "Source root is not a symlink or junction.", "Use a real project directory rather than a symlink or junction."),
        check("explicit-command", bool(normalized_command), "An explicit command is configured.", "Select and review one explicit Agent startup command."),
        command_check(normalized_command),
        check("explicit-image", bool(normalized_image), "An explicit container image is configured.", "Select an explicit local container image."),
        image_reference_check(normalized_image),
        check("digest-pinned-image", image_is_digest_pinned(normalized_image), "Image is pinned by sha256 digest.", "Pin the image as name@sha256:<64 hex characters>."),
        docker_cli_check(),
        policy_check("network-none", "Container network must remain disabled."),
        policy_check("read-only-rootfs", "Container root filesystem must remain read-only."),
        policy_check("no-host-sockets", "Docker/Podman and other host control sockets must not be mounted."),
        policy_check("no-host-secrets", "Host environment variables, credentials and secret files must not be injected."),
        policy_check("resource-limits", "CPU, memory, process and timeout limits are mandatory."),
        staging_check(root, staging_path, sensitive_inventory),
        confirmation_check(operator_confirmed),
    ]
    blockers = [item for item in checks if item["status"] == "block"]
    warnings = [item for item in checks if item["status"] == "warn"]
    plan: dict[str, object] = {
        "schema": RUNTIME_PLAN_SCHEMA,
        "mode": "preflight-only",
        "execution_enabled": False,
        "decision": "blocked" if blockers else "awaiting_explicit_execution_approval",
        "project_id": project_id,
        "source_path": str(root) if root else source_path,
        "proposed_command": redact_command(normalized_command) if normalized_command else None,
        "proposed_image": redact_image_reference(normalized_image) if normalized_image else None,
        "timeout_seconds": max(1, min(30, int(timeout_seconds))),
        "staging": {
            "status": "not_created",
            "path": str(staging_path),
            "source_mode": "filtered-copy",
            "container_mount": "/workspace:ro",
            "excluded_directory_names": sorted(EXCLUDED_DIRECTORY_NAMES),
            "excluded_sensitive_names": sorted(SENSITIVE_NAMES),
            "excluded_sensitive_suffixes": sorted(SENSITIVE_SUFFIXES),
            **sensitive_inventory,
        },
        "isolation_policy": {
            "runtime": "docker",
            "network": "none",
            "root_filesystem": "read-only",
            "workspace": "filtered-copy-read-only",
            "environment_injection": "none",
            "privileged": False,
            "capabilities": "drop-all",
            "no_new_privileges": True,
            "host_sockets": "none",
            "tmpfs": "/tmp:rw,noexec,nosuid,size=128m",
            "resource_limits": {"cpus": "1", "memory": "512m", "pids": 128, "timeout_seconds": max(1, min(30, int(timeout_seconds)))},
        },
        "checks": checks,
        "summary": {
            "pass_count": sum(item["status"] == "pass" for item in checks),
            "warning_count": len(warnings),
            "blocking_count": len(blockers),
            "candidate_path_count": len(selected_paths),
            "sensitive_file_count": int(sensitive_inventory["sensitive_file_count"]),
            "inventory_truncated": bool(sensitive_inventory["inventory_truncated"]),
        },
        "candidate_dataflow_paths": selected_paths,
        "next_action": (
            "Resolve every blocking preflight check. This phase never creates the staging copy or runs the container."
            if blockers
            else "Preflight passed, but execution remains disabled until a separate user-approved implementation stage creates the filtered copy and runs one reviewed target."
        ),
        "limitations": [
            "This plan performs no container execution, image pull, package installation, network request or staging copy.",
            "Docker CLI presence does not prove that the daemon is running or that the digest-pinned image exists locally.",
            "Sensitive-file inventory uses file names and suffixes only; it never opens or returns secret values.",
            "Future runtime evidence must distinguish observed, policy-blocked, not-observed and not-instrumented states.",
        ],
    }
    plan_sha256 = sha256(json.dumps(plan, ensure_ascii=False, sort_keys=True).encode("utf-8")).hexdigest()
    evidence_template = build_runtime_evidence_template(selected_paths)
    evidence_template["plan_sha256"] = plan_sha256
    plan["plan_sha256"] = plan_sha256
    plan["evidence_template"] = evidence_template
    return plan


def build_runtime_evidence_template(paths: list[dict[str, object]]) -> dict[str, object]:
    return {
        "schema": EVIDENCE_SCHEMA,
        "status": "not_run",
        "execution_id": None,
        "plan_sha256": None,
        "image_digest": None,
        "staging_sha256": None,
        "started_at": None,
        "finished_at": None,
        "exit_code": None,
        "timed_out": False,
        "policy": {
            "network": "not_verified",
            "filesystem": "not_verified",
            "privileges": "not_verified",
            "resource_limits": "not_verified",
        },
        "observations": {
            "processes": [],
            "file_access": [],
            "network_attempts": [],
            "tool_calls": [],
        },
        "path_results": [
            {
                "dataflow_path_id": str(item.get("id") or ""),
                "static_severity": item.get("severity"),
                "static_confidence": item.get("confidence"),
                "runtime_status": "not_run",
                "observation_ids": [],
                "reason": "No controlled execution has been performed.",
            }
            for item in paths
        ],
        "redaction": {"applied": True, "secret_values_stored": False},
    }


def correlate_runtime_observations(
    dataflow_paths: list[dict[str, object]],
    observations: dict[str, object],
) -> list[dict[str, object]]:
    events = normalized_observations(observations)
    results: list[dict[str, object]] = []
    for path in dataflow_paths:
        capability = str(path.get("capability") or "")
        relevant = matching_observations(capability, events)
        policy_blocked = [item for item in relevant if item.get("outcome") == "blocked_by_policy"]
        observed = [item for item in relevant if item.get("outcome") in {"observed", "allowed", "attempted"}]
        if observed:
            status = "observed"
            reason = "Runtime observations matched the static capability path."
            matched = observed
        elif policy_blocked:
            status = "blocked_by_policy"
            reason = "A matching runtime attempt was blocked by the sandbox policy."
            matched = policy_blocked
        else:
            status = "not_observed"
            reason = "No matching event was recorded; this does not prove that the path is impossible."
            matched = []
        results.append({
            "dataflow_path_id": str(path.get("id") or ""),
            "static_severity": path.get("severity"),
            "static_confidence": path.get("confidence"),
            "runtime_status": status,
            "observation_ids": [str(item.get("id") or "") for item in matched if item.get("id")],
            "reason": reason,
        })
    return results


def select_runtime_candidate_paths(dataflow: dict[str, object] | None) -> list[dict[str, object]]:
    paths = dataflow.get("paths") if isinstance(dataflow, dict) and isinstance(dataflow.get("paths"), list) else []
    selected = [
        item for item in paths
        if isinstance(item, dict) and str(item.get("severity") or "") in {"critical", "high"}
    ]
    return [{
        "id": str(item.get("id") or ""),
        "kind": str(item.get("kind") or ""),
        "title": str(item.get("title") or "")[:300],
        "severity": str(item.get("severity") or ""),
        "confidence": str(item.get("confidence") or ""),
        "asset_path": str(item.get("asset_path") or "")[:500],
        "tool_asset_path": str(item.get("tool_asset_path") or "")[:500] or None,
        "capability": str(item.get("capability") or "")[:200],
        "resource_type": str(item.get("resource_type") or "")[:100],
        "resource_scope": str(item.get("resource_scope") or "")[:300],
    } for item in selected[:100]]


def inspect_sensitive_inventory(root: Path | None) -> dict[str, object]:
    if root is None:
        return {"scanned_file_count": 0, "sensitive_file_count": 0, "sensitive_categories": {}, "linked_directory_count": 0, "inventory_truncated": False}
    scanned = 0
    sensitive = 0
    linked_directories = 0
    categories: dict[str, int] = {}
    truncated = False
    try:
        for current_root, directories, files in os.walk(root, followlinks=False):
            retained_directories: list[str] = []
            for name in directories:
                directory_path = Path(current_root) / name
                if name.lower() in EXCLUDED_DIRECTORY_NAMES:
                    continue
                if is_link_or_junction(directory_path):
                    linked_directories += 1
                    continue
                retained_directories.append(name)
            directories[:] = retained_directories
            for name in files:
                scanned += 1
                if scanned > MAX_DISCOVERED_FILES:
                    truncated = True
                    break
                category = sensitive_category(name)
                if category:
                    sensitive += 1
                    categories[category] = categories.get(category, 0) + 1
            if truncated:
                break
    except OSError:
        truncated = True
    return {
        "scanned_file_count": min(scanned, MAX_DISCOVERED_FILES),
        "sensitive_file_count": sensitive,
        "sensitive_categories": categories,
        "linked_directory_count": linked_directories,
        "inventory_truncated": truncated,
    }


def sensitive_category(name: str) -> str | None:
    lowered = name.lower()
    if lowered == ".env" or lowered.startswith(".env."):
        return "environment-file"
    if lowered in SENSITIVE_NAMES:
        return "credential-file"
    if Path(lowered).suffix in SENSITIVE_SUFFIXES:
        return "private-key-or-certificate"
    return None


def normalized_observations(observations: dict[str, object]) -> list[dict[str, object]]:
    result: list[dict[str, object]] = []
    for key in ("processes", "file_access", "network_attempts", "tool_calls"):
        values = observations.get(key)
        if not isinstance(values, list):
            continue
        for value in values[:1_000]:
            if isinstance(value, dict):
                result.append({**value, "observation_type": key})
    return result


def observation_matches(capability: str, event: dict[str, object]) -> bool:
    event_type = str(event.get("observation_type") or "")
    declared = str(event.get("capability") or event.get("tool") or "").lower()
    if capability in {"shell-execution", "server-process", "all-capabilities"}:
        return event_type == "processes" or any(token in declared for token in ("shell", "command", "process"))
    if capability in {"filesystem-read", "filesystem-write", "secret-access"}:
        return event_type == "file_access" or any(token in declared for token in ("file", "secret", "env"))
    if capability == "network-egress":
        return event_type == "network_attempts" or any(token in declared for token in ("http", "network", "browser"))
    return event_type == "tool_calls" and capability.lower() in declared


def matching_observations(capability: str, events: list[dict[str, object]]) -> list[dict[str, object]]:
    if capability != "secret-access + network-egress":
        return [item for item in events if observation_matches(capability, item)]
    secret_events = [item for item in events if observation_matches("secret-access", item)]
    network_events = [item for item in events if observation_matches("network-egress", item)]
    if not secret_events or not network_events:
        return []
    return [*secret_events, *network_events]


def resolve_source_root(value: str | None) -> Path | None:
    if not value:
        return None
    try:
        candidate = Path(value).expanduser().resolve(strict=True)
    except OSError:
        return None
    return candidate if candidate.is_dir() else None


def staging_workspace_path(project_id: str) -> Path:
    repository_root = Path(__file__).resolve().parents[4]
    return repository_root / STAGING_RELATIVE_ROOT / safe_identifier(project_id)


def safe_identifier(value: str) -> str:
    normalized = re.sub(r"[^A-Za-z0-9_-]", "-", value)[:80]
    return normalized or sha256(value.encode("utf-8", errors="replace")).hexdigest()[:16]


def is_link_or_junction(path: Path) -> bool:
    if path.is_symlink():
        return True
    junction_check = getattr(os.path, "isjunction", None)
    return bool(junction_check and junction_check(path))


def image_is_digest_pinned(image: str) -> bool:
    return bool(re.fullmatch(r"[A-Za-z0-9._/@:-]+@sha256:[0-9a-fA-F]{64}", image))


def command_check(command: str) -> dict[str, object]:
    if not command:
        return check_result("command-policy", "block", "No command is available for review.", "Select one explicit Agent startup command.")
    for reason, pattern in UNSAFE_COMMAND_PATTERNS:
        if pattern.search(command):
            return check_result("command-policy", "block", f"Command matched blocked category: {reason}.", "Remove download, installation, privilege, nested-container, secret-enumeration or destructive behavior.")
    if len(command) > 1_000 or "\n" in command or "\r" in command:
        return check_result("command-policy", "block", "Command is multiline or exceeds the review limit.", "Use one command of at most 1,000 characters.")
    return check_result("command-policy", "pass", "Command passed the static preflight policy.", None)


def image_reference_check(image: str) -> dict[str, object]:
    if not image:
        return check_result("image-reference-policy", "block", "No image reference is available for review.", "Select one explicit digest-pinned local image.")
    prefix = image.rsplit("@sha256:", 1)[0]
    unsafe = (
        bool(re.search(r"\s", image))
        or "://" in image
        or "@" in prefix
        or bool(re.search(r"(?i)(token|password|secret|api[-_]?key)=", image))
    )
    return check_result(
        "image-reference-policy",
        "block" if unsafe else "pass",
        "Image reference contains credentials, a URL scheme or whitespace." if unsafe else "Image reference passed the static credential and syntax policy.",
        "Use a credential-free registry/name@sha256:<digest> reference." if unsafe else None,
    )


def docker_cli_check() -> dict[str, object]:
    available = shutil.which("docker") is not None
    return check_result(
        "docker-cli",
        "pass" if available else "block",
        "Docker CLI is available." if available else "Docker CLI was not found; no image was downloaded and no daemon was contacted.",
        None if available else "Install or expose Docker only after operator approval; this phase does not install it.",
    )


def staging_check(root: Path | None, staging: Path, inventory: dict[str, object]) -> dict[str, object]:
    if root is None:
        return check_result("filtered-staging", "block", "Filtered staging cannot be planned without a valid source directory.", "Configure the project source directory.")
    if staging.exists():
        return check_result("filtered-staging", "block", "A staging path exists but was not created, filtered or hash-verified by this preflight.", "Recreate and hash a filtered staging copy in the future execution stage.")
    count = int(inventory.get("sensitive_file_count") or 0)
    links = int(inventory.get("linked_directory_count") or 0)
    detail = f"Future filtered staging must exclude {count} detected sensitive-name files and {links} linked directories; values were not read."
    return check_result("filtered-staging", "block", detail, "Create, review and hash a filtered D-drive staging copy in a separately approved execution stage.")


def confirmation_check(confirmed: bool) -> dict[str, object]:
    return check_result(
        "operator-confirmation",
        "pass" if confirmed else "block",
        "Operator explicitly confirmed the proposed target." if confirmed else "No explicit confirmation is recorded for this exact command, image and target.",
        None if confirmed else "Confirm the exact target only after all other checks pass.",
    )


def policy_check(identifier: str, detail: str) -> dict[str, object]:
    return check_result(identifier, "pass", detail, None)


def check(identifier: str, condition: bool, success: str, failure: str) -> dict[str, object]:
    return check_result(identifier, "pass" if condition else "block", success if condition else failure, None if condition else failure)


def check_result(identifier: str, status: str, detail: str, remediation: str | None) -> dict[str, object]:
    return {"id": identifier, "status": status, "detail": detail[:500], "remediation": remediation[:500] if remediation else None}


def redact_command(command: str) -> str:
    redacted = command
    patterns: Iterable[re.Pattern[str]] = (
        re.compile(r"(?i)(--?(?:token|secret|password|api[-_]?key))(?:=|\s+)([^\s]+)"),
        re.compile(r"(?i)([A-Za-z_][A-Za-z0-9_]*(?:TOKEN|SECRET|PASSWORD|KEY)[A-Za-z0-9_]*)=([^\s]+)"),
        re.compile(r"(?i)(https?://)([^/@\s:]+):([^/@\s]+)@"),
    )
    for pattern in patterns:
        if pattern.pattern.startswith("(?i)(https"):
            redacted = pattern.sub(r"\1[redacted]@", redacted)
        else:
            redacted = pattern.sub(r"\1=[redacted]", redacted)
    return redacted[:1_000]


def redact_image_reference(image: str) -> str:
    prefix = image.rsplit("@sha256:", 1)[0]
    if "://" in image or "@" in prefix or re.search(r"(?i)(token|password|secret|api[-_]?key)=", image):
        return "[redacted-invalid-image-reference]"
    return image[:300]
