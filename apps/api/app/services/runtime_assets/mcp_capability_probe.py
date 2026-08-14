from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
from typing import Any


PROBE_PREFIX = "@@AGENT_MCP_PROBE@@"
PROBE_SCHEMA = "ai-security-platform.agent-mcp-capability-probe-result/v1"
PROBE_VERSION = "1.0.0"
MAX_NAMES = 100
MAX_LABEL_CHARACTERS = 120


def canonical_sha256(value: object) -> str:
    encoded = json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def safe_label(value: object) -> str:
    text = str(value or "").strip()[:MAX_LABEL_CHARACTERS]
    text = re.sub(r"(?i)(token|password|secret|api[_-]?key)=([^\s&]+)", r"\1=[redacted]", text)
    return text if re.fullmatch(r"[A-Za-z0-9_.:/@-]{1,120}", text) else "[redacted-label]"


def resource_scheme(value: object) -> str:
    uri = str(value or "")
    return safe_label(uri.split(":", 1)[0] if ":" in uri else "unknown")


def result_item(responses: dict[int, dict[str, Any]], request_id: int) -> dict[str, Any]:
    response = responses.get(request_id, {})
    result = response.get("result")
    return result if isinstance(result, dict) else {}


def list_names(value: object, key: str) -> list[str]:
    if not isinstance(value, list):
        return []
    return sorted({
        safe_label(item.get(key))
        for item in value[:MAX_NAMES]
        if isinstance(item, dict) and item.get(key)
    })[:MAX_NAMES]


def run_probe(
    observer: str, server_command: list[str], timeout_seconds: int, ledger_fd_path: str
) -> int:
    requests = [
        {
            "jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {
                "protocolVersion": "2025-06-18", "capabilities": {},
                "clientInfo": {"name": "ai-security-platform-capability-probe", "version": PROBE_VERSION},
            },
        },
        {"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
        {"jsonrpc": "2.0", "id": 3, "method": "resources/list", "params": {}},
        {"jsonrpc": "2.0", "id": 4, "method": "prompts/list", "params": {}},
    ]
    payload = "".join(json.dumps(item, separators=(",", ":")) + "\n" for item in requests)
    command = [sys.executable, "-I", "-B", observer]
    if ledger_fd_path != "-":
        command.extend(["--ledger-fd-path", ledger_fd_path])
    command.extend(["--", *server_command])
    status = "error"
    responses: dict[int, dict[str, Any]] = {}
    observer_exit_code: int | None = None
    error_code: str | None = None
    try:
        completed = subprocess.run(
            command, input=payload, capture_output=True, text=True,
            timeout=max(1, min(15, timeout_seconds)), check=False,
        )
        observer_exit_code = completed.returncode
        for line in completed.stdout.splitlines()[:20]:
            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(item, dict) and isinstance(item.get("id"), int):
                responses[int(item["id"])] = item
        initialize_succeeded = isinstance(responses.get(1, {}).get("result"), dict)
        optional_complete = all(identifier in responses for identifier in (2, 3, 4))
        optional_errors = any(isinstance(responses.get(identifier, {}).get("error"), dict) for identifier in (2, 3, 4))
        if initialize_succeeded and observer_exit_code == 0:
            status = "success" if optional_complete and not optional_errors else "partial"
        elif initialize_succeeded:
            error_code = "observer-nonzero-exit"
        else:
            error_code = "initialize-response-missing"
    except subprocess.TimeoutExpired:
        error_code = "probe-timeout"

    initialize = result_item(responses, 1)
    server_info = initialize.get("serverInfo") if isinstance(initialize.get("serverInfo"), dict) else {}
    tools = result_item(responses, 2).get("tools")
    resources = result_item(responses, 3).get("resources")
    prompts = result_item(responses, 4).get("prompts")
    resource_schemes = sorted({
        resource_scheme(item.get("uri"))
        for item in resources[:MAX_NAMES]
        if isinstance(resources, list) and isinstance(item, dict)
    }) if isinstance(resources, list) else []
    method_outcomes = {
        method: (
            "success" if isinstance(responses.get(request_id, {}).get("result"), dict)
            else "error" if isinstance(responses.get(request_id, {}).get("error"), dict)
            else "missing"
        )
        for method, request_id in {
            "initialize": 1, "tools/list": 2, "resources/list": 3, "prompts/list": 4,
        }.items()
    }
    result: dict[str, object] = {
        "schema": PROBE_SCHEMA,
        "probe_version": PROBE_VERSION,
        "status": status,
        "protocol_version": safe_label(initialize.get("protocolVersion")),
        "server_name": safe_label(server_info.get("name")),
        "server_version": safe_label(server_info.get("version")),
        "tool_names": list_names(tools, "name"),
        "resource_schemes": resource_schemes,
        "prompt_names": list_names(prompts, "name"),
        "method_outcomes": method_outcomes,
        "observer_exit_code": observer_exit_code,
        "error_code": error_code,
        "content_actions_performed": False,
        "content_stored": False,
    }
    result["result_sha256"] = canonical_sha256(result)
    sys.stderr.write(PROBE_PREFIX + json.dumps(result, ensure_ascii=False, sort_keys=True) + "\n")
    sys.stderr.flush()
    return 0 if status in {"success", "partial"} else 70


def main() -> int:
    parser = argparse.ArgumentParser(description="Read-only MCP capability discovery probe")
    parser.add_argument("--observer", required=True)
    parser.add_argument("--timeout-seconds", type=int, default=5)
    parser.add_argument("--ledger-fd-path", default="/proc/1/fd/2")
    parser.add_argument("server_command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    server_command = list(args.server_command)
    if server_command[:1] == ["--"]:
        server_command = server_command[1:]
    if not server_command or len(server_command) > 64:
        return 64
    return run_probe(args.observer, server_command, args.timeout_seconds, args.ledger_fd_path)


if __name__ == "__main__":
    raise SystemExit(main())
