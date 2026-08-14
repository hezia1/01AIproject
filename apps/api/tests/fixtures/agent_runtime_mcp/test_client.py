from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path


REQUESTS = [
    {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-06-18",
            "capabilities": {},
            "clientInfo": {"name": "bounded-fixture-client", "version": "1.0.0"},
        },
    },
    {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
    {
        "jsonrpc": "2.0",
        "id": 3,
        "method": "tools/call",
        "params": {"name": "bounded_add", "arguments": {"a": 2, "b": 4}},
    },
    {"jsonrpc": "2.0", "id": 4, "method": "resources/list", "params": {}},
    {"jsonrpc": "2.0", "id": 5, "method": "prompts/list", "params": {}},
]


def main() -> None:
    server_path = Path(__file__).with_name("mcp_server.py")
    payload = "".join(json.dumps(item, separators=(",", ":")) + "\n" for item in REQUESTS)
    completed = subprocess.run(
        [sys.executable, "-I", "-B", str(server_path)],
        input=payload,
        capture_output=True,
        text=True,
        timeout=3,
        check=False,
    )
    if completed.returncode != 0:
        raise RuntimeError("bounded MCP server returned a non-zero exit code")
    responses = [json.loads(line) for line in completed.stdout.splitlines() if line.strip()]
    by_id = {item.get("id"): item for item in responses}
    if sorted(by_id) != [1, 2, 3, 4, 5]:
        raise RuntimeError("bounded MCP server returned an incomplete response set")
    if by_id[1]["result"]["serverInfo"]["name"] != "bounded-mcp-integration":
        raise RuntimeError("unexpected MCP server identity")
    if [item["name"] for item in by_id[2]["result"]["tools"]] != ["bounded_add"]:
        raise RuntimeError("unexpected MCP tool inventory")
    if by_id[3]["result"]["structuredContent"] != {"sum": 6}:
        raise RuntimeError("bounded MCP tool returned an unexpected result")
    if [item["uri"] for item in by_id[4]["result"]["resources"]] != ["fixture://status"]:
        raise RuntimeError("unexpected MCP resource inventory")
    if [item["name"] for item in by_id[5]["result"]["prompts"]] != ["add-two-integers"]:
        raise RuntimeError("unexpected MCP prompt inventory")
    print(json.dumps({
        "schema": "ai-security-platform.agent-runtime-mcp-result/v1",
        "server": "bounded-mcp-integration",
        "tool": "bounded_add",
        "result": 6,
        "tool_count": 1,
        "resource_count": 1,
        "prompt_count": 1,
        "network_used": False,
        "secret_values_returned": False,
    }, ensure_ascii=False, sort_keys=True))


if __name__ == "__main__":
    main()
