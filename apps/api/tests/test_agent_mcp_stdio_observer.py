from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from app.services import agent_target_runtime


FIXTURE_ROOT = Path(__file__).parent / "fixtures" / "agent_runtime_mcp"
OBSERVER = Path(agent_target_runtime.__file__).with_name("runtime_assets") / "mcp_stdio_observer.py"
SERVER = FIXTURE_ROOT / "mcp_server.py"


def request(request_id: int, method: str, params: dict[str, object]) -> dict[str, object]:
    return {"jsonrpc": "2.0", "id": request_id, "method": method, "params": params}


def test_stdio_observer_proxies_protocol_and_emits_redacted_bounded_ledger() -> None:
    requests = [
        request(1, "initialize", {"protocolVersion": "2025-06-18"}),
        {"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}},
        request(2, "tools/list", {}),
        request(3, "tools/call", {"name": "bounded_add", "arguments": {"a": 2, "b": 4}}),
        request(4, "resources/list", {}),
        request(5, "prompts/list", {}),
        request(6, "resources/read", {"uri": "fixture://status"}),
        request(7, "prompts/get", {"name": "add-two-integers", "arguments": {"a": "2", "b": "4"}}),
    ]
    payload = "".join(json.dumps(item, separators=(",", ":")) + "\n" for item in requests)

    completed = subprocess.run(
        [sys.executable, "-I", "-B", str(OBSERVER), "--", sys.executable, "-I", "-B", str(SERVER)],
        input=payload, capture_output=True, text=True, timeout=5, check=False,
    )

    assert completed.returncode == 0
    responses = [json.loads(line) for line in completed.stdout.splitlines()]
    assert [item["id"] for item in responses] == list(range(1, 8))
    assert responses[2]["result"]["structuredContent"] == {"sum": 6}
    ledger, _, clean_stderr = agent_target_runtime.extract_mcp_audit_ledger("", completed.stderr)
    assert clean_stderr == ""
    assert ledger["rejected_event_count"] == 0
    assert ledger["summary"]["request_count"] == 8
    assert ledger["summary"]["response_count"] == 7
    assert ledger["summary"]["notification_count"] == 1
    assert ledger["summary"]["tool_call_count"] == 1
    assert ledger["summary"]["resource_read_count"] == 1
    assert ledger["summary"]["prompt_get_count"] == 1
    assert ledger["summary"]["child_process_count"] == 1
    assert "fixture://status" not in completed.stderr
    assert '"a":2' not in completed.stderr
    assert '"sum":6' not in completed.stderr
    assert all("params" not in event and "result" not in event for event in ledger["events"])


def test_stdio_observer_fails_closed_on_oversized_request_line() -> None:
    oversized = "x" * (64 * 1024 + 1) + "\n"

    completed = subprocess.run(
        [sys.executable, "-I", "-B", str(OBSERVER), "--", sys.executable, "-I", "-B", str(SERVER)],
        input=oversized, capture_output=True, text=True, timeout=5, check=False,
    )

    assert completed.returncode == 70
    ledger, _, _ = agent_target_runtime.extract_mcp_audit_ledger("", completed.stderr)
    assert any(
        event.get("event_type") == "observer_error" and event.get("code") == "request-line-too-large"
        for event in ledger["events"]
    )
    assert oversized[:100] not in completed.stderr
