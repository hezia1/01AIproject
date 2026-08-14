from __future__ import annotations

import json
import sys
from typing import Any


PROTOCOL_VERSION = "2025-06-18"
SERVER_INFO = {"name": "bounded-mcp-integration", "version": "1.0.0"}
TOOL = {
    "name": "bounded_add",
    "description": "Add two integers between -1000 and 1000.",
    "inputSchema": {
        "type": "object",
        "properties": {
            "a": {"type": "integer", "minimum": -1000, "maximum": 1000},
            "b": {"type": "integer", "minimum": -1000, "maximum": 1000},
        },
        "required": ["a", "b"],
        "additionalProperties": False,
    },
    "annotations": {
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
    },
}
RESOURCE = {
    "uri": "fixture://status",
    "name": "bounded-fixture-status",
    "description": "Static status for the offline integration target.",
    "mimeType": "application/json",
}
PROMPT = {
    "name": "add-two-integers",
    "description": "Request a bounded integer addition.",
    "arguments": [
        {"name": "a", "description": "First integer", "required": True},
        {"name": "b", "description": "Second integer", "required": True},
    ],
}


class ProtocolError(ValueError):
    def __init__(self, code: int, message: str) -> None:
        super().__init__(message)
        self.code = code


def bounded_integer(value: Any, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ProtocolError(-32602, f"{name} must be an integer")
    if value < -1000 or value > 1000:
        raise ProtocolError(-32602, f"{name} is outside the allowed range")
    return value


def result_response(request_id: Any, result: dict[str, Any]) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": request_id, "result": result}


def error_response(request_id: Any, code: int, message: str) -> dict[str, Any]:
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "error": {"code": code, "message": message},
    }


def handle_request(request: dict[str, Any]) -> dict[str, Any] | None:
    request_id = request.get("id")
    method = request.get("method")
    params = request.get("params") if isinstance(request.get("params"), dict) else {}
    if request_id is None:
        return None
    if method == "initialize":
        return result_response(request_id, {
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": {"tools": {}, "resources": {}, "prompts": {}},
            "serverInfo": SERVER_INFO,
        })
    if method == "tools/list":
        return result_response(request_id, {"tools": [TOOL]})
    if method == "tools/call":
        if params.get("name") != TOOL["name"]:
            raise ProtocolError(-32601, "unknown tool")
        arguments = params.get("arguments") if isinstance(params.get("arguments"), dict) else {}
        a = bounded_integer(arguments.get("a"), "a")
        b = bounded_integer(arguments.get("b"), "b")
        total = a + b
        return result_response(request_id, {
            "content": [{"type": "text", "text": str(total)}],
            "structuredContent": {"sum": total},
            "isError": False,
        })
    if method == "resources/list":
        return result_response(request_id, {"resources": [RESOURCE]})
    if method == "resources/read":
        if params.get("uri") != RESOURCE["uri"]:
            raise ProtocolError(-32602, "unknown resource")
        return result_response(request_id, {
            "contents": [{
                "uri": RESOURCE["uri"],
                "mimeType": RESOURCE["mimeType"],
                "text": json.dumps({"status": "ready", "network": False}, sort_keys=True),
            }]
        })
    if method == "prompts/list":
        return result_response(request_id, {"prompts": [PROMPT]})
    if method == "prompts/get":
        if params.get("name") != PROMPT["name"]:
            raise ProtocolError(-32602, "unknown prompt")
        arguments = params.get("arguments") if isinstance(params.get("arguments"), dict) else {}
        a = bounded_integer(int(arguments.get("a", 0)), "a")
        b = bounded_integer(int(arguments.get("b", 0)), "b")
        return result_response(request_id, {
            "description": PROMPT["description"],
            "messages": [{
                "role": "user",
                "content": {"type": "text", "text": f"Add {a} and {b} with bounded_add."},
            }],
        })
    raise ProtocolError(-32601, "method not found")


def main() -> None:
    for raw_line in sys.stdin:
        request_id: Any = None
        try:
            request = json.loads(raw_line)
            if not isinstance(request, dict):
                raise ProtocolError(-32600, "request must be an object")
            request_id = request.get("id")
            response = handle_request(request)
        except json.JSONDecodeError:
            response = error_response(None, -32700, "parse error")
        except ProtocolError as exc:
            response = error_response(request_id, exc.code, str(exc))
        except (TypeError, ValueError):
            response = error_response(request_id, -32602, "invalid parameters")
        if response is not None:
            sys.stdout.write(json.dumps(response, ensure_ascii=False, sort_keys=True) + "\n")
            sys.stdout.flush()


if __name__ == "__main__":
    main()
