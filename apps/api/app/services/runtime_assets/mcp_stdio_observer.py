from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, BinaryIO, TextIO


AUDIT_PREFIX = "@@AGENT_MCP_AUDIT@@"
AUDIT_SCHEMA = "ai-security-platform.agent-mcp-stdio-event/v1"
OBSERVER_VERSION = "1.0.1"
MAX_LINE_BYTES = 64 * 1024
MAX_EVENTS = 500
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


def request_subject(method: str, params: dict[str, Any]) -> tuple[str, str]:
    if method == "tools/call":
        return "tool", safe_label(params.get("name"))
    if method == "resources/read":
        uri = str(params.get("uri") or "")
        scheme = uri.split(":", 1)[0] if ":" in uri else "unknown"
        return "resource-scheme", safe_label(scheme)
    if method == "prompts/get":
        return "prompt", safe_label(params.get("name"))
    return "method", safe_label(method)


def redacted_request_projection(request: dict[str, Any]) -> dict[str, object]:
    method = safe_label(request.get("method"))
    params = request.get("params") if isinstance(request.get("params"), dict) else {}
    subject_kind, subject = request_subject(method, params)
    return {
        "jsonrpc": safe_label(request.get("jsonrpc")),
        "method": method,
        "request_id_type": type(request.get("id")).__name__,
        "parameter_keys": sorted(safe_label(key) for key in params)[:50],
        "subject_kind": subject_kind,
        "subject": subject,
    }


def redacted_response_projection(response: object) -> dict[str, object]:
    item = response if isinstance(response, dict) else {}
    error = item.get("error") if isinstance(item.get("error"), dict) else {}
    result = item.get("result") if isinstance(item.get("result"), dict) else {}
    return {
        "jsonrpc": safe_label(item.get("jsonrpc")),
        "request_id_type": type(item.get("id")).__name__,
        "outcome": "error" if error else "success",
        "error_code": error.get("code") if isinstance(error.get("code"), int) else None,
        "result_keys": sorted(safe_label(key) for key in result)[:50],
    }


class AuditWriter:
    def __init__(self, stream: TextIO) -> None:
        self.stream = stream
        self.sequence = 0
        self.lock = threading.Lock()

    def emit(self, event_type: str, values: dict[str, object]) -> str:
        with self.lock:
            self.sequence += 1
            event_id = f"mcp-{self.sequence:04d}"
            event: dict[str, object] = {
                "schema": AUDIT_SCHEMA,
                "observer_version": OBSERVER_VERSION,
                "event_id": event_id,
                "sequence": self.sequence,
                "occurred_at": datetime.now(timezone.utc).isoformat(),
                "event_type": event_type,
                **values,
            }
            event["event_sha256"] = canonical_sha256(event)
            self.stream.write(AUDIT_PREFIX + json.dumps(event, ensure_ascii=False, sort_keys=True) + "\n")
            self.stream.flush()
            return event_id


def open_ledger_stream(path: str | None) -> TextIO:
    if not path:
        return sys.stderr
    descriptor = os.open(path, os.O_WRONLY | os.O_APPEND)
    return os.fdopen(descriptor, "w", encoding="utf-8", buffering=1)


def drain_stderr(stream: BinaryIO, state: dict[str, object]) -> None:
    digest = hashlib.sha256()
    total = 0
    while True:
        chunk = stream.read(8192)
        if not chunk:
            break
        total += len(chunk)
        digest.update(chunk)
    state["bytes"] = total
    state["sha256"] = digest.hexdigest()


def parse_json_line(raw: bytes) -> object:
    try:
        return json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return {}


def run_proxy(server_command: list[str], ledger: AuditWriter) -> int:
    if not server_command or len(server_command) > 64:
        ledger.emit("observer_error", {"code": "invalid-server-command"})
        return 64
    process = subprocess.Popen(
        server_command,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        shell=False,
        bufsize=0,
    )
    if process.stdin is None or process.stdout is None or process.stderr is None:
        ledger.emit("observer_error", {"code": "missing-server-pipe"})
        process.kill()
        return 70
    command_projection = {
        "executable": safe_label(Path(server_command[0]).name),
        "argument_count": max(0, len(server_command) - 1),
    }
    pid_sha256 = hashlib.sha256(str(process.pid).encode("ascii")).hexdigest()
    ledger.emit("child_process", {
        "phase": "start",
        "process_role": "mcp-server",
        "executable": command_projection["executable"],
        "argument_count": command_projection["argument_count"],
        "command_metadata_sha256": canonical_sha256(command_projection),
        "pid_sha256": pid_sha256,
    })
    stderr_state: dict[str, object] = {"bytes": 0, "sha256": hashlib.sha256(b"").hexdigest()}
    stderr_thread = threading.Thread(
        target=drain_stderr, args=(process.stderr, stderr_state), daemon=True
    )
    stderr_thread.start()
    request_count = 0
    observer_failed = False
    try:
        while request_count < MAX_EVENTS:
            raw_request = sys.stdin.buffer.readline(MAX_LINE_BYTES + 1)
            if not raw_request:
                break
            if len(raw_request) > MAX_LINE_BYTES:
                ledger.emit("observer_error", {"code": "request-line-too-large"})
                observer_failed = True
                break
            request_count += 1
            request = parse_json_line(raw_request)
            request_item = request if isinstance(request, dict) else {}
            request_projection = redacted_request_projection(request_item)
            method = str(request_projection["method"])
            subject_kind = str(request_projection["subject_kind"])
            subject = str(request_projection["subject"])
            expects_response = request_item.get("id") is not None
            request_event_id = ledger.emit("mcp_request", {
                "direction": "client-to-server",
                "method": method,
                "subject_kind": subject_kind,
                "subject": subject,
                "expects_response": expects_response,
                "payload_bytes": len(raw_request),
                "redacted_metadata_sha256": canonical_sha256(request_projection),
            })
            process.stdin.write(raw_request)
            process.stdin.flush()
            if not expects_response:
                continue
            started = time.perf_counter()
            raw_response = process.stdout.readline(MAX_LINE_BYTES + 1)
            duration_ms = int((time.perf_counter() - started) * 1000)
            if not raw_response or len(raw_response) > MAX_LINE_BYTES:
                ledger.emit("mcp_response", {
                    "direction": "server-to-client",
                    "method": method,
                    "subject_kind": subject_kind,
                    "subject": subject,
                    "payload_bytes": len(raw_response),
                    "redacted_metadata_sha256": canonical_sha256({"outcome": "missing-or-oversized"}),
                    "outcome": "missing-or-oversized",
                    "duration_ms": duration_ms,
                    "request_event_id": request_event_id,
                })
                observer_failed = True
                break
            response = parse_json_line(raw_response)
            response_projection = redacted_response_projection(response)
            ledger.emit("mcp_response", {
                "direction": "server-to-client",
                "method": method,
                "subject_kind": subject_kind,
                "subject": subject,
                "payload_bytes": len(raw_response),
                "redacted_metadata_sha256": canonical_sha256(response_projection),
                "outcome": response_projection["outcome"],
                "duration_ms": duration_ms,
                "request_event_id": request_event_id,
            })
            sys.stdout.buffer.write(raw_response)
            sys.stdout.buffer.flush()
        if request_count >= MAX_EVENTS:
            ledger.emit("observer_error", {"code": "event-limit-reached"})
            observer_failed = True
    except (BrokenPipeError, OSError):
        ledger.emit("observer_error", {"code": "stdio-proxy-failed"})
        observer_failed = True
    finally:
        try:
            process.stdin.close()
        except OSError:
            pass
        timed_out = False
        try:
            exit_code = process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            timed_out = True
            process.kill()
            exit_code = process.wait(timeout=2)
        stderr_thread.join(timeout=1)
        ledger.emit("child_process", {
            "phase": "exit",
            "process_role": "mcp-server",
            "executable": command_projection["executable"],
            "argument_count": command_projection["argument_count"],
            "command_metadata_sha256": canonical_sha256(command_projection),
            "pid_sha256": pid_sha256,
            "exit_code": exit_code,
            "timed_out": timed_out,
            "stderr_bytes": int(stderr_state.get("bytes") or 0),
        })
    return 70 if observer_failed else int(exit_code)


def main() -> int:
    parser = argparse.ArgumentParser(description="Bounded stdio JSON-RPC observer")
    parser.add_argument("--ledger-fd-path")
    parser.add_argument("server_command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    command = list(args.server_command)
    if command[:1] == ["--"]:
        command = command[1:]
    stream = open_ledger_stream(args.ledger_fd_path)
    try:
        return run_proxy(command, AuditWriter(stream))
    finally:
        if stream is not sys.stderr:
            stream.close()


if __name__ == "__main__":
    raise SystemExit(main())
