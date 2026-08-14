from __future__ import annotations

import argparse
import hashlib
import http.client
import ipaddress
import json
import re
import socket
import ssl
import sys
import time
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urljoin, urlsplit, urlunsplit


PROBE_PREFIX = "@@AGENT_REMOTE_MCP_PROBE@@"
PROBE_SCHEMA = "ai-security-platform.agent-remote-mcp-capability-probe-result/v1"
PROBE_VERSION = "1.0.0"
MODERN_PROTOCOL_VERSION = "2026-07-28"
LEGACY_PROTOCOL_VERSION = "2025-11-25"
MAX_RESPONSE_BYTES = 512 * 1024
MAX_SSE_LINE_BYTES = 64 * 1024
MAX_NAMES = 100
MAX_LABEL_CHARACTERS = 120
MAX_REDIRECTS = 2


class ProbeError(RuntimeError):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def canonical_sha256(value: object) -> str:
    encoded = json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def safe_label(value: object) -> str:
    text = str(value or "").strip()[:MAX_LABEL_CHARACTERS]
    return text if re.fullmatch(r"[A-Za-z0-9_.:/@-]{1,120}", text) else "[redacted-label]"


def normalized_names(value: object, key: str) -> list[str]:
    if not isinstance(value, list):
        return []
    return sorted({
        safe_label(item.get(key))
        for item in value[:MAX_NAMES]
        if isinstance(item, dict) and item.get(key)
    })[:MAX_NAMES]


def resource_schemes(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    schemes: set[str] = set()
    for item in value[:MAX_NAMES]:
        if not isinstance(item, dict):
            continue
        uri = str(item.get("uri") or "")
        schemes.add(safe_label(uri.split(":", 1)[0] if ":" in uri else "unknown"))
    return sorted(schemes)[:MAX_NAMES]


def public_endpoint(value: str) -> str:
    parsed = urlsplit(value)
    host = parsed.hostname or ""
    port = parsed.port
    display_host = f"[{host}]" if ":" in host else host
    netloc = f"{display_host}:{port}" if port and port not in {80, 443} else display_host
    return urlunsplit((parsed.scheme.lower(), netloc, parsed.path or "/", "", ""))


def endpoint_parts(value: str, *, allow_http: bool = False) -> tuple[str, str, int, str]:
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError as exc:
        raise ProbeError("invalid-endpoint") from exc
    allowed_schemes = {"https", "http"} if allow_http else {"https"}
    if parsed.scheme.lower() not in allowed_schemes:
        raise ProbeError("https-required")
    if not parsed.hostname or parsed.username is not None or parsed.password is not None or parsed.fragment:
        raise ProbeError("invalid-endpoint")
    host = parsed.hostname.rstrip(".").lower()
    try:
        ipaddress.ip_address(host)
    except ValueError:
        if not re.fullmatch(r"[a-z0-9.-]{1,253}", host):
            raise ProbeError("invalid-hostname")
    resolved_port = port or (443 if parsed.scheme.lower() == "https" else 80)
    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query
    return parsed.scheme.lower(), host, resolved_port, path


def validate_approved_ips(values: list[str]) -> list[str]:
    approved: list[str] = []
    for value in values[:16]:
        try:
            address = ipaddress.ip_address(value)
        except ValueError as exc:
            raise ProbeError("invalid-approved-ip") from exc
        if not address.is_global:
            raise ProbeError("non-public-approved-ip")
        approved.append(address.compressed)
    if not approved:
        raise ProbeError("approved-ip-missing")
    return sorted(set(approved))


class PinnedHTTPConnection(http.client.HTTPConnection):
    def __init__(self, host: str, port: int, pinned_ip: str, timeout: float):
        super().__init__(host, port, timeout=timeout)
        self.pinned_ip = pinned_ip

    def connect(self) -> None:
        self.sock = socket.create_connection((self.pinned_ip, self.port), self.timeout)


class PinnedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, host: str, port: int, pinned_ip: str, timeout: float):
        super().__init__(host, port, timeout=timeout, context=ssl.create_default_context())
        self.pinned_ip = pinned_ip

    def connect(self) -> None:
        raw = socket.create_connection((self.pinned_ip, self.port), self.timeout)
        self.sock = self._context.wrap_socket(raw, server_hostname=self.host)


@dataclass
class HttpResult:
    status: int
    content_type: str
    headers: dict[str, str]
    body: bytes
    endpoint: str
    remote_ip: str
    redirect_chain: list[str] = field(default_factory=list)


class PinnedHttpClient:
    def __init__(
        self, endpoint: str, approved_ips: list[str], timeout_seconds: int,
        *, allow_http: bool = False,
    ) -> None:
        self.endpoint = endpoint
        self.approved_ips = validate_approved_ips(approved_ips) if not allow_http else sorted(set(approved_ips))
        self.timeout = max(1, min(15, int(timeout_seconds)))
        self.allow_http = allow_http
        self.origin = endpoint_parts(endpoint, allow_http=allow_http)[:3]
        self.request_log: list[dict[str, object]] = []
        self.redirects: list[str] = []

    def connection(self, scheme: str, host: str, port: int, ip: str):
        if scheme == "https":
            return PinnedHTTPSConnection(host, port, ip, self.timeout)
        if self.allow_http:
            return PinnedHTTPConnection(host, port, ip, self.timeout)
        raise ProbeError("https-required")

    def request(
        self, method: str, endpoint: str, *, headers: dict[str, str], body: bytes | None,
        stream: bool = False,
    ) -> HttpResult | tuple[http.client.HTTPConnection, http.client.HTTPResponse, str, str]:
        current = endpoint
        redirects: list[str] = []
        for _ in range(MAX_REDIRECTS + 1):
            scheme, host, port, path = endpoint_parts(current, allow_http=self.allow_http)
            if (scheme, host, port) != self.origin:
                raise ProbeError("cross-origin-redirect-blocked")
            last_error: OSError | None = None
            for ip in self.approved_ips:
                connection = self.connection(scheme, host, port, ip)
                try:
                    connection.request(method, path, body=body, headers=headers)
                    response = connection.getresponse()
                except (OSError, ssl.SSLError, http.client.HTTPException) as exc:
                    connection.close()
                    last_error = exc if isinstance(exc, OSError) else OSError(str(exc))
                    continue
                if response.status in {301, 302, 303, 307, 308}:
                    location = response.getheader("Location")
                    response.read(MAX_RESPONSE_BYTES + 1)
                    connection.close()
                    if not location or len(redirects) >= MAX_REDIRECTS:
                        raise ProbeError("redirect-limit")
                    redirected = urljoin(current, location)
                    endpoint_parts(redirected, allow_http=self.allow_http)
                    redirects.append(public_endpoint(redirected))
                    current = redirected
                    break
                content_type = str(response.getheader("Content-Type") or "").split(";", 1)[0].strip().lower()
                if stream:
                    self.redirects.extend(redirects)
                    return connection, response, current, ip
                payload = response.read(MAX_RESPONSE_BYTES + 1)
                connection.close()
                if len(payload) > MAX_RESPONSE_BYTES:
                    raise ProbeError("response-too-large")
                result = HttpResult(
                    status=response.status, content_type=content_type,
                    headers={key.lower(): value for key, value in response.getheaders()},
                    body=payload, endpoint=current, remote_ip=ip,
                    redirect_chain=redirects,
                )
                self.redirects.extend(redirects)
                return result
            else:
                raise ProbeError("connection-failed") from last_error
        raise ProbeError("redirect-limit")

    def rpc(
        self, request_id: int, method: str, params: dict[str, object], *,
        protocol_version: str | None = None, session_id: str | None = None,
        endpoint: str | None = None,
    ) -> tuple[dict[str, Any], HttpResult]:
        message = {"jsonrpc": "2.0", "id": request_id, "method": method, "params": params}
        headers = {
            "Accept": "application/json, text/event-stream",
            "Content-Type": "application/json",
            "User-Agent": f"ai-security-platform-remote-mcp-probe/{PROBE_VERSION}",
            "Mcp-Method": method,
        }
        if protocol_version:
            headers["MCP-Protocol-Version"] = protocol_version
        if session_id:
            headers["Mcp-Session-Id"] = session_id
        started = time.perf_counter()
        result = self.request(
            "POST", endpoint or self.endpoint, headers=headers,
            body=json.dumps(message, separators=(",", ":")).encode("utf-8"),
        )
        assert isinstance(result, HttpResult)
        response = parse_rpc_response(result, request_id)
        self.request_log.append({
            "method": method, "http_status": result.status,
            "content_type": result.content_type or "missing",
            "response_bytes": len(result.body), "remote_ip": result.remote_ip,
            "elapsed_ms": int((time.perf_counter() - started) * 1000),
            "outcome": "success" if isinstance(response.get("result"), dict) else "error",
        })
        return response, result

    def notification(
        self, method: str, params: dict[str, object], *,
        protocol_version: str, session_id: str | None,
    ) -> HttpResult:
        message = {"jsonrpc": "2.0", "method": method, "params": params}
        headers = {
            "Accept": "application/json, text/event-stream",
            "Content-Type": "application/json",
            "User-Agent": f"ai-security-platform-remote-mcp-probe/{PROBE_VERSION}",
            "Mcp-Method": method,
            "MCP-Protocol-Version": protocol_version,
        }
        if session_id:
            headers["Mcp-Session-Id"] = session_id
        result = self.request(
            "POST", self.endpoint, headers=headers,
            body=json.dumps(message, separators=(",", ":")).encode("utf-8"),
        )
        assert isinstance(result, HttpResult)
        self.request_log.append({
            "method": method, "http_status": result.status,
            "content_type": result.content_type or "missing",
            "response_bytes": len(result.body), "remote_ip": result.remote_ip,
            "elapsed_ms": 0, "outcome": "accepted" if result.status in {200, 202, 204} else "error",
        })
        return result

    def open_sse(self, endpoint: str) -> "LiveSseStream":
        started = time.perf_counter()
        opened = self.request(
            "GET", endpoint,
            headers={
                "Accept": "text/event-stream",
                "User-Agent": f"ai-security-platform-remote-mcp-probe/{PROBE_VERSION}",
            },
            body=None, stream=True,
        )
        assert isinstance(opened, tuple)
        connection, response, final_endpoint, remote_ip = opened
        content_type = str(response.getheader("Content-Type") or "").split(";", 1)[0].strip().lower()
        self.request_log.append({
            "method": "legacy-sse-connect", "http_status": response.status,
            "content_type": content_type or "missing", "response_bytes": 0,
            "remote_ip": remote_ip,
            "elapsed_ms": int((time.perf_counter() - started) * 1000),
            "outcome": "success" if 200 <= response.status < 300 and content_type == "text/event-stream" else "error",
        })
        if not (200 <= response.status < 300) or content_type != "text/event-stream":
            response.read(MAX_RESPONSE_BYTES + 1)
            connection.close()
            raise ProbeError("legacy-sse-unavailable")
        return LiveSseStream(connection, response, final_endpoint)


class LiveSseStream:
    def __init__(
        self, connection: http.client.HTTPConnection,
        response: http.client.HTTPResponse, endpoint: str,
    ) -> None:
        self.connection = connection
        self.response = response
        self.endpoint = endpoint
        self.bytes_read = 0

    def close(self) -> None:
        self.connection.close()

    def next_event(self) -> tuple[str, str]:
        event_name = "message"
        data_lines: list[str] = []
        while self.bytes_read <= MAX_RESPONSE_BYTES:
            raw = self.response.readline(MAX_SSE_LINE_BYTES + 1)
            if not raw:
                raise ProbeError("legacy-sse-closed")
            self.bytes_read += len(raw)
            if len(raw) > MAX_SSE_LINE_BYTES or self.bytes_read > MAX_RESPONSE_BYTES:
                raise ProbeError("legacy-sse-too-large")
            try:
                line = raw.decode("utf-8").rstrip("\r\n")
            except UnicodeDecodeError as exc:
                raise ProbeError("invalid-utf8-response") from exc
            if not line:
                if data_lines:
                    return event_name, "\n".join(data_lines)
                event_name = "message"
            elif line.startswith("event:"):
                event_name = line[6:].strip()
            elif line.startswith("data:"):
                data_lines.append(line[5:].lstrip())
        raise ProbeError("legacy-sse-too-large")

    def response_for(self, request_id: int) -> dict[str, Any]:
        for _ in range(100):
            event, data = self.next_event()
            if event not in {"message", "jsonrpc"}:
                continue
            try:
                item = json.loads(data)
            except json.JSONDecodeError:
                continue
            if isinstance(item, dict) and item.get("jsonrpc") == "2.0" and item.get("id") == request_id:
                return item
        raise ProbeError("legacy-rpc-response-missing")


def parse_sse_events(body: bytes) -> list[tuple[str, str]]:
    try:
        text = body.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ProbeError("invalid-utf8-response") from exc
    events: list[tuple[str, str]] = []
    event_name = "message"
    data_lines: list[str] = []
    for line in text.splitlines() + [""]:
        if len(line.encode("utf-8")) > MAX_SSE_LINE_BYTES:
            raise ProbeError("sse-line-too-large")
        if not line:
            if data_lines:
                events.append((event_name, "\n".join(data_lines)))
            event_name, data_lines = "message", []
        elif line.startswith("event:"):
            event_name = line[6:].strip()
        elif line.startswith("data:"):
            data_lines.append(line[5:].lstrip())
    return events


def parse_rpc_response(result: HttpResult, request_id: int) -> dict[str, Any]:
    if result.status < 200 or result.status >= 300:
        return {"jsonrpc": "2.0", "id": request_id, "error": {"code": -32000}}
    payloads: list[str]
    if result.content_type == "application/json":
        try:
            payloads = [result.body.decode("utf-8")]
        except UnicodeDecodeError as exc:
            raise ProbeError("invalid-utf8-response") from exc
    elif result.content_type == "text/event-stream":
        payloads = [data for event, data in parse_sse_events(result.body) if event in {"message", "jsonrpc"}]
    else:
        raise ProbeError("unsupported-content-type")
    for payload in payloads[:100]:
        try:
            item = json.loads(payload)
        except json.JSONDecodeError:
            continue
        if isinstance(item, dict) and item.get("jsonrpc") == "2.0" and item.get("id") == request_id:
            return item
    raise ProbeError("rpc-response-missing")


def modern_params() -> dict[str, object]:
    return {"_meta": {
        "io.modelcontextprotocol/protocolVersion": MODERN_PROTOCOL_VERSION,
        "io.modelcontextprotocol/clientInfo": {
            "name": "ai-security-platform-remote-capability-probe", "version": PROBE_VERSION,
        },
        "io.modelcontextprotocol/clientCapabilities": {},
    }}


def result_object(response: dict[str, Any]) -> dict[str, Any]:
    value = response.get("result")
    return value if isinstance(value, dict) else {}


def method_outcome(response: dict[str, Any] | None) -> str:
    if not isinstance(response, dict):
        return "missing"
    if isinstance(response.get("result"), dict):
        return "success"
    return "error" if isinstance(response.get("error"), dict) else "missing"


def probe_streamable(client: PinnedHttpClient) -> dict[str, object]:
    responses: dict[str, dict[str, Any]] = {}
    protocol_version = ""
    server_info: dict[str, Any] = {}
    session_id: str | None = None
    transport_mode = "streamable-http-modern"
    next_id = 1

    discover, _ = client.rpc(next_id, "server/discover", modern_params(), protocol_version=MODERN_PROTOCOL_VERSION)
    responses["server/discover"] = discover
    next_id += 1
    discover_result = result_object(discover)
    supported = discover_result.get("supportedVersions")
    modern = isinstance(supported, list) and MODERN_PROTOCOL_VERSION in supported
    if modern:
        protocol_version = MODERN_PROTOCOL_VERSION
        meta = discover_result.get("_meta") if isinstance(discover_result.get("_meta"), dict) else {}
        server_info = meta.get("io.modelcontextprotocol/serverInfo") if isinstance(meta.get("io.modelcontextprotocol/serverInfo"), dict) else {}
    else:
        initialize_params = {
            "protocolVersion": LEGACY_PROTOCOL_VERSION, "capabilities": {},
            "clientInfo": {"name": "ai-security-platform-remote-capability-probe", "version": PROBE_VERSION},
        }
        initialize, initialize_http = client.rpc(next_id, "initialize", initialize_params)
        responses["initialize"] = initialize
        next_id += 1
        initialized = result_object(initialize)
        if not initialized:
            raise ProbeError("version-negotiation-failed")
        transport_mode = "streamable-http-legacy"
        protocol_version = str(initialized.get("protocolVersion") or LEGACY_PROTOCOL_VERSION)
        server_info = initialized.get("serverInfo") if isinstance(initialized.get("serverInfo"), dict) else {}
        raw_session = initialize_http.headers.get("mcp-session-id")
        if raw_session:
            if len(raw_session) > 1024 or any(ord(char) < 0x21 or ord(char) > 0x7E for char in raw_session):
                raise ProbeError("invalid-session-id")
            session_id = raw_session
        notification = client.notification(
            "notifications/initialized", {}, protocol_version=protocol_version, session_id=session_id,
        )
        if notification.status not in {200, 202, 204}:
            raise ProbeError("initialized-notification-rejected")

    list_params = modern_params() if modern else {}
    for method in ("tools/list", "resources/list", "prompts/list"):
        response, _ = client.rpc(
            next_id, method, list_params,
            protocol_version=protocol_version, session_id=session_id,
        )
        responses[method] = response
        next_id += 1

    tools = result_object(responses["tools/list"]).get("tools")
    resources = result_object(responses["resources/list"]).get("resources")
    prompts = result_object(responses["prompts/list"]).get("prompts")
    outcomes = {
        method: method_outcome(responses.get(method))
        for method in ("server/discover", "initialize", "tools/list", "resources/list", "prompts/list")
    }
    list_outcomes = [outcomes[method] for method in ("tools/list", "resources/list", "prompts/list")]
    status = "success" if all(value == "success" for value in list_outcomes) else "partial"
    return {
        "status": status, "transport_mode": transport_mode,
        "protocol_version": safe_label(protocol_version),
        "server_name": safe_label(server_info.get("name")),
        "server_version": safe_label(server_info.get("version")),
        "tool_names": normalized_names(tools, "name"),
        "resource_schemes": resource_schemes(resources),
        "prompt_names": normalized_names(prompts, "name"),
        "method_outcomes": outcomes,
        "session_established": bool(session_id),
    }


def probe_legacy_sse(client: PinnedHttpClient) -> dict[str, object]:
    stream = client.open_sse(client.endpoint)
    responses: dict[str, dict[str, Any]] = {}
    try:
        message_endpoint = ""
        for _ in range(20):
            event, data = stream.next_event()
            if event == "endpoint":
                message_endpoint = urljoin(stream.endpoint, data.strip())
                break
        if not message_endpoint:
            raise ProbeError("legacy-endpoint-event-missing")
        endpoint_parts(message_endpoint, allow_http=client.allow_http)
        if endpoint_parts(message_endpoint, allow_http=client.allow_http)[:3] != client.origin:
            raise ProbeError("legacy-endpoint-cross-origin")

        protocol_version = LEGACY_PROTOCOL_VERSION
        server_info: dict[str, Any] = {}
        requests = [
            (1, "initialize", {
                "protocolVersion": LEGACY_PROTOCOL_VERSION, "capabilities": {},
                "clientInfo": {"name": "ai-security-platform-remote-capability-probe", "version": PROBE_VERSION},
            }),
            (2, "tools/list", {}),
            (3, "resources/list", {}),
            (4, "prompts/list", {}),
        ]
        for request_id, method, params in requests:
            message = {"jsonrpc": "2.0", "id": request_id, "method": method, "params": params}
            headers = {
                "Accept": "application/json, text/event-stream", "Content-Type": "application/json",
                "User-Agent": f"ai-security-platform-remote-mcp-probe/{PROBE_VERSION}",
            }
            started = time.perf_counter()
            sent = client.request(
                "POST", message_endpoint, headers=headers,
                body=json.dumps(message, separators=(",", ":")).encode("utf-8"),
            )
            assert isinstance(sent, HttpResult)
            client.request_log.append({
                "method": method, "http_status": sent.status,
                "content_type": sent.content_type or "missing",
                "response_bytes": len(sent.body), "remote_ip": sent.remote_ip,
                "elapsed_ms": int((time.perf_counter() - started) * 1000),
                "outcome": "accepted" if sent.status in {200, 202, 204} else "error",
            })
            if sent.status not in {200, 202, 204}:
                raise ProbeError("legacy-message-rejected")
            response = stream.response_for(request_id)
            responses[method] = response
            if method == "initialize":
                initialized = result_object(response)
                if not initialized:
                    raise ProbeError("legacy-initialize-failed")
                protocol_version = str(initialized.get("protocolVersion") or LEGACY_PROTOCOL_VERSION)
                server_info = initialized.get("serverInfo") if isinstance(initialized.get("serverInfo"), dict) else {}
                notification = {
                    "jsonrpc": "2.0", "method": "notifications/initialized", "params": {},
                }
                notified = client.request(
                    "POST", message_endpoint, headers=headers,
                    body=json.dumps(notification, separators=(",", ":")).encode("utf-8"),
                )
                assert isinstance(notified, HttpResult)
                client.request_log.append({
                    "method": "notifications/initialized", "http_status": notified.status,
                    "content_type": notified.content_type or "missing",
                    "response_bytes": len(notified.body), "remote_ip": notified.remote_ip,
                    "elapsed_ms": 0,
                    "outcome": "accepted" if notified.status in {200, 202, 204} else "error",
                })
                if notified.status not in {200, 202, 204}:
                    raise ProbeError("legacy-initialized-notification-rejected")

        tools = result_object(responses["tools/list"]).get("tools")
        resources = result_object(responses["resources/list"]).get("resources")
        prompts = result_object(responses["prompts/list"]).get("prompts")
        outcomes = {
            method: method_outcome(responses.get(method))
            for method in ("initialize", "tools/list", "resources/list", "prompts/list")
        }
        status = "success" if all(outcomes.get(method) == "success" for method in ("tools/list", "resources/list", "prompts/list")) else "partial"
        return {
            "status": status, "transport_mode": "legacy-http-sse",
            "protocol_version": safe_label(protocol_version),
            "server_name": safe_label(server_info.get("name")),
            "server_version": safe_label(server_info.get("version")),
            "tool_names": normalized_names(tools, "name"),
            "resource_schemes": resource_schemes(resources),
            "prompt_names": normalized_names(prompts, "name"),
            "method_outcomes": {"server/discover": "missing", **outcomes},
            "session_established": True,
        }
    finally:
        stream.close()


def probe_remote_mcp(
    endpoint: str, approved_ips: list[str], timeout_seconds: int, *, allow_http: bool = False,
    transport_hint: str = "auto-http",
) -> dict[str, object]:
    client = PinnedHttpClient(endpoint, approved_ips, timeout_seconds, allow_http=allow_http)
    error_code: str | None = None
    result: dict[str, object] = {
        "status": "error", "transport_mode": "unknown", "protocol_version": "",
        "server_name": "", "server_version": "", "tool_names": [],
        "resource_schemes": [], "prompt_names": [], "method_outcomes": {},
        "session_established": False,
    }
    try:
        if transport_hint == "legacy-sse":
            result.update(probe_legacy_sse(client))
        else:
            try:
                result.update(probe_streamable(client))
            except ProbeError as streamable_error:
                if streamable_error.code not in {"version-negotiation-failed", "unsupported-content-type"}:
                    raise
                result.update(probe_legacy_sse(client))
    except ProbeError as exc:
        error_code = exc.code
    result.update({
        "schema": PROBE_SCHEMA, "probe_version": PROBE_VERSION,
        "endpoint": public_endpoint(endpoint),
        "approved_ips": client.approved_ips,
        "redirects": client.redirects[:MAX_REDIRECTS],
        "network_requests": client.request_log[:10],
        "error_code": error_code,
        "authentication_sent": False, "configured_headers_used": False,
        "content_actions_performed": False, "content_stored": False,
    })
    result["result_sha256"] = canonical_sha256(result)
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description="Read-only remote MCP capability probe")
    parser.add_argument("--endpoint", required=True)
    parser.add_argument("--approved-ip", action="append", default=[])
    parser.add_argument("--timeout-seconds", type=int, default=8)
    parser.add_argument("--transport-hint", choices=("auto-http", "streamable-http", "legacy-sse"), default="auto-http")
    args = parser.parse_args()
    result = probe_remote_mcp(
        args.endpoint, args.approved_ip, args.timeout_seconds,
        transport_hint=args.transport_hint,
    )
    sys.stderr.write(PROBE_PREFIX + json.dumps(result, ensure_ascii=False, sort_keys=True) + "\n")
    sys.stderr.flush()
    return 0 if result.get("status") in {"success", "partial"} else 70


if __name__ == "__main__":
    raise SystemExit(main())
