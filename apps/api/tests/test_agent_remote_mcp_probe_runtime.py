from __future__ import annotations

import json
import queue
import subprocess
import threading
from hashlib import sha256
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace
from uuid import uuid4

import pytest
from fastapi import HTTPException

from app.models import AgentRemoteMcpProbeRuntimeRequest
from app.routers import agent as agent_router
from app.services import agent_remote_mcp_probe_runtime as remote_runtime
from app.services import agent_target_runtime as target_runtime
from app.services.agent_staging import build_filtered_staging, load_filtered_staging_manifest
from app.services.runtime_assets import mcp_remote_capability_probe as remote_probe


IMAGE = "python@sha256:" + "a" * 64
CONTAINER_ID = "b" * 64
PLAN_SHA256 = "c" * 64
SCAN_ID = "scan-remote-1"
PUBLIC_IP = "93.184.216.34"


def completed(returncode: int = 0, stdout: str = "", stderr: str = "") -> SimpleNamespace:
    return SimpleNamespace(returncode=returncode, stdout=stdout, stderr=stderr)


def build_staging(tmp_path: Path, config: dict[str, object] | None = None) -> dict[str, object]:
    source = tmp_path / "source"
    source.mkdir()
    (source / ".mcp.json").write_text(json.dumps(config or {
        "mcpServers": {"remote-catalog": {
            "url": "https://mcp.example.com/mcp", "transport": "streamable-http",
        }},
    }), encoding="utf-8")
    return build_filtered_staging(
        source_path=str(source), project_id="project-remote",
        destination_root=tmp_path / "staging" / "project-remote",
        binding={
            "scan_task_id": SCAN_ID, "plan_sha256": PLAN_SHA256,
            "command_sha256": sha256(b"python app.py").hexdigest(),
            "image": IMAGE, "timeout_seconds": 5,
        },
    )


def remote_result_line() -> str:
    result: dict[str, object] = {
        "schema": remote_runtime.REMOTE_MCP_RESULT_SCHEMA,
        "probe_version": "1.0.0", "status": "success",
        "transport_mode": "streamable-http-modern",
        "protocol_version": "2026-07-28", "server_name": "remote-server",
        "server_version": "2.0.0", "endpoint": "https://mcp.example.com/mcp",
        "approved_ips": [PUBLIC_IP], "redirects": [],
        "tool_names": ["search_public_catalog"],
        "resource_schemes": ["catalog"], "prompt_names": ["search-help"],
        "method_outcomes": {
            "server/discover": "success", "initialize": "missing",
            "tools/list": "success", "resources/list": "success", "prompts/list": "success",
        },
        "network_requests": [{
            "method": "tools/list", "http_status": 200,
            "content_type": "application/json", "response_bytes": 64,
            "remote_ip": PUBLIC_IP, "elapsed_ms": 2, "outcome": "success",
        }],
        "session_established": False, "error_code": None,
        "authentication_sent": False, "configured_headers_used": False,
        "content_actions_performed": False, "content_stored": False,
    }
    result["result_sha256"] = remote_runtime.canonical_sha256(result)
    return remote_runtime.REMOTE_MCP_PREFIX + json.dumps(result) + "\n"


def inspect_payload(staging: Path, observer: Path, probe_tokens: list[str]) -> dict[str, object]:
    return {
        "Config": {
            "Image": IMAGE, "Entrypoint": [probe_tokens[0]], "Cmd": probe_tokens[1:],
            "User": "65534:65534", "Env": ["PATH=/usr/local/bin"],
            "Healthcheck": {"Test": ["NONE"]},
        },
        "HostConfig": {
            "NetworkMode": "bridge", "ReadonlyRootfs": True, "CapDrop": ["ALL"],
            "SecurityOpt": ["no-new-privileges:true"], "Privileged": False,
            "NanoCpus": 500_000_000, "Memory": 256 * 1024 * 1024, "PidsLimit": 64,
            "Tmpfs": {"/tmp": "rw,noexec,nosuid,size=32m"}, "IpcMode": "none", "PidMode": "",
            "LogConfig": {"Type": "local", "Config": {"max-size": "1m", "max-file": "1", "compress": "false"}},
            "PortBindings": {}, "ExtraHosts": None,
        },
        "Mounts": [
            {"Source": str(staging), "Destination": "/workspace", "RW": False},
            {"Source": str(observer), "Destination": "/opt/agent-observer", "RW": False},
        ],
        "State": {"ExitCode": 0},
    }


def test_remote_candidates_are_staging_bound_and_secret_fields_are_not_exposed(tmp_path: Path, monkeypatch) -> None:
    staging = build_staging(tmp_path, {"mcpServers": {
        "public": {"url": "https://mcp.example.com/mcp", "type": "streamable-http"},
        "private": {
            "url": "https://private.example.com/mcp?token=must-not-leak",
            "headers": {"Authorization": "Bearer must-not-leak"},
            "accessToken": "must-not-leak",
        },
    }})
    path = Path(str(staging["destination_path"]))
    candidates = remote_runtime.discover_remote_candidates(path, load_filtered_staging_manifest(path))
    monkeypatch.setattr(remote_runtime, "resolve_staging_root", lambda project_id: path.parent)
    status = remote_runtime.list_remote_mcp_probe_status("project-remote", SCAN_ID, True)
    public = next(item for item in candidates if item["server_name"] == "public")
    private = next(item for item in candidates if item["server_name"] == "private")

    assert public["eligible"] is True
    assert private["eligible"] is False
    assert "no_configured_headers" in private["rejection_reasons"]
    assert "no_configured_credentials" in private["rejection_reasons"]
    assert "no_url_query_or_fragment" in private["rejection_reasons"]
    serialized = json.dumps(status)
    assert "must-not-leak" not in serialized
    assert "_endpoint" not in serialized


def test_top_level_remote_mcp_endpoint_is_discovered(tmp_path: Path) -> None:
    staging = build_staging(tmp_path, {
        "url": "https://mcp.example.com/mcp", "transport": "streamable-http",
    })
    path = Path(str(staging["destination_path"]))

    candidates = remote_runtime.discover_remote_candidates(path, load_filtered_staging_manifest(path))

    assert len(candidates) == 1
    assert candidates[0]["server_name"] == "default"
    assert candidates[0]["eligible"] is True


@pytest.mark.parametrize("url", [
    "http://example.com/mcp",
    "https://localhost/mcp",
    "https://127.0.0.1/mcp",
    "https://169.254.169.254/latest/meta-data",
    "https://example.com:8443/mcp",
    "https://user:password@example.com/mcp",
])
def test_remote_candidate_static_policy_rejects_unsafe_endpoints(url: str) -> None:
    candidate = remote_runtime.build_remote_candidate(
        relative_path=".mcp.json", config_sha256="d" * 64,
        server_name="unsafe", node={"url": url},
    )
    assert candidate is not None
    assert candidate["eligible"] is False


def test_dns_policy_rejects_any_non_public_resolution() -> None:
    with pytest.raises(target_runtime.TargetRuntimeRejected, match="blocks loopback"):
        remote_runtime.resolve_public_addresses(
            "https://mcp.example.com/mcp",
            lambda host, port: [PUBLIC_IP, "10.0.0.5"],
        )


class ModernMcpHandler(BaseHTTPRequestHandler):
    response_mode = "json"
    seen_headers: list[dict[str, str]] = []

    def log_message(self, format: str, *args) -> None:
        return

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length") or 0)
        request = json.loads(self.rfile.read(length))
        self.__class__.seen_headers.append({key.lower(): value for key, value in self.headers.items()})
        method = request.get("method")
        request_id = request.get("id")
        if method == "server/discover":
            result = {
                "supportedVersions": [remote_probe.MODERN_PROTOCOL_VERSION],
                "capabilities": {"tools": {}, "resources": {}, "prompts": {}},
                "_meta": {"io.modelcontextprotocol/serverInfo": {"name": "local-modern", "version": "1.0.0"}},
            }
        elif method == "tools/list":
            result = {"tools": [{"name": "bounded_search", "description": "SECRET-CONTENT"}]}
        elif method == "resources/list":
            result = {"resources": [{"uri": "fixture://catalog/secret-value"}]}
        elif method == "prompts/list":
            result = {"prompts": [{"name": "bounded-help", "description": "SECRET-CONTENT"}]}
        else:
            result = {}
        payload = json.dumps({"jsonrpc": "2.0", "id": request_id, "result": result}).encode("utf-8")
        if self.__class__.response_mode == "sse":
            payload = b"event: message\ndata: " + payload + b"\n\n"
            content_type = "text/event-stream"
        else:
            content_type = "application/json"
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)


@pytest.mark.parametrize("response_mode", ["json", "sse"])
def test_fixed_probe_handles_modern_json_and_sse_without_auth_or_content(response_mode: str) -> None:
    ModernMcpHandler.response_mode = response_mode
    ModernMcpHandler.seen_headers = []
    server = ThreadingHTTPServer(("127.0.0.1", 0), ModernMcpHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        endpoint = f"http://localhost:{server.server_port}/mcp"
        result = remote_probe.probe_remote_mcp(
            endpoint, ["127.0.0.1"], 3, allow_http=True,
        )
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)

    assert result["status"] == "success"
    assert result["transport_mode"] == "streamable-http-modern"
    assert result["tool_names"] == ["bounded_search"]
    assert result["resource_schemes"] == ["fixture"]
    assert result["prompt_names"] == ["bounded-help"]
    assert "SECRET-CONTENT" not in json.dumps(result)
    assert all("authorization" not in headers and "cookie" not in headers for headers in ModernMcpHandler.seen_headers)
    assert result["authentication_sent"] is False
    assert result["content_actions_performed"] is False


class LegacySseHandler(BaseHTTPRequestHandler):
    messages: queue.Queue[bytes | None] = queue.Queue()
    active = True

    def log_message(self, format: str, *args) -> None:
        return

    def do_GET(self) -> None:
        if self.path != "/sse":
            self.send_error(404)
            return
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.end_headers()
        self.wfile.write(b"event: endpoint\ndata: /messages?session=secret-session\n\n")
        self.wfile.flush()
        while self.__class__.active:
            try:
                payload = self.__class__.messages.get(timeout=0.2)
            except queue.Empty:
                continue
            if payload is None:
                break
            try:
                self.wfile.write(b"event: message\ndata: " + payload + b"\n\n")
                self.wfile.flush()
            except (BrokenPipeError, ConnectionResetError):
                break

    def do_POST(self) -> None:
        if not self.path.startswith("/messages?session="):
            self.send_error(404)
            return
        length = int(self.headers.get("Content-Length") or 0)
        request = json.loads(self.rfile.read(length))
        request_id = request.get("id")
        method = request.get("method")
        if request_id is not None:
            if method == "initialize":
                result = {
                    "protocolVersion": "2024-11-05",
                    "serverInfo": {"name": "legacy-local", "version": "1.0.0"},
                    "capabilities": {},
                }
            elif method == "tools/list":
                result = {"tools": [{"name": "legacy_search"}]}
            elif method == "resources/list":
                result = {"resources": [{"uri": "legacy://catalog/item"}]}
            elif method == "prompts/list":
                result = {"prompts": [{"name": "legacy-help"}]}
            else:
                result = {}
            self.__class__.messages.put(json.dumps({
                "jsonrpc": "2.0", "id": request_id, "result": result,
            }).encode("utf-8"))
        self.send_response(202)
        self.send_header("Content-Length", "0")
        self.end_headers()


def test_fixed_probe_supports_legacy_http_sse_without_storing_session_query() -> None:
    LegacySseHandler.messages = queue.Queue()
    LegacySseHandler.active = True
    server = ThreadingHTTPServer(("127.0.0.1", 0), LegacySseHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        result = remote_probe.probe_remote_mcp(
            f"http://localhost:{server.server_port}/sse", ["127.0.0.1"], 3,
            allow_http=True, transport_hint="legacy-sse",
        )
    finally:
        LegacySseHandler.active = False
        LegacySseHandler.messages.put(None)
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)

    assert result["status"] == "success"
    assert result["transport_mode"] == "legacy-http-sse"
    assert result["tool_names"] == ["legacy_search"]
    assert result["resource_schemes"] == ["legacy"]
    assert result["prompt_names"] == ["legacy-help"]
    assert "secret-session" not in json.dumps(result)


class LegacyStreamableHandler(BaseHTTPRequestHandler):
    session_id = "secret-streamable-session"

    def log_message(self, format: str, *args) -> None:
        return

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length") or 0)
        request = json.loads(self.rfile.read(length))
        method = request.get("method")
        request_id = request.get("id")
        if method == "notifications/initialized":
            assert self.headers.get("Mcp-Session-Id") == self.session_id
            assert self.headers.get("MCP-Protocol-Version") == "2025-11-25"
            self.send_response(202)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        if method == "server/discover":
            response = {"jsonrpc": "2.0", "id": request_id, "error": {"code": -32601, "message": "not found"}}
        elif method == "initialize":
            response = {"jsonrpc": "2.0", "id": request_id, "result": {
                "protocolVersion": "2025-11-25", "capabilities": {},
                "serverInfo": {"name": "legacy-streamable", "version": "1.0.0"},
            }}
        else:
            assert self.headers.get("Mcp-Session-Id") == self.session_id
            assert self.headers.get("MCP-Protocol-Version") == "2025-11-25"
            values = {
                "tools/list": {"tools": [{"name": "session_search"}]},
                "resources/list": {"resources": [{"uri": "session://catalog/item"}]},
                "prompts/list": {"prompts": [{"name": "session-help"}]},
            }
            response = {"jsonrpc": "2.0", "id": request_id, "result": values.get(method, {})}
        payload = json.dumps(response).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        if method == "initialize":
            self.send_header("Mcp-Session-Id", self.session_id)
        self.end_headers()
        self.wfile.write(payload)


def test_fixed_probe_supports_legacy_streamable_session_without_storing_session_id() -> None:
    server = ThreadingHTTPServer(("127.0.0.1", 0), LegacyStreamableHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        result = remote_probe.probe_remote_mcp(
            f"http://localhost:{server.server_port}/mcp", ["127.0.0.1"], 3,
            allow_http=True, transport_hint="streamable-http",
        )
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)

    assert result["status"] == "success"
    assert result["transport_mode"] == "streamable-http-legacy"
    assert result["protocol_version"] == "2025-11-25"
    assert result["tool_names"] == ["session_search"]
    assert result["session_established"] is True
    assert LegacyStreamableHandler.session_id not in json.dumps(result)


def test_remote_probe_validation_uses_fixed_network_probe_and_emits_evidence(tmp_path: Path, monkeypatch) -> None:
    staging = build_staging(tmp_path)
    staging_path = Path(str(staging["destination_path"]))
    manifest = load_filtered_staging_manifest(staging_path)
    candidate = remote_runtime.discover_remote_candidates(staging_path, manifest)[0]
    observer_path, _ = target_runtime.resolve_observer_asset()
    probe_tokens = [
        "python", "-I", "-B", "/opt/agent-observer/mcp_remote_capability_probe.py",
        "--endpoint", "https://mcp.example.com/mcp", "--timeout-seconds", "5",
        "--transport-hint", "streamable-http",
        "--approved-ip", PUBLIC_IP,
    ]
    inspected = inspect_payload(staging_path, observer_path, probe_tokens)
    commands: list[list[str]] = []
    monkeypatch.setattr(target_runtime, "staging_workspace_path", lambda project_id: staging_path.parent)
    monkeypatch.setattr(remote_runtime, "docker_executable", lambda: "docker")
    monkeypatch.setattr(
        remote_runtime, "write_remote_mcp_probe_evidence",
        lambda project_id, execution_id, evidence: tmp_path / "remote-evidence.json",
    )

    def fake_run(command, **kwargs):
        commands.append(command)
        if command[1:3] == ["context", "inspect"]:
            return completed(stdout=json.dumps("npipe:////./pipe/dockerDesktopLinuxEngine"))
        if command[1:3] == ["image", "inspect"]:
            return completed(stdout=json.dumps([{"Id": "sha256:" + "d" * 64}]))
        if command[1] == "create":
            return completed(stdout=CONTAINER_ID + "\n")
        if command[1:3] == ["container", "inspect"]:
            return completed(stdout=json.dumps([inspected]))
        if command[1] in {"start", "wait", "rm"}:
            return completed(stdout="0\n")
        if command[1] == "logs":
            return completed(stderr=remote_result_line())
        raise AssertionError(command)

    evidence = remote_runtime.run_remote_mcp_probe_validation(
        project_id="project-remote", scan_task_id=SCAN_ID, image=IMAGE,
        timeout_seconds=5, plan_sha256=PLAN_SHA256,
        staging_build_id=str(staging["build_id"]), staging_sha256=str(staging["staging_sha256"]),
        manifest_sha256=str(staging["manifest_sha256"]), candidate_id=str(candidate["candidate_id"]),
        authorization_phrase=remote_runtime.REMOTE_MCP_AUTHORIZATION_PHRASE,
        operator_confirmed=True, run_command=fake_run,
        resolver=lambda host, port: [PUBLIC_IP],
    )

    assert evidence["decision"] == "pass"
    assert evidence["policy_verified"] is True
    assert evidence["capability_probe"]["tool_names"] == ["search_public_catalog"]
    assert evidence["network_policy"]["approved_ips"] == [PUBLIC_IP]
    assert evidence["output"]["content_stored"] is False
    create = next(item for item in commands if item[1] == "create")
    assert create[create.index("--network") + 1] == "bridge"
    assert "/opt/agent-observer/mcp_remote_capability_probe.py" in create
    assert not any(item[1:2] == ["pull"] for item in commands)


def test_remote_probe_requires_confirmation_before_dns_or_docker() -> None:
    called = False

    def resolver(host: str, port: int) -> list[str]:
        nonlocal called
        called = True
        return [PUBLIC_IP]

    with pytest.raises(target_runtime.TargetRuntimeRejected, match="separate authorization phrase"):
        remote_runtime.run_remote_mcp_probe_validation(
            project_id="project-remote", scan_task_id=SCAN_ID, image=IMAGE,
            timeout_seconds=5, plan_sha256=PLAN_SHA256, staging_build_id="missing",
            staging_sha256="d" * 64, manifest_sha256="e" * 64,
            candidate_id="f" * 24, authorization_phrase="", operator_confirmed=False,
            resolver=resolver,
        )
    assert called is False


def test_remote_probe_endpoint_is_disabled_by_default(monkeypatch) -> None:
    called = False
    monkeypatch.setattr(agent_router, "require_agent_fixture_modules", lambda db, project_id: None)
    monkeypatch.setattr(agent_router, "enabled_agent_module", lambda db, project_id: SimpleNamespace(config={}))

    def unexpected_run(**kwargs):
        nonlocal called
        called = True

    monkeypatch.setattr(agent_router, "run_remote_mcp_probe_validation", unexpected_run)
    request = AgentRemoteMcpProbeRuntimeRequest(
        image=IMAGE, timeout_seconds=5, plan_sha256=PLAN_SHA256,
        staging_build_id="build-1", staging_sha256="d" * 64,
        manifest_sha256="e" * 64, candidate_id="f" * 24,
        authorization_phrase=remote_runtime.REMOTE_MCP_AUTHORIZATION_PHRASE,
        operator_confirmed=True,
    )

    with pytest.raises(HTTPException) as exc:
        agent_router.validate_project_agent_remote_mcp_probe(uuid4(), request, SimpleNamespace())

    assert exc.value.status_code == 403
    assert called is False
