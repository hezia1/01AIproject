from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import os
from pathlib import Path
import re
import subprocess
import sys
from threading import Thread
from types import SimpleNamespace
from urllib.parse import unquote
from uuid import uuid4

from app.db_models import SandboxTargetInstanceRecord, SandboxTaskRecord
from app.services import sandbox_orchestrator as orchestrator
from app.services import sandbox_browser_executor as browser_executor
from app.services.sandbox_browser_executor import _execute_csrf_probe, _execute_xss_probe, _redact_har
from app.services.sandbox_launch_planner import _validated_ai_candidate, build_launch_plan
from app.services.sandbox_templates import discover_sandbox_templates
from app.routers.sandbox import browser_session_target_ids


class FakeDb:
    def __init__(self) -> None:
        self.items: list[object] = []

    def add(self, item: object) -> None:
        self.items.append(item)

    def flush(self) -> None:
        for item in self.items:
            if getattr(item, "id", None) is None:
                item.id = str(uuid4())


def completed(returncode: int = 0, stdout: str = "", stderr: str = "") -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess([], returncode, stdout, stderr)


def test_browser_session_cleanup_only_selects_owned_running_docker_targets() -> None:
    owned_session, other_session = uuid4(), uuid4()
    owned = SandboxTargetInstanceRecord(id=str(uuid4()), mode="docker", status="running", policy={"browser_session_id": str(owned_session)})
    stopped = SandboxTargetInstanceRecord(id=str(uuid4()), mode="docker", status="stopped", policy={"browser_session_id": str(owned_session)})
    external = SandboxTargetInstanceRecord(id=str(uuid4()), mode="external", status="running", policy={"browser_session_id": str(owned_session)})
    other = SandboxTargetInstanceRecord(id=str(uuid4()), mode="docker", status="running", policy={"browser_session_id": str(other_session)})

    assert browser_session_target_ids([owned, stopped, external, other], owned_session) == [owned.id]


def test_source_start_template_includes_detected_runtime_port(tmp_path: Path) -> None:
    (tmp_path / "package.json").write_text('{"scripts":{"start":"node server.js"}}', encoding="utf-8")
    (tmp_path / "server.js").write_text("const port = process.env.PORT || '9090';", encoding="utf-8")

    start = next(item for item in discover_sandbox_templates(str(tmp_path)) if item.command_type == "start")

    assert start.command == "npm start"
    assert start.container_port == 9090


def test_source_start_template_detects_package_app_js_entrypoint(tmp_path: Path) -> None:
    (tmp_path / "package.json").write_text('{"main":"app.js","scripts":{"start":"node app.js"}}', encoding="utf-8")
    (tmp_path / "app.js").write_text("const PORT = process.env.PORT || 3000;\napp.listen(PORT);", encoding="utf-8")

    start = next(item for item in discover_sandbox_templates(str(tmp_path)) if item.command_type == "start")

    assert start.command == "npm start"
    assert start.container_port == 3000


def test_source_start_template_follows_typescript_script_entrypoint(tmp_path: Path) -> None:
    (tmp_path / "src").mkdir()
    (tmp_path / "package.json").write_text('{"scripts":{"start":"tsx src/http.ts"}}', encoding="utf-8")
    (tmp_path / "src" / "http.ts").write_text("const port = process.env.PORT || '4173';", encoding="utf-8")

    start = next(item for item in discover_sandbox_templates(str(tmp_path)) if item.command_type == "start")

    assert start.container_port == 4173


def test_runtime_port_does_not_confuse_dependency_port_with_app_port(tmp_path: Path) -> None:
    (tmp_path / ".env").write_text("DATABASE_PORT=5432\n", encoding="utf-8")
    (tmp_path / "package.json").write_text('{"scripts":{"start":"node app.js"}}', encoding="utf-8")
    (tmp_path / "app.js").write_text("const PORT = process.env.PORT || 3000;", encoding="utf-8")

    start = next(item for item in discover_sandbox_templates(str(tmp_path)) if item.command_type == "start")

    assert start.container_port == 3000


def test_unhealthy_docker_target_explains_configured_port(monkeypatch) -> None:
    target = SandboxTargetInstanceRecord(
        mode="docker", status="starting", runtime_url="http://127.0.0.1:49152",
        container_port=8000, health_path="/", health_detail={},
    )
    monkeypatch.setattr(orchestrator, "urlopen", lambda *_args, **_kwargs: (_ for _ in ()).throw(orchestrator.URLError("connection refused")))

    orchestrator.check_target_health(target)

    assert target.status == "unhealthy"
    assert target.health_detail["diagnostic_code"] == "target_port_or_health_mismatch"
    assert target.health_detail["configured_container_port"] == 8000
    assert "启动前确认区" in target.health_detail["remediation"]


def test_start_docker_target_uses_project_scoped_isolation(monkeypatch, tmp_path: Path) -> None:
    calls: list[list[str]] = []
    (tmp_path / "package.json").write_text('{"scripts":{"start":"node server.js"}}', encoding="utf-8")

    def fake_docker(args: list[str], **_kwargs) -> subprocess.CompletedProcess[str]:
        calls.append(args)
        if args and args[0] == "inspect" and args[-1] == "{{.State.Status}}|{{.State.ExitCode}}|{{.State.Error}}":
            return completed(stdout="running|0|\n")
        if args[:2] == ["port", args[1] if len(args) > 1 else ""]:
            return completed(stdout="127.0.0.1:49152\n")
        if args and args[0] == "port":
            return completed(stdout="127.0.0.1:49152\n")
        if args[:2] == ["run", "-d"]:
            return completed(stdout="container-id\n")
        return completed(stdout="ok\n")

    monkeypatch.setattr(orchestrator, "_image_exists", lambda _image: True)
    monkeypatch.setattr(orchestrator, "_allocate_loopback_port", lambda: 49152)
    monkeypatch.setattr(orchestrator, "_run_docker", fake_docker)
    monkeypatch.setattr(orchestrator, "check_target_health", lambda record: setattr(record, "status", "running") or record)
    project = SimpleNamespace(id=str(uuid4()), source_path=str(tmp_path), sandbox_image="demo:local", sandbox_command="python app.py")

    target = orchestrator.start_docker_target(
        FakeDb(), project, image="demo:local", command="python app.py", container_port=8000,
        health_path="/health", operator="tester", confirmed=True,
    )

    run = next(call for call in calls if call[:2] == ["run", "-d"])
    gateway_run = next(call for call in calls if call[:2] == ["run", "-d"] and "-p" in call)
    assert ["--read-only"] == [value for value in run if value == "--read-only"]
    assert run[run.index("--cap-drop"):run.index("--cap-drop") + 2] == ["--cap-drop", "ALL"]
    assert run[run.index("--network"):run.index("--network") + 2][1].startswith("aisec-sbx-net-")
    assert "-p" not in run
    assert gateway_run[gateway_run.index("-p"):gateway_run.index("-p") + 2] == ["-p", "127.0.0.1:49152:8080"]
    assert ["network", "connect"] == next(call[:2] for call in calls if call[:2] == ["network", "connect"])
    prepare = next(call for call in calls if call[:2] == ["run", "--rm"])
    assert f"{tmp_path.resolve()}:/source:ro" in prepare
    assert any(value.startswith("aisec-sbx-work-") and value.endswith(":/workspace") for value in prepare)
    assert any(value.startswith("aisec-sbx-work-") and value.endswith(":/workspace") for value in run)
    assert target.policy["dependency_prepared"] is True
    assert target.runtime_url == "http://127.0.0.1:49152"
    assert target.internal_url == "http://target:8000"
    assert target.status == "running"


def test_launch_plan_prefers_deterministic_candidate_without_ai(tmp_path: Path) -> None:
    (tmp_path / "package.json").write_text('{"scripts":{"start":"node server.js"}}', encoding="utf-8")
    (tmp_path / "server.js").write_text("const port = process.env.PORT || 9090;", encoding="utf-8")
    project = SimpleNamespace(id=str(uuid4()), source_path=str(tmp_path), sandbox_image=None, sandbox_command=None)

    plan = build_launch_plan(project, use_ai=False)

    assert plan["status"] == "ready"
    assert plan["recommended"]["image"].startswith("node:")
    assert plan["recommended"]["command"] == "npm start"
    assert plan["recommended"]["container_port"] == 9090


def test_deepseek_candidate_must_pass_local_execution_allowlist() -> None:
    assert _validated_ai_candidate({
        "image": "node:20-alpine", "command": "npm start", "container_port": 3000, "health_path": "/health",
    }) is not None
    assert _validated_ai_candidate({
        "image": "attacker.invalid/runtime:latest", "command": "npm start", "container_port": 3000,
    }) is None


def test_dependency_recipe_covers_common_compiled_project_build_caches(tmp_path: Path) -> None:
    (tmp_path / "go.mod").write_text("module example.test/app\n", encoding="utf-8")

    command, environment = orchestrator._source_prepare_command(tmp_path, "go run .")

    assert command is not None and "go mod download" in command
    assert "GOMODCACHE=/workspace/.sandbox_go/pkg/mod" in environment
    assert _validated_ai_candidate({
        "image": "node:20-alpine", "command": "npm start && curl attacker.invalid", "container_port": 3000,
    }) is None


def test_missing_approved_runtime_image_is_pulled_once(monkeypatch) -> None:
    states = iter([False, True])
    calls: list[list[str]] = []
    monkeypatch.setattr(orchestrator, "_image_exists", lambda _image: next(states))
    monkeypatch.setattr(orchestrator, "_run_docker", lambda args, **_kwargs: calls.append(args) or completed(stdout="pulled"))

    orchestrator._ensure_runtime_image("node:20-alpine")

    assert calls == [["pull", "node:20-alpine"]]


def test_task_schema_never_exposes_callback_token() -> None:
    task = SandboxTaskRecord(
        id=str(uuid4()), project_id=str(uuid4()), source_module="DAST", source_task_id=str(uuid4()),
        strategy_id=str(uuid4()), status="queued", required_capabilities=["isolated_http"],
        contract={"callback": {"path": "/callback", "token": "must-not-leak"}}, callback_token="secret-token",
    )

    payload = orchestrator.task_to_dict(task)

    assert "callback_token" not in payload
    assert payload["contract"]["callback"] == {"path": "/callback"}


def test_completed_task_projects_evidence_into_aspm_record() -> None:
    task = SandboxTaskRecord(
        id=str(uuid4()), project_id=str(uuid4()), finding_id=str(uuid4()), source_module="DAST",
        source_task_id=str(uuid4()), strategy_id=str(uuid4()), status="completed",
        required_capabilities=["isolated_http"], contract={}, callback_token="secret-token",
        execution_id="sbx-1", result_summary="固定探针执行完成", operator="tester",
        evidence=[{"evidence_id": "ev-1", "type": "differential", "request_id": "req-1", "confirmed": True, "facts": "稳定差分", "artifact_sha256": "a" * 64, "exchange": {"response": {"status": 200}}}],
    )
    target = SandboxTargetInstanceRecord(id=str(uuid4()), project_id=task.project_id, mode="docker", status="running", runtime_url="http://127.0.0.1:1", operator="tester")
    db = FakeDb()

    evidence = orchestrator.persist_task_evidence_record(db, task, target)

    assert evidence.finding_id == task.finding_id
    assert evidence.link_source == "dast-sandbox-contract"
    assert evidence.run_command.startswith("fixed-policy:")
    assert evidence.observed_network[0]["request_id"] == "req-1"
    assert evidence.observed_tool_calls[0]["arbitrary_command"] is False


def test_runtime_contract_rewrites_only_origin_for_docker_target() -> None:
    contract = {
        "target": {"url": "https://example.test/api/item?id=1", "allowed_paths": ["/api/item"]},
        "steps": [{
            "url": "https://example.test/api/item?id=2", "setup_url": "https://example.test/app/form",
            "kind": "sandbox_probe",
        }],
    }
    target = SandboxTargetInstanceRecord(mode="docker", runtime_url="http://127.0.0.1:49152", internal_url="http://target:8000")

    rewritten = orchestrator._runtime_contract(contract, target)

    assert rewritten["target"]["url"] == "http://target:8000/api/item?id=1"
    assert rewritten["steps"][0]["url"] == "http://target:8000/api/item?id=2"
    assert rewritten["steps"][0]["setup_url"] == "http://target:8000/app/form"
    assert contract["target"]["url"] == "https://example.test/api/item?id=1"


class ProbeHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(b"stable response")

    def log_message(self, *_args) -> None:
        return


class LoginRedirectHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        self.send_response(302)
        self.send_header("Location", "/login")
        self.end_headers()

    def log_message(self, *_args) -> None:
        return


def test_fixed_executor_allows_anonymous_redirect_to_login() -> None:
    server = ThreadingHTTPServer(("127.0.0.1", 0), LoginRedirectHandler)
    Thread(target=server.serve_forever, daemon=True).start()
    target = f"http://127.0.0.1:{server.server_port}/"
    contract = {
        "schema": "ai-security-platform.dast-sandbox-handoff/v1",
        "target": {"url": target, "allowed_paths": ["/"]},
        "roles": [{"alias": "anonymous", "description": "anonymous"}],
        "steps": [{
            "id": "security", "kind": "sandbox_probe", "capability": "isolated_http",
            "probe": "security_misconfiguration", "role": "anonymous", "method": "GET",
            "url": target, "request_id": str(uuid4()),
        }],
    }
    runner = Path(orchestrator.__file__).with_name("sandbox_http_executor.py")
    try:
        result = subprocess.run([sys.executable, str(runner)], input=json.dumps(contract), text=True, capture_output=True, timeout=20, check=False)
    finally:
        server.shutdown()

    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout)["status"] == "completed"


def test_fixed_executor_returns_coverage_without_shell_command() -> None:
    server = ThreadingHTTPServer(("127.0.0.1", 0), ProbeHandler)
    Thread(target=server.serve_forever, daemon=True).start()
    target = f"http://127.0.0.1:{server.server_port}/probe"
    contract = {
        "schema": "ai-security-platform.dast-sandbox-handoff/v1",
        "target": {"url": target, "allowed_paths": ["/probe"]},
        "steps": [{"id": "probe", "kind": "sandbox_probe", "capability": "isolated_http", "probe": "path_traversal", "method": "GET", "url": target, "parameter": "file", "request_id": str(uuid4())}],
    }
    runner = Path(orchestrator.__file__).with_name("sandbox_http_executor.py")
    try:
        result = subprocess.run([sys.executable, str(runner)], input=json.dumps(contract), text=True, capture_output=True, timeout=20, check=False)
    finally:
        server.shutdown()

    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)
    assert payload["status"] == "completed"
    assert payload["verdict_signal"] == "not_exploitable"
    assert any(item["type"] == "coverage" and item["probe_count"] >= 2 for item in payload["evidence"])


class AccessControlFlowHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        cookie = str(self.headers.get("Cookie") or "")
        self.send_response(200 if "role=owner" in cookie else 403)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b'{"resource":"owned"}' if "role=owner" in cookie else b'{"error":"forbidden"}')

    def log_message(self, *_args) -> None:
        return


def test_fixed_executor_runs_generated_access_control_flow_in_sandbox() -> None:
    server = ThreadingHTTPServer(("127.0.0.1", 0), AccessControlFlowHandler)
    Thread(target=server.serve_forever, daemon=True).start()
    target = f"http://127.0.0.1:{server.server_port}/app/useredit"
    contract = {
        "schema": "ai-security-platform.dast-sandbox-handoff/v1",
        "task_id": "task-access-control",
        "target": {"url": target, "allowed_paths": ["/app/useredit"]},
        "limits": {"timeout_seconds": 10, "max_requests": 10},
        "roles": [
            {"alias": "resource_owner", "credential_ref": "env:DAST_OWNER"},
            {"alias": "peer_user", "credential_ref": "env:DAST_PEER"},
        ],
        "steps": [
            {"id": "owner-read", "kind": "http_request", "role": "resource_owner", "method": "GET", "url": target, "request_id": "req-owner"},
            {"id": "peer-read", "kind": "http_request", "role": "peer_user", "method": "GET", "url": target, "request_id": "req-peer"},
            {"id": "authorization-differential", "kind": "assert_compare", "mode": "access_control", "left": "owner-read", "right": "peer-read"},
        ],
    }
    runner = Path(orchestrator.__file__).with_name("sandbox_http_executor.py")
    environment = {
        **os.environ,
        "DAST_OWNER": json.dumps({"cookie": "role=owner"}),
        "DAST_PEER": json.dumps({"cookie": "role=peer"}),
    }
    try:
        result = subprocess.run([sys.executable, str(runner)], input=json.dumps(contract), text=True, capture_output=True, timeout=20, check=False, env=environment)
    finally:
        server.shutdown()

    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)
    assert payload["status"] == "completed"
    assert payload["verdict_signal"] == "not_exploitable"
    assert any(item["type"] == "differential" and item["assertion"]["mode"] == "access_control" for item in payload["evidence"])


class AuthenticatedBodyProbeHandler(BaseHTTPRequestHandler):
    observed_cookies: list[str] = []
    observed_bodies: list[str] = []

    def do_POST(self) -> None:
        body = self.rfile.read(int(self.headers.get("Content-Length") or 0)).decode("utf-8", errors="replace")
        self.__class__.observed_cookies.append(str(self.headers.get("Cookie") or ""))
        self.__class__.observed_bodies.append(body)
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(b"8675320" if "8675309+11" in unquote(body) else b"2")

    def log_message(self, *_args) -> None:
        return


def test_fixed_executor_applies_session_and_body_location() -> None:
    AuthenticatedBodyProbeHandler.observed_cookies = []
    AuthenticatedBodyProbeHandler.observed_bodies = []
    server = ThreadingHTTPServer(("127.0.0.1", 0), AuthenticatedBodyProbeHandler)
    Thread(target=server.serve_forever, daemon=True).start()
    target = f"http://127.0.0.1:{server.server_port}/calc"
    contract = {
        "schema": "ai-security-platform.dast-sandbox-handoff/v1",
        "target": {"url": target, "allowed_paths": ["/calc"]},
        "roles": [{"alias": "authenticated_user", "credential_ref": "env:DAST_TEST_AUTH"}],
        "steps": [{
            "id": "code-proof", "kind": "sandbox_probe", "capability": "isolated_http",
            "probe": "code_injection", "role": "authenticated_user", "method": "POST",
            "url": target, "parameter": "eqn", "location": "json", "request_id": str(uuid4()),
        }],
    }
    runner = Path(orchestrator.__file__).with_name("sandbox_http_executor.py")
    environment = {**os.environ, "DAST_TEST_AUTH": json.dumps({"cookie": "connect.sid=demo-session"})}
    try:
        result = subprocess.run([sys.executable, str(runner)], input=json.dumps(contract), text=True, capture_output=True, timeout=20, check=False, env=environment)
    finally:
        server.shutdown()

    assert result.returncode == 0, result.stderr
    assert AuthenticatedBodyProbeHandler.observed_cookies == ["connect.sid=demo-session", "connect.sid=demo-session"]
    assert all('"eqn"' in body for body in AuthenticatedBodyProbeHandler.observed_bodies)
    assert json.loads(result.stdout)["verdict_signal"] == "exploitable"


def test_fixed_executor_sends_code_injection_as_form_field_when_mapped() -> None:
    AuthenticatedBodyProbeHandler.observed_cookies = []
    AuthenticatedBodyProbeHandler.observed_bodies = []
    server = ThreadingHTTPServer(("127.0.0.1", 0), AuthenticatedBodyProbeHandler)
    Thread(target=server.serve_forever, daemon=True).start()
    target = f"http://127.0.0.1:{server.server_port}/calc"
    contract = {
        "schema": "ai-security-platform.dast-sandbox-handoff/v1",
        "target": {"url": target, "allowed_paths": ["/calc"]},
        "roles": [{"alias": "authenticated_user", "credential_ref": "env:DAST_TEST_AUTH"}],
        "steps": [{
            "id": "code-proof", "kind": "sandbox_probe", "capability": "isolated_http",
            "probe": "code_injection", "role": "authenticated_user", "method": "POST",
            "url": target, "parameter": "eqn", "location": "form_field", "request_id": str(uuid4()),
        }],
    }
    runner = Path(orchestrator.__file__).with_name("sandbox_http_executor.py")
    environment = {**os.environ, "DAST_TEST_AUTH": json.dumps({"cookie": "connect.sid=demo-session"})}
    try:
        result = subprocess.run([sys.executable, str(runner)], input=json.dumps(contract), text=True, capture_output=True, timeout=20, check=False, env=environment)
    finally:
        server.shutdown()

    assert result.returncode == 0, result.stderr
    assert AuthenticatedBodyProbeHandler.observed_bodies == ["eqn=1%2B1", "eqn=8675309%2B11"]
    assert json.loads(result.stdout)["verdict_signal"] == "exploitable"


def test_browser_capability_is_ready_when_fixed_image_exists(monkeypatch) -> None:
    monkeypatch.setattr(orchestrator.shutil, "which", lambda _name: "docker")
    monkeypatch.setattr(orchestrator, "_run_docker", lambda _args, **_kwargs: completed(stdout="27.0\n"))
    monkeypatch.setattr(orchestrator, "_image_exists", lambda _image: True)

    health = orchestrator.capability_health()

    assert health["capabilities"]["browser"]["status"] == "ready"
    assert "Playwright" in health["capabilities"]["browser"]["detail"]


def test_launch_plan_detects_monorepo_app_and_fixed_support_services(tmp_path: Path) -> None:
    api = tmp_path / "apps" / "api"
    (api / "app").mkdir(parents=True)
    (api / "requirements.txt").write_text("fastapi\nuvicorn\n", encoding="utf-8")
    (api / "app" / "main.py").write_text("from fastapi import FastAPI\napp = FastAPI()\n", encoding="utf-8")
    (tmp_path / "infra").mkdir()
    (tmp_path / "infra" / "docker-compose.yml").write_text(
        "services:\n  postgres:\n    image: postgres:16\n    ports: ['5432:5432']\n    environment:\n      POSTGRES_PASSWORD: must-not-be-copied\n  arbitrary:\n    image: attacker.invalid/demo:latest\n",
        encoding="utf-8",
    )
    project = SimpleNamespace(id=str(uuid4()), source_path=str(tmp_path), sandbox_image=None, sandbox_command=None)

    plan = build_launch_plan(project, use_ai=False)

    assert plan["status"] == "ready"
    assert plan["recommended"]["source_subdir"] == "apps/api"
    assert plan["recommended"]["command"].startswith("uvicorn app.main:app")
    assert plan["orchestration"]["mode"] == "multi_service"
    assert plan["orchestration"]["support_services"] == [{
        "name": "postgres", "kind": "postgres", "image": "postgres:16",
        "source": "infra/docker-compose.yml", "healthcheck": "pg_isready",
    }]
    assert "must-not-be-copied" not in json.dumps(plan)


def test_support_service_orchestration_has_no_host_port(monkeypatch) -> None:
    calls: list[list[str]] = []
    monkeypatch.setattr(orchestrator, "_ensure_runtime_image", lambda _image: None)
    monkeypatch.setattr(orchestrator, "_run_docker", lambda args, **_kwargs: calls.append(args) or completed(stdout="ok\n"))

    names, environment, summary = orchestrator._start_support_services(
        "instance-1", "abc123", "internal-net",
        [{"kind": "postgres", "image": "postgres:16"}, {"kind": "redis", "image": "redis:7"}],
    )

    run_calls = [call for call in calls if call[:2] == ["run", "-d"]]
    assert names == ["aisec-sbx-postgres-abc123", "aisec-sbx-redis-abc123"]
    assert all("-p" not in call and "--publish" not in call for call in run_calls)
    assert any(value.startswith("DATABASE_URL=postgresql://") for value in environment)
    assert "REDIS_URL=redis://redis:6379/0" in environment
    assert [item["status"] for item in summary] == ["ready", "ready"]


def test_execute_task_routes_browser_steps_to_fixed_adapter(monkeypatch) -> None:
    project_id, task_id, target_id = str(uuid4()), str(uuid4()), str(uuid4())
    task = SandboxTaskRecord(
        id=task_id, project_id=project_id, source_module="DAST", source_task_id=str(uuid4()),
        strategy_id=str(uuid4()), status="queued", required_capabilities=["browser"], callback_token="x" * 64,
        contract={"target": {"url": "https://example.test/page", "allowed_paths": ["/page"]}, "steps": [{"id": "page", "kind": "browser_action", "action": "navigate", "url": "https://example.test/page", "request_id": "req-1"}]},
    )
    target = SandboxTargetInstanceRecord(id=target_id, project_id=project_id, mode="external", status="running", runtime_url="https://example.test", internal_url="https://example.test", operator="tester")
    adapters: list[str] = []
    monkeypatch.setattr(orchestrator, "capability_health", lambda: {"capabilities": {"browser": {"status": "ready"}}})
    monkeypatch.setattr(orchestrator, "_run_policy_executor", lambda **kwargs: adapters.append(kwargs["adapter"]) or {"status": "completed", "evidence": [{"type": "screenshot", "request_id": "req-1", "artifact_sha256": "a" * 64}], "verdict_signal": "uncertain", "verdict_reason": "captured"})

    result = orchestrator.execute_task(FakeDb(), task, target, "tester")

    assert adapters == ["browser"]
    assert result["status"] == "completed"
    assert task.evidence[0]["type"] == "screenshot"


def test_execute_task_routes_csrf_probe_to_browser_adapter(monkeypatch) -> None:
    project_id, task_id, target_id = str(uuid4()), str(uuid4()), str(uuid4())
    task = SandboxTaskRecord(
        id=task_id, project_id=project_id, source_module="DAST", source_task_id=str(uuid4()),
        strategy_id=str(uuid4()), status="queued", required_capabilities=["browser"], callback_token="x" * 64,
        contract={"target": {"url": "http://target/app/useredit", "allowed_paths": ["/app/useredit"]}, "steps": [{"id": "csrf", "kind": "sandbox_probe", "capability": "browser", "probe": "csrf", "role": "user", "method": "POST", "url": "http://target/app/useredit", "parameters": ["name"], "request_id": "req-csrf"}]},
    )
    target = SandboxTargetInstanceRecord(id=target_id, project_id=project_id, mode="docker", status="running", runtime_url="http://127.0.0.1:51065", internal_url="http://target", network_name="sandbox-net", operator="tester")
    adapters: list[str] = []
    monkeypatch.setattr(orchestrator, "capability_health", lambda: {"capabilities": {"browser": {"status": "ready"}}})
    monkeypatch.setattr(orchestrator, "_run_policy_executor", lambda **kwargs: adapters.append(kwargs["adapter"]) or {"status": "completed", "evidence": [{"type": "differential", "request_id": "req-csrf", "confirmed": True, "complete": True}], "verdict_signal": "exploitable", "verdict_reason": "csrf bypass"})

    result = orchestrator.execute_task(FakeDb(), task, target, "tester")

    assert adapters == ["browser"]
    assert result["status"] == "completed"
    assert result["verdict_signal"] == "exploitable"


def test_execute_task_routes_access_control_mutation_probe_to_browser_adapter(monkeypatch) -> None:
    project_id, task_id, target_id = str(uuid4()), str(uuid4()), str(uuid4())
    task = SandboxTaskRecord(
        id=task_id, project_id=project_id, source_module="DAST", source_task_id=str(uuid4()),
        strategy_id=str(uuid4()), status="queued", required_capabilities=["browser"], callback_token="x" * 64,
        contract={"target": {"url": "http://target/app/useredit", "allowed_paths": ["/app/useredit"]}, "steps": [{"id": "idor", "kind": "sandbox_probe", "capability": "browser", "probe": "access_control_mutation", "role": "peer_user", "owner_role": "resource_owner", "method": "POST", "url": "http://target/app/useredit", "parameters": ["id", "name"], "request_id": "req-idor"}]},
    )
    target = SandboxTargetInstanceRecord(id=target_id, project_id=project_id, mode="docker", status="running", runtime_url="http://127.0.0.1:51065", internal_url="http://target", network_name="sandbox-net", operator="tester")
    adapters: list[str] = []
    monkeypatch.setattr(orchestrator, "capability_health", lambda: {"capabilities": {"browser": {"status": "ready"}}})
    monkeypatch.setattr(orchestrator, "_run_policy_executor", lambda **kwargs: adapters.append(kwargs["adapter"]) or {"status": "completed", "evidence": [{"type": "authorization", "request_id": "req-idor", "confirmed": True, "complete": True}], "verdict_signal": "exploitable", "verdict_reason": "idor mutation"})

    result = orchestrator.execute_task(FakeDb(), task, target, "tester")

    assert adapters == ["browser"]
    assert result["status"] == "completed"
    assert result["verdict_signal"] == "exploitable"


def test_execute_task_routes_local_contract_steps_to_sandbox_http_adapter(monkeypatch) -> None:
    project_id, task_id, target_id = str(uuid4()), str(uuid4()), str(uuid4())
    task = SandboxTaskRecord(
        id=task_id, project_id=project_id, source_module="DAST", source_task_id=str(uuid4()),
        strategy_id=str(uuid4()), status="queued", required_capabilities=["isolated_http"], callback_token="x" * 64,
        contract={
            "target": {"url": "http://target/app/useredit", "allowed_paths": ["/app/useredit"]},
            "steps": [
                {"id": "owner", "kind": "http_request", "role": "owner", "method": "GET", "url": "http://target/app/useredit", "request_id": "req-owner"},
                {"id": "assert", "kind": "assert_compare", "mode": "access_control", "left": "owner", "right": "owner"},
            ],
        },
    )
    target = SandboxTargetInstanceRecord(id=target_id, project_id=project_id, mode="docker", status="running", runtime_url="http://127.0.0.1:51065", internal_url="http://target", network_name="sandbox-net", operator="tester")
    adapters: list[str] = []
    monkeypatch.setattr(orchestrator, "capability_health", lambda: {"capabilities": {"isolated_http": {"status": "ready"}}})
    monkeypatch.setattr(orchestrator, "_run_policy_executor", lambda **kwargs: adapters.append(kwargs["adapter"]) or {"status": "completed", "evidence": [{"type": "differential", "request_id": "req-owner", "confirmed": False, "complete": True}], "verdict_signal": "not_exploitable", "verdict_reason": "bounded flow completed"})

    result = orchestrator.execute_task(FakeDb(), task, target, "tester")

    assert adapters == ["http"]
    assert result["status"] == "completed"


def test_execute_task_routes_agent_protocol_to_fixed_adapter(monkeypatch) -> None:
    project_id, task_id, target_id = str(uuid4()), str(uuid4()), str(uuid4())
    task = SandboxTaskRecord(
        id=task_id, project_id=project_id, source_module="DAST", source_task_id=str(uuid4()),
        strategy_id=str(uuid4()), status="queued", required_capabilities=["agent_runtime"], callback_token="x" * 64,
        contract={
            "target": {"url": "http://target/agent", "allowed_paths": ["/agent"]},
            "steps": [{"id": "agent", "kind": "sandbox_probe", "capability": "agent_runtime", "probe": "prompt_injection", "method": "POST", "url": "http://target/agent", "request_id": "req-agent"}],
        },
    )
    target = SandboxTargetInstanceRecord(
        id=target_id, project_id=project_id, mode="docker", status="running",
        runtime_url="http://127.0.0.1:51065", internal_url="http://target", network_name="sandbox-net", operator="tester",
    )
    adapters: list[str] = []
    monkeypatch.setattr(orchestrator, "capability_health", lambda: {"capabilities": {"agent_runtime": {"status": "ready"}}})
    monkeypatch.setattr(orchestrator, "_run_policy_executor", lambda **kwargs: adapters.append(kwargs["adapter"]) or {
        "status": "completed", "evidence": [{"type": "runtime_trace", "request_id": "req-agent", "confirmed": False, "complete": True}],
        "verdict_signal": "uncertain", "verdict_reason": "protocol executed",
    })

    result = orchestrator.execute_task(FakeDb(), task, target, "tester")

    assert result["status"] == "completed"
    assert adapters == ["agent"]


class AgentProtocolHandler(BaseHTTPRequestHandler):
    verdict = "blocked"

    def do_POST(self) -> None:
        body = json.loads(self.rfile.read(int(self.headers.get("Content-Length") or 0)))
        probe = body["_dast_probe"]
        allowed = self.__class__.verdict == "allowed"
        evidence = {
            "schema": "ai-security-platform.agent-runtime-evidence/v1",
            "request_id": probe["request_id"], "marker": probe["marker"], "complete": True,
            "policy_decision": "allowed" if allowed else "blocked",
            "untrusted_input_reached_tool": allowed,
            "tool_calls": [{
                "name": probe["synthetic_tool"], "synthetic": True, "sensitive": True,
                "boundary": "sensitive", "marker": probe["marker"],
            }] if allowed else [],
        }
        content = json.dumps({"dast_runtime_evidence": evidence}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(content)))
        self.end_headers()
        self.wfile.write(content)

    def log_message(self, *_args) -> None:
        return


def _run_agent_protocol(verdict: str) -> dict[str, object]:
    AgentProtocolHandler.verdict = verdict
    server = ThreadingHTTPServer(("127.0.0.1", 0), AgentProtocolHandler)
    Thread(target=server.serve_forever, daemon=True).start()
    target = f"http://127.0.0.1:{server.server_port}/agent"
    contract = {
        "schema": "ai-security-platform.dast-sandbox-handoff/v1",
        "isolation": {"mode": "docker", "disposable": True},
        "target": {"url": target, "allowed_paths": ["/agent"]}, "roles": [{"alias": "anonymous"}],
        "steps": [{
            "id": "agent", "kind": "sandbox_probe", "capability": "agent_runtime",
            "probe": "prompt_injection", "role": "anonymous", "method": "POST", "url": target,
            "parameter": "prompt", "request_id": "req-agent-protocol",
        }],
    }
    runner = Path(orchestrator.__file__).with_name("sandbox_agent_executor.py")
    try:
        result = subprocess.run([sys.executable, str(runner)], input=json.dumps(contract), text=True, capture_output=True, timeout=20, check=False)
    finally:
        server.shutdown()
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout)


def test_generic_agent_runtime_protocol_returns_red_and_green() -> None:
    assert _run_agent_protocol("allowed")["verdict_signal"] == "exploitable"
    assert _run_agent_protocol("blocked")["verdict_signal"] == "not_exploitable"


class UploadBoundaryHandler(BaseHTTPRequestHandler):
    reject_active = False
    stored: dict[str, tuple[bytes, str]] = {}

    def do_POST(self) -> None:
        body = self.rfile.read(int(self.headers.get("Content-Length") or 0))
        match = re.search(br'filename="([^"]+)"', body)
        filename = match.group(1).decode() if match else "unknown"
        marker_match = re.search(br"DAST_UPLOAD_[0-9a-f]+", body)
        marker = marker_match.group(0) if marker_match else b""
        if self.__class__.reject_active and filename.endswith(".html"):
            self.send_response(415)
            self.end_headers()
            return
        content_type = "text/html" if filename.endswith(".html") else "text/plain"
        self.__class__.stored[filename] = (marker, content_type)
        content = json.dumps({"url": f"/upload/{filename}"}).encode()
        self.send_response(201)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(content)))
        self.end_headers()
        self.wfile.write(content)

    def do_GET(self) -> None:
        filename = unquote(self.path.rsplit("/", 1)[-1])
        content, content_type = self.__class__.stored.get(filename, (b"", "text/plain"))
        self.send_response(200 if content else 404)
        self.send_header("Content-Type", content_type)
        self.end_headers()
        self.wfile.write(content)

    def log_message(self, *_args) -> None:
        return


def _run_file_upload_probe(*, reject_active: bool) -> dict[str, object]:
    UploadBoundaryHandler.reject_active = reject_active
    UploadBoundaryHandler.stored = {}
    server = ThreadingHTTPServer(("127.0.0.1", 0), UploadBoundaryHandler)
    Thread(target=server.serve_forever, daemon=True).start()
    target = f"http://127.0.0.1:{server.server_port}/upload"
    contract = {
        "schema": "ai-security-platform.dast-sandbox-handoff/v1",
        "isolation": {"mode": "docker", "disposable": True},
        "target": {"url": target, "allowed_paths": ["/upload"]}, "roles": [{"alias": "anonymous"}],
        "steps": [{
            "id": "upload", "kind": "sandbox_probe", "capability": "isolated_http",
            "probe": "file_upload", "role": "anonymous", "method": "POST", "url": target,
            "parameter": "file", "location": "form", "request_id": "req-upload",
        }],
    }
    runner = Path(orchestrator.__file__).with_name("sandbox_http_executor.py")
    try:
        result = subprocess.run([sys.executable, str(runner)], input=json.dumps(contract), text=True, capture_output=True, timeout=20, check=False)
    finally:
        server.shutdown()
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout)


def test_file_upload_probe_returns_green_for_enforced_extension_boundary() -> None:
    payload = _run_file_upload_probe(reject_active=True)

    assert payload["verdict_signal"] == "not_exploitable"
    assert any(item["type"] == "coverage" and item["negative_conclusion_supported"] for item in payload["evidence"])


def test_file_upload_probe_returns_red_for_public_active_content() -> None:
    payload = _run_file_upload_probe(reject_active=False)

    assert payload["verdict_signal"] == "exploitable"
    assert any(item["type"] == "differential" and item["confirmed"] for item in payload["evidence"])


def test_xss_probe_executes_unique_marker_in_isolated_browser(tmp_path: Path) -> None:
    console: list[str] = []

    class Locator:
        def evaluate_all(self, _script):
            return []

    class Response:
        status = 200

    class Page:
        url = "http://target/search"
        html = "<html></html>"

        def locator(self, _selector):
            return Locator()

        def goto(self, url, **_kwargs):
            self.url = url
            decoded = unquote(url)
            marker = next((part.split("'")[0] for part in decoded.split("DAST_XSS_")[1:]), "")
            if marker:
                token = "DAST_XSS_" + marker
                console.append(token)
                self.html = f"<html>{token}</html>"
            return Response()

        def wait_for_timeout(self, _milliseconds):
            return None

        def content(self):
            return self.html

        def screenshot(self, path, **_kwargs):
            Path(path).write_bytes(b"png")

    context = SimpleNamespace(cookies=lambda _urls: [], add_cookies=lambda _cookies: None)
    result = _execute_xss_probe(
        context, Page(),
        {"kind": "sandbox_probe", "probe": "xss", "url": "http://target/search", "method": "GET", "parameter": "q", "location": "query", "request_id": "req-xss"},
        "http://target", ["/search"], tmp_path, 1, {}, console,
    )

    assert result["status"] == "completed"
    assert result["verdict_signal"] == "exploitable"
    assert any(item["type"] == "browser" and item["confirmed"] is True for item in result["evidence"])


def test_persistent_xss_probe_returns_uncertain_when_rollback_is_not_verified(tmp_path: Path, monkeypatch) -> None:
    form = {
        "index": 0, "action": "http://target/app/useredit", "method": "POST",
        "enctype": "application/x-www-form-urlencoded",
        "fields": [
            {"name": "id", "type": "hidden", "value": "1", "checked": True, "max_length": -1},
            {"name": "email", "type": "text", "value": "original@example.invalid", "checked": True, "max_length": -1},
        ],
    }

    class Page:
        url = "http://target/app/useredit"
        marker = ""

        def goto(self, url, **_kwargs):
            self.url = url

        def wait_for_timeout(self, _milliseconds):
            return None

        def content(self):
            return f"<html>{self.marker}</html>"

        def screenshot(self, path, **_kwargs):
            Path(path).write_bytes(b"png")

    def browser_forms(_page):
        return [form]

    def submit_form(page, _form, payload, remove_names=None):
        value = str(payload.get("email") or "")
        if "DAST_XSS_" in value:
            page.marker = value
        return {"status": 200, "headers": {}, "set_cookie_headers": [], "body": b"", "duration_ms": 1}

    monkeypatch.setattr(browser_executor, "_browser_forms", browser_forms)
    monkeypatch.setattr(browser_executor, "_submit_dom_form", submit_form)
    context = SimpleNamespace(cookies=lambda _urls: [], add_cookies=lambda _cookies: None)

    result = _execute_xss_probe(
        context, Page(),
        {"kind": "sandbox_probe", "probe": "xss", "url": "http://target/app/admin/users", "setup_url": "http://target/app/useredit", "setup_method": "POST", "parameter": "email", "location": "form_field", "request_id": "req-xss"},
        "http://target", ["/app/useredit", "/app/admin/users"], tmp_path, 1, {}, [],
    )

    assert result["status"] == "completed"
    assert result["verdict_signal"] == "uncertain"
    browser = next(item for item in result["evidence"] if item["type"] == "browser")
    assert browser["exchange"]["rollback_verified"] is False


def test_csrf_browser_probe_executes_three_variants_and_rolls_back(tmp_path: Path, monkeypatch) -> None:
    state = {"name": "Original Name"}

    class Locator:
        def evaluate_all(self, _script):
            return [{
                "index": 0, "action": "http://target/app/useredit", "method": "POST",
                "enctype": "application/x-www-form-urlencoded",
                "fields": [
                    {"name": "_csrf", "type": "hidden", "value": "fresh-token", "checked": True, "max_length": -1},
                    {"name": "id", "type": "hidden", "value": "1", "checked": True, "max_length": -1},
                    {"name": "name", "type": "text", "value": state["name"], "checked": True, "max_length": 80},
                ],
            }]

    class Page:
        url = "http://target/app/useredit"

        def locator(self, _selector):
            return Locator()

        def goto(self, url, **_kwargs):
            self.url = url

        def screenshot(self, path, **_kwargs):
            Path(path).write_bytes(b"png")

    def post_form(_url, payload, headers=None):
        # Vulnerable fixture: the authenticated state-changing endpoint ignores
        # missing/invalid tokens. Valid control and rollback therefore work too.
        state["name"] = payload["name"]
        return {"status": 200, "headers": {}, "set_cookie_headers": [], "body": b"ok", "duration_ms": 1}

    monkeypatch.setattr(browser_executor, "_http_post_form", post_form)
    context = SimpleNamespace(cookies=lambda _urls: [], add_cookies=lambda _cookies: None)
    result = _execute_csrf_probe(
        context, Page(),
        {"url": "http://target/app/useredit", "parameters": ["id", "name"], "request_id": "request-csrf"},
        "http://target", ["/app/useredit"], tmp_path, 1, {},
    )

    assert result["status"] == "completed"
    assert result["verdict_signal"] == "exploitable"
    assert state["name"] == "Original Name"
    differential = next(item for item in result["evidence"] if item["type"] == "differential")
    assert differential["confirmed"] is True
    assert len(differential["exchange"]["variants"]) == 3
    assert differential["exchange"]["rollback_verified"] is True


def test_startup_diagnostic_classifies_and_redacts_secret() -> None:
    diagnostic = orchestrator.diagnose_startup_failure("Module not found; token=super-secret", stage="target_container")

    assert diagnostic["code"] == "dependency_or_entrypoint"
    assert "super-secret" not in diagnostic["detail"]
    assert diagnostic["remediation"]


def test_browser_har_redaction_removes_credentials_and_query_values(tmp_path: Path) -> None:
    har = tmp_path / "network.har"
    har.write_text(json.dumps({"log": {"entries": [{"request": {
        "headers": [{"name": "Authorization", "value": "Bearer must-not-leak"}],
        "cookies": [{"name": "session", "value": "must-not-leak"}],
        "queryString": [{"name": "token", "value": "must-not-leak"}],
    }}]}}), encoding="utf-8")

    _redact_har(har)

    content = har.read_text(encoding="utf-8")
    assert "must-not-leak" not in content
    assert content.count("[REDACTED]") == 3
