from __future__ import annotations

import json
import subprocess
import sys
from hashlib import sha256
from pathlib import Path
from types import SimpleNamespace
from uuid import uuid4

import pytest
from fastapi import HTTPException

from app.models import AgentMcpProbeRuntimeRequest
from app.routers import agent as agent_router
from app.services import agent_mcp_probe_runtime as probe_runtime
from app.services import agent_target_runtime as target_runtime
from app.services.agent_staging import build_filtered_staging, load_filtered_staging_manifest


IMAGE = "python@sha256:" + "a" * 64
CONTAINER_ID = "b" * 64
PLAN_SHA256 = "c" * 64
SCAN_ID = "scan-1"


def completed(returncode: int = 0, stdout: str = "", stderr: str = "") -> SimpleNamespace:
    return SimpleNamespace(returncode=returncode, stdout=stdout, stderr=stderr)


def build_staging(tmp_path: Path, config: dict[str, object] | None = None) -> dict[str, object]:
    source = tmp_path / "source"
    source.mkdir()
    (source / ".mcp.json").write_text(json.dumps(config or {
        "mcpServers": {"calculator": {
            "command": "python", "args": ["-I", "-B", "mcp_server.py"], "transport": "stdio",
        }},
    }), encoding="utf-8")
    (source / "mcp_server.py").write_text("print('fixture')\n", encoding="utf-8")
    return build_filtered_staging(
        source_path=str(source), project_id="project-1",
        destination_root=tmp_path / "staging" / "project-1",
        binding={
            "scan_task_id": SCAN_ID, "plan_sha256": PLAN_SHA256,
            "command_sha256": sha256(b"python app.py").hexdigest(),
            "image": IMAGE, "timeout_seconds": 5,
        },
    )


def probe_result_line() -> str:
    result: dict[str, object] = {
        "schema": probe_runtime.MCP_PROBE_RESULT_SCHEMA,
        "probe_version": "1.0.0", "status": "success",
        "protocol_version": "2025-06-18", "server_name": "bounded-server",
        "server_version": "1.0.0", "tool_names": ["bounded_add"],
        "resource_schemes": ["fixture"], "prompt_names": ["add-two-integers"],
        "method_outcomes": {
            "initialize": "success", "tools/list": "success",
            "resources/list": "success", "prompts/list": "success",
        },
        "observer_exit_code": 0, "error_code": None,
        "content_actions_performed": False, "content_stored": False,
    }
    result["result_sha256"] = probe_runtime.canonical_sha256(result)
    return probe_runtime.MCP_PROBE_PREFIX + json.dumps(result) + "\n"


def inspect_payload(staging: Path, observer: Path, probe_tokens: list[str]) -> dict[str, object]:
    return {
        "Config": {
            "Image": IMAGE, "Entrypoint": [probe_tokens[0]], "Cmd": probe_tokens[1:],
            "User": "65534:65534", "Env": ["PATH=/usr/local/bin"],
            "Healthcheck": {"Test": ["NONE"]},
        },
        "HostConfig": {
            "NetworkMode": "none", "ReadonlyRootfs": True, "CapDrop": ["ALL"],
            "SecurityOpt": ["no-new-privileges:true"], "Privileged": False,
            "NanoCpus": 500_000_000, "Memory": 256 * 1024 * 1024, "PidsLimit": 64,
            "Tmpfs": {"/tmp": "rw,noexec,nosuid,size=32m"}, "IpcMode": "none", "PidMode": "",
            "LogConfig": {"Type": "local", "Config": {"max-size": "1m", "max-file": "1", "compress": "false"}},
        },
        "Mounts": [
            {"Source": str(staging), "Destination": "/workspace", "RW": False},
            {"Source": str(observer), "Destination": "/opt/agent-observer", "RW": False},
        ],
        "State": {"ExitCode": 0},
    }


def test_candidate_discovery_is_staging_bound_and_hides_command_tokens(tmp_path: Path, monkeypatch) -> None:
    staging = build_staging(tmp_path)
    path = Path(str(staging["destination_path"]))
    candidates = probe_runtime.discover_stdio_candidates(path, load_filtered_staging_manifest(path))
    monkeypatch.setattr(probe_runtime, "resolve_staging_root", lambda project_id: path.parent)

    status = probe_runtime.list_mcp_probe_status("project-1", SCAN_ID, True)

    assert candidates[0]["eligible"] is True
    assert candidates[0]["server_name"] == "calculator"
    assert candidates[0]["command_preview"] == "python -I -B mcp_server.py"
    assert status["builds"][0]["candidates"][0]["candidate_id"] == candidates[0]["candidate_id"]
    assert "_command_tokens" not in status["builds"][0]["candidates"][0]


def test_candidate_with_environment_or_remote_transport_is_rejected(tmp_path: Path) -> None:
    staging = build_staging(tmp_path, {"mcpServers": {
        "secret-server": {"command": "python", "args": ["server.py"], "env": {"TOKEN": "hidden"}},
        "remote-server": {"url": "https://example.invalid/mcp", "transport": "streamable-http"},
    }})
    path = Path(str(staging["destination_path"]))
    candidates = probe_runtime.discover_stdio_candidates(path, load_filtered_staging_manifest(path))
    by_name = {item["server_name"]: item for item in candidates}

    assert by_name["secret-server"]["eligible"] is False
    assert "no_configured_environment" in by_name["secret-server"]["rejection_reasons"]
    assert by_name["remote-server"]["eligible"] is False
    assert "stdio_transport" in by_name["remote-server"]["rejection_reasons"]
    assert "hidden" not in json.dumps(candidates)


def test_probe_asset_discovers_inventory_without_content_actions() -> None:
    root = Path(target_runtime.__file__).with_name("runtime_assets")
    probe = root / "mcp_capability_probe.py"
    observer = root / "mcp_stdio_observer.py"
    server = Path(__file__).parent / "fixtures" / "agent_runtime_mcp" / "mcp_server.py"

    result = subprocess.run(
        [sys.executable, "-I", "-B", str(probe), "--observer", str(observer),
         "--ledger-fd-path", "-", "--", sys.executable, "-I", "-B", str(server)],
        capture_output=True, text=True, timeout=10, check=False,
    )
    parsed, _, clean_stderr = probe_runtime.extract_probe_result("", result.stderr)

    assert result.returncode == 0
    assert clean_stderr == ""
    assert parsed["status"] == "success"
    assert parsed["tool_names"] == ["bounded_add"]
    assert parsed["resource_schemes"] == ["fixture"]
    assert parsed["prompt_names"] == ["add-two-integers"]
    assert parsed["content_actions_performed"] is False


def test_mcp_probe_validation_uses_fixed_probe_and_emits_evidence(tmp_path: Path, monkeypatch) -> None:
    staging = build_staging(tmp_path)
    staging_path = Path(str(staging["destination_path"]))
    manifest = load_filtered_staging_manifest(staging_path)
    candidate = probe_runtime.discover_stdio_candidates(staging_path, manifest)[0]
    observer_path, _ = target_runtime.resolve_observer_asset()
    probe_tokens = [
        "python", "-I", "-B", "/opt/agent-observer/mcp_capability_probe.py",
        "--observer", "/opt/agent-observer/mcp_stdio_observer.py",
        "--timeout-seconds", "5", "--", "python", "-I", "-B", "mcp_server.py",
    ]
    inspected = inspect_payload(staging_path, observer_path, probe_tokens)
    commands: list[list[str]] = []
    monkeypatch.setattr(target_runtime, "staging_workspace_path", lambda project_id: staging_path.parent)
    monkeypatch.setattr(probe_runtime, "docker_executable", lambda: "docker")
    monkeypatch.setattr(
        probe_runtime, "write_mcp_probe_evidence",
        lambda project_id, execution_id, evidence: tmp_path / "mcp-probe-evidence.json",
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
            return completed(stderr=probe_result_line())
        raise AssertionError(command)

    evidence = probe_runtime.run_mcp_probe_validation(
        project_id="project-1", scan_task_id=SCAN_ID, image=IMAGE, timeout_seconds=5,
        plan_sha256=PLAN_SHA256, staging_build_id=str(staging["build_id"]),
        staging_sha256=str(staging["staging_sha256"]), manifest_sha256=str(staging["manifest_sha256"]),
        candidate_id=str(candidate["candidate_id"]),
        authorization_phrase=probe_runtime.MCP_PROBE_AUTHORIZATION_PHRASE,
        operator_confirmed=True, run_command=fake_run,
    )

    assert evidence["decision"] == "pass"
    assert evidence["policy_verified"] is True
    assert evidence["capability_probe"]["tool_names"] == ["bounded_add"]
    assert evidence["output"]["content_stored"] is False
    assert evidence["container"]["removed_after_run"] is True
    create = next(item for item in commands if item[1] == "create")
    assert "/opt/agent-observer/mcp_capability_probe.py" in create
    assert not any(item[1:2] == ["pull"] for item in commands)


def test_mcp_probe_requires_separate_confirmation_before_docker(tmp_path: Path) -> None:
    called = False

    def fake_run(command, **kwargs):
        nonlocal called
        called = True
        return completed()

    with pytest.raises(target_runtime.TargetRuntimeRejected, match="separate authorization phrase"):
        probe_runtime.run_mcp_probe_validation(
            project_id="project-1", scan_task_id=SCAN_ID, image=IMAGE, timeout_seconds=5,
            plan_sha256=PLAN_SHA256, staging_build_id="missing", staging_sha256="d" * 64,
            manifest_sha256="e" * 64, candidate_id="f" * 24,
            authorization_phrase="", operator_confirmed=False, run_command=fake_run,
        )
    assert called is False


def test_mcp_probe_endpoint_is_disabled_by_default(monkeypatch) -> None:
    called = False
    monkeypatch.setattr(agent_router, "require_agent_fixture_modules", lambda db, project_id: None)
    monkeypatch.setattr(
        agent_router, "enabled_agent_module",
        lambda db, project_id: SimpleNamespace(config={}),
    )

    def unexpected_run(**kwargs):
        nonlocal called
        called = True

    monkeypatch.setattr(agent_router, "run_mcp_probe_validation", unexpected_run)
    request = AgentMcpProbeRuntimeRequest(
        image=IMAGE, timeout_seconds=5, plan_sha256=PLAN_SHA256,
        staging_build_id="build-1", staging_sha256="d" * 64,
        manifest_sha256="e" * 64, candidate_id="f" * 24,
        authorization_phrase=probe_runtime.MCP_PROBE_AUTHORIZATION_PHRASE,
        operator_confirmed=True,
    )

    with pytest.raises(HTTPException) as exc:
        agent_router.validate_project_agent_mcp_probe(uuid4(), request, SimpleNamespace())

    assert exc.value.status_code == 403
    assert called is False
