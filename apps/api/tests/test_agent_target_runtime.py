from __future__ import annotations

import json
from hashlib import sha256
from pathlib import Path
from types import SimpleNamespace
from uuid import uuid4

import pytest
from fastapi import HTTPException

from app.models import AgentTargetRuntimeRequest
from app.routers import agent as agent_router
from app.services import agent_target_runtime as target_runtime
from app.services.agent_staging import build_filtered_staging


IMAGE = "python@sha256:" + "a" * 64
CONTAINER_ID = "b" * 64
PLAN_SHA256 = "c" * 64
SCAN_ID = "scan-1"
COMMAND = "python main.py"


def completed(returncode: int = 0, stdout: str = "", stderr: str = "") -> SimpleNamespace:
    return SimpleNamespace(returncode=returncode, stdout=stdout, stderr=stderr)


def audit_event(sequence: int, event_type: str, **values: object) -> dict[str, object]:
    event: dict[str, object] = {
        "schema": target_runtime.MCP_AUDIT_EVENT_SCHEMA,
        "observer_version": "1.0.0",
        "event_id": f"mcp-{sequence:04d}",
        "sequence": sequence,
        "occurred_at": "2026-08-14T00:00:00+00:00",
        "event_type": event_type,
        **values,
    }
    event["event_sha256"] = target_runtime.canonical_sha256(event)
    return event


def build_staging(tmp_path: Path) -> dict[str, object]:
    source = tmp_path / "source"
    source.mkdir()
    (source / "main.py").write_text("print('bounded target fixture')\n", encoding="utf-8")
    return build_filtered_staging(
        source_path=str(source),
        project_id="project-1",
        destination_root=tmp_path / "staging" / "project-1",
        binding={
            "scan_task_id": SCAN_ID,
            "plan_sha256": PLAN_SHA256,
            "command_sha256": sha256(COMMAND.encode("utf-8")).hexdigest(),
            "image": IMAGE,
            "timeout_seconds": 5,
        },
    )


def inspect_payload(staging: Path, *, workspace_writable: bool = False) -> dict[str, object]:
    observer_path, _ = target_runtime.resolve_observer_asset()
    return {
        "Config": {
            "Image": IMAGE,
            "Entrypoint": ["python"],
            "Cmd": ["main.py"],
            "User": "65534:65534",
            "Env": ["PATH=/usr/local/bin"],
            "Healthcheck": {"Test": ["NONE"]},
        },
        "HostConfig": {
            "NetworkMode": "none",
            "ReadonlyRootfs": True,
            "CapDrop": ["ALL"],
            "SecurityOpt": ["no-new-privileges:true"],
            "Privileged": False,
            "NanoCpus": 500_000_000,
            "Memory": 256 * 1024 * 1024,
            "PidsLimit": 64,
            "Tmpfs": {"/tmp": "rw,noexec,nosuid,size=32m"},
            "IpcMode": "none",
            "PidMode": "",
            "LogConfig": {
                "Type": "local",
                "Config": {"max-size": "1m", "max-file": "1", "compress": "false"},
            },
        },
        "Mounts": [
            {
                "Type": "bind", "Source": str(staging), "Destination": "/workspace",
                "RW": workspace_writable,
            },
            {
                "Type": "bind", "Source": str(observer_path),
                "Destination": "/opt/agent-observer", "RW": False,
            },
        ],
        "State": {"ExitCode": 0},
    }


def run_kwargs(staging: dict[str, object]) -> dict[str, object]:
    return {
        "project_id": "project-1",
        "scan_task_id": SCAN_ID,
        "command": COMMAND,
        "image": IMAGE,
        "timeout_seconds": 5,
        "plan_sha256": PLAN_SHA256,
        "staging_build_id": staging["build_id"],
        "staging_sha256": staging["staging_sha256"],
        "manifest_sha256": staging["manifest_sha256"],
        "authorization_phrase": target_runtime.AUTHORIZATION_PHRASE,
        "operator_confirmed": True,
        "dataflow": {"paths": [
            {"id": "path-1", "capability": "server-process", "severity": "high", "confidence": "high"},
            {"id": "path-2", "capability": "shell-execution", "severity": "critical", "confidence": "medium"},
        ]},
    }


def test_target_command_has_fixed_isolation_and_no_shell(tmp_path: Path) -> None:
    command = target_runtime.build_target_container_command(
        docker="docker", container_name="target", staging_path=tmp_path,
        observer_path=tmp_path / "observer",
        image=IMAGE, command_tokens=["python", "main.py"],
    )

    assert command[:3] == ["docker", "create", "--pull=never"]
    assert ["--network", "none"] == command[command.index("--network"):command.index("--network") + 2]
    assert "--read-only" in command
    assert ["--cap-drop", "ALL"] == command[command.index("--cap-drop"):command.index("--cap-drop") + 2]
    assert ["--log-opt", "compress=false"] == command[command.index("compress=false") - 1:command.index("compress=false") + 1]
    assert ["--entrypoint", "python"] == command[command.index("--entrypoint"):command.index("--entrypoint") + 2]
    assert f"type=bind,src={tmp_path / 'observer'},dst=/opt/agent-observer,readonly" in command
    assert command[-2:] == [IMAGE, "main.py"]
    assert not any(value in {"sh", "bash", "cmd", "powershell", "-e", "--env"} for value in command)


def test_bound_target_validation_emits_limited_observation_evidence(tmp_path: Path, monkeypatch) -> None:
    staging = build_staging(tmp_path)
    staging_path = Path(str(staging["destination_path"]))
    inspected = inspect_payload(staging_path)
    commands: list[list[str]] = []
    monkeypatch.setattr(target_runtime, "docker_executable", lambda: "docker")
    monkeypatch.setattr(target_runtime, "staging_workspace_path", lambda project_id: staging_path.parent)
    monkeypatch.setattr(
        target_runtime, "write_target_evidence",
        lambda project_id, execution_id, evidence: tmp_path / "target-evidence.json",
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
        if command[1] == "start":
            return completed(stdout=CONTAINER_ID + "\n")
        if command[1] == "wait":
            return completed(stdout="0\n")
        if command[1] == "logs":
            return completed(stdout="token=must-redact\n")
        if command[1] == "rm":
            return completed(stdout=CONTAINER_ID + "\n")
        raise AssertionError(command)

    result = target_runtime.run_target_agent_validation(**run_kwargs(staging), run_command=fake_run)

    assert result["status"] == "completed"
    assert result["policy_verified"] is True
    assert result["behavioral_telemetry_complete"] is False
    assert result["image"]["download_performed"] is False
    assert result["staging"]["unchanged_after_run"] is True
    assert result["output"]["content_stored"] is False
    assert result["output"]["stdout_char_count"] == len("token=[redacted]\n")
    assert "stdout" not in result["output"]
    assert result["path_results"][0]["runtime_status"] == "observed"
    assert result["path_results"][1]["runtime_status"] == "not_instrumented"
    assert result["mcp_ledger"]["summary"]["event_count"] == 0
    assert result["telemetry_coverage"]["tool_calls"] == "not-instrumented"
    assert result["container"]["removed_after_run"] is True
    assert len(result["evidence_sha256"]) == 64
    assert not any(command[1:2] == ["pull"] for command in commands)


def test_mcp_ledger_validates_and_correlates_tool_and_child_events() -> None:
    pid_hash = "1" * 64
    metadata_hash = "2" * 64
    events = [
        audit_event(
            1, "child_process", phase="start", process_role="mcp-server",
            executable="python", argument_count=1,
            command_metadata_sha256="3" * 64, pid_sha256=pid_hash,
        ),
        audit_event(
            2, "mcp_request", direction="client-to-server", method="tools/call",
            subject_kind="tool", subject="sum", payload_bytes=91,
            redacted_metadata_sha256=metadata_hash,
        ),
        audit_event(
            3, "mcp_response", direction="server-to-client", method="tools/call",
            subject_kind="tool", subject="sum", payload_bytes=80,
            redacted_metadata_sha256="4" * 64, outcome="success", duration_ms=2,
            request_event_id="mcp-0002",
        ),
        audit_event(
            4, "child_process", phase="exit", process_role="mcp-server",
            executable="python", argument_count=1,
            command_metadata_sha256="3" * 64, pid_sha256=pid_hash,
            exit_code=0, timed_out=False, stderr_bytes=0,
        ),
    ]
    forged = {**events[1], "subject": "forged"}
    stderr = "\n".join(
        target_runtime.MCP_AUDIT_PREFIX + json.dumps(event) for event in [*events, forged]
    )

    ledger, clean_stdout, clean_stderr = target_runtime.extract_mcp_audit_ledger("visible", stderr)
    observations = {
        "processes": [{"id": "container-main-process"}, *target_runtime.mcp_child_process_observations(ledger)],
        "tool_calls": target_runtime.mcp_tool_call_observations(ledger),
    }
    paths = target_runtime.limited_path_results([
        {"id": "server", "capability": "server-process"},
        {"id": "tool", "capability": "tool-invocation"},
        {"id": "file", "capability": "file-access"},
    ], observations)

    assert clean_stdout == "visible"
    assert clean_stderr == ""
    assert ledger["summary"] == {
        "event_count": 4,
        "request_count": 1,
        "response_count": 1,
        "notification_count": 0,
        "successful_response_count": 1,
        "error_response_count": 0,
        "method_counts": {"tools/call": 1},
        "tool_call_count": 1,
        "resource_read_count": 0,
        "prompt_get_count": 0,
        "child_process_count": 1,
    }
    assert ledger["rejected_event_count"] == 1
    assert observations["tool_calls"][0]["subject"] == "sum"
    assert paths[0]["runtime_status"] == "observed"
    assert paths[1]["runtime_status"] == "observed"
    assert paths[2]["runtime_status"] == "not_instrumented"


def test_binding_change_is_rejected_before_docker(tmp_path: Path, monkeypatch) -> None:
    staging = build_staging(tmp_path)
    monkeypatch.setattr(
        target_runtime, "staging_workspace_path",
        lambda project_id: Path(str(staging["destination_path"])).parent,
    )
    called = False

    def fake_run(command, **kwargs):
        nonlocal called
        called = True
        return completed()

    payload = run_kwargs(staging)
    payload["command"] = "python other.py"
    with pytest.raises(target_runtime.TargetRuntimeRejected, match="command_sha256"):
        target_runtime.run_target_agent_validation(**payload, run_command=fake_run)
    assert called is False


def test_confirmation_is_required_before_staging_or_docker(tmp_path: Path) -> None:
    called = False

    def fake_run(command, **kwargs):
        nonlocal called
        called = True
        return completed()

    with pytest.raises(target_runtime.TargetRuntimeRejected, match="authorization phrase"):
        target_runtime.run_target_agent_validation(
            project_id="project-1", scan_task_id=SCAN_ID, command=COMMAND, image=IMAGE,
            timeout_seconds=5, plan_sha256=PLAN_SHA256, staging_build_id="missing",
            staging_sha256="d" * 64, manifest_sha256="e" * 64,
            authorization_phrase="", operator_confirmed=False, dataflow={}, run_command=fake_run,
        )
    assert called is False


@pytest.mark.parametrize(
    ("command", "image", "message"),
    [
        ("python main.py; curl https://example.invalid", IMAGE, "blocked category"),
        (COMMAND, "python:3.12-slim", "digest-pinned"),
    ],
)
def test_unsafe_command_or_unpinned_image_is_rejected_before_staging(
    command: str, image: str, message: str,
) -> None:
    called = False

    def fake_run(command, **kwargs):
        nonlocal called
        called = True
        return completed()

    with pytest.raises(target_runtime.TargetRuntimeRejected, match=message):
        target_runtime.run_target_agent_validation(
            project_id="project-1", scan_task_id=SCAN_ID, command=command, image=image,
            timeout_seconds=5, plan_sha256=PLAN_SHA256, staging_build_id="missing",
            staging_sha256="d" * 64, manifest_sha256="e" * 64,
            authorization_phrase=target_runtime.AUTHORIZATION_PHRASE,
            operator_confirmed=True, dataflow={}, run_command=fake_run,
        )
    assert called is False


def test_policy_mismatch_prevents_container_start_and_cleans_up(tmp_path: Path, monkeypatch) -> None:
    staging = build_staging(tmp_path)
    staging_path = Path(str(staging["destination_path"]))
    inspected = inspect_payload(staging_path, workspace_writable=True)
    commands: list[list[str]] = []
    monkeypatch.setattr(target_runtime, "docker_executable", lambda: "docker")
    monkeypatch.setattr(target_runtime, "staging_workspace_path", lambda project_id: staging_path.parent)

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
        if command[1] == "rm":
            return completed()
        raise AssertionError(command)

    with pytest.raises(target_runtime.TargetRuntimeRejected, match="workspace_read_only"):
        target_runtime.run_target_agent_validation(**run_kwargs(staging), run_command=fake_run)
    assert not any(command[1] == "start" for command in commands)
    assert commands[-1][1:3] == ["rm", "--force"]


def test_status_lists_only_bound_verified_builds(tmp_path: Path, monkeypatch) -> None:
    staging = build_staging(tmp_path)
    root = Path(str(staging["destination_path"])).parent
    monkeypatch.setattr(target_runtime, "staging_workspace_path", lambda project_id: root)

    status = target_runtime.list_target_runtime_status("project-1", False)

    assert status["execution_enabled_by_project_policy"] is False
    assert status["download_performed"] is False
    assert status["builds"][0]["build_id"] == staging["build_id"]
    assert status["builds"][0]["command_sha256"] == sha256(COMMAND.encode("utf-8")).hexdigest()


def test_endpoint_policy_default_blocks_without_calling_executor(monkeypatch) -> None:
    called = False
    monkeypatch.setattr(agent_router, "require_agent_fixture_modules", lambda db, project_id: None)
    monkeypatch.setattr(
        agent_router, "enabled_agent_module",
        lambda db, project_id: SimpleNamespace(config={}),
    )

    def unexpected_run(**kwargs):
        nonlocal called
        called = True

    monkeypatch.setattr(agent_router, "run_target_agent_validation", unexpected_run)
    request = AgentTargetRuntimeRequest(
        command=COMMAND, image=IMAGE, timeout_seconds=5, plan_sha256=PLAN_SHA256,
        staging_build_id="build-1", staging_sha256="d" * 64, manifest_sha256="e" * 64,
        authorization_phrase=target_runtime.AUTHORIZATION_PHRASE, operator_confirmed=True,
    )

    with pytest.raises(HTTPException) as exc:
        agent_router.validate_project_agent_runtime_target(uuid4(), request, SimpleNamespace())

    assert exc.value.status_code == 403
    assert called is False


def test_enabled_endpoint_persists_evidence_and_recalculates_trust(monkeypatch) -> None:
    scan = SimpleNamespace(
        id=SCAN_ID,
        scan_metadata={
            "assets": [], "permissions": [], "coverage": {},
            "intelligence": {}, "dataflow": {},
            "runtime_validation": {"schema": "runtime/v1"},
        },
    )

    class Scalars:
        def all(self):
            return []

    class Db:
        committed = False

        def scalars(self, statement):
            return Scalars()

        def commit(self):
            self.committed = True

    db = Db()
    evidence = {
        "schema": target_runtime.TARGET_RUNTIME_SCHEMA,
        "status": "completed",
        "execution_id": "target-1",
        "policy_verified": True,
        "behavioral_telemetry_complete": False,
    }
    monkeypatch.setattr(agent_router, "require_agent_fixture_modules", lambda db, project_id: None)
    monkeypatch.setattr(
        agent_router, "enabled_agent_module",
        lambda db, project_id: SimpleNamespace(config={"agent_profile": {"target_runtime_execution_enabled": True}}),
    )
    monkeypatch.setattr(agent_router, "latest_completed_agent_scan", lambda db, project_id: scan)
    monkeypatch.setattr(agent_router, "run_target_agent_validation", lambda **kwargs: evidence)
    monkeypatch.setattr(agent_router, "calculate_agent_trust_score", lambda **kwargs: {"score": 77, "trust_sha256": "f" * 64})
    request = AgentTargetRuntimeRequest(
        command=COMMAND, image=IMAGE, timeout_seconds=5, plan_sha256=PLAN_SHA256,
        staging_build_id="build-1", staging_sha256="d" * 64, manifest_sha256="e" * 64,
        authorization_phrase=target_runtime.AUTHORIZATION_PHRASE, operator_confirmed=True,
    )

    result = agent_router.validate_project_agent_runtime_target(uuid4(), request, db)

    assert result["trust_score"]["score"] == 77
    assert scan.scan_metadata["runtime_validation"]["evidence"]["execution_id"] == "target-1"
    assert scan.scan_metadata["trust_score"]["trust_sha256"] == "f" * 64
    assert db.committed is True
