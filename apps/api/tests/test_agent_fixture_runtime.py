import json
from pathlib import Path
from types import SimpleNamespace
from uuid import uuid4

import pytest
from fastapi import HTTPException

from app.models import AgentFixtureRuntimeRequest
from app.routers import agent as agent_router
from app.services import agent_fixture_runtime as fixture_runtime


IMAGE = "python@sha256:" + "a" * 64
CONTAINER_ID = "b" * 64


def completed(returncode: int = 0, stdout: str = "", stderr: str = "") -> SimpleNamespace:
    return SimpleNamespace(returncode=returncode, stdout=stdout, stderr=stderr)


def inspect_payload(staging: Path) -> dict[str, object]:
    return {
        "Config": {
            "Image": IMAGE,
            "Cmd": fixture_runtime.FIXED_CONTAINER_COMMAND,
            "User": "65534:65534",
            "Env": ["PATH=/usr/local/bin"],
        },
        "HostConfig": {
            "NetworkMode": "none",
            "ReadonlyRootfs": True,
            "CapDrop": ["ALL"],
            "SecurityOpt": ["no-new-privileges:true"],
            "Privileged": False,
            "NanoCpus": 500_000_000,
            "Memory": 128 * 1024 * 1024,
            "PidsLimit": 32,
            "Tmpfs": {"/tmp": "rw,noexec,nosuid,size=16m"},
        },
        "Mounts": [{"Type": "bind", "Source": str(staging), "Destination": "/workspace", "RW": False}],
        "State": {"ExitCode": 0},
    }


def probe_output() -> str:
    return json.dumps({
        "schema": "ai-security-platform.agent-fixture-probe/v1",
        "fixture": "harmless-offline-fixture",
        "checks": {
            "root_filesystem_write_blocked": True,
            "workspace_write_blocked": True,
            "network_egress_blocked": True,
            "host_canary_absent": True,
            "effective_capabilities_zero": True,
            "no_new_privileges_enabled": True,
            "tmpfs_write_succeeded": True,
        },
        "cgroup": {"cpu_max": "50000 100000", "memory_max": str(128 * 1024 * 1024), "pids_max": "32"},
        "secret_values_returned": False,
    }) + "\n"


def test_fixed_container_command_has_all_mandatory_controls(tmp_path: Path) -> None:
    command = fixture_runtime.build_fixture_container_command(
        docker="docker",
        container_name="fixture-name",
        staging_path=tmp_path,
        image=IMAGE,
    )

    assert command[:3] == ["docker", "create", "--pull=never"]
    assert ["--network", "none"] == command[command.index("--network"):command.index("--network") + 2]
    assert "--read-only" in command
    assert ["--cap-drop", "ALL"] == command[command.index("--cap-drop"):command.index("--cap-drop") + 2]
    assert ["--security-opt", "no-new-privileges:true"] == command[command.index("--security-opt"):command.index("--security-opt") + 2]
    assert ["--user", "65534:65534"] == command[command.index("--user"):command.index("--user") + 2]
    assert not any("docker.sock" in value for value in command)
    assert not any(value in {"-e", "--env", "--env-file"} for value in command)
    assert command[-5:] == [IMAGE, *fixture_runtime.FIXED_CONTAINER_COMMAND]


def test_local_image_discovery_never_pulls(monkeypatch) -> None:
    commands: list[list[str]] = []
    monkeypatch.setattr(fixture_runtime, "docker_executable", lambda: "docker")

    def fake_run(command, **kwargs):
        commands.append(command)
        if command[1:3] == ["context", "inspect"]:
            return completed(stdout=json.dumps("npipe:////./pipe/dockerDesktopLinuxEngine"))
        return completed(stdout=json.dumps({
            "Repository": "python", "Digest": "sha256:" + "a" * 64,
            "ID": "abc", "Size": "179MB",
        }) + "\n")

    result = fixture_runtime.list_local_fixture_images(fake_run)

    assert result["available"] is True
    assert result["recommended_image"] == IMAGE
    assert result["download_performed"] is False
    assert commands == [
        ["docker", "context", "inspect", "--format", "{{json .Endpoints.docker.Host}}"],
        ["docker", "image", "ls", "python", "--digests", "--format", "{{json .}}"],
    ]


def test_fixture_validation_uses_fixed_policy_and_emits_pass(tmp_path: Path, monkeypatch) -> None:
    staging = tmp_path / "staging-build"
    staging.mkdir()
    commands: list[list[str]] = []
    environments: list[dict[str, str]] = []
    inspected = inspect_payload(staging)
    monkeypatch.setattr(fixture_runtime, "docker_executable", lambda: "docker")
    monkeypatch.setattr(fixture_runtime, "build_filtered_staging", lambda **kwargs: {
        "destination_path": str(staging),
        "staging_sha256": "c" * 64,
        "manifest_sha256": "d" * 64,
        "verification": {"status": "verified"},
    })
    monkeypatch.setattr(fixture_runtime, "write_fixture_evidence", lambda project_id, run_id, evidence: tmp_path / "evidence.json")

    def fake_run(command, **kwargs):
        commands.append(command)
        if "env" in kwargs:
            environments.append(kwargs["env"])
        if command[1:3] == ["context", "inspect"]:
            return completed(stdout=json.dumps("npipe:////./pipe/dockerDesktopLinuxEngine"))
        if command[1:3] == ["image", "inspect"]:
            return completed(stdout=json.dumps([{"Id": "sha256:" + "e" * 64}]))
        if command[1] == "create":
            return completed(stdout=CONTAINER_ID + "\n")
        if command[1:3] == ["container", "inspect"]:
            return completed(stdout=json.dumps([inspected]))
        if command[1] == "start":
            return completed(stdout=probe_output())
        if command[1] == "rm":
            return completed(stdout=CONTAINER_ID + "\n")
        raise AssertionError(command)

    result = fixture_runtime.run_harmless_fixture_validation(
        project_id="project-1", image=IMAGE, run_command=fake_run,
    )

    assert result["decision"] == "pass"
    assert result["execution_enabled_for_real_agents"] is False
    assert all(result["policy_checks"].values())
    assert result["image"]["download_performed"] is False
    assert result["container"]["removed_after_run"] is True
    assert result["staging"]["staging_sha256"] == "c" * 64
    assert all(environment["AGENT_HOST_CANARY"] == "present-on-host-cli-only" for environment in environments)
    assert not any("pull" in command[1:2] for command in commands)
    assert commands[-1][1:3] == ["rm", "--force"]


def test_unpinned_or_non_python_image_is_rejected_before_docker(monkeypatch) -> None:
    called = False

    def fake_run(command, **kwargs):
        nonlocal called
        called = True
        return completed()

    with pytest.raises(fixture_runtime.FixtureRuntimeRejected, match="python@sha256"):
        fixture_runtime.run_harmless_fixture_validation(
            project_id="project-1", image="python:3.12-slim", run_command=fake_run,
        )
    with pytest.raises(fixture_runtime.FixtureRuntimeRejected, match="python@sha256"):
        fixture_runtime.run_harmless_fixture_validation(
            project_id="project-1", image="node@sha256:" + "a" * 64, run_command=fake_run,
        )
    assert called is False


def test_policy_evaluation_fails_closed_on_writable_workspace(tmp_path: Path) -> None:
    payload = inspect_payload(tmp_path)
    payload["Mounts"][0]["RW"] = True

    checks = fixture_runtime.configured_policy_checks(payload, tmp_path, IMAGE)

    assert checks["workspace_read_only"] is False
    assert checks["network_none"] is True


def test_remote_docker_context_is_rejected(monkeypatch) -> None:
    monkeypatch.delenv("DOCKER_HOST", raising=False)

    with pytest.raises(fixture_runtime.FixtureRuntimeRejected, match="Remote Docker contexts"):
        fixture_runtime.ensure_local_docker_context(
            "docker",
            lambda command, **kwargs: completed(stdout=json.dumps("tcp://remote.example:2376")),
        )


class FixtureEndpointDb:
    def get(self, model: object, identity: str) -> object:
        return SimpleNamespace(id=identity)

    def scalar(self, statement: object) -> object:
        return SimpleNamespace(config={})


def test_fixture_endpoint_requires_separate_confirmation(monkeypatch) -> None:
    called = False

    def unexpected_run(**kwargs):
        nonlocal called
        called = True

    monkeypatch.setattr(agent_router, "run_harmless_fixture_validation", unexpected_run)

    with pytest.raises(HTTPException) as exc:
        agent_router.validate_project_agent_runtime_fixture(
            uuid4(), AgentFixtureRuntimeRequest(image=IMAGE), FixtureEndpointDb(),
        )

    assert exc.value.status_code == 400
    assert called is False


def test_fixture_endpoint_preserves_real_agent_disabled_boundary(monkeypatch) -> None:
    monkeypatch.setattr(agent_router, "run_harmless_fixture_validation", lambda **kwargs: {
        "schema": fixture_runtime.FIXTURE_RUNTIME_SCHEMA,
        "decision": "pass",
        "execution_enabled_for_real_agents": False,
    })

    result = agent_router.validate_project_agent_runtime_fixture(
        uuid4(),
        AgentFixtureRuntimeRequest(image=IMAGE, operator_confirmed=True),
        FixtureEndpointDb(),
    )

    assert result["decision"] == "pass"
    assert result["execution_enabled_for_real_agents"] is False
