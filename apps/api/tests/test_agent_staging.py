import json
from pathlib import Path
from types import SimpleNamespace
from uuid import uuid4

import pytest
from fastapi import HTTPException

from app.models import AgentStagingBuildRequest
from app.routers import agent as agent_router
from app.services import agent_staging


FIXTURE = Path(__file__).parent / "fixtures" / "agent_runtime_safe"


class StagingEndpointDb:
    def __init__(self, project: object) -> None:
        self.project = project
        self.scalar_calls = 0

    def get(self, model: object, identity: str) -> object:
        return self.project

    def scalar(self, statement: object) -> object | None:
        self.scalar_calls += 1
        if self.scalar_calls <= 2:
            return SimpleNamespace(config={})
        return None


def build_fixture_staging(tmp_path: Path) -> dict[str, object]:
    return agent_staging.build_filtered_staging(
        source_path=str(FIXTURE),
        project_id="harmless-fixture",
        destination_root=tmp_path / "staging" / "harmless-fixture",
    )


def test_harmless_fixture_build_is_verified_without_execution(tmp_path: Path) -> None:
    result = build_fixture_staging(tmp_path)

    assert result["status"] == "ready"
    assert result["summary"]["copied_file_count"] == 5
    assert result["summary"]["copied_bytes"] == sum(path.stat().st_size for path in FIXTURE.iterdir() if path.is_file())
    assert result["summary"]["runtime_executed"] is False
    assert result["summary"]["exclusion_records_truncated"] is False
    assert all(item["reason"] == "excluded-directory" for item in result["exclusions"])
    assert result["security"] == {
        "links_followed": False,
        "secret_values_returned": False,
        "existing_destination_overwritten": False,
        "container_or_agent_executed": False,
    }
    assert result["verification"]["status"] == "verified"
    destination = Path(result["destination_path"])
    assert destination.parent == tmp_path / "staging" / "harmless-fixture"
    assert (destination / agent_staging.MANIFEST_NAME).is_file()
    assert sorted(item["path"] for item in result["files"]) == [
        "README.md", "agent.json", "policy_probe.py", "request.json", "runner.py",
    ]


def test_sensitive_names_and_secret_content_are_excluded(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "normal.txt").write_text("safe fixture", encoding="utf-8")
    (source / ".env").write_text("IGNORED_VALUE=never-return-this", encoding="utf-8")
    (source / "client.pem").write_text("not copied", encoding="utf-8")
    (source / "ordinary.txt").write_text(
        "-----BEGIN PRIVATE KEY-----\nnot-a-real-key\n", encoding="utf-8"
    )

    result = agent_staging.build_filtered_staging(
        source_path=str(source),
        project_id="filtered",
        destination_root=tmp_path / "staging" / "filtered",
    )

    assert [item["path"] for item in result["files"]] == ["normal.txt"]
    reasons = {item["path"]: item["reason"] for item in result["exclusions"]}
    assert reasons == {
        ".env": "environment-file",
        "client.pem": "private-key-or-certificate",
        "ordinary.txt": "private-key-content",
    }
    assert "never-return-this" not in json.dumps(result)


def test_existing_build_is_never_overwritten(tmp_path: Path) -> None:
    first = build_fixture_staging(tmp_path)
    second = build_fixture_staging(tmp_path)

    assert first["destination_path"] != second["destination_path"]
    assert Path(first["destination_path"]).is_dir()
    assert Path(second["destination_path"]).is_dir()
    assert first["staging_sha256"] == second["staging_sha256"]


def test_verification_detects_payload_tampering(tmp_path: Path) -> None:
    result = build_fixture_staging(tmp_path)
    destination = Path(result["destination_path"])
    (destination / "request.json").write_text("{}", encoding="utf-8")

    with pytest.raises(ValueError, match="integrity mismatch"):
        agent_staging.verify_filtered_staging(destination)


def test_verification_rejects_manifest_path_traversal(tmp_path: Path) -> None:
    result = build_fixture_staging(tmp_path)
    destination = Path(result["destination_path"])
    manifest_path = destination / agent_staging.MANIFEST_NAME
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["files"][0]["path"] = "../outside.txt"
    manifest["manifest_sha256"] = agent_staging.manifest_sha256(manifest)
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    with pytest.raises(ValueError, match="unsafe relative path"):
        agent_staging.verify_filtered_staging(destination)


def test_verification_rejects_duplicate_manifest_paths(tmp_path: Path) -> None:
    result = build_fixture_staging(tmp_path)
    destination = Path(result["destination_path"])
    manifest_path = destination / agent_staging.MANIFEST_NAME
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["files"].append(dict(manifest["files"][0]))
    manifest["staging_sha256"] = agent_staging.staging_payload_sha256(manifest["files"])
    manifest["manifest_sha256"] = agent_staging.manifest_sha256(manifest)
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    with pytest.raises(ValueError, match="duplicate path"):
        agent_staging.verify_filtered_staging(destination)


def test_file_and_total_limits_fail_closed(tmp_path: Path, monkeypatch) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "one.txt").write_bytes(b"1234")
    monkeypatch.setattr(agent_staging, "MAX_STAGING_FILE_BYTES", 3)

    with pytest.raises(ValueError, match="per-file limit"):
        agent_staging.build_filtered_staging(
            source_path=str(source),
            project_id="limited",
            destination_root=tmp_path / "staging" / "limited",
        )
    assert not (tmp_path / "staging" / "limited").exists()


@pytest.mark.skipif(not hasattr(Path, "symlink_to"), reason="symlinks unavailable")
def test_links_are_excluded_without_being_followed(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    outside = tmp_path / "outside.txt"
    outside.write_text("outside payload", encoding="utf-8")
    link = source / "outside-link.txt"
    try:
        link.symlink_to(outside)
    except OSError:
        pytest.skip("symlink creation is not permitted")

    result = agent_staging.build_filtered_staging(
        source_path=str(source),
        project_id="linked",
        destination_root=tmp_path / "staging" / "linked",
    )

    assert result["files"] == []
    assert result["exclusions"] == [{"path": "outside-link.txt", "reason": "link-or-junction"}]


def test_simulated_link_directory_is_not_traversed(tmp_path: Path, monkeypatch) -> None:
    source = tmp_path / "source"
    linked = source / "simulated-link"
    linked.mkdir(parents=True)
    (linked / "must-not-copy.txt").write_text("outside-like payload", encoding="utf-8")
    original = agent_staging.is_link_or_junction
    monkeypatch.setattr(
        agent_staging,
        "is_link_or_junction",
        lambda path: path.name == "simulated-link" or original(path),
    )

    result = agent_staging.build_filtered_staging(
        source_path=str(source),
        project_id="simulated-link",
        destination_root=tmp_path / "staging" / "simulated-link",
    )

    assert result["files"] == []
    assert result["exclusions"] == [{"path": "simulated-link", "reason": "link-or-junction"}]


def test_staging_endpoint_requires_exact_confirmed_plan(monkeypatch) -> None:
    project_id = uuid4()
    db = StagingEndpointDb(SimpleNamespace(source_path=str(FIXTURE), sandbox_command="python runner.py", sandbox_image="fixture@sha256:" + "a" * 64))
    monkeypatch.setattr(agent_router, "build_agent_runtime_plan", lambda **kwargs: {
        "plan_sha256": "b" * 64,
        "checks": [],
    })
    called = False

    def unexpected_build(**kwargs):
        nonlocal called
        called = True

    monkeypatch.setattr(agent_router, "build_filtered_staging", unexpected_build)

    with pytest.raises(HTTPException) as exc:
        agent_router.build_project_agent_runtime_staging(
            project_id,
            AgentStagingBuildRequest(plan_sha256="a" * 64, operator_confirmed=True),
            db,
        )

    assert exc.value.status_code == 409
    assert called is False


def test_staging_endpoint_returns_not_run_boundary(monkeypatch) -> None:
    project_id = uuid4()
    digest = "c" * 64
    db = StagingEndpointDb(SimpleNamespace(source_path=str(FIXTURE), sandbox_command="python runner.py", sandbox_image="fixture@sha256:" + "a" * 64))
    required = {
        "sandbox-module", "source-directory", "source-link-boundary", "explicit-command",
        "command-policy", "explicit-image", "image-reference-policy", "digest-pinned-image",
        "operator-confirmation",
    }
    monkeypatch.setattr(agent_router, "build_agent_runtime_plan", lambda **kwargs: {
        "plan_sha256": digest,
        "checks": [{"id": identifier, "status": "pass"} for identifier in required],
    })
    monkeypatch.setattr(agent_router, "build_filtered_staging", lambda **kwargs: {
        "schema": agent_staging.STAGING_SCHEMA,
        "status": "ready",
        "destination_path": str(Path("D:/staging/build-1")),
        "staging_sha256": "d" * 64,
        "verification": {"status": "verified", "runtime_executed": False},
    })

    result = agent_router.build_project_agent_runtime_staging(
        project_id,
        AgentStagingBuildRequest(plan_sha256=digest, operator_confirmed=True),
        db,
    )

    assert result["execution_enabled"] is False
    assert result["runtime_status"] == "not_run"
    assert result["staging"]["verification"] == {"status": "verified", "runtime_executed": False}
