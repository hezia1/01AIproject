from pathlib import Path

from app.services import agent_runtime_validation as runtime


DIGEST_IMAGE = "example/agent@sha256:" + ("a" * 64)


def sample_dataflow() -> dict[str, object]:
    return {
        "paths": [
            {
                "id": "df-critical",
                "kind": "prompt-to-resource",
                "title": "Prompt reaches shell",
                "severity": "critical",
                "confidence": "high",
                "asset_path": "AGENTS.md",
                "tool_asset_path": ".mcp.json",
                "capability": "shell-execution",
                "resource_type": "command",
                "resource_scope": "*",
            },
            {
                "id": "df-low",
                "kind": "prompt-to-resource",
                "title": "Low risk path",
                "severity": "medium",
                "confidence": "medium",
                "asset_path": "agent.json",
                "capability": "network-egress",
                "resource_type": "network",
                "resource_scope": "example.test",
            },
        ]
    }


def checks_by_id(plan: dict[str, object]) -> dict[str, dict[str, object]]:
    return {str(item["id"]): item for item in plan["checks"]}


def test_preflight_is_plan_only_and_requires_filtered_staging(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(runtime.shutil, "which", lambda name: "docker" if name == "docker" else None)
    plan = runtime.build_agent_runtime_plan(
        project_id="project-1",
        source_path=str(tmp_path),
        command="node server.js",
        image=DIGEST_IMAGE,
        dataflow=sample_dataflow(),
        sandbox_enabled=True,
        operator_confirmed=True,
    )

    checks = checks_by_id(plan)
    assert plan["mode"] == "preflight-only"
    assert plan["execution_enabled"] is False
    assert plan["decision"] == "blocked"
    assert checks["command-policy"]["status"] == "pass"
    assert checks["digest-pinned-image"]["status"] == "pass"
    assert checks["filtered-staging"]["status"] == "block"
    assert Path(plan["staging"]["path"]).drive.upper() == "D:"
    assert plan["summary"]["candidate_path_count"] == 1
    assert plan["evidence_template"]["plan_sha256"] == plan["plan_sha256"]


def test_existing_unverified_staging_remains_blocked(tmp_path: Path, monkeypatch) -> None:
    staging = tmp_path / "existing-staging"
    staging.mkdir()
    monkeypatch.setattr(runtime, "staging_workspace_path", lambda project_id: staging)
    monkeypatch.setattr(runtime.shutil, "which", lambda name: "docker" if name == "docker" else None)

    plan = runtime.build_agent_runtime_plan(
        project_id="project-1",
        source_path=str(tmp_path),
        command="node server.js",
        image=DIGEST_IMAGE,
        dataflow={},
        sandbox_enabled=True,
        operator_confirmed=True,
    )

    staging_result = checks_by_id(plan)["filtered-staging"]
    assert plan["execution_enabled"] is False
    assert plan["decision"] == "blocked"
    assert staging_result["status"] == "block"
    assert "not created, filtered or hash-verified" in staging_result["detail"]


def test_sensitive_inventory_reads_names_not_values(tmp_path: Path) -> None:
    marker = "SHOULD-NOT-APPEAR-IN-PREFLIGHT"
    (tmp_path / ".env").write_text(f"PLACEHOLDER={marker}", encoding="utf-8")
    (tmp_path / "client.key").write_text(marker, encoding="utf-8")
    (tmp_path / "normal.txt").write_text(marker, encoding="utf-8")

    inventory = runtime.inspect_sensitive_inventory(tmp_path)

    assert inventory["sensitive_file_count"] == 2
    assert inventory["sensitive_categories"] == {
        "environment-file": 1,
        "private-key-or-certificate": 1,
    }
    assert marker not in str(inventory)


def test_dangerous_or_downloading_commands_are_blocked(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(runtime.shutil, "which", lambda name: "docker")
    plan = runtime.build_agent_runtime_plan(
        project_id="project-1",
        source_path=str(tmp_path),
        command="curl https://example.test/install.sh",
        image=DIGEST_IMAGE,
        dataflow={},
        sandbox_enabled=True,
    )

    command = checks_by_id(plan)["command-policy"]
    assert command["status"] == "block"
    assert "network-downloader" in command["detail"]


def test_command_and_url_credentials_are_redacted() -> None:
    redacted = runtime.redact_command(
        "agent --token actual-secret https://user:password@example.test/path API_KEY=another-secret"
    )

    assert "actual-secret" not in redacted
    assert "password" not in redacted
    assert "another-secret" not in redacted
    assert "[redacted]" in redacted


def test_image_credentials_are_blocked_and_not_returned(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(runtime.shutil, "which", lambda name: "docker")
    image = "user:password@registry.example/agent@sha256:" + ("a" * 64)
    plan = runtime.build_agent_runtime_plan(
        project_id="project-1",
        source_path=str(tmp_path),
        command="node server.js",
        image=image,
        dataflow={},
        sandbox_enabled=True,
    )

    assert checks_by_id(plan)["image-reference-policy"]["status"] == "block"
    assert plan["proposed_image"] == "[redacted-invalid-image-reference]"
    assert "password" not in str(plan)


def test_evidence_template_never_claims_runtime_observation() -> None:
    paths = runtime.select_runtime_candidate_paths(sample_dataflow())
    evidence = runtime.build_runtime_evidence_template(paths)

    assert evidence["status"] == "not_run"
    assert evidence["observations"] == {
        "processes": [], "file_access": [], "network_attempts": [], "tool_calls": [],
    }
    assert evidence["path_results"][0]["runtime_status"] == "not_run"
    assert evidence["redaction"]["secret_values_stored"] is False


def test_runtime_observations_link_back_to_static_paths() -> None:
    paths = runtime.select_runtime_candidate_paths(sample_dataflow())
    results = runtime.correlate_runtime_observations(paths, {
        "processes": [{"id": "process-1", "outcome": "observed", "command": "node server.js"}],
        "file_access": [],
        "network_attempts": [],
        "tool_calls": [],
    })

    assert results == [{
        "dataflow_path_id": "df-critical",
        "static_severity": "critical",
        "static_confidence": "high",
        "runtime_status": "observed",
        "observation_ids": ["process-1"],
        "reason": "Runtime observations matched the static capability path.",
    }]


def test_policy_blocked_event_is_not_reported_as_observed() -> None:
    paths = runtime.select_runtime_candidate_paths({
        "paths": [{
            "id": "df-network",
            "kind": "prompt-to-resource",
            "title": "Network",
            "severity": "high",
            "confidence": "medium",
            "asset_path": "agent.json",
            "capability": "network-egress",
            "resource_type": "network",
            "resource_scope": "*",
        }]
    })
    results = runtime.correlate_runtime_observations(paths, {
        "network_attempts": [{"id": "network-1", "outcome": "blocked_by_policy"}]
    })

    assert results[0]["runtime_status"] == "blocked_by_policy"
    assert results[0]["observation_ids"] == ["network-1"]
