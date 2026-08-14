from __future__ import annotations

import json
import subprocess
import sys
from dataclasses import asdict
from pathlib import Path

from app.services import agent_runtime_validation, agent_staging
from app.services.agent_dataflow import analyze_agent_dataflow
from app.services.agent_scanner import scan_agent_tree
from app.services.agent_staging import MANIFEST_NAME, build_filtered_staging
from app.services.agent_trust import calculate_agent_trust_score


FIXTURE = Path(__file__).parent / "fixtures" / "agent_runtime_mcp"
DIGEST_IMAGE = "python@sha256:" + "a" * 64
COMMAND = "python -I -B test_client.py"


def finding_payload(item) -> dict[str, object]:
    return {
        "rule_id": item.rule_id,
        "severity": item.severity.value,
        "status": "open",
        "file_path": item.file_path,
    }


def test_representative_mcp_fixture_is_detected_across_asset_types() -> None:
    result = scan_agent_tree(str(FIXTURE))
    assets = {item.path: item for item in result.assets}

    assert set(assets) == {".mcp.json", "AGENTS.md", "plugin.json", "prompt.yaml", "tools.json"}
    assert {item.asset_type for item in assets.values()} == {
        "mcp-config", "instruction", "plugin-manifest", "prompt", "tool-schema",
    }
    assert all(item.status == "parsed" for item in assets.values())
    assert assets[".mcp.json"].transport == "stdio"
    assert assets[".mcp.json"].entrypoint == "python"
    assert "bounded_add" in assets[".mcp.json"].declared_tools
    assert "fixture://status" in assets[".mcp.json"].declared_resources
    assert "add-two-integers" in assets[".mcp.json"].declared_prompts
    assert any(item.capability == "server-process" for item in assets[".mcp.json"].permissions)
    assert all("secret" not in item.evidence.lower() for item in result.findings)


def test_representative_mcp_fixture_builds_dataflow_and_trust_evidence() -> None:
    scan = scan_agent_tree(str(FIXTURE))
    dataflow = analyze_agent_dataflow(scan.assets, scan.findings)
    coverage = {
        "discovered_asset_count": len(scan.assets),
        "parsed_asset_count": sum(item.status == "parsed" for item in scan.assets),
        "failed_asset_count": sum(item.status == "failed" for item in scan.assets),
        "skipped_file_count": len(scan.skipped_files),
    }
    trust = calculate_agent_trust_score(
        assets=[asdict(item) for item in scan.assets],
        permissions=[asdict(item) for item in scan.permissions],
        findings=[finding_payload(item) for item in [*scan.findings, *dataflow.findings]],
        coverage=coverage,
        intelligence={"summary": {"coordinate_count": 0, "covered_count": 0}},
        dataflow=dataflow.report,
        runtime_validation={
            "schema": "runtime/v1",
            "mode": "preflight-only",
            "execution_enabled": False,
            "isolation_policy": {"network": "none"},
        },
    )

    assert dataflow.report["summary"]["path_count"] >= 1
    assert any(item["capability"] == "server-process" for item in dataflow.report["paths"])
    assert any(item.capability == "tool-invocation" for item in scan.permissions)
    assert trust["evidence_summary"]["asset_count"] == 5
    assert trust["evidence_summary"]["target_runtime_observed"] is False
    assert len(trust["trust_sha256"]) == 64


def test_representative_mcp_fixture_preflight_is_safe_and_plan_only(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(agent_runtime_validation.shutil, "which", lambda name: "docker")
    monkeypatch.setattr(
        agent_runtime_validation,
        "staging_workspace_path",
        lambda project_id: tmp_path / "staging" / project_id,
    )
    plan = agent_runtime_validation.build_agent_runtime_plan(
        project_id="representative-mcp",
        source_path=str(FIXTURE),
        command=COMMAND,
        image=DIGEST_IMAGE,
        dataflow={},
        sandbox_enabled=True,
        operator_confirmed=True,
        timeout_seconds=10,
    )
    checks = {item["id"]: item for item in plan["checks"]}

    assert plan["execution_enabled"] is False
    assert plan["mode"] == "preflight-only"
    assert checks["command-policy"]["status"] == "pass"
    assert checks["digest-pinned-image"]["status"] == "pass"
    assert checks["filtered-staging"]["status"] == "block"


def test_representative_mcp_fixture_staging_is_complete_and_verified(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(agent_staging, "validate_destination_root", lambda destination: None)
    result = build_filtered_staging(
        source_path=str(FIXTURE),
        project_id="representative-mcp",
        destination_root=tmp_path / "staging" / "representative-mcp",
    )
    destination = Path(str(result["destination_path"]))

    assert result["verification"]["status"] == "verified"
    assert result["summary"]["copied_file_count"] == 8
    assert (destination / MANIFEST_NAME).is_file()
    assert sorted(item["path"] for item in result["files"]) == [
        ".mcp.json", "AGENTS.md", "README.md", "mcp_server.py", "plugin.json",
        "prompt.yaml", "test_client.py", "tools.json",
    ]


def test_representative_mcp_protocol_smoke_is_offline_and_deterministic() -> None:
    completed = subprocess.run(
        [sys.executable, "-I", "-B", str(FIXTURE / "test_client.py")],
        cwd=FIXTURE,
        capture_output=True,
        text=True,
        timeout=5,
        check=False,
    )

    assert completed.returncode == 0, completed.stderr
    result = json.loads(completed.stdout)
    assert result == {
        "network_used": False,
        "prompt_count": 1,
        "resource_count": 1,
        "result": 6,
        "schema": "ai-security-platform.agent-runtime-mcp-result/v1",
        "secret_values_returned": False,
        "server": "bounded-mcp-integration",
        "tool": "bounded_add",
        "tool_count": 1,
    }
