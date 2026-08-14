from datetime import datetime, timedelta
from uuid import uuid4

from app.db_models import ScanTaskRecord
from app.routers.agent import agent_scan_snapshot, build_agent_coverage, build_agent_scan_diff
from app.services.agent_scanner import AgentAsset


def scan(metadata: dict, created_at: datetime) -> ScanTaskRecord:
    return ScanTaskRecord(
        id=str(uuid4()),
        project_id=str(uuid4()),
        scan_type="agent",
        status="completed",
        scan_metadata=metadata,
        created_at=created_at,
        started_at=created_at,
        finished_at=created_at,
    )


def permission(scope: str, approval: str = "unknown") -> dict[str, str]:
    return {
        "asset_path": "mcp.json",
        "subject": "mcpservers:filesystem",
        "capability": "filesystem-access",
        "access": "read-write",
        "resource_type": "filesystem",
        "scope": scope,
        "approval": approval,
        "risk_level": "high",
        "source": "mcpServers.filesystem.roots",
    }


def test_adapter_coverage_records_generic_and_unvalidated_schema_gaps():
    assets = [
        AgentAsset(
            path="mcp.json",
            asset_type="mcp-config",
            format="json",
            parser="structured-json",
            status="parsed",
            checks=[],
            metadata={"config_adapter": {
                "id": "mcp-structural-v1",
                "label": "MCP 结构化配置",
                "validation_level": "structural",
                "status": "supported",
                "schema_reference_declared": False,
                "schema_reference_validation": "not-declared",
                "limitation": "结构化范围。",
            }},
        ),
        AgentAsset(
            path="plugins/plugin.json",
            asset_type="plugin-manifest",
            format="json",
            parser="structured-json",
            status="parsed",
            checks=[],
            metadata={"config_adapter": {
                "id": "plugin-manifest-generic-v1",
                "label": "插件清单通用配置",
                "validation_level": "generic",
                "status": "generic",
                "schema_reference_declared": True,
                "schema_reference_validation": "not-fetched",
                "limitation": "不联网获取 Schema。",
            }},
        ),
    ]

    coverage = build_agent_coverage(assets)

    assert coverage.adapter_coverage["mcp-structural-v1"].parsed_asset_count == 1
    assert coverage.adapter_coverage["plugin-manifest-generic-v1"].schema_references_not_validated == 1
    assert coverage.generic_parser_asset_count == 1
    assert coverage.schema_references_not_validated == 1


def test_agent_scan_diff_reports_asset_and_permission_semantics() -> None:
    now = datetime(2026, 8, 10, 12, 0, 0)
    base = scan(
        {
            "assets": [
                {"path": "mcp.json", "asset_type": "mcp-config", "format": "json", "parser": "structured-json", "status": "parsed", "checks": [], "version": "1", "permission_count": 1},
                {"path": "plugins/old/plugin.json", "asset_type": "plugin-manifest", "format": "json", "parser": "structured-json", "status": "parsed", "checks": []},
            ],
            "permissions": [permission("D:/workspace/old"), permission("D:/workspace/shared")],
        },
        now,
    )
    target = scan(
        {
            "assets": [
                {"path": "mcp.json", "asset_type": "mcp-config", "format": "json", "parser": "structured-json", "status": "parsed", "checks": [], "version": "2", "permission_count": 1},
                {"path": "skills/new/SKILL.md", "asset_type": "skill", "format": "md", "parser": "markdown+yaml-frontmatter", "status": "parsed", "checks": []},
            ],
            "permissions": [permission("D:/workspace/new", "required"), permission("D:/workspace/shared", "required")],
        },
        now + timedelta(minutes=5),
    )

    result = build_agent_scan_diff(uuid4(), target, base)

    assert result.has_comparison is True
    assert result.summary.assets_added == 1
    assert result.summary.assets_removed == 1
    assert result.summary.assets_changed == 1
    assert result.summary.permissions_added == 1
    assert result.summary.permissions_removed == 1
    assert result.summary.permissions_changed == 1
    assert {item.direction for item in result.permissions} == {"expanded", "reduced"}
    assert any(item.change_type == "changed" and item.direction == "reduced" for item in result.permissions)


def test_first_agent_scan_has_no_fabricated_comparison() -> None:
    target = scan({"assets": [], "permissions": []}, datetime(2026, 8, 10, 12, 0, 0))

    result = build_agent_scan_diff(uuid4(), target, None)

    assert result.has_comparison is False
    assert result.base_scan_id is None
    assert result.assets == []
    assert result.permissions == []


def test_agent_scan_diff_counts_source_and_integrity_changes() -> None:
    now = datetime(2026, 8, 11, 12, 0, 0)
    common = {"path": "mcp.json", "asset_type": "mcp-config", "format": "json", "parser": "structured-json", "status": "parsed", "checks": []}
    base = scan({"assets": [{**common, "file_sha256": "a" * 64, "provenance": [{"source_ref": "npm:server", "package_version": "1.0.0"}]}], "permissions": []}, now)
    target = scan({"assets": [{**common, "file_sha256": "b" * 64, "provenance": [{"source_ref": "npm:server", "package_version": "2.0.0"}]}], "permissions": []}, now + timedelta(minutes=5))

    result = build_agent_scan_diff(uuid4(), target, base)

    assert result.summary.source_changes == 1
    assert result.summary.integrity_changes == 1
    assert {"provenance", "file_sha256"} <= set(result.assets[0].changes)


def test_agent_snapshot_exposes_runtime_preflight_without_execution_claims() -> None:
    project_id = uuid4()
    target = scan({
        "assets": [],
        "permissions": [],
        "runtime_validation": {
            "schema": "ai-security-platform.agent-runtime-plan/v1",
            "mode": "preflight-only",
            "execution_enabled": False,
            "decision": "blocked",
        },
        "trust_score": {
            "schema": "ai-security-platform.agent-trust-score/v1",
            "score": 63,
            "grade": "low",
            "confidence": "medium",
            "trust_sha256": "a" * 64,
        },
    }, datetime(2026, 8, 12, 12, 0, 0))

    snapshot = agent_scan_snapshot(project_id, target)

    assert snapshot.runtime_validation["mode"] == "preflight-only"
    assert snapshot.runtime_validation["execution_enabled"] is False
    assert snapshot.trust_score["score"] == 63
    assert snapshot.trust_score["trust_sha256"] == "a" * 64
