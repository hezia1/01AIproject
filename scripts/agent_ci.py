"""Run the AGENT static governance scan locally and export delivery evidence."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import sys
from typing import Any
from uuid import uuid4


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "apps" / "api"))

from app.services.agent_governance import (  # noqa: E402
    build_agent_html_report,
    build_agent_sarif,
    effective_agent_profile,
    evaluate_agent_quality_gate,
    filter_agent_findings,
    finding_governance_status,
    finding_identity,
    permission_identity,
)
from app.services.agent_scanner import AgentAsset, AgentFinding, AgentPermission, scan_agent_tree  # noqa: E402
from app.services.agent_intelligence import analyze_agent_intelligence  # noqa: E402
from app.services.agent_dataflow import analyze_agent_dataflow  # noqa: E402
from app.services.agent_runtime_validation import build_agent_runtime_plan  # noqa: E402
from app.services.agent_trust import calculate_agent_trust_score  # noqa: E402
from app.services.agent_audit import build_agent_offline_audit, compare_agent_offline_audits  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description="Offline AGENT asset and permission governance scan")
    parser.add_argument("--source", default=".", help="Directory containing Agent/MCP/plugin assets")
    parser.add_argument("--profile", default="", help="Exported AGENT CI config or raw profile JSON")
    parser.add_argument("--baseline", default="", help="Optional prior AGENT JSON report used for new-only and permission expansion checks")
    parser.add_argument("--json", dest="json_path", default="agent-result.json")
    parser.add_argument("--sarif", dest="sarif_path", default="agent-result.sarif")
    parser.add_argument("--html", dest="html_path", default="agent-result.html")
    parser.add_argument("--fail-on-block", action="store_true", help="Return exit code 1 when the project quality gate blocks")
    parser.add_argument("--offline", action="store_true", help="Document that no network-backed enrichment was requested")
    parser.add_argument("--runtime-command", default="", help="Optional command to statically preflight; it is never executed")
    parser.add_argument("--runtime-image", default="", help="Optional digest-pinned local image to statically preflight; it is never pulled")
    args = parser.parse_args()

    try:
        source = Path(args.source).expanduser().resolve(strict=True)
        if not source.is_dir():
            raise ValueError(f"AGENT source is not a directory: {source}")
        profile = load_profile(args.profile)
        baseline = load_baseline(args.baseline)
        output = scan_agent_tree(str(source), excluded_paths=list(profile.get("excluded_paths") or []))
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        parser.error(str(exc))

    intelligence_output = analyze_agent_intelligence(output.assets)
    dataflow_output = analyze_agent_dataflow(
        output.assets, [*output.findings, *intelligence_output.findings], profile
    )
    findings = filter_agent_findings(
        [*output.findings, *intelligence_output.findings, *dataflow_output.findings], profile
    )
    runtime_validation = build_agent_runtime_plan(
        project_id="local-ci",
        source_path=str(source),
        command=args.runtime_command,
        image=args.runtime_image,
        dataflow=dataflow_output.report,
        sandbox_enabled=True,
    )
    finding_payloads = []
    suppressed_count = 0
    for finding in findings:
        status, exception_id, disposition = finding_governance_status(finding, profile)
        if status != "open":
            suppressed_count += 1
        finding_payloads.append(finding_payload(finding, status, exception_id, disposition))
    asset_payloads = asset_payloads_with_counts(output.assets, findings)
    permission_payloads = [permission_payload(item) for item in output.permissions]
    coverage = coverage_payload(output.assets, output.skipped_files, asset_payloads)
    trust_score = calculate_agent_trust_score(
        assets=asset_payloads,
        permissions=permission_payloads,
        findings=finding_payloads,
        coverage=coverage,
        intelligence=intelligence_output.report,
        dataflow=dataflow_output.report,
        runtime_validation=runtime_validation,
    )
    audit = build_agent_offline_audit(
        assets=asset_payloads,
        findings=finding_payloads,
        coverage=coverage,
        intelligence=intelligence_output.report,
        dataflow=dataflow_output.report,
        trust_score=trust_score,
    )
    audit_comparison = compare_agent_offline_audits(
        baseline.get("audit") if isinstance(baseline.get("audit"), dict) else None,
        audit,
    )

    baseline_findings = baseline.get("findings") if isinstance(baseline.get("findings"), list) else []
    baseline_permissions = baseline.get("permissions") if isinstance(baseline.get("permissions"), list) else []
    baseline_assets = baseline.get("assets") if isinstance(baseline.get("assets"), list) else []
    previous_finding_ids = {finding_identity(item) for item in baseline_findings if isinstance(item, dict)}
    previous_permission_ids = {permission_identity(item) for item in baseline_permissions if isinstance(item, dict)}
    new_finding_ids = {finding_identity(item) for item in finding_payloads} - previous_finding_ids
    expanded_permission_ids = {permission_identity(item) for item in permission_payloads} - previous_permission_ids
    changed_integrity_ids, changed_source_ids = changed_asset_evidence(
        [item for item in baseline_assets if isinstance(item, dict)], asset_payloads
    ) if args.baseline else (set(), set())
    gate = evaluate_agent_quality_gate(
        findings=finding_payloads,
        permissions=output.permissions,
        coverage=coverage,
        profile=profile,
        new_finding_identities=new_finding_ids,
        expanded_permission_identities=expanded_permission_ids,
        assets=asset_payloads,
        changed_integrity_identities=changed_integrity_ids,
        changed_source_identities=changed_source_ids,
        intelligence=intelligence_output.report,
        dataflow=dataflow_output.report,
        trust_score=trust_score,
    )
    scan_id = str(uuid4())
    report = {
        "scan_task_id": scan_id,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "source_path": str(source),
        "offline": True,
        "rule_version": output.rule_version,
        "summary": {
            "asset_count": len(asset_payloads),
            "provenance_count": sum(len(item.get("provenance") or []) for item in asset_payloads),
            "permission_count": len(permission_payloads),
            "finding_count": len(finding_payloads),
            "suppressed_count": suppressed_count,
            "coverage": coverage,
        },
        "assets": asset_payloads,
        "permissions": permission_payloads,
        "findings": finding_payloads,
        "quality_gate": gate,
        "intelligence": intelligence_output.report,
        "dataflow": dataflow_output.report,
        "audit": audit,
        "audit_comparison": audit_comparison,
        "runtime_validation": runtime_validation,
        "trust_score": trust_score,
        "profile": profile,
        "skipped_files": output.skipped_files,
        "baseline": {"provided": bool(args.baseline), "path": str(Path(args.baseline).resolve()) if args.baseline else None},
        "capability_boundaries": [
            "This command performs local static analysis only and never connects to or executes Agent, MCP, plugin, or tool code.",
            "Without --baseline, every current finding and permission is treated as new for gate evaluation.",
            "All evidence emitted by the scanner uses its credential-redaction path.",
            "Offline intelligence checks use only bundled rules and explicitly configured local files; checked-no-match is not a clean bill of health.",
            "Data-flow paths are static, confidence-labelled relationships and do not prove observed runtime behavior.",
            "The audit is a local rule-based review draft; it does not invoke an external model or change findings, gates, or trust scores.",
            "Audit comparison labels only changes in local static review candidates; not-current-candidate is not a remediation or security conclusion.",
            "Runtime validation is preflight-only; this command does not create staging files, pull images or run the proposed Agent command.",
        ],
    }
    write_text(args.json_path, json.dumps(report, ensure_ascii=False, indent=2))
    write_text(args.sarif_path, json.dumps(build_agent_sarif(finding_payloads, scan_id), ensure_ascii=False, indent=2))
    write_text(args.html_path, build_agent_html_report(report))
    print(json.dumps({
        "asset_count": len(asset_payloads),
        "permission_count": len(permission_payloads),
        "finding_count": len(finding_payloads),
        "vulnerable_package_count": int((intelligence_output.report.get("summary") or {}).get("vulnerable_package_count") or 0),
        "malicious_match_count": int((intelligence_output.report.get("summary") or {}).get("malicious_match_count") or 0),
        "high_risk_dataflow_count": sum(
            int((dataflow_output.report.get("summary") or {}).get(key) or 0)
            for key in ("critical_path_count", "high_path_count")
        ),
        "runtime_preflight": runtime_validation.get("decision"),
        "trust_score": trust_score.get("score"),
        "trust_grade": trust_score.get("grade"),
        "suppressed_count": suppressed_count,
        "quality_gate": gate.get("decision"),
        "failed": gate.get("decision") == "block",
    }, ensure_ascii=False))
    return 1 if args.fail_on_block and gate.get("decision") == "block" else 0


def load_profile(path: str) -> dict[str, object]:
    if not path:
        return effective_agent_profile({})
    profile_path = Path(path).expanduser().resolve()
    if not profile_path.is_file():
        raise ValueError(f"AGENT profile file does not exist: {profile_path}")
    payload = json.loads(profile_path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("AGENT profile JSON must be an object")
    raw_profile: Any = payload.get("profile", payload)
    if not isinstance(raw_profile, dict):
        raise ValueError("AGENT profile JSON does not contain a valid profile object")
    return effective_agent_profile({"agent_profile": raw_profile})


def load_baseline(path: str) -> dict[str, object]:
    if not path:
        return {}
    baseline_path = Path(path).expanduser().resolve()
    if not baseline_path.is_file():
        raise ValueError(f"AGENT baseline report does not exist: {baseline_path}")
    payload = json.loads(baseline_path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("AGENT baseline report must be a JSON object")
    return payload


def finding_payload(finding: AgentFinding, status: str, exception_id: str | None, disposition: str | None) -> dict[str, object]:
    return {
        "rule_id": finding.rule_id,
        "title": finding.title,
        "severity": finding.severity.value,
        "file_path": finding.file_path,
        "line_start": finding.line_start,
        "line_end": finding.line_end,
        "evidence": finding.evidence,
        "category": finding.category,
        "description": finding.description,
        "remediation": finding.remediation,
        "trust_impact": finding.trust_impact,
        "status": status,
        "governance_exception_id": exception_id,
        "governance_disposition": disposition,
    }


def permission_payload(permission: AgentPermission) -> dict[str, str]:
    return {
        "asset_path": permission.asset_path,
        "subject": permission.subject,
        "capability": permission.capability,
        "access": permission.access,
        "resource_type": permission.resource_type,
        "scope": permission.scope,
        "approval": permission.approval,
        "risk_level": permission.risk_level,
        "source": permission.source,
    }


def asset_payloads_with_counts(assets: list[AgentAsset], findings: list[AgentFinding]) -> list[dict[str, object]]:
    counts: dict[str, int] = {}
    for finding in findings:
        counts[finding.file_path] = counts.get(finding.file_path, 0) + 1
    return [{
        "path": asset.path,
        "asset_type": asset.asset_type,
        "format": asset.format,
        "parser": asset.parser,
        "status": asset.status,
        "checks": asset.checks,
        "finding_count": counts.get(asset.path, 0),
        "detail": asset.detail,
        "name": asset.name,
        "version": asset.version,
        "publisher": asset.publisher,
        "transport": asset.transport,
        "entrypoint": asset.entrypoint,
        "declared_tools": asset.declared_tools,
        "declared_resources": asset.declared_resources,
        "declared_prompts": asset.declared_prompts,
        "permission_count": len(asset.permissions),
        "provenance": [{
            "subject": item.subject,
            "package_name": item.package_name,
            "package_version": item.package_version,
            "source_type": item.source_type,
            "source_ref": item.source_ref,
            "installation_method": item.installation_method,
            "version_status": item.version_status,
            "publisher_claim": item.publisher_claim,
            "publisher_status": item.publisher_status,
            "source_visibility": item.source_visibility,
            "authentication_status": item.authentication_status,
            "onboarding_status": item.onboarding_status,
            "connection_status": item.connection_status,
            "issues": item.issues,
        } for item in asset.provenance],
        "file_sha256": asset.file_sha256,
        "directory_sha256": asset.directory_sha256,
        "integrity_status": asset.integrity_status,
        "integrity_issues": asset.integrity_issues,
        "metadata": asset.metadata,
    } for asset in assets]


def changed_asset_evidence(
    baseline: list[dict[str, object]],
    current: list[dict[str, object]],
) -> tuple[set[str], set[str]]:
    baseline_map = {asset_identity(item): item for item in baseline}
    current_map = {asset_identity(item): item for item in current}
    integrity: set[str] = set()
    source: set[str] = set()
    for identity in baseline_map.keys() & current_map.keys():
        previous = baseline_map[identity]
        target = current_map[identity]
        if (previous.get("file_sha256") or previous.get("directory_sha256")) and any(previous.get(field) != target.get(field) for field in (
            "file_sha256", "directory_sha256", "integrity_status", "integrity_issues",
        )):
            integrity.add(identity)
        if "provenance" in previous and previous.get("provenance") != target.get("provenance"):
            source.add(identity)
    return integrity, source


def asset_identity(asset: dict[str, object]) -> str:
    return f"{asset.get('asset_type') or 'unknown'}::{asset.get('path') or ''}"


def coverage_payload(assets: list[AgentAsset], skipped: list[dict[str, str]], payloads: list[dict[str, object]]) -> dict[str, object]:
    asset_types: dict[str, int] = {}
    findings_by_type: dict[str, int] = {}
    adapter_coverage: dict[str, dict[str, object]] = {}
    for item in payloads:
        asset_type = str(item.get("asset_type") or "unknown")
        asset_types[asset_type] = asset_types.get(asset_type, 0) + 1
        findings_by_type[asset_type] = findings_by_type.get(asset_type, 0) + int(item.get("finding_count") or 0)
    for asset in assets:
        adapter = asset.metadata.get("config_adapter") if isinstance(asset.metadata, dict) else None
        adapter = adapter if isinstance(adapter, dict) else {}
        adapter_id = str(adapter.get("id") or "unclassified")
        item = adapter_coverage.setdefault(adapter_id, {
            "asset_count": 0,
            "parsed_asset_count": 0,
            "failed_asset_count": 0,
            "label": str(adapter.get("label") or "未分类配置"),
            "validation_level": str(adapter.get("validation_level") or "unknown"),
            "status": str(adapter.get("status") or "unknown"),
            "schema_reference_count": 0,
            "schema_references_not_validated": 0,
            "limitation": str(adapter.get("limitation") or "未记录"),
        })
        item["asset_count"] = int(item["asset_count"]) + 1
        item["parsed_asset_count"] = int(item["parsed_asset_count"]) + int(asset.status == "parsed")
        item["failed_asset_count"] = int(item["failed_asset_count"]) + int(asset.status == "failed")
        item["schema_reference_count"] = int(item["schema_reference_count"]) + int(
            adapter.get("schema_reference_declared") is True
        )
        item["schema_references_not_validated"] = int(item["schema_references_not_validated"]) + int(
            adapter.get("schema_reference_validation") == "not-fetched"
        )
    return {
        "discovered_asset_count": len(assets),
        "parsed_asset_count": sum(1 for item in assets if item.status == "parsed"),
        "failed_asset_count": sum(1 for item in assets if item.status != "parsed"),
        "skipped_file_count": len(skipped),
        "findings_by_asset_type": findings_by_type,
        "asset_types": asset_types,
        "adapter_coverage": adapter_coverage,
        "generic_parser_asset_count": sum(
            int(item.get("asset_count") or 0)
            for item in adapter_coverage.values()
            if item.get("status") == "generic"
        ),
        "schema_references_not_validated": sum(
            int(item.get("schema_references_not_validated") or 0)
            for item in adapter_coverage.values()
        ),
    }


def write_text(path: str, content: str) -> None:
    output = Path(path).expanduser().resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(content, encoding="utf-8")


if __name__ == "__main__":
    raise SystemExit(main())
