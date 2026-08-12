from __future__ import annotations

import json
from datetime import datetime, timezone
from fnmatch import fnmatchcase
from html import escape
from pathlib import PurePosixPath
from typing import Any
from uuid import uuid4

from app.services.agent_scanner import AGENT_RULE_VERSION, AgentFinding, AgentPermission


DEFAULT_AGENT_PROFILE: dict[str, object] = {
    "profile_version": 1,
    "rule_version": AGENT_RULE_VERSION,
    "disabled_rule_ids": [],
    "excluded_paths": [],
    "permission_allowlist": [],
    "required_approval_capabilities": [
        "all-capabilities",
        "shell-execution",
        "filesystem-write",
        "secret-access",
    ],
    "exceptions": [],
    "audit_log": [],
    "quality_gate": {
        "enabled": True,
        "threshold": "high",
        "block_new_only": False,
        "max_blocking_findings": 0,
        "block_wildcard_permissions": True,
        "block_parse_failures": True,
        "block_skipped_files": False,
        "block_permission_expansion": True,
        "require_approval_for_high_risk": True,
        "block_unpinned_sources": True,
        "block_insecure_sources": True,
        "block_unknown_sources": False,
        "block_partial_integrity": True,
        "block_integrity_changes": True,
        "block_source_changes": True,
        "block_known_vulnerabilities": True,
        "block_malicious_packages": True,
        "block_package_confusion": True,
        "block_intelligence_gaps": False,
        "block_stale_intelligence": False,
        "max_intelligence_age_days": 30,
        "block_high_risk_dataflow_paths": True,
        "block_low_trust_score": False,
        "minimum_trust_score": 70,
    },
}

SEVERITY_RANK = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1, "none": 0}
DECISION_STATUSES = {"approved", "rejected", "revoked"}


def effective_agent_profile(config: dict[str, object] | None) -> dict[str, object]:
    saved = (config or {}).get("agent_profile")
    profile = dict(DEFAULT_AGENT_PROFILE)
    if isinstance(saved, dict):
        profile.update({key: value for key, value in saved.items() if key in DEFAULT_AGENT_PROFILE})
    profile["rule_version"] = AGENT_RULE_VERSION
    profile["profile_version"] = bounded_int(profile.get("profile_version"), 1, 1, 100_000)
    profile["disabled_rule_ids"] = normalize_string_list(profile.get("disabled_rule_ids"), 200)
    profile["excluded_paths"] = normalize_string_list(profile.get("excluded_paths"), 200)
    profile["required_approval_capabilities"] = normalize_string_list(profile.get("required_approval_capabilities"), 100)
    profile["permission_allowlist"] = normalize_permission_allowlist(profile.get("permission_allowlist"))
    profile["exceptions"] = normalize_exceptions(profile.get("exceptions"))
    profile["audit_log"] = normalize_audit_log(profile.get("audit_log"))
    profile["quality_gate"] = normalize_quality_gate(profile.get("quality_gate"))
    return profile


def update_agent_profile(
    config: dict[str, object] | None,
    payload: dict[str, object],
    *,
    actor: str,
) -> dict[str, object]:
    profile = effective_agent_profile(config)
    allowed_fields = {
        "disabled_rule_ids",
        "excluded_paths",
        "permission_allowlist",
        "required_approval_capabilities",
        "quality_gate",
    }
    unknown = set(payload) - allowed_fields
    if unknown:
        raise ValueError(f"Unsupported AGENT profile fields: {', '.join(sorted(unknown))}")
    if "disabled_rule_ids" in payload:
        profile["disabled_rule_ids"] = normalize_string_list(payload["disabled_rule_ids"], 200, strict=True)
    if "excluded_paths" in payload:
        profile["excluded_paths"] = normalize_string_list(payload["excluded_paths"], 200, strict=True)
    if "required_approval_capabilities" in payload:
        profile["required_approval_capabilities"] = normalize_string_list(payload["required_approval_capabilities"], 100, strict=True)
    if "permission_allowlist" in payload:
        profile["permission_allowlist"] = normalize_permission_allowlist(payload["permission_allowlist"], strict=True)
    if "quality_gate" in payload:
        profile["quality_gate"] = normalize_quality_gate(payload["quality_gate"], strict=True)
    profile["profile_version"] = int(profile["profile_version"]) + 1
    append_profile_audit(profile, "profile.update", actor, {"fields": sorted(payload)})
    return profile


def add_agent_exception(
    config: dict[str, object] | None,
    payload: dict[str, object],
    *,
    actor: str,
) -> tuple[dict[str, object], dict[str, object]]:
    profile = effective_agent_profile(config)
    item = normalize_exception(payload, strict=True)
    item.update({
        "id": str(uuid4()),
        "status": "pending",
        "requester": actor,
        "approver": None,
        "approval_note": None,
        "created_at": utc_now(),
        "updated_at": utc_now(),
        "history": [{"action": "created", "actor": actor, "at": utc_now(), "note": item["reason"]}],
    })
    profile["exceptions"] = [*profile["exceptions"], item]
    profile["profile_version"] = int(profile["profile_version"]) + 1
    append_profile_audit(profile, "exception.create", actor, {"exception_id": item["id"], "kind": item["kind"], "disposition": item["disposition"]})
    return profile, item


def decide_agent_exception(
    config: dict[str, object] | None,
    exception_id: str,
    payload: dict[str, object],
    *,
    actor: str,
) -> tuple[dict[str, object], dict[str, object]]:
    profile = effective_agent_profile(config)
    decision = str(payload.get("status") or "").strip().lower()
    if decision not in DECISION_STATUSES:
        raise ValueError("status must be approved, rejected, or revoked")
    note = str(payload.get("approval_note") or "").strip()
    if not note:
        raise ValueError("approval_note is required")
    updated_item: dict[str, object] | None = None
    items: list[dict[str, object]] = []
    for item in profile["exceptions"]:
        if item.get("id") != exception_id:
            items.append(item)
            continue
        candidate = dict(item)
        candidate.update({
            "status": decision,
            "approver": actor,
            "approval_note": note[:1000],
            "updated_at": utc_now(),
            "history": [
                *(item.get("history") if isinstance(item.get("history"), list) else []),
                {"action": decision, "actor": actor, "at": utc_now(), "note": note[:1000]},
            ][-50:],
        })
        updated_item = candidate
        items.append(candidate)
    if updated_item is None:
        raise ValueError("AGENT exception not found")
    profile["exceptions"] = items
    profile["profile_version"] = int(profile["profile_version"]) + 1
    append_profile_audit(profile, f"exception.{decision}", actor, {"exception_id": exception_id})
    return profile, updated_item


def persist_agent_profile_config(module_config: dict[str, object] | None, profile: dict[str, object]) -> dict[str, object]:
    config = dict(module_config or {})
    config["agent_profile"] = profile
    return config


def filter_agent_findings(findings: list[AgentFinding], profile: dict[str, object]) -> list[AgentFinding]:
    disabled = set(str(item) for item in profile.get("disabled_rule_ids") or [])
    return [finding for finding in findings if finding.rule_id not in disabled]


def finding_governance_status(finding: AgentFinding, profile: dict[str, object]) -> tuple[str, str | None, str | None]:
    for item in active_agent_exceptions(profile):
        if item.get("kind") != "finding" or not matches_finding_exception(finding, item):
            continue
        disposition = str(item.get("disposition") or "accept_risk")
        status = "false_positive" if disposition == "suppress" else "accepted_risk"
        return status, str(item.get("id")), disposition
    return "open", None, None


def permission_is_exempt(permission: AgentPermission | dict[str, object], profile: dict[str, object]) -> tuple[bool, str | None]:
    data = permission_to_mapping(permission)
    for item in profile.get("permission_allowlist") or []:
        if isinstance(item, dict) and matches_permission_selector(data, item):
            return True, f"allowlist:{item.get('id') or 'profile'}"
    for item in active_agent_exceptions(profile):
        if item.get("kind") == "permission" and matches_permission_selector(data, item):
            return True, f"exception:{item.get('id')}"
    return False, None


def evaluate_agent_quality_gate(
    *,
    findings: list[dict[str, object]],
    permissions: list[AgentPermission | dict[str, object]],
    coverage: dict[str, object],
    profile: dict[str, object],
    new_finding_identities: set[str] | None = None,
    expanded_permission_identities: set[str] | None = None,
    assets: list[dict[str, object]] | None = None,
    changed_integrity_identities: set[str] | None = None,
    changed_source_identities: set[str] | None = None,
    intelligence: dict[str, object] | None = None,
    dataflow: dict[str, object] | None = None,
    trust_score: dict[str, object] | None = None,
) -> dict[str, object]:
    gate = profile.get("quality_gate") if isinstance(profile.get("quality_gate"), dict) else normalize_quality_gate(None)
    if not gate.get("enabled"):
        return gate_result("pass", [], [], [], gate, trust_score=trust_score)
    threshold = str(gate.get("threshold") or "high")
    threshold_rank = SEVERITY_RANK.get(threshold, SEVERITY_RANK["high"])
    governed_active_findings = [item for item in findings if str(item.get("status") or "open") not in {"accepted_risk", "false_positive", "fixed", "closed"}]
    active_findings = list(governed_active_findings)
    if gate.get("block_new_only"):
        identities = new_finding_identities or set()
        active_findings = [item for item in active_findings if finding_identity(item) in identities]
    blocking_findings = [] if threshold == "none" else [
        item for item in active_findings
        if SEVERITY_RANK.get(str(item.get("severity") or "info"), 0) >= threshold_rank
    ]
    reasons: list[str] = []
    if len(blocking_findings) > int(gate.get("max_blocking_findings") or 0):
        reasons.append(f"{len(blocking_findings)} active findings meet or exceed {threshold}")
    if gate.get("block_wildcard_permissions") and any(item.get("rule_id") == "AGENT.MCP.WILDCARD_PERMISSION" for item in active_findings):
        reasons.append("wildcard or all-capability permission is present")
    if gate.get("block_parse_failures") and int(coverage.get("failed_asset_count") or 0) > 0:
        reasons.append(f"{int(coverage.get('failed_asset_count') or 0)} Agent assets failed structured parsing")
    if gate.get("block_skipped_files") and int(coverage.get("skipped_file_count") or 0) > 0:
        reasons.append(f"{int(coverage.get('skipped_file_count') or 0)} Agent files were skipped")

    intelligence_rule_policy = {
        "AGENT.INTEL.KNOWN_VULNERABILITY": "block_known_vulnerabilities",
        "AGENT.INTEL.MALICIOUS_PACKAGE": "block_malicious_packages",
        "AGENT.INTEL.PACKAGE_CONFUSION": "block_package_confusion",
    }
    blocking_intelligence = [
        item for item in active_findings
        if gate.get(intelligence_rule_policy.get(str(item.get("rule_id") or ""), ""))
    ]
    intelligence_reason_labels = {
        "AGENT.INTEL.KNOWN_VULNERABILITY": "known vulnerable Agent dependencies",
        "AGENT.INTEL.MALICIOUS_PACKAGE": "local malicious-package intelligence matches",
        "AGENT.INTEL.PACKAGE_CONFUSION": "protected-package name confusion signals",
    }
    for rule_id, label in intelligence_reason_labels.items():
        count = sum(str(item.get("rule_id") or "") == rule_id for item in blocking_intelligence)
        if count:
            reasons.append(f"{count} {label} are present")
    intelligence_summary = intelligence.get("summary") if isinstance(intelligence, dict) and isinstance(intelligence.get("summary"), dict) else {}
    if gate.get("block_intelligence_gaps"):
        gap_count = sum(int(intelligence_summary.get(key) or 0) for key in (
            "not_covered_count", "version_unresolved_count", "unsupported_count",
        ))
        if gap_count:
            reasons.append(f"{gap_count} Agent package coordinates lack complete local intelligence coverage")
    stale_sources: list[str] = []
    if gate.get("block_stale_intelligence") and isinstance(intelligence, dict):
        sources = intelligence.get("sources") if isinstance(intelligence.get("sources"), dict) else {}
        maximum_age = int(gate.get("max_intelligence_age_days") or 30)
        for source_name in ("osv_mirror", "threat_intelligence"):
            source = sources.get(source_name) if isinstance(sources.get(source_name), dict) else {}
            age = source.get("age_days")
            if source.get("status") == "available" and (not isinstance(age, int) or age > maximum_age):
                stale_sources.append(source_name)
        if stale_sources:
            reasons.append(f"{len(stale_sources)} configured Agent intelligence sources exceed the freshness policy")

    blocking_finding_map = {finding_identity(item): item for item in [*blocking_findings, *blocking_intelligence]}
    dataflow_rule_ids = {
        "AGENT.FLOW.POTENTIAL_SECRET_EXFILTRATION",
        "AGENT.FLOW.UNTRUSTED_TO_HIGH_RISK_TOOL",
        "AGENT.FLOW.PROMPT_TO_SENSITIVE_RESOURCE",
    }
    blocking_dataflow = [
        item for item in active_findings
        if gate.get("block_high_risk_dataflow_paths")
        and str(item.get("rule_id") or "") in dataflow_rule_ids
        and str(item.get("severity") or "") in {"critical", "high"}
    ]
    if blocking_dataflow:
        reasons.append(f"{len(blocking_dataflow)} high-risk Prompt-to-tool-to-resource paths are present")
    blocking_finding_map.update({finding_identity(item): item for item in blocking_dataflow})
    blocking_findings = list(blocking_finding_map.values())

    expanded_ids = expanded_permission_identities or set()
    unapproved_permissions: list[dict[str, object]] = []
    expanded_permissions: list[dict[str, object]] = []
    required_capabilities = set(str(item) for item in profile.get("required_approval_capabilities") or [])
    for permission in permissions:
        data = permission_to_mapping(permission)
        exempt, exemption = permission_is_exempt(data, profile)
        if exempt:
            continue
        identity = permission_identity(data)
        if gate.get("block_permission_expansion") and identity in expanded_ids:
            expanded_permissions.append({**data, "exemption": exemption})
        if (
            gate.get("require_approval_for_high_risk")
            and (str(data.get("risk_level")) in {"critical", "high"} or str(data.get("capability")) in required_capabilities)
            and data.get("approval") != "required"
        ):
            unapproved_permissions.append({**data, "exemption": exemption})
    if expanded_permissions:
        reasons.append(f"{len(expanded_permissions)} new or expanded permission boundaries are not allowlisted")
    if unapproved_permissions:
        reasons.append(f"{len(unapproved_permissions)} high-risk permissions do not require approval")

    blocked_assets: list[dict[str, object]] = []
    integrity_changed = changed_integrity_identities or set()
    source_changed = changed_source_identities or set()
    unpinned_count = 0
    insecure_count = 0
    unknown_count = 0
    partial_count = 0
    integrity_change_count = 0
    source_change_count = 0
    for asset in assets or []:
        identity = asset_governance_identity(asset)
        provenance = asset.get("provenance") if isinstance(asset.get("provenance"), list) else []
        issue_names = {
            str(issue)
            for item in provenance if isinstance(item, dict)
            for issue in (item.get("issues") if isinstance(item.get("issues"), list) else [])
        }
        asset_reasons: list[str] = []
        if gate.get("block_unpinned_sources") and "version-unpinned" in issue_names and asset_has_active_rules(
            asset, governed_active_findings, {"AGENT.SUPPLY.UNPINNED_VERSION"}
        ):
            unpinned_count += 1
            asset_reasons.append("version-unpinned")
        if gate.get("block_insecure_sources") and issue_names & {
            "insecure-http-source", "embedded-source-credentials", "local-path-escape",
        } and asset_has_active_rules(asset, governed_active_findings, {
            "AGENT.SUPPLY.INSECURE_SOURCE", "AGENT.SUPPLY.SOURCE_CREDENTIALS", "AGENT.SUPPLY.LOCAL_PATH_ESCAPE",
        }):
            insecure_count += 1
            asset_reasons.append("insecure-source")
        if gate.get("block_unknown_sources") and "source-unknown" in issue_names and asset_has_active_rules(
            asset, governed_active_findings, {"AGENT.SUPPLY.SOURCE_UNKNOWN"}
        ):
            unknown_count += 1
            asset_reasons.append("source-unknown")
        if gate.get("block_partial_integrity") and str(asset.get("integrity_status")) == "partial" and asset_has_active_rules(
            asset, governed_active_findings, {"AGENT.SUPPLY.INTEGRITY_PARTIAL"}
        ):
            partial_count += 1
            asset_reasons.append("integrity-partial")
        if gate.get("block_integrity_changes") and identity in integrity_changed:
            integrity_change_count += 1
            asset_reasons.append("integrity-changed")
        if gate.get("block_source_changes") and identity in source_changed:
            source_change_count += 1
            asset_reasons.append("source-changed")
        if asset_reasons:
            blocked_assets.append({
                "identity": identity,
                "path": asset.get("path"),
                "asset_type": asset.get("asset_type"),
                "reasons": asset_reasons,
            })
    if unpinned_count:
        reasons.append(f"{unpinned_count} Agent assets use missing or floating dependency versions")
    if insecure_count:
        reasons.append(f"{insecure_count} Agent assets use insecure or out-of-project sources")
    if unknown_count:
        reasons.append(f"{unknown_count} Agent assets do not declare an implementation source")
    if partial_count:
        reasons.append(f"{partial_count} Agent assets have partial directory integrity evidence")
    if integrity_change_count:
        reasons.append(f"{integrity_change_count} Agent asset integrity digests changed from the previous scan")
    if source_change_count:
        reasons.append(f"{source_change_count} Agent asset source declarations changed from the previous scan")
    if gate.get("block_low_trust_score"):
        minimum_trust_score = int(gate.get("minimum_trust_score") or 70)
        actual_trust_score = int((trust_score or {}).get("score") or 0)
        if actual_trust_score < minimum_trust_score:
            reasons.append(f"Agent trust score {actual_trust_score} is below the required {minimum_trust_score}")
    decision = "block" if reasons else "pass"
    return gate_result(
        decision,
        reasons,
        blocking_findings,
        [*expanded_permissions, *unapproved_permissions],
        gate,
        blocked_assets,
        blocking_intelligence,
        stale_sources,
        blocking_dataflow,
        dataflow.get("summary") if isinstance(dataflow, dict) and isinstance(dataflow.get("summary"), dict) else {},
        trust_score,
    )


def gate_result(
    decision: str,
    reasons: list[str],
    findings: list[dict[str, object]],
    permissions: list[dict[str, object]],
    policy: dict[str, object],
    assets: list[dict[str, object]] | None = None,
    intelligence_findings: list[dict[str, object]] | None = None,
    stale_intelligence_sources: list[str] | None = None,
    dataflow_findings: list[dict[str, object]] | None = None,
    dataflow_summary: dict[str, object] | None = None,
    trust_score: dict[str, object] | None = None,
) -> dict[str, object]:
    deduped_permissions = {permission_identity(item): item for item in permissions}
    return {
        "decision": decision,
        "exit_code": 1 if decision == "block" else 0,
        "reasons": reasons,
        "blocking_finding_count": len(findings),
        "blocking_permission_count": len(deduped_permissions),
        "blocking_asset_count": len(assets or []),
        "blocking_intelligence_count": len(intelligence_findings or []),
        "blocking_dataflow_count": len(dataflow_findings or []),
        "blocked_findings": findings[:100],
        "blocked_permissions": list(deduped_permissions.values())[:100],
        "blocked_assets": (assets or [])[:100],
        "blocked_intelligence": (intelligence_findings or [])[:100],
        "stale_intelligence_sources": stale_intelligence_sources or [],
        "blocked_dataflow": (dataflow_findings or [])[:100],
        "dataflow_summary": dataflow_summary or {},
        "trust_score": {
            "score": int((trust_score or {}).get("score") or 0),
            "grade": (trust_score or {}).get("grade"),
            "confidence": (trust_score or {}).get("confidence"),
            "trust_sha256": (trust_score or {}).get("trust_sha256"),
        } if trust_score else {},
        "policy": policy,
        "limitations": [
            "The gate evaluates static declarations and findings; it does not execute Agent, MCP, plugin, or tool code.",
            "Allowlist and approved exceptions are project-scoped governance decisions, not proof that a capability is safe at runtime.",
        ],
    }


def build_agent_sarif(findings: list[dict[str, object]], scan_id: str) -> dict[str, object]:
    rules: dict[str, dict[str, object]] = {}
    results: list[dict[str, object]] = []
    for finding in findings:
        rule_id = str(finding.get("rule_id") or "AGENT.UNKNOWN")
        rules[rule_id] = {
            "id": rule_id,
            "name": rule_id.replace(".", "_"),
            "shortDescription": {"text": str(finding.get("title") or rule_id)},
            "help": {"text": str(finding.get("remediation") or "Review the Agent security boundary.")},
        }
        physical_location: dict[str, object] = {
            "artifactLocation": {"uri": str(finding.get("file_path") or "agent-project")},
        }
        line = finding.get("line_start")
        if isinstance(line, int) and line > 0:
            physical_location["region"] = {"startLine": line}
        results.append({
            "ruleId": rule_id,
            "level": sarif_level(str(finding.get("severity") or "info")),
            "message": {"text": str(finding.get("description") or finding.get("title") or rule_id)},
            "locations": [{"physicalLocation": physical_location}],
            "properties": {"status": finding.get("status"), "scanTaskId": scan_id},
        })
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "AI Security Platform AGENT", "version": AGENT_RULE_VERSION, "rules": list(rules.values())}},
            "results": results,
        }],
    }


def _build_agent_html_report_without_trust(report: dict[str, object]) -> str:
    summary = report.get("summary") if isinstance(report.get("summary"), dict) else {}
    gate = report.get("quality_gate") if isinstance(report.get("quality_gate"), dict) else {}
    assets = report.get("assets") if isinstance(report.get("assets"), list) else []
    findings = report.get("findings") if isinstance(report.get("findings"), list) else []
    intelligence = report.get("intelligence") if isinstance(report.get("intelligence"), dict) else {}
    intelligence_summary = intelligence.get("summary") if isinstance(intelligence.get("summary"), dict) else {}
    intelligence_packages = intelligence.get("packages") if isinstance(intelligence.get("packages"), list) else []
    dataflow = report.get("dataflow") if isinstance(report.get("dataflow"), dict) else {}
    dataflow_summary = dataflow.get("summary") if isinstance(dataflow.get("summary"), dict) else {}
    dataflow_paths = dataflow.get("paths") if isinstance(dataflow.get("paths"), list) else []
    runtime_validation = report.get("runtime_validation") if isinstance(report.get("runtime_validation"), dict) else {}
    runtime_summary = runtime_validation.get("summary") if isinstance(runtime_validation.get("summary"), dict) else {}
    runtime_checks = runtime_validation.get("checks") if isinstance(runtime_validation.get("checks"), list) else []
    asset_rows = "".join(
        f"<tr><td>{escape(str(item.get('path') or '-'))}</td><td>{escape(str(item.get('asset_type') or '-'))}</td><td>{escape(str(item.get('integrity_status') or '-'))}<br><small>{escape(str(item.get('directory_sha256') or item.get('file_sha256') or '-'))[:20]}</small></td><td>{len(item.get('provenance') or [])}</td><td>{int(item.get('permission_count') or 0)}</td><td>{int(item.get('finding_count') or 0)}</td></tr>"
        for item in assets if isinstance(item, dict)
    )
    provenance_rows = "".join(
        f"<tr><td>{escape(str(asset.get('path') or '-'))}</td><td>{escape(str(source.get('subject') or '-'))}</td><td>{escape(str(source.get('package_name') or '-'))}<br><small>{escape(str(source.get('package_version') or '-'))} · {escape(str(source.get('version_status') or '-'))}</small></td><td>{escape(str(source.get('source_type') or '-'))}<br><small>{escape(str(source.get('source_ref') or '-'))}</small></td><td>{escape(str(source.get('installation_method') or '-'))}</td><td>{escape(str(source.get('publisher_claim') or '-'))}<br><small>{escape(str(source.get('publisher_status') or '-'))}</small></td><td>{escape(', '.join(str(issue) for issue in (source.get('issues') if isinstance(source.get('issues'), list) else [])))}</td></tr>"
        for asset in assets if isinstance(asset, dict)
        for source in (asset.get("provenance") if isinstance(asset.get("provenance"), list) else [])
        if isinstance(source, dict)
    )
    finding_rows = "".join(
        f"<tr><td>{escape(str(item.get('severity') or '-'))}</td><td>{escape(str(item.get('rule_id') or '-'))}</td><td>{escape(str(item.get('title') or '-'))}</td><td>{escape(str(item.get('file_path') or '-'))}</td><td>{escape(str(item.get('status') or '-'))}</td></tr>"
        for item in findings if isinstance(item, dict)
    )
    intelligence_rows = "".join(
        f"<tr><td>{escape(str(item.get('package_name') or '-'))}<br><small>{escape(str(item.get('ecosystem') or '-'))} · {escape(str(item.get('asset_path') or '-'))}</small></td><td>{escape(str(item.get('package_version') or 'unresolved'))}</td><td>{escape(str(item.get('lookup_status') or '-'))}<br><small>{escape(', '.join(str(source) for source in (item.get('coverage_sources') if isinstance(item.get('coverage_sources'), list) else [])))}</small></td><td>{escape(', '.join(str(match.get('id') or '-') for match in (item.get('vulnerabilities') if isinstance(item.get('vulnerabilities'), list) else []) if isinstance(match, dict))) or '-'}</td><td>{len(item.get('threats') or []) + len(item.get('confusion_signals') or [])}</td></tr>"
        for item in intelligence_packages if isinstance(item, dict)
    )
    dataflow_rows = "".join(
        f"<tr><td>{escape(str(item.get('severity') or '-'))}<br><small>{escape(str(item.get('confidence') or '-'))} confidence</small></td><td>{escape(str(item.get('title') or '-'))}<br><small>{escape(str(item.get('asset_path') or '-'))}</small></td><td>{escape(str(item.get('capability') or '-'))}<br><small>{escape(str(item.get('resource_type') or '-'))}: {escape(str(item.get('resource_scope') or '-'))}</small></td><td>{escape(', '.join(str(control.get('type') or '-') for control in (item.get('controls') if isinstance(item.get('controls'), list) else []) if isinstance(control, dict))) or '-'}</td><td>{escape(', '.join(str(value) for value in (item.get('missing_controls') if isinstance(item.get('missing_controls'), list) else []))) or '-'}</td></tr>"
        for item in dataflow_paths if isinstance(item, dict)
    )
    runtime_rows = "".join(
        f"<tr><td>{escape(str(item.get('status') or '-'))}</td><td>{escape(str(item.get('id') or '-'))}</td><td>{escape(str(item.get('detail') or '-'))}</td><td>{escape(str(item.get('remediation') or '-'))}</td></tr>"
        for item in runtime_checks if isinstance(item, dict)
    )
    gate_reasons = "".join(
        f"<li>{escape(str(reason))}</li>" for reason in gate.get("reasons", [])
    ) if isinstance(gate.get("reasons"), list) else ""
    return f"""<!doctype html><html lang='zh-CN'><head><meta charset='utf-8'><title>AGENT 安全报告</title><style>body{{font-family:system-ui,sans-serif;max-width:1100px;margin:40px auto;color:#172033}}table{{border-collapse:collapse;width:100%;margin-bottom:28px}}th,td{{border:1px solid #d9e0ec;padding:9px;text-align:left}}.meta{{background:#f5f7fb;padding:16px;border-radius:8px}}</style></head><body><h1>AGENT 安全报告</h1><div class='meta'><p>项目：{escape(str(report.get('project_id') or '-'))}</p><p>扫描批次：{escape(str(report.get('scan_task_id') or '-'))}</p><p>资产：{int(summary.get('asset_count') or 0)}；来源：{int(summary.get('provenance_count') or 0)}；权限：{int(summary.get('permission_count') or 0)}；风险：{int(summary.get('finding_count') or 0)}</p><p>本地情报包坐标：{int(intelligence_summary.get('coordinate_count') or 0)}；漏洞包：{int(intelligence_summary.get('vulnerable_package_count') or 0)}；恶意包命中：{int(intelligence_summary.get('malicious_match_count') or 0)}</p><p>静态数据流路径：{int(dataflow_summary.get('path_count') or 0)}；严重/高风险：{int(dataflow_summary.get('critical_path_count') or 0) + int(dataflow_summary.get('high_path_count') or 0)}；保守推断边：{int(dataflow_summary.get('inferred_edge_count') or 0)}</p><p>运行预检：{escape(str(runtime_validation.get('decision') or 'not_available'))}；阻断项：{int(runtime_summary.get('blocking_count') or 0)}；执行已启用：{escape(str(runtime_validation.get('execution_enabled') or False))}</p><p>质量门禁：{escape(str(gate.get('decision') or 'unknown'))}</p>{f'<ul>{gate_reasons}</ul>' if gate_reasons else ''}</div><h2>资产完整性</h2><table><thead><tr><th>路径</th><th>类型</th><th>完整性 / SHA-256</th><th>来源</th><th>权限</th><th>问题</th></tr></thead><tbody>{asset_rows}</tbody></table><h2>来源与安装声明</h2><table><thead><tr><th>资产</th><th>主体</th><th>包 / 版本</th><th>来源</th><th>安装方式</th><th>发布者声明</th><th>问题</th></tr></thead><tbody>{provenance_rows}</tbody></table><h2>离线漏洞与恶意包情报</h2><table><thead><tr><th>包 / 资产</th><th>版本</th><th>查询状态 / 覆盖源</th><th>漏洞</th><th>威胁信号</th></tr></thead><tbody>{intelligence_rows}</tbody></table><p>“checked_no_match”只表示已配置的本地来源未匹配该精确版本，不代表组件无漏洞。</p><h2>Prompt → 工具 → 资源静态路径</h2><table><thead><tr><th>等级 / 置信度</th><th>路径 / 资产</th><th>能力 / 资源</th><th>已声明控制</th><th>缺失控制</th></tr></thead><tbody>{dataflow_rows}</tbody></table><p>数据流路径来自静态配置关系；低置信度和 conservative-inference 表示保守推断，不代表已观察到运行时调用或数据传输。</p><h2>AGENT 受控运行预检（仅计划）</h2><table><thead><tr><th>状态</th><th>检查</th><th>说明</th><th>处理建议</th></tr></thead><tbody>{runtime_rows}</tbody></table><p>该预检不会创建过滤副本、拉取镜像或运行容器；项目源目录不会直接作为未来 AGENT 运行时工作区。</p><h2>风险发现</h2><table><thead><tr><th>等级</th><th>规则</th><th>标题</th><th>位置</th><th>状态</th></tr></thead><tbody>{finding_rows}</tbody></table><p>本报告只包含静态声明、治理决策、本地情报匹配和本地 SHA-256 证据；发布者字段未经身份验证，也不代表运行时安全证明。</p></body></html>"""


def build_agent_html_report(report: dict[str, object]) -> str:
    html = _build_agent_html_report_without_trust(report)
    trust = report.get("trust_score") if isinstance(report.get("trust_score"), dict) else {}
    if not trust:
        return html
    dimension_rows = "".join(
        f"<tr><td>{escape(str(item.get('label') or item.get('id') or '-'))}</td>"
        f"<td>{int(item.get('score') or 0)} / {int(item.get('max_score') or 0)}</td>"
        f"<td>{escape(str(item.get('status') or '-'))}</td>"
        f"<td>{escape('; '.join(str(value.get('detail') or '') for value in item.get('deductions', []) if isinstance(value, dict))) or '-'}</td></tr>"
        for item in trust.get("dimensions", []) if isinstance(item, dict)
    )
    improvements = "".join(
        f"<li><strong>{escape(str(item.get('title') or '-'))}</strong>：{escape(str(item.get('action') or '-'))}</li>"
        for item in trust.get("improvements", []) if isinstance(item, dict)
    )
    trust_section = (
        "<h2>可解释的 AGENT 信任评分</h2>"
        f"<p><strong>{int(trust.get('score') or 0)} / 100</strong>；等级：{escape(str(trust.get('grade') or '-'))}；"
        f"证据置信度：{escape(str(trust.get('confidence') or '-'))}；证据完整度：{int(trust.get('evidence_completeness') or 0)}%</p>"
        "<p>该分数归纳当前扫描证据，不是安全保证；缺少目标运行证据时静态总分最高 90。</p>"
        "<table><thead><tr><th>分项</th><th>得分</th><th>状态</th><th>主要扣分证据</th></tr></thead>"
        f"<tbody>{dimension_rows}</tbody></table>"
        f"<h3>优先改进</h3><ul>{improvements}</ul>"
        f"<p><small>评分证据摘要 SHA-256：{escape(str(trust.get('trust_sha256') or '-'))}</small></p>"
    )
    return html.replace("</body>", f"{trust_section}</body>")


def finding_identity(finding: AgentFinding | dict[str, object]) -> str:
    if isinstance(finding, AgentFinding):
        return f"{finding.rule_id}::{finding.file_path}::{finding.line_start}::{finding.title}"
    return f"{finding.get('rule_id') or ''}::{finding.get('file_path') or ''}::{finding.get('line_start') or 0}::{finding.get('title') or ''}"


def permission_identity(permission: AgentPermission | dict[str, object]) -> str:
    data = permission_to_mapping(permission)
    fields = ("asset_path", "subject", "capability", "access", "resource_type", "scope")
    return "::".join(str(data.get(field) or "") for field in fields)


def asset_governance_identity(asset: dict[str, object]) -> str:
    return f"{asset.get('asset_type') or 'unknown'}::{asset.get('path') or ''}"


def asset_has_active_rules(
    asset: dict[str, object],
    findings: list[dict[str, object]],
    rule_ids: set[str],
) -> bool:
    asset_path = str(asset.get("path") or "")
    return any(
        str(item.get("file_path") or "") == asset_path and str(item.get("rule_id") or "") in rule_ids
        for item in findings
    )


def permission_to_mapping(permission: AgentPermission | dict[str, object]) -> dict[str, object]:
    if isinstance(permission, dict):
        return dict(permission)
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


def active_agent_exceptions(profile: dict[str, object]) -> list[dict[str, object]]:
    now = datetime.now(timezone.utc)
    result: list[dict[str, object]] = []
    for item in profile.get("exceptions") or []:
        if not isinstance(item, dict) or item.get("status") != "approved":
            continue
        expires_at = parse_datetime(item.get("expires_at"))
        if expires_at is not None and expires_at <= now:
            continue
        result.append(item)
    return result


def matches_finding_exception(finding: AgentFinding, selector: dict[str, object]) -> bool:
    rule_id = str(selector.get("rule_id") or "*")
    path_pattern = str(selector.get("path_pattern") or "*")
    return wildcard_match(finding.rule_id, rule_id) and path_matches(finding.file_path, path_pattern)


def matches_permission_selector(permission: dict[str, object], selector: dict[str, object]) -> bool:
    return (
        path_matches(str(permission.get("asset_path") or ""), str(selector.get("path_pattern") or "*"))
        and wildcard_match(str(permission.get("subject") or ""), str(selector.get("subject_pattern") or "*"))
        and wildcard_match(str(permission.get("capability") or ""), str(selector.get("capability") or "*"))
        and wildcard_match(str(permission.get("scope") or ""), str(selector.get("scope_pattern") or "*"))
    )


def normalize_permission_allowlist(value: object, strict: bool = False) -> list[dict[str, object]]:
    if value is None:
        return []
    if not isinstance(value, list):
        if strict:
            raise ValueError("permission_allowlist must be a list")
        return []
    result: list[dict[str, object]] = []
    for raw in value[:200]:
        if not isinstance(raw, dict):
            if strict:
                raise ValueError("permission allowlist entries must be objects")
            continue
        reason = str(raw.get("reason") or "").strip()
        if strict and not reason:
            raise ValueError("permission allowlist reason is required")
        result.append({
            "id": str(raw.get("id") or uuid4()),
            "path_pattern": bounded_text(raw.get("path_pattern"), "*", 500),
            "subject_pattern": bounded_text(raw.get("subject_pattern"), "*", 300),
            "capability": bounded_text(raw.get("capability"), "*", 120),
            "scope_pattern": bounded_text(raw.get("scope_pattern"), "*", 500),
            "reason": reason[:1000],
        })
    return result


def normalize_exceptions(value: object) -> list[dict[str, object]]:
    if not isinstance(value, list):
        return []
    result: list[dict[str, object]] = []
    for raw in value[-200:]:
        if not isinstance(raw, dict):
            continue
        try:
            item = normalize_exception(raw)
        except ValueError:
            continue
        item.update({
            "id": str(raw.get("id") or uuid4()),
            "status": str(raw.get("status") or "pending"),
            "requester": raw.get("requester"),
            "approver": raw.get("approver"),
            "approval_note": raw.get("approval_note"),
            "created_at": raw.get("created_at") or utc_now(),
            "updated_at": raw.get("updated_at") or utc_now(),
            "history": raw.get("history") if isinstance(raw.get("history"), list) else [],
        })
        result.append(item)
    return result


def normalize_exception(value: dict[str, object], strict: bool = False) -> dict[str, object]:
    kind = str(value.get("kind") or "finding").strip().lower()
    disposition = str(value.get("disposition") or "accept_risk").strip().lower()
    reason = str(value.get("reason") or "").strip()
    if kind not in {"finding", "permission"}:
        raise ValueError("exception kind must be finding or permission")
    if disposition not in {"suppress", "accept_risk"}:
        raise ValueError("disposition must be suppress or accept_risk")
    if strict and not reason:
        raise ValueError("exception reason is required")
    expires_at = value.get("expires_at")
    if expires_at and parse_datetime(expires_at) is None:
        raise ValueError("expires_at must be an ISO-8601 datetime")
    return {
        "kind": kind,
        "disposition": disposition,
        "rule_id": bounded_text(value.get("rule_id"), "*", 300),
        "path_pattern": bounded_text(value.get("path_pattern"), "*", 500),
        "subject_pattern": bounded_text(value.get("subject_pattern"), "*", 300),
        "capability": bounded_text(value.get("capability"), "*", 120),
        "scope_pattern": bounded_text(value.get("scope_pattern"), "*", 500),
        "reason": reason[:1000],
        "expires_at": str(expires_at) if expires_at else None,
    }


def normalize_quality_gate(value: object, strict: bool = False) -> dict[str, object]:
    default = dict(DEFAULT_AGENT_PROFILE["quality_gate"])
    if value is None:
        return default
    if not isinstance(value, dict):
        if strict:
            raise ValueError("quality_gate must be an object")
        return default
    allowed = set(default)
    if strict and set(value) - allowed:
        raise ValueError(f"Unsupported quality gate fields: {', '.join(sorted(set(value) - allowed))}")
    gate = {**default, **{key: item for key, item in value.items() if key in allowed}}
    for key in (
        "enabled",
        "block_new_only",
        "block_wildcard_permissions",
        "block_parse_failures",
        "block_skipped_files",
        "block_permission_expansion",
        "require_approval_for_high_risk",
        "block_unpinned_sources",
        "block_insecure_sources",
        "block_unknown_sources",
        "block_partial_integrity",
        "block_integrity_changes",
        "block_source_changes",
        "block_known_vulnerabilities",
        "block_malicious_packages",
        "block_package_confusion",
        "block_intelligence_gaps",
        "block_stale_intelligence",
        "block_high_risk_dataflow_paths",
        "block_low_trust_score",
    ):
        if strict and not isinstance(gate[key], bool):
            raise ValueError(f"quality_gate.{key} must be a boolean")
        gate[key] = bool(gate[key])
    threshold = str(gate.get("threshold") or "high").lower()
    if threshold not in SEVERITY_RANK:
        raise ValueError("quality_gate.threshold is invalid")
    gate["threshold"] = threshold
    gate["max_blocking_findings"] = bounded_int(gate.get("max_blocking_findings"), 0, 0, 10_000)
    gate["max_intelligence_age_days"] = bounded_int(gate.get("max_intelligence_age_days"), 30, 1, 3650)
    gate["minimum_trust_score"] = bounded_int(gate.get("minimum_trust_score"), 70, 0, 100)
    return gate


def normalize_string_list(value: object, limit: int, strict: bool = False) -> list[str]:
    if value is None:
        return []
    if not isinstance(value, list):
        if strict:
            raise ValueError("profile list fields must be lists")
        return []
    result = [str(item).strip()[:500] for item in value[:limit] if str(item).strip()]
    return list(dict.fromkeys(result))


def normalize_audit_log(value: object) -> list[dict[str, object]]:
    return [dict(item) for item in value[-200:] if isinstance(item, dict)] if isinstance(value, list) else []


def append_profile_audit(profile: dict[str, object], action: str, actor: str, detail: dict[str, object]) -> None:
    audit = profile.get("audit_log") if isinstance(profile.get("audit_log"), list) else []
    profile["audit_log"] = [*audit, {"id": str(uuid4()), "action": action, "actor": actor, "at": utc_now(), "detail": detail}][-200:]


def path_matches(path: str, pattern: str) -> bool:
    normalized_path = path.replace("\\", "/")
    normalized_pattern = pattern.replace("\\", "/")
    return fnmatchcase(normalized_path, normalized_pattern) or PurePosixPath(normalized_path).match(normalized_pattern)


def wildcard_match(value: str, pattern: str) -> bool:
    return fnmatchcase(value.lower(), pattern.lower())


def parse_datetime(value: object) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed.replace(tzinfo=timezone.utc) if parsed.tzinfo is None else parsed.astimezone(timezone.utc)


def bounded_text(value: object, default: str, limit: int) -> str:
    text = str(value or default).strip()
    return (text or default)[:limit]


def bounded_int(value: object, default: int, minimum: int, maximum: int) -> int:
    try:
        parsed = int(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        parsed = default
    return max(minimum, min(maximum, parsed))


def sarif_level(severity: str) -> str:
    return "error" if severity in {"critical", "high"} else "warning" if severity == "medium" else "note"


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def dumps_report(report: dict[str, object]) -> str:
    return json.dumps(report, ensure_ascii=False, indent=2)
