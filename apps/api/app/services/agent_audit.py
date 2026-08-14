"""Offline, evidence-linked review drafts for the AGENT module.

This service intentionally does not call an external model.  It turns existing
static evidence into bounded human-review candidates and labels the result so
it cannot be mistaken for an AI verdict or runtime observation.
"""
from __future__ import annotations

from datetime import datetime, timezone
from hashlib import sha256
import json
from typing import Any


SEVERITY_RANK = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}
MAX_AUDIT_ITEMS = 100
MAX_AUDIT_COMPARISON_ITEMS = MAX_AUDIT_ITEMS * 2


def build_agent_offline_audit(
    *,
    assets: list[dict[str, object]],
    findings: list[dict[str, object]],
    coverage: dict[str, object],
    intelligence: dict[str, object],
    dataflow: dict[str, object],
    trust_score: dict[str, object],
) -> dict[str, object]:
    """Build a deterministic review queue from evidence already produced locally."""
    active_findings = [
        item for item in findings
        if str(item.get("status") or "open") not in {"accepted_risk", "false_positive", "fixed", "closed"}
    ]
    ordered_findings = sorted(
        active_findings,
        key=lambda item: (
            -SEVERITY_RANK.get(str(item.get("severity") or "info"), 0),
            str(item.get("rule_id") or ""),
            str(item.get("file_path") or ""),
            int(item.get("line_start") or 0),
        ),
    )
    items = [finding_review_item(item) for item in ordered_findings[:MAX_AUDIT_ITEMS]]
    items.extend(coverage_review_items(coverage))
    items.extend(private_source_review_items(assets))
    items.extend(dataflow_review_items(dataflow))
    items = items[:MAX_AUDIT_ITEMS]
    intelligence_summary = intelligence.get("summary") if isinstance(intelligence.get("summary"), dict) else {}
    dataflow_summary = dataflow.get("summary") if isinstance(dataflow.get("summary"), dict) else {}
    summary = {
        "active_finding_count": len(active_findings),
        "review_item_count": len(items),
        "critical_or_high_finding_count": sum(
            str(item.get("severity") or "") in {"critical", "high"} for item in active_findings
        ),
        "coverage_gap_count": sum(item["kind"] == "coverage-gap" for item in items),
        "private_source_preflight_gap_count": sum(item["kind"] == "private-source-preflight" for item in items),
        "high_risk_static_path_count": sum(
            int(dataflow_summary.get(key) or 0) for key in ("critical_path_count", "high_path_count")
        ),
        "local_intelligence_gap_count": sum(
            int(intelligence_summary.get(key) or 0)
            for key in ("not_covered_count", "version_unresolved_count", "unsupported_count")
        ),
        "trust_score": int(trust_score.get("score") or 0),
        "trust_grade": str(trust_score.get("grade") or "unknown"),
    }
    report: dict[str, object] = {
        "schema": "ai-security-platform.agent-offline-audit/v1",
        "mode": "local-rule-based-draft",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "model_status": "not-run",
        "external_model_invoked": False,
        "summary": summary,
        "items": items,
        "limitations": [
            "This is a local review draft generated from existing static evidence; no external AI model was invoked.",
            "Review candidates do not change finding severity, governance status, quality-gate decision, or trust score.",
            "Static paths and source declarations are not observed runtime behavior, connectivity proof, publisher verification, or exploitability proof.",
            "The audit stores references and bounded summaries, not source credential values, tool parameters, response bodies, or prompt contents.",
        ],
    }
    report["audit_sha256"] = canonical_sha256(report)
    return report


def compare_agent_offline_audits(
    base_audit: dict[str, object] | None,
    target_audit: dict[str, object] | None,
) -> dict[str, object]:
    """Compare two local review queues without making a remediation claim."""
    target_items = comparable_audit_items(target_audit)
    if target_items is None:
        return audit_comparison(
            has_comparison=False,
            comparison_status="target-audit-not-available",
            limitations=[
                "The target scan has no compatible offline audit draft, so no review-candidate comparison was produced.",
                "No comparison result is a statement about remediation, safety, runtime behavior, connectivity, or exploitability.",
            ],
        )
    base_items = comparable_audit_items(base_audit)
    if base_items is None:
        return audit_comparison(
            has_comparison=False,
            comparison_status="base-audit-not-available",
            limitations=[
                "The previous scan has no compatible offline audit draft, so current review candidates are not labelled as new.",
                "No comparison result is a statement about remediation, safety, runtime behavior, connectivity, or exploitability.",
            ],
        )
    base_map = {str(item["id"]): item for item in base_items}
    target_map = {str(item["id"]): item for item in target_items}
    items: list[dict[str, object]] = []
    for identity in sorted(target_map.keys() - base_map.keys()):
        items.append(audit_comparison_item(target_map[identity], "new"))
    for identity in sorted(target_map.keys() & base_map.keys()):
        items.append(audit_comparison_item(target_map[identity], "still-pending"))
    for identity in sorted(base_map.keys() - target_map.keys()):
        items.append(audit_comparison_item(base_map[identity], "not-current-candidate"))
    items.sort(key=lambda item: (
        {"new": 0, "still-pending": 1, "not-current-candidate": 2}.get(str(item["result"]), 3),
        -SEVERITY_RANK.get(str(item["priority"]), 0),
        str(item["title"]),
    ))
    items = items[:MAX_AUDIT_COMPARISON_ITEMS]
    return audit_comparison(
        has_comparison=True,
        comparison_status="ready",
        items=items,
        limitations=[
            "The comparison uses stable local review-candidate identities from two static scan outputs; it does not execute or contact an Agent, MCP server, plugin, tool, or external model.",
            "not-current-candidate means only that the latest static evidence did not generate the same review candidate. It is not proof of remediation, safety, runtime absence, connectivity, publisher verification, or non-exploitability.",
            "A changed title or evidence reference produces a new candidate and a prior not-current-candidate entry; human review is required to interpret that change.",
        ],
    )


def comparable_audit_items(audit: dict[str, object] | None) -> list[dict[str, object]] | None:
    if not isinstance(audit, dict) or audit.get("schema") != "ai-security-platform.agent-offline-audit/v1":
        return None
    raw_items = audit.get("items")
    if not isinstance(raw_items, list):
        return None
    return [
        item for item in raw_items
        if isinstance(item, dict) and isinstance(item.get("id"), str) and item.get("id")
    ]


def audit_comparison_item(item: dict[str, object], result: str) -> dict[str, object]:
    return {
        "id": str(item["id"]),
        "result": result,
        "kind": str(item.get("kind") or "unknown"),
        "priority": str(item.get("priority") or "info"),
        "title": str(item.get("title") or "Unnamed review candidate"),
        "evidence_refs": [str(value) for value in item.get("evidence_refs", []) if isinstance(value, str)][:12],
    }


def audit_comparison(
    *, has_comparison: bool, comparison_status: str, items: list[dict[str, object]] | None = None,
    limitations: list[str],
) -> dict[str, object]:
    result_items = items or []
    return {
        "has_comparison": has_comparison,
        "comparison_status": comparison_status,
        "summary": {
            "new_count": sum(item["result"] == "new" for item in result_items),
            "still_pending_count": sum(item["result"] == "still-pending" for item in result_items),
            "not_current_candidate_count": sum(item["result"] == "not-current-candidate" for item in result_items),
        },
        "items": result_items,
        "limitations": limitations,
    }


def finding_review_item(item: dict[str, object]) -> dict[str, object]:
    rule_id = str(item.get("rule_id") or "AGENT.UNKNOWN")
    file_path = str(item.get("file_path") or "agent-project")
    line = int(item.get("line_start") or 0)
    return review_item(
        kind="finding",
        priority=str(item.get("severity") or "info"),
        title=str(item.get("title") or rule_id),
        rationale="Review the static finding, its declared control boundary, and whether the proposed remediation fits the intended Agent capability.",
        evidence_refs=[f"rule:{rule_id}", f"asset:{file_path}", f"line:{line}"],
        questions=[
            "Is the capability required for the documented task?",
            "Is the configured scope the minimum necessary?",
            "Does the remediation preserve required controls and approvals?",
        ],
    )


def coverage_review_items(coverage: dict[str, object]) -> list[dict[str, object]]:
    result: list[dict[str, object]] = []
    generic_count = int(coverage.get("generic_parser_asset_count") or 0)
    if generic_count:
        result.append(review_item(
            kind="coverage-gap",
            priority="medium",
            title="Generic configuration parsing requires schema review",
            rationale="The scanner parsed these assets with generic structural rules rather than a vendor-specific schema contract.",
            evidence_refs=[f"coverage:generic_parser_asset_count={generic_count}"],
            questions=["Which vendor schema or documented contract applies?", "Can a local schema profile be added without fetching external content?"],
        ))
    schema_count = int(coverage.get("schema_references_not_validated") or 0)
    if schema_count:
        result.append(review_item(
            kind="coverage-gap",
            priority="medium",
            title="Declared schema references were not validated",
            rationale="The scan deliberately did not download or contact schema locations.",
            evidence_refs=[f"coverage:schema_references_not_validated={schema_count}"],
            questions=["Can the required schema be supplied and governed locally?", "Does the declared reference contain a stable vendor contract?"],
        ))
    return result


def private_source_review_items(assets: list[dict[str, object]]) -> list[dict[str, object]]:
    result: list[dict[str, object]] = []
    for asset in assets:
        path = str(asset.get("path") or "agent-project")
        provenance = asset.get("provenance") if isinstance(asset.get("provenance"), list) else []
        for source in provenance:
            if not isinstance(source, dict) or source.get("source_visibility") != "private-declared":
                continue
            onboarding = str(source.get("onboarding_status") or "not-applicable")
            if onboarding == "preflight-ready":
                continue
            result.append(review_item(
                kind="private-source-preflight",
                priority="medium",
                title="Private source declaration needs onboarding review",
                rationale="The source is declared private, but its local onboarding declaration is incomplete or blocked. No connection was attempted.",
                evidence_refs=[
                    f"asset:{path}",
                    f"source-type:{source.get('source_type') or 'unknown'}",
                    f"onboarding:{onboarding}",
                    f"connection:{source.get('connection_status') or 'not-attempted'}",
                ],
                questions=["Is a scoped credential reference declared?", "Should any future connection be separately approved for this exact source?"],
            ))
    return result


def dataflow_review_items(dataflow: dict[str, object]) -> list[dict[str, object]]:
    paths = dataflow.get("paths") if isinstance(dataflow.get("paths"), list) else []
    result: list[dict[str, object]] = []
    for path in paths:
        if not isinstance(path, dict) or str(path.get("severity") or "") not in {"critical", "high"}:
            continue
        result.append(review_item(
            kind="static-dataflow",
            priority=str(path.get("severity") or "high"),
            title=str(path.get("title") or "High-risk static Agent path"),
            rationale="This is a confidence-labelled static relationship, not an observed runtime call or transfer.",
            evidence_refs=[
                f"path:{path.get('id') or 'unknown'}",
                f"asset:{path.get('asset_path') or 'agent-project'}",
                f"confidence:{path.get('confidence') or 'unknown'}",
            ],
            questions=["Is the capability reachable in the intended workflow?", "Are the declared approval and scope controls sufficient?"],
        ))
    return result


def review_item(
    *, kind: str, priority: str, title: str, rationale: str, evidence_refs: list[str], questions: list[str]
) -> dict[str, object]:
    identity = {"kind": kind, "title": title, "evidence_refs": evidence_refs}
    return {
        "id": f"audit-{sha256(json.dumps(identity, sort_keys=True).encode('utf-8')).hexdigest()[:16]}",
        "kind": kind,
        "priority": priority,
        "title": title[:300],
        "rationale": rationale[:1000],
        "evidence_refs": evidence_refs[:12],
        "review_questions": questions[:6],
        "review_status": "pending-human-review",
        "model_status": "not-run",
    }


def canonical_sha256(value: Any) -> str:
    return sha256(json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()
