from __future__ import annotations

from typing import Any

from app.db_models import FindingRecord
from app.security_skill_models import SecuritySkillManifest


def execute_manifest(manifest: SecuritySkillManifest, findings: list[FindingRecord]) -> dict[str, Any]:
    selectors = manifest.selectors
    rule_ids = {value.casefold() for value in selectors.rule_ids}
    categories = {value.casefold() for value in selectors.categories}
    statuses = {value.casefold() for value in selectors.statuses}
    selected: list[FindingRecord] = []
    selector_matches = 0
    evidence_excluded = 0
    for finding in findings:
        category = str((finding.ai_review or {}).get("category", ""))
        checks = (
            not selectors.sources or finding.source.upper() in selectors.sources,
            not rule_ids or finding.rule_id.casefold() in rule_ids,
            not categories or category.casefold() in categories,
            not selectors.severities or finding.severity.lower() in selectors.severities,
            not statuses or finding.status.casefold() in statuses,
        )
        if not all(checks):
            continue
        selector_matches += 1
        evidence = {
            "finding_location": bool(finding.file_path and finding.line_start is not None),
            "finding_evidence": bool(finding.evidence),
            "ai_review": bool(finding.ai_review),
        }
        if not all(evidence[item] for item in manifest.evidence_required):
            evidence_excluded += 1
            continue
        selected.append(finding)

    return {
        "action": manifest.action,
        "current_finding_count": len(findings),
        "selector_match_count": selector_matches,
        "matched_count": len(selected),
        "evidence_excluded_count": evidence_excluded,
        "matched_findings": [{
            "id": str(item.id), "title": item.title, "source": item.source,
            "rule_id": item.rule_id, "severity": item.severity, "status": item.status,
            "file_path": item.file_path, "line_start": item.line_start,
            "evidence_refs": {
                "finding_location": bool(item.file_path and item.line_start is not None),
                "finding_evidence": bool(item.evidence), "ai_review": bool(item.ai_review),
            },
        } for item in selected],
        "limitations": [
            "仅复核项目最新已完成扫描所对应的现有 Finding，不会重新运行 SCA、SAST 或 AGENT。",
            "执行完成只表示筛选流程完成；零命中不代表项目无漏洞，命中也不等于动态复现成功。",
            "Skill 为声明式清单，不执行用户上传的 Python、Shell 或其他任意代码。",
        ],
    }
