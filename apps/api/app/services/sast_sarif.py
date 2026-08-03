from __future__ import annotations

from typing import Iterable

from app.db_models import FindingRecord
from app.services.sast_scanner import ParsedFinding


def build_sast_sarif(findings: Iterable[FindingRecord], scan_task_id: str | None = None) -> dict[str, object]:
    items = list(findings)
    rules: dict[str, dict[str, object]] = {}
    results: list[dict[str, object]] = []
    for finding in items:
        rules.setdefault(
            finding.rule_id,
            {
                "id": finding.rule_id,
                "name": finding.title,
                "shortDescription": {"text": finding.title},
                "help": {"text": str((finding.ai_review or {}).get("remediation") or "Review and remediate this finding.")},
            },
        )
        location: dict[str, object] = {
            "physicalLocation": {
                "artifactLocation": {"uri": finding.file_path or "unknown"},
                "region": {"startLine": finding.line_start or 1, "endLine": finding.line_end or finding.line_start or 1},
            }
        }
        results.append(
            {
                "ruleId": finding.rule_id,
                "level": sarif_level(finding.severity),
                "message": {"text": finding.evidence or finding.title},
                "locations": [location],
                "properties": {"finding_id": str(finding.id), "scan_task_id": scan_task_id or finding.scan_task_id, "source": "SAST"},
            }
        )
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{"tool": {"driver": {"name": "AI Security Platform SAST", "rules": list(rules.values())}}, "results": results}],
    }


def sarif_level(severity: str) -> str:
    return "error" if severity in {"critical", "high"} else "warning" if severity == "medium" else "note"


def build_sast_sarif_from_parsed(findings: Iterable[ParsedFinding]) -> dict[str, object]:
    items = list(findings)
    rules: dict[str, dict[str, object]] = {}
    results: list[dict[str, object]] = []
    for finding in items:
        rules.setdefault(
            finding.rule_id,
            {
                "id": finding.rule_id,
                "name": finding.title,
                "shortDescription": {"text": finding.title},
                "help": {"text": finding.remediation},
            },
        )
        results.append(
            {
                "ruleId": finding.rule_id,
                "level": sarif_level(finding.severity.value),
                "message": {"text": finding.evidence or finding.title},
                "locations": [{"physicalLocation": {"artifactLocation": {"uri": finding.file_path}, "region": {"startLine": finding.line_start, "endLine": finding.line_end}}}],
                "properties": {"source": "SAST", "category": finding.category, "cwe": finding.cwe, "owasp": finding.owasp},
            }
        )
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{"tool": {"driver": {"name": "AI Security Platform SAST", "rules": list(rules.values())}}, "results": results}],
    }
