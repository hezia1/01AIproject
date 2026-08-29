from pathlib import Path

from app.db_models import (
    DastValidationRecord,
    FindingRecord,
    KnowledgeEntryRecord,
    ProjectRecord,
    SandboxEvidenceRecord,
)


GOVERNED_STATUSES = {"fixed", "closed", "false_positive"}


def infer_knowledge_type(finding: FindingRecord, validations: list[DastValidationRecord]) -> str:
    if finding.status == "false_positive":
        return "false_positive_experience"
    if finding.status in {"fixed", "closed"}:
        return "remediation"
    if validations:
        return "validation_playbook"
    return "vulnerability_pattern"


def build_applicability(project: ProjectRecord, finding: FindingRecord) -> dict[str, object]:
    extension = Path(finding.file_path or "").suffix.lower()
    category = str((finding.ai_review or {}).get("category") or "uncategorized")
    return {
        "source_module": finding.source,
        "rule_id": finding.rule_id,
        "category": category,
        "file_extension": extension or None,
        "default_branch": project.default_branch,
        "governance_status": finding.status,
        "source_project_id": str(project.id),
    }


def build_evidence_refs(
    finding: FindingRecord,
    validations: list[DastValidationRecord],
    evidence: list[SandboxEvidenceRecord],
) -> list[dict[str, object]]:
    references: list[dict[str, object]] = [{
        "kind": "finding",
        "id": str(finding.id),
        "summary": finding.evidence or finding.title,
    }]
    references.extend({
        "kind": "dast_validation",
        "id": str(item.id),
        "verdict": item.verdict,
        "summary": item.evidence_summary or item.target_url,
    } for item in validations)
    references.extend({
        "kind": "sandbox_evidence",
        "id": str(item.id),
        "summary": item.evidence_summary or item.strategy_name or item.run_command,
    } for item in evidence)
    return references


def entry_publish_ready(entry: KnowledgeEntryRecord) -> bool:
    kinds = {str(item.get("kind")) for item in (entry.evidence_refs or []) if isinstance(item, dict)}
    governance_status = str((entry.applicability or {}).get("governance_status") or "")
    has_conclusion = "dast_validation" in kinds or "sandbox_evidence" in kinds or governance_status in GOVERNED_STATUSES
    return bool(entry.summary.strip() and entry.rule_id and entry.applicability and has_conclusion)


def default_summary(finding: FindingRecord) -> str:
    review = finding.ai_review or {}
    return str(
        review.get("summary")
        or review.get("description")
        or finding.remediation_note
        or finding.evidence
        or finding.title
    )


def entry_snapshot(entry: KnowledgeEntryRecord) -> dict[str, object]:
    return {
        "knowledge_type": entry.knowledge_type,
        "title": entry.title,
        "summary": entry.summary,
        "rule_id": entry.rule_id,
        "source_module": entry.source_module,
        "severity": entry.severity,
        "category": entry.category,
        "status": entry.status,
        "applicability": entry.applicability or {},
        "evidence_refs": entry.evidence_refs or [],
        "tags": entry.tags or [],
        "reviewer": entry.reviewer,
        "review_note": entry.review_note,
    }


def restore_snapshot(entry: KnowledgeEntryRecord, snapshot: dict[str, object]) -> None:
    for field in (
        "knowledge_type", "title", "summary", "rule_id", "source_module", "severity",
        "category", "status", "applicability", "evidence_refs", "tags", "reviewer", "review_note",
    ):
        if field in snapshot:
            setattr(entry, field, snapshot[field])


def recommendation_score(
    entry: KnowledgeEntryRecord,
    findings: list[FindingRecord],
) -> tuple[int, list[str], list[str]]:
    reasons: list[str] = []
    matched_ids: list[str] = []
    score = 0
    entry_category = (entry.category or "").lower()
    for finding in findings:
        finding_score = 0
        finding_reasons: list[str] = []
        if finding.rule_id == entry.rule_id:
            finding_score += 80
            finding_reasons.append("命中相同检测规则")
        finding_category = str((finding.ai_review or {}).get("category") or "").lower()
        if entry_category and finding_category == entry_category:
            finding_score += 15
            finding_reasons.append("风险分类一致")
        if finding_score and finding.source == entry.source_module:
            finding_score += 5
            finding_reasons.append("来源模块一致")
        if finding_score > score:
            score = min(finding_score, 100)
            reasons = finding_reasons
        if finding_score:
            matched_ids.append(str(finding.id))
    return score, reasons, matched_ids
