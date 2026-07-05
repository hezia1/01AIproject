from __future__ import annotations

from dataclasses import dataclass

from app.db_models import FindingRecord
from app.services.sast_noise import noise_reason


PIPELINE = ["scanner_agent", "review_agent", "evidence_agent", "fix_agent"]


@dataclass(frozen=True)
class AgentContext:
    finding: FindingRecord
    current_review: dict


class ScannerAgent:
    name = "scanner_agent"

    def run(self, context: AgentContext) -> dict:
        engine = "semgrep" if str(context.finding.rule_id).startswith("SEMGREP.") else "local_rule"
        return {
            "category": context.current_review.get("category") or infer_category(context.finding),
            "language": context.current_review.get("language") or infer_language(context.finding.file_path),
            "description": context.current_review.get("description") or context.finding.evidence or context.finding.title,
            "scanner_engine": engine,
            "noise_reason": noise_reason(context.finding.file_path or ""),
        }


class ReviewAgent:
    name = "review_agent"

    def run(self, context: AgentContext) -> dict:
        likelihood = "medium"
        verdict = "manual_review_required"
        priority = "P2"
        reason = noise_reason(context.finding.file_path or "")

        if context.finding.severity in {"critical", "high"}:
            likelihood = "low"
            verdict = "priority_review"
            priority = "P1"
        if reason:
            likelihood = "high"
            verdict = f"noise_candidate:{reason}"
            priority = "P3"
        if context.finding.rule_id.startswith("SEMGREP.") and context.finding.severity in {"high", "critical"} and not reason:
            likelihood = "low"

        return {
            "false_positive_likelihood": likelihood,
            "review_verdict": verdict,
            "priority": priority,
        }


class EvidenceAgent:
    name = "evidence_agent"

    def run(self, context: AgentContext) -> dict:
        location = f"{context.finding.file_path or '-'}:{context.finding.line_start or '-'}"
        evidence = context.finding.evidence or "no code snippet"
        return {
            "summary": f"{context.finding.title}; location={location}; rule={context.finding.rule_id}.",
            "evidence_summary": f"{location} matched evidence: {evidence[:240]}",
        }


class FixAgent:
    name = "fix_agent"

    def run(self, context: AgentContext) -> dict:
        category = str(context.current_review.get("category") or infer_category(context.finding))
        remediation = context.current_review.get("remediation") or remediation_for_category(category)
        return {
            "remediation": remediation,
            "fix_strategy": remediation_for_category(category),
        }


AGENTS = [ScannerAgent(), ReviewAgent(), EvidenceAgent(), FixAgent()]


def run_sast_agent_pipeline(finding: FindingRecord) -> dict:
    review = dict(finding.ai_review or {})
    for agent in AGENTS:
        context = AgentContext(finding=finding, current_review=review)
        review.update(agent.run(context))

    review["agent_pipeline"] = PIPELINE
    review.setdefault("summary", finding.title)
    review.setdefault("false_positive_likelihood", "medium")
    review.setdefault("remediation", remediation_for_category(str(review.get("category") or "")))
    return review


def infer_category(finding: FindingRecord) -> str:
    text = f"{finding.rule_id} {finding.title}".lower()
    if any(keyword in text for keyword in ["sql", "injection"]):
        return "injection"
    if any(keyword in text for keyword in ["command", "exec", "eval", "rce"]):
        return "rce"
    if any(keyword in text for keyword in ["secret", "password", "token", "key"]):
        return "secret"
    if "ssrf" in text:
        return "ssrf"
    if "path" in text or "traversal" in text:
        return "path-traversal"
    if "crypto" in text or "tls" in text:
        return "crypto"
    if "deserialize" in text or "deserialization" in text:
        return "deserialization"
    return "security"


def infer_language(file_path: str | None) -> str:
    if not file_path:
        return "Unknown"
    suffix = file_path.rsplit(".", 1)[-1].lower() if "." in file_path else ""
    return {
        "py": "Python",
        "js": "JavaScript",
        "ts": "TypeScript",
        "java": "Java",
        "go": "Go",
        "yml": "YAML",
        "yaml": "YAML",
        "json": "JSON",
    }.get(suffix, "Unknown")


def remediation_for_category(category: str) -> str:
    return {
        "injection": "Use parameterized queries, input allowlists, and context-aware encoding; then add injection regression tests.",
        "rce": "Remove dynamic execution and command concatenation; use argument arrays, command allowlists, and least-privilege runtime.",
        "secret": "Remove hardcoded credentials, rotate exposed secrets, and use a secret manager or environment injection.",
        "ssrf": "Restrict target protocol, host, and IP ranges; block internal networks and cloud metadata endpoints.",
        "path-traversal": "Pin file operations to a fixed root, normalize paths, and reject '..', absolute paths, and non-allowlisted names.",
        "crypto": "Replace weak algorithms or transport settings with modern crypto and enforce TLS validation.",
        "deserialization": "Avoid deserializing untrusted input; use safer formats such as JSON and add type allowlists.",
    }.get(category, "Follow the rule guidance, add a security regression test, and rescan with SAST.")
