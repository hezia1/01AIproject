from datetime import datetime
from uuid import uuid4

from app.db_models import ComponentRecord, DastValidationRecord, FindingRecord
from app.services.evidence_link_suggestions import (
    build_dast_link_suggestions,
    build_sandbox_link_suggestions,
)


PROJECT_ID = str(uuid4())


def make_finding(
    title: str,
    rule_id: str,
    file_path: str,
    source: str = "SAST",
    severity: str = "high",
    component_id: str | None = None,
    ai_review: dict | None = None,
) -> FindingRecord:
    return FindingRecord(
        id=str(uuid4()),
        project_id=PROJECT_ID,
        component_id=component_id,
        source=source,
        rule_id=rule_id,
        title=title,
        severity=severity,
        file_path=file_path,
        status="open",
        evidence=title,
        ai_review=ai_review,
        created_at=datetime(2026, 7, 26, 10, 0, 0),
        updated_at=datetime(2026, 7, 26, 10, 0, 0),
    )


def test_dast_suggestion_explains_url_and_vulnerability_family_match() -> None:
    matching = make_finding(
        "Login SQL injection",
        "CWE-89",
        "app/login.py",
        ai_review={"cwe": "CWE-89", "category": "sql-injection"},
    )
    unrelated = make_finding("Hardcoded secret", "CWE-798", "settings.py")

    suggestions = build_dast_link_suggestions(
        "https://example.test/login?query=CWE-89",
        [unrelated, matching],
        {},
    )

    assert str(suggestions[0].finding_id) == matching.id
    assert suggestions[0].confidence >= 80
    assert suggestions[0].confidence_level == "high"
    assert any("漏洞类型" in reason for reason in suggestions[0].reasons)
    assert any("风险标识" in reason for reason in suggestions[0].reasons)


def test_sandbox_prefers_traceable_exploitable_validation_with_command_match() -> None:
    finding = make_finding("Command execution in runner", "CWE-78", "agent_runner.py")
    validation = DastValidationRecord(
        id=str(uuid4()),
        project_id=PROJECT_ID,
        finding_id=str(finding.id),
        component_id=None,
        link_source="explicit-selection",
        link_confidence=100,
        target_url="https://example.test/runner",
        verdict="exploitable",
        created_at=datetime(2026, 7, 26, 10, 1, 0),
        updated_at=datetime(2026, 7, 26, 10, 1, 0),
    )

    suggestions = build_sandbox_link_suggestions(
        "python agent_runner.py",
        [finding],
        {},
        [validation],
    )

    assert str(suggestions[0].validation_id) == validation.id
    assert str(suggestions[0].finding_id) == finding.id
    assert suggestions[0].confidence >= 80
    assert any("可利用" in reason for reason in suggestions[0].reasons)


def test_low_signal_candidate_is_not_auto_confirmable() -> None:
    finding = make_finding("Hardcoded secret", "CWE-798", "settings.py", severity="medium")

    suggestions = build_dast_link_suggestions(
        "https://example.test/health",
        [finding],
        {},
    )

    assert suggestions[0].confidence < 80
    assert suggestions[0].confidence_level == "low"
