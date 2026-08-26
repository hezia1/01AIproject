from datetime import datetime
from uuid import uuid4

from app.db_models import FindingRecord
from app.services.finding_retest import compare_finding_records


PROJECT_ID = str(uuid4())


def finding(
    rule_id: str,
    title: str,
    line_start: int,
    severity: str = "high",
) -> FindingRecord:
    return FindingRecord(
        id=str(uuid4()),
        project_id=PROJECT_ID,
        scan_task_id=str(uuid4()),
        source="SAST",
        rule_id=rule_id,
        title=title,
        severity=severity,
        file_path="src/app.py",
        line_start=line_start,
        status="open",
        created_at=datetime(2026, 7, 26, 12, 0, 0),
        updated_at=datetime(2026, 7, 26, 12, 0, 0),
    )


def test_retest_comparison_reports_still_present_resolved_new_and_changed() -> None:
    stable_old = finding("sql-injection", "SQL injection", 10)
    resolved = finding("hardcoded-secret", "Hardcoded secret", 20)
    changed_old = finding("command-exec", "Command execution", 30, "high")

    stable_new = finding("sql-injection", "SQL injection", 10)
    added = finding("path-traversal", "Path traversal", 40)
    changed_new = finding("command-exec", "Command execution", 35, "critical")

    items = compare_finding_records(
        [stable_old, resolved, changed_old],
        [stable_new, added, changed_new],
    )
    results = {item.title: item.result for item in items}

    assert results == {
        "SQL injection": "still_present",
        "Hardcoded secret": "resolved",
        "Command execution": "changed",
        "Path traversal": "new",
    }


def test_retest_comparison_preserves_repeated_findings_in_the_same_file() -> None:
    previous = [
        finding("xss", "Unescaped output", 10),
        finding("xss", "Unescaped output", 20),
        finding("xss", "Unescaped output", 40),
    ]
    current = [
        finding("xss", "Unescaped output", 20),
        finding("xss", "Unescaped output", 30),
        finding("xss", "Unescaped output", 50),
        finding("xss", "Unescaped output", 60),
    ]

    items = compare_finding_records(previous, current)

    assert len(items) == 4
    assert sum(item.result == "still_present" for item in items) == 1
    assert sum(item.result == "changed" for item in items) == 2
    assert sum(item.result == "new" for item in items) == 1
    assert sum(item.result in {"still_present", "changed", "new"} for item in items) == len(current)
    assert sum(item.result in {"still_present", "changed", "resolved"} for item in items) == len(previous)
    assert len({item.identity for item in items}) == len(items)
