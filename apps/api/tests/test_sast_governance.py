from datetime import datetime

import pytest

from app.db_models import FindingRecord
from app.services.sast_governance import add_suppression, apply_suppressions, effective_sast_profile, update_sast_profile
from app.services.sast_sarif import build_sast_sarif
from app.services.sast_scanner import scan_source_tree


def test_sast_profile_keeps_a_valid_engine_enabled():
    profile = update_sast_profile({}, {"semgrep_enabled": False, "include_local_rules": True, "semgrep_config": "rules/security.yml"})

    assert profile["semgrep_enabled"] is False
    assert profile["semgrep_config"] == "rules/security.yml"
    with pytest.raises(ValueError, match="At least one SAST engine"):
        update_sast_profile({}, {"semgrep_enabled": False, "include_local_rules": False})


def test_sast_suppression_filters_matching_rule_and_path(tmp_path):
    source = tmp_path / "service.py"
    source.write_text('password = "super-secret"\n', encoding="utf-8")
    finding = scan_source_tree(str(tmp_path)).findings[0]
    profile = add_suppression({}, {"rule_id": finding.rule_id, "path_pattern": "*.py", "reason": "test-only secret"})

    kept, applied = apply_suppressions([finding], profile["suppressions"])

    assert kept == []
    assert applied[0]["rule_id"] == finding.rule_id


def test_sast_sarif_contains_location_and_rule():
    finding = FindingRecord(
        id="a0000000-0000-0000-0000-000000000001",
        project_id="a0000000-0000-0000-0000-000000000002",
        scan_task_id="a0000000-0000-0000-0000-000000000003",
        source="SAST",
        rule_id="SAST.TEST.RULE",
        title="Test finding",
        severity="high",
        file_path="src/app.py",
        line_start=12,
        line_end=12,
        evidence="dangerous call",
        ai_review={"remediation": "Use a safe API."},
        created_at=datetime.now(),
        updated_at=datetime.now(),
    )

    sarif = build_sast_sarif([finding], str(finding.scan_task_id))
    run = sarif["runs"][0]

    assert run["tool"]["driver"]["rules"][0]["id"] == "SAST.TEST.RULE"
    assert run["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "src/app.py"


def test_default_profile_is_safe_and_normalized():
    profile = effective_sast_profile({"sast_profile": {"semgrep_config": "p/default", "suppressions": "invalid"}})

    assert profile["include_local_rules"] is True
    assert profile["suppressions"] == []
