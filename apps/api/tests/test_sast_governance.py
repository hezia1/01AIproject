from datetime import datetime

import pytest

from app.db_models import FindingRecord
from app.services.sast_governance import add_custom_rule, add_suppression, apply_suppressions, effective_sast_profile, update_sast_profile, validate_custom_rule_payload
from app.services.sast_sarif import build_sast_sarif
from app.services.sast_scanner import scan_source_tree
from app.services.semgrep_scanner import DEFAULT_SEMGREP_IMAGE
from app.routers.sast import sast_quality_gate


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


def test_quality_gate_profile_supports_branch_and_new_finding_policies():
    profile = update_sast_profile({}, {"quality_gate": {"enabled": True, "threshold": "medium", "block_new_only": True, "max_blocking_findings": 2, "branch_patterns": ["main", "release/*"], "excluded_rule_ids": ["SAST.TEST.EXCLUDED"]}})

    assert profile["quality_gate"]["threshold"] == "medium"
    assert profile["quality_gate"]["branch_patterns"] == ["main", "release/*"]
    assert profile["quality_gate"]["block_new_only"] is True


def test_quality_gate_honors_branch_and_maximum_blocking_findings():
    finding = FindingRecord(rule_id="SAST.TEST.RULE", severity="high", file_path="app.py", line_start=1)
    profile = update_sast_profile({}, {"quality_gate": {"enabled": True, "threshold": "high", "max_blocking_findings": 2, "branch_patterns": ["main"]}})

    outside = sast_quality_gate([finding], profile, "feature/demo")
    within_allowance = sast_quality_gate([finding, finding], profile, "main")
    over_allowance = sast_quality_gate([finding, finding, finding], profile, "main")

    assert outside["status"] == "pass"
    assert within_allowance["status"] == "pass"
    assert over_allowance["status"] == "block"


def test_custom_rule_is_validated_and_runs_in_local_scanner(tmp_path):
    payload = {
        "rule_id": "CUSTOM.PROJECT.UNSAFE_LOG",
        "title": "Unsafe debug log",
        "severity": "medium",
        "category": "logging",
        "pattern": r"logger\.debug\(",
        "file_extensions": [".py"],
        "test_sample": "logger.debug('token=%s', token)",
    }
    validation = validate_custom_rule_payload(payload)
    profile = add_custom_rule({}, payload)
    source = tmp_path / "service.py"
    source.write_text("logger.debug('token=%s', token)\n", encoding="utf-8")

    result = scan_source_tree(str(tmp_path), custom_rules=profile["custom_rules"])

    assert validation["test_sample_matched"] is True
    assert [item.rule_id for item in result.findings] == ["CUSTOM.PROJECT.UNSAFE_LOG"]


def test_semgrep_docker_image_is_pinned():
    assert DEFAULT_SEMGREP_IMAGE.startswith("semgrep/semgrep:")
    assert not DEFAULT_SEMGREP_IMAGE.endswith(":latest")
